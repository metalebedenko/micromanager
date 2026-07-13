use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::net::protocol::{
    EngineerSessionMeta, LeaseGrant, LeaseMeta, SessionMeta, SESSION_SCHEMA,
};
use crate::net::session_store::{SessionStore, StoreError};
use crate::net::share::{OperationReply, OperationRequest, ShareClient, ShareError};

pub const CONTROLLER_LEASE_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    next: u64,
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self { next: 1 }
    }
}

impl Iterator for ReconnectBackoff {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next;
        self.next = self.next.saturating_mul(2).min(30);
        Some(current)
    }
}

async fn connect_with_backoff<T, Dial, DialFuture, Sleep, SleepFuture>(
    mut dial: Dial,
    mut sleep: Sleep,
) -> Result<T, ControllerError>
where
    Dial: FnMut() -> DialFuture,
    DialFuture: std::future::Future<Output = Result<T, ShareError>>,
    Sleep: FnMut(u64) -> SleepFuture,
    SleepFuture: std::future::Future<Output = ()>,
{
    let mut backoff = ReconnectBackoff::default();
    loop {
        match dial().await {
            Ok(connected) => return Ok(connected),
            Err(ShareError::Busy { expires_at_unix }) => {
                return Err(ControllerError::Busy { expires_at_unix });
            }
            Err(error) if is_reconnectable(&error) => {
                sleep(backoff.next().unwrap_or(30)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn is_reconnectable(error: &ShareError) -> bool {
    matches!(error, ShareError::Transport(_) | ShareError::ReplyLost)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireError {
    Busy { expires_at_unix: u64 },
}

#[derive(Debug, Clone)]
struct LeaseOwner {
    controller_id: String,
    token_hash: String,
    expires_at_unix: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct LeaseManager {
    duration_secs: u64,
    owner: Option<LeaseOwner>,
}

impl LeaseManager {
    #[cfg(test)]
    pub(crate) fn new(duration_secs: u64) -> Self {
        Self {
            duration_secs,
            owner: None,
        }
    }

    pub(crate) fn restore(duration_secs: u64, lease: &LeaseMeta, token_hash: Option<&str>) -> Self {
        let owner =
            lease
                .controller_id
                .as_ref()
                .zip(token_hash)
                .map(|(controller_id, token_hash)| LeaseOwner {
                    controller_id: controller_id.clone(),
                    token_hash: token_hash.to_owned(),
                    expires_at_unix: lease.expires_at_unix,
                });
        Self {
            duration_secs,
            owner,
        }
    }

    pub(crate) fn acquire(
        &mut self,
        now_unix: u64,
        controller_id: &str,
        token_hash: &str,
    ) -> Result<LeaseGrant, AcquireError> {
        if let Some(owner) = &mut self.owner {
            if owner.token_hash == token_hash {
                owner.controller_id = controller_id.to_owned();
                owner.expires_at_unix = now_unix.saturating_add(self.duration_secs);
                return Ok(owner.grant());
            }
            if now_unix < owner.expires_at_unix {
                return Err(AcquireError::Busy {
                    expires_at_unix: owner.expires_at_unix,
                });
            }
        }
        let owner = LeaseOwner {
            controller_id: controller_id.to_owned(),
            token_hash: token_hash.to_owned(),
            expires_at_unix: now_unix.saturating_add(self.duration_secs),
        };
        let grant = owner.grant();
        self.owner = Some(owner);
        Ok(grant)
    }

    pub(crate) fn disconnect(&mut self, token_hash: &str) -> bool {
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.token_hash == token_hash)
        {
            self.owner = None;
            true
        } else {
            false
        }
    }

    pub(crate) fn protect_while_operation_active(&mut self, now_unix: u64) {
        if let Some(owner) = &mut self.owner {
            owner.expires_at_unix = owner
                .expires_at_unix
                .max(now_unix.saturating_add(self.duration_secs));
        }
    }

    pub(crate) fn snapshot(&self) -> (LeaseMeta, Option<String>) {
        match &self.owner {
            Some(owner) => (
                LeaseMeta {
                    controller_id: Some(owner.controller_id.clone()),
                    expires_at_unix: owner.expires_at_unix,
                },
                Some(owner.token_hash.clone()),
            ),
            None => (LeaseMeta::default(), None),
        }
    }
}

impl LeaseOwner {
    fn grant(&self) -> LeaseGrant {
        LeaseGrant {
            controller_id: self.controller_id.clone(),
            expires_at_unix: self.expires_at_unix,
        }
    }
}

#[derive(Debug)]
pub enum ControllerError {
    Busy { expires_at_unix: u64 },
    Reconnecting,
    UnknownInProgress { operation_id: String },
    Storage(StoreError),
    RemoteStorage(String),
    QueueFull,
    Remote(String),
    Transport(String),
    InvalidState(String),
}

impl std::fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy { expires_at_unix } => {
                write!(formatter, "session busy until {expires_at_unix}")
            }
            Self::Reconnecting => formatter.write_str("session is reconnecting"),
            Self::UnknownInProgress { operation_id } => write!(
                formatter,
                "operation {operation_id} is still running after the caller timeout"
            ),
            Self::Storage(error) => error.fmt(formatter),
            Self::RemoteStorage(message) => {
                write!(formatter, "remote session storage unavailable: {message}")
            }
            Self::QueueFull => formatter.write_str("remote operation queue is full"),
            Self::Remote(message) => write!(formatter, "remote session error: {message}"),
            Self::Transport(message) => write!(formatter, "controller transport error: {message}"),
            Self::InvalidState(message) => write!(formatter, "invalid controller state: {message}"),
        }
    }
}

impl std::error::Error for ControllerError {}

impl From<StoreError> for ControllerError {
    fn from(value: StoreError) -> Self {
        Self::Storage(value)
    }
}

impl From<ShareError> for ControllerError {
    fn from(value: ShareError) -> Self {
        match value {
            ShareError::Busy { expires_at_unix } => Self::Busy { expires_at_unix },
            ShareError::RemoteStorage(message) => Self::RemoteStorage(message),
            ShareError::QueueFull => Self::QueueFull,
            ShareError::Remote(message) => Self::Remote(message),
            error => Self::Transport(error.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct SessionController {
    inner: Arc<ControllerInner>,
}

#[derive(Debug, Clone)]
pub struct ControllerStatus {
    pub session_id: String,
    pub queue_len: usize,
    pub lease: LeaseMeta,
    pub last_operation: Option<crate::net::protocol::OperationRecord>,
}

pub struct SessionRegistry {
    sessions_dir: PathBuf,
    sessions: tokio::sync::Mutex<HashMap<String, SessionController>>,
}

impl SessionRegistry {
    pub fn new(sessions_dir: impl Into<PathBuf>) -> Self {
        Self {
            sessions_dir: sessions_dir.into(),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    pub async fn connect(&self, invite: &str) -> Result<SessionController, ControllerError> {
        let controller = SessionController::connect(&self.sessions_dir, invite).await?;
        let session_id = controller.session_id()?.to_owned();
        self.sessions
            .lock()
            .await
            .insert(session_id, controller.clone());
        Ok(controller)
    }

    pub async fn get(&self, session_id: &str) -> Result<SessionController, ControllerError> {
        validate_session_id(session_id)?;
        let mut sessions = self.sessions.lock().await;
        if let Some(controller) = sessions.get(session_id).cloned() {
            return Ok(controller);
        }
        let controller = SessionController::resume(&self.sessions_dir.join(session_id)).await?;
        sessions.insert(session_id.to_owned(), controller.clone());
        Ok(controller)
    }

    pub async fn disconnect(&self, session_id: &str) -> Result<(), ControllerError> {
        let active = { self.sessions.lock().await.remove(session_id) };
        let controller = if let Some(controller) = active {
            controller
        } else {
            self.get(session_id).await?
        };
        controller.disconnect().await
    }
}

struct ControllerInner {
    session_dir: PathBuf,
    controller_id: String,
    resume_token: String,
    invite: String,
    store: SessionStore,
    client: tokio::sync::Mutex<ShareClient>,
    dispatcher: tokio::sync::Mutex<()>,
}

impl SessionController {
    pub async fn connect(sessions_dir: &Path, invite: &str) -> Result<Self, ControllerError> {
        let controller_id = random_id(24);
        let resume_token = random_resume_token();
        let peer = crate::net::decode_invite(invite)
            .map_err(|error| ControllerError::InvalidState(error.to_string()))?
            .addr
            .id
            .to_string();
        let provisional: std::sync::Mutex<Option<(PathBuf, SessionStore)>> =
            std::sync::Mutex::new(None);
        let client = connect_with_backoff(
            || {
                ShareClient::connect_with_credentials_and_hello(
                    invite,
                    &controller_id,
                    &resume_token,
                    |session_id| {
                        let mut provisional = provisional.lock().map_err(|_| {
                            ShareError::Remote("provisional session lock was poisoned".into())
                        })?;
                        let session_dir = sessions_dir.join(session_id);
                        if let Some((existing_dir, _)) = provisional.as_ref() {
                            return if *existing_dir == session_dir {
                                Ok(())
                            } else {
                                Err(ShareError::WrongSession)
                            };
                        }
                        let store = SessionStore::create_engineer(
                            &session_dir,
                            EngineerSessionMeta {
                                schema: SESSION_SCHEMA,
                                session_id: session_id.to_owned(),
                                peer: peer.clone(),
                                invite: invite.to_owned(),
                                controller_resume_token: resume_token.clone(),
                                lease: LeaseMeta {
                                    controller_id: Some(controller_id.clone()),
                                    expires_at_unix: 0,
                                },
                            },
                        )?;
                        *provisional = Some((session_dir, store));
                        Ok(())
                    },
                )
            },
            |delay| tokio::time::sleep(Duration::from_secs(delay)),
        )
        .await?;
        let (session_dir, store) = provisional
            .into_inner()
            .map_err(|_| ControllerError::InvalidState("provisional session lock poisoned".into()))?
            .ok_or_else(|| {
                ControllerError::InvalidState("share omitted the session identity".into())
            })?;
        let SessionMeta::Engineer(mut meta) = store.load_meta()? else {
            return Err(ControllerError::InvalidState(
                "provisional engineer metadata changed role".into(),
            ));
        };
        meta.lease.expires_at_unix = client.lease_grant().expires_at_unix;
        store.save_meta(&SessionMeta::Engineer(meta))?;
        Ok(Self::from_parts(ControllerInner {
            session_dir,
            controller_id,
            resume_token,
            invite: invite.to_owned(),
            store,
            client: tokio::sync::Mutex::new(client),
            dispatcher: tokio::sync::Mutex::new(()),
        }))
    }

    pub async fn resume(session_dir: &Path) -> Result<Self, ControllerError> {
        let store = SessionStore::open(session_dir)?;
        let SessionMeta::Engineer(mut meta) = store.load_meta()? else {
            return Err(ControllerError::InvalidState(
                "share metadata cannot resume an engineer controller".into(),
            ));
        };
        let controller_id = meta
            .lease
            .controller_id
            .clone()
            .ok_or_else(|| ControllerError::InvalidState("controller_id is missing".into()))?;
        let client = connect_with_backoff(
            || {
                ShareClient::connect_with_credentials(
                    &meta.invite,
                    &controller_id,
                    &meta.controller_resume_token,
                )
            },
            |delay| tokio::time::sleep(Duration::from_secs(delay)),
        )
        .await?;
        meta.lease.expires_at_unix = client.lease_grant().expires_at_unix;
        store.save_meta(&SessionMeta::Engineer(meta.clone()))?;
        Ok(Self::from_parts(ControllerInner {
            session_dir: session_dir.to_owned(),
            controller_id,
            resume_token: meta.controller_resume_token,
            invite: meta.invite,
            store,
            client: tokio::sync::Mutex::new(client),
            dispatcher: tokio::sync::Mutex::new(()),
        }))
    }

    fn from_parts(inner: ControllerInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn session_dir(&self) -> &Path {
        &self.inner.session_dir
    }

    pub fn controller_id(&self) -> &str {
        &self.inner.controller_id
    }

    pub fn session_id(&self) -> Result<&str, ControllerError> {
        let SessionMeta::Engineer(meta) = self.inner.store.load_meta()? else {
            return Err(ControllerError::InvalidState(
                "share metadata replaced engineer controller metadata".into(),
            ));
        };
        // The metadata is read from disk, so return the path component owned by the controller.
        self.inner
            .session_dir
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| *value == meta.session_id)
            .ok_or_else(|| ControllerError::InvalidState("session identity mismatch".into()))
    }

    pub fn status(&self) -> Result<ControllerStatus, ControllerError> {
        let SessionMeta::Engineer(meta) = self.inner.store.load_meta()? else {
            return Err(ControllerError::InvalidState(
                "share metadata replaced engineer controller metadata".into(),
            ));
        };
        let status = self.inner.store.status()?;
        Ok(ControllerStatus {
            session_id: meta.session_id,
            queue_len: status.queue_len,
            lease: meta.lease,
            last_operation: status.last_operation,
        })
    }

    #[cfg(test)]
    fn test_resume_token(&self) -> &str {
        &self.inner.resume_token
    }

    pub async fn disconnect(self) -> Result<(), ControllerError> {
        let _dispatcher = self.inner.dispatcher.lock().await;
        self.inner.client.lock().await.disconnect().await?;
        Ok(())
    }

    pub async fn execute_with_timeout(
        &self,
        request: OperationRequest,
        caller_timeout: Duration,
    ) -> Result<OperationReply, ControllerError> {
        let operation_id = request.operation_id.clone();
        let controller = self.clone();
        let mut task = tokio::spawn(async move { controller.execute_inner(request).await });
        match tokio::time::timeout(caller_timeout, &mut task).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(ControllerError::Transport(format!(
                "operation dispatcher failed: {error}"
            ))),
            Err(_) => Err(ControllerError::UnknownInProgress { operation_id }),
        }
    }

    pub async fn execute(
        &self,
        request: OperationRequest,
    ) -> Result<OperationReply, ControllerError> {
        let controller = self.clone();
        tokio::spawn(async move { controller.execute_inner(request).await })
            .await
            .map_err(|error| {
                ControllerError::Transport(format!("operation dispatcher failed: {error}"))
            })?
    }

    async fn execute_inner(
        &self,
        mut request: OperationRequest,
    ) -> Result<OperationReply, ControllerError> {
        let _dispatcher = self.inner.dispatcher.lock().await;
        request.session_id = self.inner.client.lock().await.session_id().to_owned();
        let first = self
            .inner
            .client
            .lock()
            .await
            .execute(request.clone())
            .await;
        let reply = match first {
            Ok(reply) => reply,
            Err(error) if is_reconnectable(&error) => {
                match self.reconnect_and_reconcile(&request.operation_id).await? {
                    Some(record) => OperationReply { record },
                    None => {
                        request.session_id = self.inner.client.lock().await.session_id().to_owned();
                        self.inner.client.lock().await.execute(request).await?
                    }
                }
            }
            Err(error) => return Err(error.into()),
        };
        if reply.record.state.is_terminal() {
            return Ok(reply);
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let status = self.status_once(&reply.record.id).await;
            match status {
                Ok(record) if record.state.is_terminal() => return Ok(OperationReply { record }),
                Ok(_) => {}
                Err(error) if is_reconnectable(&error) => {
                    match self.reconnect_and_reconcile(&reply.record.id).await? {
                        Some(record) if record.state.is_terminal() => {
                            return Ok(OperationReply { record });
                        }
                        Some(_) => {}
                        None => {
                            return Err(ControllerError::InvalidState(format!(
                                "accepted operation {} disappeared during reconnect",
                                reply.record.id
                            )));
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub async fn operation_status(
        &self,
        operation_id: &str,
    ) -> Result<crate::net::protocol::OperationRecord, ControllerError> {
        let status = self.status_once(operation_id).await;
        match status {
            Ok(record) => Ok(record),
            Err(ShareError::OperationNotFound(operation_id)) => Err(ControllerError::Transport(
                ShareError::OperationNotFound(operation_id).to_string(),
            )),
            Err(error) if is_reconnectable(&error) => self
                .reconnect_and_reconcile(operation_id)
                .await?
                .ok_or_else(|| {
                    ControllerError::Transport(
                        ShareError::OperationNotFound(operation_id.to_owned()).to_string(),
                    )
                }),
            Err(error) => Err(error.into()),
        }
    }

    async fn reconnect_and_reconcile(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::net::protocol::OperationRecord>, ControllerError> {
        let mut status_backoff = ReconnectBackoff::default();
        loop {
            self.reconnect().await?;
            let status = self.status_once(operation_id).await;
            match status {
                Ok(record) => return Ok(Some(record)),
                Err(ShareError::OperationNotFound(_)) => return Ok(None),
                Err(ShareError::Busy { expires_at_unix }) => {
                    return Err(ControllerError::Busy { expires_at_unix });
                }
                Err(error) if is_reconnectable(&error) => {
                    tokio::time::sleep(Duration::from_secs(status_backoff.next().unwrap_or(30)))
                        .await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn status_once(
        &self,
        operation_id: &str,
    ) -> Result<crate::net::protocol::OperationRecord, ShareError> {
        if let Ok(client) = self.inner.client.try_lock() {
            return client.operation_status(operation_id).await;
        }
        let client = ShareClient::connect_with_credentials(
            &self.inner.invite,
            &self.inner.controller_id,
            &self.inner.resume_token,
        )
        .await?;
        client.operation_status(operation_id).await
    }

    async fn reconnect(&self) -> Result<(), ControllerError> {
        let client = connect_with_backoff(
            || {
                ShareClient::connect_with_credentials(
                    &self.inner.invite,
                    &self.inner.controller_id,
                    &self.inner.resume_token,
                )
            },
            |delay| tokio::time::sleep(Duration::from_secs(delay)),
        )
        .await?;
        self.persist_lease(&client)?;
        *self.inner.client.lock().await = client;
        Ok(())
    }

    fn persist_lease(&self, client: &ShareClient) -> Result<(), ControllerError> {
        let SessionMeta::Engineer(mut meta) = self.inner.store.load_meta()? else {
            return Err(ControllerError::InvalidState(
                "share metadata replaced engineer controller metadata".into(),
            ));
        };
        meta.lease.controller_id = Some(self.inner.controller_id.clone());
        meta.lease.expires_at_unix = client.lease_grant().expires_at_unix;
        self.inner.store.save_meta(&SessionMeta::Engineer(meta))?;
        Ok(())
    }
}

fn validate_session_id(session_id: &str) -> Result<(), ControllerError> {
    if session_id.is_empty()
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ControllerError::InvalidState(
            "session_id must contain only ASCII letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(())
}

fn random_id(length: usize) -> String {
    use rand::Rng;
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn random_resume_token() -> String {
    use base64::Engine;
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::net::share::{ShareClient, ShareError, ShareService};
    use crate::server::executor::StdoutTerminalObserver;

    use super::{
        connect_with_backoff, AcquireError, ControllerError, LeaseManager, ReconnectBackoff,
        SessionController,
    };

    #[test]
    fn matching_token_renews_before_and_after_expiry() {
        let mut lease = LeaseManager::new(60);
        let first = lease.acquire(100, "controller-a", "hash-a").unwrap();
        assert_eq!(first.expires_at_unix, 160);

        let renewed = lease.acquire(150, "controller-a", "hash-a").unwrap();
        assert_eq!(renewed.expires_at_unix, 210);
        let after_expiry = lease.acquire(300, "controller-a", "hash-a").unwrap();
        assert_eq!(after_expiry.expires_at_unix, 360);
    }

    #[test]
    fn second_controller_is_busy_until_expiry() {
        let mut lease = LeaseManager::new(60);
        lease.acquire(100, "controller-a", "hash-a").unwrap();

        assert_eq!(
            lease.acquire(159, "controller-b", "hash-b"),
            Err(AcquireError::Busy {
                expires_at_unix: 160
            })
        );
        let takeover = lease.acquire(160, "controller-b", "hash-b").unwrap();
        assert_eq!(takeover.controller_id, "controller-b");
    }

    #[test]
    fn old_token_is_busy_after_takeover() {
        let mut lease = LeaseManager::new(60);
        lease.acquire(100, "controller-a", "hash-a").unwrap();
        lease.acquire(160, "controller-b", "hash-b").unwrap();

        assert_eq!(
            lease.acquire(161, "controller-a", "hash-a"),
            Err(AcquireError::Busy {
                expires_at_unix: 220
            })
        );
    }

    #[test]
    fn explicit_disconnect_releases_only_matching_token() {
        let mut lease = LeaseManager::new(60);
        lease.acquire(100, "controller-a", "hash-a").unwrap();
        assert!(!lease.disconnect("hash-b"));
        assert!(lease.disconnect("hash-a"));
        assert!(lease.acquire(101, "controller-b", "hash-b").is_ok());
    }

    #[test]
    fn running_operation_prevents_mid_command_lease_takeover() {
        let mut lease = LeaseManager::new(60);
        lease.acquire(100, "controller-a", "hash-a").unwrap();

        lease.protect_while_operation_active(160);

        assert_eq!(
            lease.acquire(160, "controller-b", "hash-b"),
            Err(AcquireError::Busy {
                expires_at_unix: 220
            })
        );
    }

    #[tokio::test]
    async fn same_controller_reconnects_and_second_controller_is_busy() {
        let share_state = tempfile::tempdir().unwrap();
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let invite = share.invitation().to_owned();

        let first = ShareClient::connect_with_credentials(&invite, "controller-a", "token-a")
            .await
            .unwrap();
        drop(first);
        ShareClient::connect_with_credentials(&invite, "controller-a", "token-a")
            .await
            .unwrap();
        let busy = ShareClient::connect_with_credentials(&invite, "controller-b", "token-b").await;
        assert!(
            matches!(busy, Err(ShareError::Busy { .. })),
            "unexpected result: {:?}",
            busy.as_ref().err()
        );
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn lease_takeover_uses_injected_clock_and_invalidates_old_token() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let share_state = tempfile::tempdir().unwrap();
        let now = Arc::new(AtomicU64::new(100));
        let clock_now = Arc::clone(&now);
        let clock: Arc<dyn Fn() -> u64 + Send + Sync> =
            Arc::new(move || clock_now.load(Ordering::SeqCst));
        let share = ShareService::start_with_clock(
            share_state.path(),
            Arc::new(StdoutTerminalObserver),
            clock,
        )
        .await
        .unwrap();
        let invite = share.invitation().to_owned();

        let old = ShareClient::connect_with_credentials(&invite, "controller-a", "token-a")
            .await
            .unwrap();
        assert!(matches!(
            ShareClient::connect_with_credentials(&invite, "controller-b", "token-b").await,
            Err(ShareError::Busy {
                expires_at_unix: 160
            })
        ));

        now.store(160, Ordering::SeqCst);
        ShareClient::connect_with_credentials(&invite, "controller-b", "token-b")
            .await
            .unwrap();
        assert!(matches!(
            old.operation_status("missing").await,
            Err(ShareError::Busy {
                expires_at_unix: 220
            })
        ));
        assert!(matches!(
            ShareClient::connect_with_credentials(&invite, "controller-a", "token-a").await,
            Err(ShareError::Busy {
                expires_at_unix: 220
            })
        ));
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn running_command_blocks_takeover_after_nominal_lease_expiry() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let share_state = tempfile::tempdir().unwrap();
        let output = share_state.path().join("lease-running.txt");
        let now = Arc::new(AtomicU64::new(100));
        let clock_now = Arc::clone(&now);
        let clock: Arc<dyn Fn() -> u64 + Send + Sync> =
            Arc::new(move || clock_now.load(Ordering::SeqCst));
        let share = ShareService::start_with_clock(
            share_state.path(),
            Arc::new(StdoutTerminalObserver),
            clock,
        )
        .await
        .unwrap();
        let invite = share.invitation().to_owned();
        let first = ShareClient::connect_with_credentials(&invite, "controller-a", "token-a")
            .await
            .unwrap();
        let operation = crate::net::share::OperationRequest {
            session_id: first.session_id().to_owned(),
            operation_id: "lease-running-op".into(),
            command: delayed_append_command(&output, "done"),
            cwd: None,
            timeout: std::time::Duration::from_secs(5),
        };
        let running = tokio::spawn(async move { first.execute(operation).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if share
                    .operation_status("lease-running-op")
                    .is_ok_and(|record| {
                        record.state == crate::net::protocol::OperationState::Running
                    })
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        now.store(160, Ordering::SeqCst);
        assert!(matches!(
            ShareClient::connect_with_credentials(&invite, "controller-b", "token-b").await,
            Err(ShareError::Busy {
                expires_at_unix: 220
            })
        ));
        assert_eq!(
            running.await.unwrap().unwrap().record.state,
            crate::net::protocol::OperationState::Succeeded
        );
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn restarted_serve_resumes_with_durable_token() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        let session_dir = controller.session_dir().to_owned();
        let controller_id = controller.controller_id().to_owned();
        let token = controller.test_resume_token().to_owned();
        let share_meta = std::fs::read_to_string(
            share_state
                .path()
                .join(share.session_id())
                .join("share-meta.json"),
        )
        .unwrap();
        assert!(
            !share_meta.contains(&token),
            "share metadata must never persist the plaintext resume token"
        );
        let crate::net::protocol::SessionMeta::Share(meta) =
            serde_json::from_str(&share_meta).unwrap()
        else {
            panic!("expected share metadata");
        };
        assert!(meta.controller_token_hash.is_some());
        drop(controller);

        let resumed = SessionController::resume(&session_dir).await.unwrap();

        assert_eq!(resumed.controller_id(), controller_id);
        assert_eq!(resumed.test_resume_token(), token);
        resumed.disconnect().await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn lost_first_lease_grant_retries_with_the_same_resume_token() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        share.test_drop_next_lease_reply();
        let engineer_path = engineer_state.path().to_owned();
        let invite = share.invitation().to_owned();
        let connect =
            tokio::spawn(async move { SessionController::connect(&engineer_path, &invite).await });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !connect.is_finished(),
            "injected lost grant must still be waiting for retry"
        );
        let provisional_meta_exists = std::fs::read_dir(engineer_state.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.path().join("engineer-meta.json").is_file());
        assert!(
            provisional_meta_exists,
            "resume token must be durable before LeaseGranted is received"
        );

        let controller = connect.await.unwrap().unwrap();

        assert!(!controller.test_resume_token().is_empty());
        controller.disconnect().await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[test]
    fn reconnect_backoff_is_capped_at_thirty_seconds() {
        assert_eq!(
            ReconnectBackoff::default().take(8).collect::<Vec<_>>(),
            [1, 2, 4, 8, 16, 30, 30, 30]
        );
    }

    #[tokio::test]
    async fn reconnect_dialer_observes_capped_backoff_without_wall_clock_sleep() {
        let mut attempts = 0;
        let delays = std::sync::Mutex::new(Vec::new());

        let connected = connect_with_backoff(
            || {
                attempts += 1;
                std::future::ready(if attempts <= 6 {
                    Err(ShareError::Transport("injected disconnect".into()))
                } else {
                    Ok("connected")
                })
            },
            |delay| {
                delays.lock().unwrap().push(delay);
                std::future::ready(())
            },
        )
        .await
        .unwrap();

        assert_eq!(connected, "connected");
        assert_eq!(*delays.lock().unwrap(), [1, 2, 4, 8, 16, 30]);
    }

    #[tokio::test]
    async fn lost_reply_reconnects_without_duplicate_side_effect() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let output = share_state.path().join("controller-once.txt");
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        share.test_drop_next_operation_reply();
        let operation = crate::net::share::OperationRequest {
            session_id: String::new(),
            operation_id: "controller-op-once".into(),
            command: append_once_command(&output),
            cwd: None,
            timeout: std::time::Duration::from_secs(5),
        };

        let reply = controller.execute(operation).await.unwrap();

        assert_eq!(
            reply.record.state,
            crate::net::protocol::OperationState::Succeeded
        );
        assert_eq!(
            std::fs::read_to_string(output)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["once"]
        );
        controller.disconnect().await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn caller_timeout_keeps_remote_operation_and_command_order_alive() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let output = share_state.path().join("controller-order.txt");
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        let first = crate::net::share::OperationRequest {
            session_id: String::new(),
            operation_id: "controller-slow-first".into(),
            command: delayed_append_command(&output, "first"),
            cwd: None,
            timeout: std::time::Duration::from_secs(5),
        };

        let timeout = controller
            .execute_with_timeout(first, std::time::Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(matches!(
            timeout,
            ControllerError::UnknownInProgress { ref operation_id }
                if operation_id == "controller-slow-first"
        ));
        let running = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            controller.operation_status("controller-slow-first"),
        )
        .await
        .expect("status must use an independent connection while execute is waiting")
        .unwrap();
        assert_eq!(running.state, crate::net::protocol::OperationState::Running);

        let second = crate::net::share::OperationRequest {
            session_id: String::new(),
            operation_id: "controller-second".into(),
            command: append_value_command(&output, "second"),
            cwd: None,
            timeout: std::time::Duration::from_secs(5),
        };
        let reply = controller.execute(second).await.unwrap();

        assert_eq!(
            reply.record.state,
            crate::net::protocol::OperationState::Succeeded
        );
        assert_eq!(
            std::fs::read_to_string(output)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        controller.disconnect().await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    fn append_once_command(path: &std::path::Path) -> String {
        format!("printf 'once\\n' >> '{}'", path.display())
    }

    #[cfg(unix)]
    fn delayed_append_command(path: &std::path::Path, value: &str) -> String {
        format!("sleep 0.2; printf '{value}\\n' >> '{}'", path.display())
    }

    #[cfg(unix)]
    fn append_value_command(path: &std::path::Path, value: &str) -> String {
        format!("printf '{value}\\n' >> '{}'", path.display())
    }

    #[cfg(windows)]
    fn append_once_command(path: &std::path::Path) -> String {
        let path = path.display().to_string().replace('\'', "''");
        format!("Add-Content -LiteralPath '{path}' -Value 'once'")
    }

    #[cfg(windows)]
    fn delayed_append_command(path: &std::path::Path, value: &str) -> String {
        let path = path.display().to_string().replace('\'', "''");
        format!("Start-Sleep -Milliseconds 200; Add-Content -LiteralPath '{path}' -Value '{value}'")
    }

    #[cfg(windows)]
    fn append_value_command(path: &std::path::Path, value: &str) -> String {
        let path = path.display().to_string().replace('\'', "''");
        format!("Add-Content -LiteralPath '{path}' -Value '{value}'")
    }
}
