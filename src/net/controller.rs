use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
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
    IdempotencyConflict { request_key: String, operation_id: String },
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
            Self::IdempotencyConflict { request_key, operation_id } => write!(
                formatter,
                "idempotency key {request_key} conflicts with operation {operation_id}"
            ),
        }
    }
}

impl std::error::Error for ControllerError {}

impl From<StoreError> for ControllerError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::QueueFull => Self::QueueFull,
            StoreError::IdempotencyConflict { request_key, operation_id } => {
                Self::IdempotencyConflict { request_key, operation_id }
            }
            error => Self::Storage(error),
        }
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
    pub connection: &'static str,
}

pub struct SessionRegistry {
    sessions_dir: PathBuf,
    sessions: tokio::sync::Mutex<HashMap<String, SessionController>>,
    resume_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    overflow_resume_lock: Arc<tokio::sync::Mutex<()>>,
}

impl SessionRegistry {
    pub fn new(sessions_dir: impl Into<PathBuf>) -> Self {
        Self {
            sessions_dir: sessions_dir.into(),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
            resume_locks: tokio::sync::Mutex::new(HashMap::new()),
            overflow_resume_lock: Arc::new(tokio::sync::Mutex::new(())),
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
        if let Some(controller) = self.sessions.lock().await.get(session_id).cloned() {
            return Ok(controller);
        }
        let resume_lock = {
            let mut locks = self.resume_locks.lock().await;
            locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            if let Some(lock) = locks.get(session_id) {
                Arc::clone(lock)
            } else if locks.len() < 256 {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(session_id.to_owned(), Arc::clone(&lock));
                lock
            } else {
                Arc::clone(&self.overflow_resume_lock)
            }
        };
        let _resume = resume_lock.lock().await;
        if let Some(controller) = self.sessions.lock().await.get(session_id).cloned() {
            self.resume_locks.lock().await.remove(session_id);
            return Ok(controller);
        }
        let controller = SessionController::resume(&self.sessions_dir.join(session_id)).await?;
        self.sessions
            .lock()
            .await
            .insert(session_id.to_owned(), controller.clone());
        self.resume_locks.lock().await.remove(session_id);
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
    connection: AtomicU8,
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
            connection: AtomicU8::new(ConnectionState::Connected as u8),
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
        let controller = Self::from_parts(ControllerInner {
            session_dir: session_dir.to_owned(),
            controller_id,
            resume_token: meta.controller_resume_token,
            invite: meta.invite,
            store,
            client: tokio::sync::Mutex::new(client),
            dispatcher: tokio::sync::Mutex::new(()),
            connection: AtomicU8::new(ConnectionState::Connected as u8),
        });
        controller.recover_unfinished().await?;
        Ok(controller)
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
        if self
            .inner
            .client
            .try_lock()
            .is_ok_and(|client| !client.is_connected())
        {
            self.inner
                .connection
                .store(ConnectionState::Reconnecting as u8, Ordering::SeqCst);
        }
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
            connection: self.connection_state().as_str(),
        })
    }

    #[cfg(test)]
    fn test_resume_token(&self) -> &str {
        &self.inner.resume_token
    }

    pub async fn disconnect(self) -> Result<(), ControllerError> {
        let _dispatcher = self.inner.dispatcher.lock().await;
        self.inner.client.lock().await.disconnect().await?;
        self.inner
            .connection
            .store(ConnectionState::Disconnected as u8, Ordering::SeqCst);
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

    pub async fn execute_session_operation(
        &self,
        request_key: Option<&str>,
        command: String,
        cwd: Option<PathBuf>,
        remote_timeout: Duration,
        caller_timeout: Duration,
    ) -> Result<OperationReply, ControllerError> {
        self.inner.store.verify_durable()?;
        let allocated = self
            .inner
            .store
            .begin_allocated_operation(
                request_key,
                &command,
                cwd.as_deref(),
                u64::try_from(remote_timeout.as_millis()).unwrap_or(u64::MAX),
            )?;
        if allocated.duplicate {
            if allocated.record.state.is_terminal() {
                return Ok(OperationReply {
                    record: allocated.record,
                });
            }
            return Err(ControllerError::UnknownInProgress {
                operation_id: allocated.record.id,
            });
        }
        self.execute_with_timeout(
            OperationRequest {
                session_id: String::new(),
                operation_id: allocated.record.id,
                command,
                cwd,
                timeout: remote_timeout,
            },
            caller_timeout,
        )
        .await
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
        request: OperationRequest,
    ) -> Result<OperationReply, ControllerError> {
        let _dispatcher = self.inner.dispatcher.lock().await;
        self.inner.store.verify_durable()?;
        match self.inner.store.operation(&request.operation_id) {
            Ok(record) if record.state.is_terminal() => return Ok(OperationReply { record }),
            Ok(record) if record.state == crate::net::protocol::OperationState::Running => {
                return Err(ControllerError::UnknownInProgress {
                    operation_id: record.id,
                });
            }
            Ok(_) => {
                self.inner
                    .store
                    .mark_dispatched_running(&request.operation_id)?;
            }
            Err(StoreError::OperationNotFound(_)) => {
                self.inner
                    .store
                    .begin_operation(&request.operation_id, &request.command)?;
                self.inner
                    .store
                    .mark_dispatched_running(&request.operation_id)?;
            }
            Err(error) => return Err(error.into()),
        }
        self.dispatch_and_wait(request).await
    }

    async fn dispatch_and_wait(
        &self,
        mut request: OperationRequest,
    ) -> Result<OperationReply, ControllerError> {
        let reply_operation_id = request.operation_id.clone();
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
                        // A healthy B has definitively reported not-found. Re-send the
                        // immutable request under the same canonical id; B's ledger
                        // deduplicates a late first packet.
                        request.session_id = self.inner.client.lock().await.session_id().to_owned();
                        match self.inner.client.lock().await.execute(request).await {
                            Ok(reply) => reply,
                            Err(error) => {
                                self.finish_definitive_rejection(
                                    &reply_operation_id,
                                    &error,
                                )?;
                                return Err(error.into());
                            }
                        }
                    }
                }
            }
            Err(error) => {
                self.finish_definitive_rejection(&request.operation_id, &error)?;
                return Err(error.into());
            }
        };
        if reply.record.state.is_terminal() {
            return self.mirror_terminal(&reply.record).map(|record| OperationReply { record });
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let status = self.status_once(&reply.record.id).await;
            match status {
                Ok(record) if record.state.is_terminal() => {
                    let record = self.mirror_terminal(&record)?;
                    return Ok(OperationReply { record });
                }
                Ok(_) => {}
                Err(error) if is_reconnectable(&error) => {
                    match self.reconnect_and_reconcile(&reply.record.id).await? {
                        Some(record) if record.state.is_terminal() => {
                            let record = self.mirror_terminal(&record)?;
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

    async fn recover_unfinished(&self) -> Result<(), ControllerError> {
        for record in self.inner.store.unfinished_operations()? {
            let _dispatcher = self.inner.dispatcher.lock().await;
            let request = request_from_record(&record);
            let recovery = match record.state {
                crate::net::protocol::OperationState::Queued => {
                    self.inner.store.mark_dispatched_running(&record.id)?;
                    self.dispatch_and_wait(request).await
                }
                crate::net::protocol::OperationState::Running => {
                    match self.status_once(&record.id).await {
                        Ok(remote) if remote.state.is_terminal() => self
                            .mirror_terminal(&remote)
                            .map(|record| OperationReply { record }),
                        Ok(remote) => self.poll_remote_to_terminal(&remote.id).await,
                        Err(ShareError::OperationNotFound(_)) => {
                            self.dispatch_and_wait(request).await
                        }
                        Err(error) if is_reconnectable(&error) => {
                            match self.reconnect_and_reconcile(&record.id).await? {
                                Some(remote) if remote.state.is_terminal() => self
                                    .mirror_terminal(&remote)
                                    .map(|record| OperationReply { record }),
                                Some(remote) => self.poll_remote_to_terminal(&remote.id).await,
                                None => self.dispatch_and_wait(request).await,
                            }
                        }
                        Err(error) => Err(error.into()),
                    }
                }
                _ => continue,
            };
            // A definitive rejection is now durable and must not prevent the
            // controller from recovering other operations.
            if recovery.is_err()
                && !self.inner.store.operation(&record.id)?.state.is_terminal()
            {
                recovery?;
            }
        }
        Ok(())
    }

    async fn poll_remote_to_terminal(
        &self,
        operation_id: &str,
    ) -> Result<OperationReply, ControllerError> {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            match self.status_once(operation_id).await {
                Ok(record) if record.state.is_terminal() => {
                    return self
                        .mirror_terminal(&record)
                        .map(|record| OperationReply { record });
                }
                Ok(_) => {}
                Err(error) if is_reconnectable(&error) => {
                    match self.reconnect_and_reconcile(operation_id).await? {
                        Some(record) if record.state.is_terminal() => {
                            return self
                                .mirror_terminal(&record)
                                .map(|record| OperationReply { record });
                        }
                        Some(_) => {}
                        None => {
                            return Err(ControllerError::UnknownInProgress {
                                operation_id: operation_id.to_owned(),
                            });
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn finish_definitive_rejection(
        &self,
        operation_id: &str,
        error: &ShareError,
    ) -> Result<(), ControllerError> {
        if is_reconnectable(error) {
            return Ok(());
        }
        self.inner.store.finish_if_nonterminal_detailed(
            operation_id,
            crate::net::protocol::OperationState::Failed,
            &format!("[error] remote rejected operation: {error}"),
            "",
            "",
            false,
        )?;
        Ok(())
    }

    pub async fn operation_status(
        &self,
        operation_id: &str,
    ) -> Result<crate::net::protocol::OperationRecord, ControllerError> {
        self.inner.store.verify_durable()?;
        Ok(self.inner.store.operation(operation_id)?)
    }

    fn mirror_terminal(
        &self,
        record: &crate::net::protocol::OperationRecord,
    ) -> Result<crate::net::protocol::OperationRecord, ControllerError> {
        Ok(self.inner.store.finish_if_nonterminal_detailed(
            &record.id,
            record.state,
            record.summary.as_deref().unwrap_or_default(),
            &record.stdout,
            &record.stderr,
            record.output_truncated,
        )?)
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
        self.inner
            .connection
            .store(ConnectionState::Reconnecting as u8, Ordering::SeqCst);
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
        self.inner
            .connection
            .store(ConnectionState::Connected as u8, Ordering::SeqCst);
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

    fn connection_state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.inner.connection.load(Ordering::SeqCst))
    }
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum ConnectionState {
    Connected = 0,
    Reconnecting = 1,
    Disconnected = 2,
}

impl ConnectionState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Reconnecting,
            2 => Self::Disconnected,
            _ => Self::Connected,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::Disconnected => "disconnected",
        }
    }
}

fn request_from_record(record: &crate::net::protocol::OperationRecord) -> OperationRequest {
    OperationRequest {
        session_id: String::new(),
        operation_id: record.id.clone(),
        command: record.command.clone(),
        cwd: record.cwd.clone(),
        timeout: Duration::from_millis(if record.remote_timeout_ms == 0 {
            300_000
        } else {
            record.remote_timeout_ms
        }),
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
    use std::time::Duration;

    use crate::net::share::{ShareClient, ShareError, ShareService};
    use crate::server::executor::StdoutTerminalObserver;

    use super::{
        connect_with_backoff, AcquireError, ControllerError, LeaseManager, ReconnectBackoff,
        SessionController, SessionRegistry,
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
    async fn definitive_remote_rejection_is_durable_terminal_and_not_replayed() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        share.test_fill_operation_queue();

        assert!(matches!(
            controller
                .execute_session_operation(
                    Some("rejected"),
                    "printf no".into(),
                    None,
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await,
            Err(ControllerError::QueueFull)
        ));
        let terminal = controller
            .operation_status("op-00000000000000000001")
            .await
            .unwrap();
        assert_eq!(terminal.state, crate::net::protocol::OperationState::Failed);
        let retry = controller
            .execute_session_operation(
                Some("rejected"),
                "printf no".into(),
                None,
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(retry.record, terminal);
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

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_registry_resume_is_coordinated_per_session() {
        let share_root_a = tempfile::tempdir().unwrap();
        let share_root_b = tempfile::tempdir().unwrap();
        let engineer_root = tempfile::tempdir().unwrap();
        let share_a = ShareService::start(
            share_root_a.path(),
            Arc::new(StdoutTerminalObserver),
        )
        .await
        .unwrap();
        let share_b = ShareService::start(
            share_root_b.path(),
            Arc::new(StdoutTerminalObserver),
        )
        .await
        .unwrap();
        let initial = SessionRegistry::new(engineer_root.path());
        let session_a = initial.connect(share_a.invitation()).await.unwrap();
        let session_b = initial.connect(share_b.invitation()).await.unwrap();
        let id_a = session_a.session_id().unwrap().to_owned();
        let id_b = session_b.session_id().unwrap().to_owned();
        drop(session_a);
        drop(session_b);
        drop(initial);

        let resumed = Arc::new(SessionRegistry::new(engineer_root.path()));
        let (first_a, second_a, first_b) = tokio::join!(
            resumed.get(&id_a),
            resumed.get(&id_a),
            resumed.get(&id_b),
        );
        let first_a = first_a.unwrap();
        let second_a = second_a.unwrap();
        let first_b = first_b.unwrap();
        assert_eq!(first_a.controller_id(), second_a.controller_id());
        assert_ne!(first_a.session_id().unwrap(), first_b.session_id().unwrap());
        drop(first_a);
        drop(second_a);
        drop(first_b);
        resumed.disconnect(&id_a).await.unwrap();
        resumed.disconnect(&id_b).await.unwrap();
        share_a.shutdown().await.unwrap();
        share_b.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resume_dispatches_durable_queued_request_once() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let output = share_state.path().join("queued-recovery.txt");
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        let session_dir = controller.session_dir().to_owned();
        let allocated = controller
            .inner
            .store
            .begin_allocated_operation(
                Some("queued-crash"),
                &append_once_command(&output),
                None,
                5_000,
            )
            .unwrap();
        drop(controller);

        let resumed = SessionController::resume(&session_dir).await.unwrap();
        let restored = resumed.operation_status(&allocated.record.id).await.unwrap();
        assert_eq!(restored.state, crate::net::protocol::OperationState::Succeeded);
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "once\n");
        resumed.disconnect().await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resume_resends_same_canonical_id_after_confirmed_remote_not_found() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let output = share_state.path().join("dispatched-recovery.txt");
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        let session_dir = controller.session_dir().to_owned();
        let allocated = controller
            .inner
            .store
            .begin_allocated_operation(
                Some("running-crash"),
                &append_once_command(&output),
                None,
                5_000,
            )
            .unwrap();
        controller
            .inner
            .store
            .mark_dispatched_running(&allocated.record.id)
            .unwrap();
        drop(controller);

        let resumed = SessionController::resume(&session_dir).await.unwrap();
        let restored = resumed.operation_status(&allocated.record.id).await.unwrap();
        assert_eq!(restored.id, allocated.record.id);
        assert_eq!(restored.state, crate::net::protocol::OperationState::Succeeded);
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "once\n");
        resumed.disconnect().await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resume_polls_remote_running_to_terminal_without_replay() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let output = share_state.path().join("remote-running.txt");
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        let session_dir = controller.session_dir().to_owned();
        let operation_id = "op-00000000000000000001";
        let command = delayed_append_command(&output, "once");
        controller
            .inner
            .store
            .begin_allocated_operation(Some("remote-running"), &command, None, 5_000)
            .unwrap();
        controller
            .inner
            .store
            .mark_dispatched_running(operation_id)
            .unwrap();
        let remote = ShareClient::connect_with_credentials(
            share.invitation(),
            controller.controller_id(),
            controller.test_resume_token(),
        )
        .await
        .unwrap();
        let session_id = remote.session_id().to_owned();
        let remote_task = tokio::spawn(async move {
            remote
                .execute(crate::net::share::OperationRequest {
                    session_id,
                    operation_id: operation_id.into(),
                    command,
                    cwd: None,
                    timeout: std::time::Duration::from_secs(5),
                })
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if share.operation_status(operation_id).is_ok_and(|record| {
                    record.state == crate::net::protocol::OperationState::Running
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(controller);

        let resumed = SessionController::resume(&session_dir).await.unwrap();
        let restored = resumed.operation_status(operation_id).await.unwrap();
        assert_eq!(restored.state, crate::net::protocol::OperationState::Succeeded);
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "once\n");
        remote_task.await.unwrap().unwrap();
        resumed.disconnect().await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resume_mirrors_remote_terminal_committed_before_local_crash() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let share = ShareService::start(share_state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let controller = SessionController::connect(engineer_state.path(), share.invitation())
            .await
            .unwrap();
        let session_dir = controller.session_dir().to_owned();
        let operation_id = "op-00000000000000000001";
        controller
            .inner
            .store
            .begin_allocated_operation(Some("terminal-crash"), "printf terminal", None, 5_000)
            .unwrap();
        controller
            .inner
            .store
            .mark_dispatched_running(operation_id)
            .unwrap();
        let remote = ShareClient::connect_with_credentials(
            share.invitation(),
            controller.controller_id(),
            controller.test_resume_token(),
        )
        .await
        .unwrap();
        let remote_record = remote
            .execute(crate::net::share::OperationRequest {
                session_id: remote.session_id().to_owned(),
                operation_id: operation_id.into(),
                command: "printf terminal".into(),
                cwd: None,
                timeout: Duration::from_secs(5),
            })
            .await
            .unwrap()
            .record;
        assert_eq!(remote_record.state, crate::net::protocol::OperationState::Succeeded);
        assert_eq!(
            controller.operation_status(operation_id).await.unwrap().state,
            crate::net::protocol::OperationState::Running
        );
        drop(remote);
        drop(controller);

        let resumed = SessionController::resume(&session_dir).await.unwrap();
        let restored = resumed.operation_status(operation_id).await.unwrap();
        assert_eq!(restored.state, crate::net::protocol::OperationState::Succeeded);
        assert_eq!(restored.stdout, "terminal");
        resumed.disconnect().await.unwrap();
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
