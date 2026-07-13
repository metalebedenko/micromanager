use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{endpoint::Connection, Endpoint};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::net::auth::{
    client_handshake, server_share_handshake, HandshakeOutcome, ShareAuthenticator,
};
use crate::net::protocol::{
    LeaseMeta, OperationRecord, OperationState, ShareSessionMeta, SESSION_SCHEMA,
};
use crate::net::session_store::{SessionStore, StoreError};
use crate::server::executor::{ExecRequest, Executor, TerminalObserver, WaitOutcome};

const SHARE_ALPN: &[u8] = b"micromanager/share/1";
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_FRAME_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    pub session_id: String,
    pub operation_id: String,
    pub command: String,
    pub cwd: Option<PathBuf>,
    #[serde(with = "duration_millis")]
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReply {
    pub record: OperationRecord,
}

#[derive(Debug)]
pub enum ShareError {
    Inactive,
    InvalidInvitation,
    WrongSession,
    Store(StoreError),
    Executor(String),
    Transport(String),
    ReplyLost,
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => formatter.write_str("share session is no longer active"),
            Self::InvalidInvitation => formatter.write_str("invalid share invitation"),
            Self::WrongSession => formatter.write_str("operation belongs to another session"),
            Self::Store(error) => error.fmt(formatter),
            Self::Executor(message) => write!(formatter, "executor error: {message}"),
            Self::Transport(message) => write!(formatter, "share transport error: {message}"),
            Self::ReplyLost => formatter.write_str("operation reply channel closed"),
        }
    }
}

impl std::error::Error for ShareError {}

impl From<StoreError> for ShareError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

pub struct ShareService {
    inner: Arc<ShareInner>,
}

pub struct ShareClient {
    session_id: String,
    streams: tokio::sync::Mutex<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)>,
    _endpoint: Endpoint,
    _connection: Connection,
}

struct ShareInner {
    session_id: String,
    invitation: String,
    active: AtomicBool,
    store: Arc<SessionStore>,
    executor: Executor,
    running: Mutex<HashSet<String>>,
    endpoint: Endpoint,
    authenticator: Arc<ShareAuthenticator>,
    accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    drop_next_operation_reply: AtomicBool,
    lifecycle: tokio::sync::Mutex<()>,
    owners: AtomicUsize,
    cleanup_started: AtomicBool,
    cleanup_result: tokio::sync::Mutex<Option<Result<(), String>>>,
    cleanup_notify: tokio::sync::Notify,
    connection_slots: Arc<tokio::sync::Semaphore>,
    runtime: tokio::runtime::Handle,
}

#[derive(Debug, Serialize, Deserialize)]
enum WireRequest {
    Execute(OperationRequest),
    Status { operation_id: String },
}

#[derive(Debug, Serialize, Deserialize)]
enum WireReply {
    Hello { session_id: String },
    Operation(OperationReply),
    Error { message: String },
}

pub async fn run_share() -> anyhow::Result<()> {
    let sessions_dir = crate::paths::state_path("sessions");
    let share = ShareService::start(
        &sessions_dir,
        Arc::new(crate::server::executor::StdoutTerminalObserver),
    )
    .await?;
    println!("=== micromanager: удалённая помощь активна ===");
    println!("Код подключения:\n{}", share.invitation());
    eprintln!("[micromanager] Команды и краткий итог будут видны здесь. `c` + Enter — повторить код, Ctrl-C — немедленно завершить доступ.");

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let loop_result: anyhow::Result<()> = loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                break signal.map_err(Into::into);
            }
            line = lines.next_line() => match line {
                Err(error) => break Err(error.into()),
                Ok(Some(line)) if line.trim().eq_ignore_ascii_case("c") => {
                    println!("Код подключения (тот же активный сеанс):\n{}", share.invitation());
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    break tokio::signal::ctrl_c().await.map_err(Into::into);
                }
            }
        }
    };
    let shutdown_result = share.shutdown().await;
    loop_result?;
    shutdown_result?;
    eprintln!("[micromanager] удалённая помощь завершена; код отозван.");
    Ok(())
}

impl ShareService {
    pub async fn start(
        sessions_dir: &Path,
        observer: Arc<dyn TerminalObserver>,
    ) -> Result<Self, ShareError> {
        reconcile_abandoned_sessions(sessions_dir)?;
        let session_id = random_token(24);
        let session_dir = sessions_dir.join(&session_id);
        let store = SessionStore::create_share(
            &session_dir,
            ShareSessionMeta {
                schema: SESSION_SCHEMA,
                session_id: session_id.clone(),
                lease: LeaseMeta::default(),
                controller_token_hash: None,
            },
        )?;
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![SHARE_ALPN.to_vec()])
            .bind()
            .await
            .map_err(transport)?;
        let secret = random_token(32);
        let invitation = crate::net::encode_invite(&crate::net::Invite {
            addr: endpoint.addr(),
            secret: secret.clone(),
            remember: false,
        });
        let inner = Arc::new(ShareInner {
            session_id,
            invitation,
            active: AtomicBool::new(true),
            store: Arc::new(store),
            executor: Executor::new(observer),
            running: Mutex::new(HashSet::new()),
            endpoint,
            authenticator: Arc::new(ShareAuthenticator::new(secret)),
            accept_task: Mutex::new(None),
            drop_next_operation_reply: AtomicBool::new(false),
            lifecycle: tokio::sync::Mutex::new(()),
            owners: AtomicUsize::new(1),
            cleanup_started: AtomicBool::new(false),
            cleanup_result: tokio::sync::Mutex::new(None),
            cleanup_notify: tokio::sync::Notify::new(),
            connection_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            runtime: tokio::runtime::Handle::current(),
        });
        let task = tokio::spawn(accept_loop(Arc::clone(&inner)));
        *inner
            .accept_task
            .lock()
            .map_err(|_| ShareError::Transport("accept task lock was poisoned".into()))? =
            Some(task);
        Ok(Self { inner })
    }

    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn invitation(&self) -> &str {
        &self.inner.invitation
    }

    pub async fn connect(&self, invitation: &str) -> Result<ShareClient, ShareError> {
        if !self.inner.active.load(Ordering::SeqCst) {
            return Err(ShareError::Inactive);
        }
        ShareClient::connect(invitation).await
    }

    pub fn operation_status(&self, operation_id: &str) -> Result<OperationRecord, ShareError> {
        Ok(self.inner.store.operation(operation_id)?)
    }

    #[cfg(test)]
    fn test_drop_next_operation_reply(&self) {
        self.inner
            .drop_next_operation_reply
            .store(true, Ordering::SeqCst);
    }

    pub async fn shutdown(&self) -> Result<(), ShareError> {
        self.inner.active.store(false, Ordering::SeqCst);
        self.inner.authenticator.revoke();
        initiate_cleanup(&self.inner, &tokio::runtime::Handle::current());
        await_cleanup(&self.inner).await
    }
}

impl Clone for ShareService {
    fn clone(&self) -> Self {
        self.inner.owners.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for ShareService {
    fn drop(&mut self) {
        if self.inner.owners.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        self.inner.active.store(false, Ordering::SeqCst);
        self.inner.authenticator.revoke();
        initiate_cleanup(&self.inner, &self.inner.runtime);
    }
}

fn initiate_cleanup(inner: &Arc<ShareInner>, runtime: &tokio::runtime::Handle) {
    if inner.cleanup_started.swap(true, Ordering::SeqCst) {
        return;
    }
    let inner = Arc::clone(inner);
    runtime.spawn(async move {
        let result = cleanup(Arc::clone(&inner))
            .await
            .map_err(|error| error.to_string());
        *inner.cleanup_result.lock().await = Some(result);
        inner.cleanup_notify.notify_waiters();
    });
}

async fn await_cleanup(inner: &ShareInner) -> Result<(), ShareError> {
    loop {
        let notified = inner.cleanup_notify.notified();
        if let Some(result) = inner.cleanup_result.lock().await.clone() {
            return result.map_err(ShareError::Executor);
        }
        notified.await;
    }
}

async fn cleanup(inner: Arc<ShareInner>) -> Result<(), ShareError> {
    let _lifecycle = inner.lifecycle.lock().await;
    let mut errors = Vec::new();
    inner.endpoint.close().await;
    let termination_failed = match inner.executor.shutdown().await {
        Ok(()) => false,
        Err(error) => {
            errors.push(error.to_string());
            true
        }
    };
    let (shutdown_state, shutdown_summary) = shutdown_terminal_state(termination_failed);
    let running: Vec<_> = match inner.running.lock() {
        Ok(running) => running.iter().cloned().collect(),
        Err(_) => {
            errors.push("running operation registry was poisoned".into());
            Vec::new()
        }
    };
    for operation_id in running {
        if let Err(error) = finish_if_running(
            &inner.store,
            &operation_id,
            shutdown_state,
            shutdown_summary,
            "",
        ) {
            errors.push(error.to_string());
        }
    }
    let accept_task = match inner.accept_task.lock() {
        Ok(mut task) => task.take(),
        Err(_) => {
            errors.push("accept task lock was poisoned".into());
            None
        }
    };
    if let Some(task) = accept_task {
        let _ = task.await;
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ShareError::Executor(errors.join("; ")))
    }
}

fn shutdown_terminal_state(termination_failed: bool) -> (OperationState, &'static str) {
    if termination_failed {
        (
            OperationState::Interrupted,
            "[error] interrupted: process termination could not be confirmed",
        )
    } else {
        (
            OperationState::Cancelled,
            "[error] cancelled: share stopped",
        )
    }
}

impl ShareClient {
    pub async fn connect(invitation: &str) -> Result<Self, ShareError> {
        let invite =
            crate::net::decode_invite(invitation).map_err(|_| ShareError::InvalidInvitation)?;
        let endpoint = Endpoint::bind(presets::Minimal).await.map_err(transport)?;
        let connection = endpoint
            .connect(invite.addr, SHARE_ALPN)
            .await
            .map_err(transport)?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(transport)?;
        match client_handshake(&mut send, &mut recv, &invite.secret)
            .await
            .map_err(transport)?
        {
            HandshakeOutcome::Ok(_) => {}
            _ => return Err(ShareError::InvalidInvitation),
        }
        let hello: WireReply = read_frame(&mut recv).await?;
        let WireReply::Hello { session_id } = hello else {
            return Err(ShareError::Transport(
                "share did not send session hello".into(),
            ));
        };
        Ok(Self {
            session_id,
            streams: tokio::sync::Mutex::new((send, recv)),
            _endpoint: endpoint,
            _connection: connection,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub async fn execute(&self, request: OperationRequest) -> Result<OperationReply, ShareError> {
        let reply = self.call(WireRequest::Execute(request)).await?;
        match reply {
            WireReply::Operation(reply) => Ok(reply),
            WireReply::Error { message } => Err(ShareError::Transport(message)),
            WireReply::Hello { .. } => {
                Err(ShareError::Transport("unexpected session hello".into()))
            }
        }
    }

    pub async fn operation_status(
        &self,
        operation_id: &str,
    ) -> Result<OperationRecord, ShareError> {
        let reply = self
            .call(WireRequest::Status {
                operation_id: operation_id.to_owned(),
            })
            .await?;
        match reply {
            WireReply::Operation(reply) => Ok(reply.record),
            WireReply::Error { message } => Err(ShareError::Transport(message)),
            WireReply::Hello { .. } => {
                Err(ShareError::Transport("unexpected session hello".into()))
            }
        }
    }

    async fn call(&self, request: WireRequest) -> Result<WireReply, ShareError> {
        let mut streams = self.streams.lock().await;
        write_frame(&mut streams.0, &request).await?;
        read_frame(&mut streams.1).await
    }
}

async fn accept_loop(inner: Arc<ShareInner>) {
    while inner.active.load(Ordering::SeqCst) {
        let permit = match Arc::clone(&inner.connection_slots).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        let Some(incoming) = inner.endpoint.accept().await else {
            break;
        };
        let connection_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_connection(connection_inner, incoming).await;
        });
    }
}

async fn handle_connection(
    inner: Arc<ShareInner>,
    incoming: iroh::endpoint::Incoming,
) -> Result<(), ShareError> {
    let (_connection, mut send, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let connection = incoming.await.map_err(transport)?;
        let (mut send, mut recv) = connection.accept_bi().await.map_err(transport)?;
        if !server_share_handshake(&mut recv, &mut send, &inner.authenticator)
            .await
            .map_err(transport)?
        {
            return Err(ShareError::InvalidInvitation);
        }
        Ok::<_, ShareError>((connection, send, recv))
    })
    .await
    .map_err(|_| ShareError::Transport("share handshake timed out".into()))??;
    write_frame(
        &mut send,
        &WireReply::Hello {
            session_id: inner.session_id.clone(),
        },
    )
    .await?;
    loop {
        let request: WireRequest =
            match tokio::time::timeout(IDLE_FRAME_TIMEOUT, read_frame(&mut recv)).await {
                Ok(Ok(request)) => request,
                Ok(Err(_)) | Err(_) => return Ok(()),
            };
        let reply = match request {
            WireRequest::Execute(request) => match inner.execute(request).await {
                Ok(reply) => WireReply::Operation(reply),
                Err(error) => WireReply::Error {
                    message: error.to_string(),
                },
            },
            WireRequest::Status { operation_id } => match inner.store.operation(&operation_id) {
                Ok(record) => WireReply::Operation(OperationReply { record }),
                Err(error) => WireReply::Error {
                    message: error.to_string(),
                },
            },
        };
        if matches!(reply, WireReply::Operation(_))
            && inner
                .drop_next_operation_reply
                .swap(false, Ordering::SeqCst)
        {
            return Ok(());
        }
        write_frame(&mut send, &reply).await?;
    }
}

impl ShareInner {
    async fn execute(
        self: &Arc<Self>,
        request: OperationRequest,
    ) -> Result<OperationReply, ShareError> {
        let lifecycle = self.lifecycle.lock().await;
        if !self.active.load(Ordering::SeqCst) {
            return Err(ShareError::Inactive);
        }
        if request.session_id != self.session_id {
            return Err(ShareError::WrongSession);
        }
        match self
            .store
            .begin_operation(&request.operation_id, &request.command)
        {
            Ok(_) => {}
            Err(StoreError::Duplicate(record)) => return Ok(OperationReply { record: *record }),
            Err(error) => return Err(error.into()),
        }
        self.store.mark_running(&request.operation_id)?;

        let exec_request = ExecRequest {
            command: request.command,
            cwd: request.cwd,
            timeout: request.timeout,
        };
        let mut running = match self.executor.start(exec_request) {
            Ok(running) => running,
            Err(error) => {
                let record = self.store.finish_operation(
                    &request.operation_id,
                    OperationState::Failed,
                    &format!("[error] {error}"),
                    "",
                )?;
                return Ok(OperationReply { record });
            }
        };
        self.running
            .lock()
            .map_err(|_| ShareError::Executor("running operation registry was poisoned".into()))?
            .insert(request.operation_id.clone());
        drop(lifecycle);

        let (reply_send, reply_recv) = tokio::sync::oneshot::channel();
        let inner = Arc::clone(self);
        let operation_id = request.operation_id;
        tokio::spawn(async move {
            let first = running.wait().await;
            match first {
                Ok(WaitOutcome::Finished(result)) => {
                    let record = persist_exec_result(&inner, &operation_id, result);
                    let _ = reply_send.send(record);
                }
                Ok(WaitOutcome::TimedOut) => {
                    let current = inner
                        .store
                        .operation(&operation_id)
                        .map_err(ShareError::from);
                    let _ = reply_send.send(current);
                    let terminal = running.wait_for_completion().await;
                    persist_wait_result(&inner, &operation_id, terminal);
                }
                Err(error) => {
                    let record = persist_wait_error(&inner, &operation_id, error.to_string());
                    let _ = reply_send.send(record);
                }
            }
            if let Ok(mut active) = inner.running.lock() {
                active.remove(&operation_id);
            }
        });

        let record = reply_recv.await.map_err(|_| ShareError::ReplyLost)??;
        Ok(OperationReply { record })
    }
}

fn persist_wait_result(
    inner: &ShareInner,
    operation_id: &str,
    result: Result<crate::server::executor::ExecResult, crate::server::executor::ExecError>,
) {
    match result {
        Ok(result) => {
            let _ = persist_exec_result(inner, operation_id, result);
        }
        Err(error) => {
            let _ = persist_wait_error(inner, operation_id, error.to_string());
        }
    }
}

fn persist_exec_result(
    inner: &ShareInner,
    operation_id: &str,
    result: crate::server::executor::ExecResult,
) -> Result<OperationRecord, ShareError> {
    let state = if !inner.active.load(Ordering::SeqCst) {
        OperationState::Cancelled
    } else if result.exit_code == Some(0) {
        OperationState::Succeeded
    } else {
        OperationState::Failed
    };
    finish_if_running(
        &inner.store,
        operation_id,
        state,
        &result.summary,
        &result.output,
    )
}

fn persist_wait_error(
    inner: &ShareInner,
    operation_id: &str,
    message: String,
) -> Result<OperationRecord, ShareError> {
    let state = if inner.active.load(Ordering::SeqCst) {
        OperationState::Failed
    } else {
        OperationState::Cancelled
    };
    finish_if_running(
        &inner.store,
        operation_id,
        state,
        &format!("[error] {message}"),
        "",
    )
}

fn finish_if_running(
    store: &SessionStore,
    operation_id: &str,
    state: OperationState,
    summary: &str,
    output: &str,
) -> Result<OperationRecord, ShareError> {
    Ok(store.finish_if_nonterminal(operation_id, state, summary, output)?)
}

fn random_token(length: usize) -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn reconcile_abandoned_sessions(sessions_dir: &Path) -> Result<(), ShareError> {
    if !sessions_dir.exists() {
        return Ok(());
    }
    let entries = std::fs::read_dir(sessions_dir).map_err(transport)?;
    for entry in entries {
        let entry = entry.map_err(transport)?;
        if !entry.file_type().map_err(transport)?.is_dir() {
            continue;
        }
        match SessionStore::open(&entry.path()) {
            Ok(store) => {
                if matches!(
                    store.load_meta()?,
                    crate::net::protocol::SessionMeta::Share(_)
                ) {
                    store.reconcile_unfinished()?;
                }
            }
            Err(StoreError::Locked) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), ShareError>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).map_err(transport)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ShareError::Transport("share frame is too large".into()));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| ShareError::Transport("share frame length overflow".into()))?;
    writer.write_u32(length).await.map_err(transport)?;
    writer.write_all(&bytes).await.map_err(transport)?;
    writer.flush().await.map_err(transport)
}

async fn read_frame<R, T>(reader: &mut R) -> Result<T, ShareError>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let length = reader.read_u32().await.map_err(transport)? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ShareError::Transport("share frame is too large".into()));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await.map_err(transport)?;
    serde_json::from_slice(&bytes).map_err(transport)
}

fn transport(error: impl std::fmt::Display) -> ShareError {
    ShareError::Transport(error.to_string())
}

mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let millis = u64::try_from(duration.as_millis()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(millis)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Duration::from_millis(u64::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::net::protocol::OperationState;
    use crate::server::executor::StdoutTerminalObserver;

    use super::{shutdown_terminal_state, OperationRequest, ShareService};

    fn request(id: &str, command: String) -> OperationRequest {
        OperationRequest {
            session_id: String::new(),
            operation_id: id.to_owned(),
            command,
            cwd: None,
            timeout: Duration::from_secs(5),
        }
    }

    #[cfg(unix)]
    fn append_once_command(path: &std::path::Path) -> String {
        format!("printf 'once\\n' >> '{}'", path.display())
    }

    #[cfg(windows)]
    fn append_once_command(path: &std::path::Path) -> String {
        let path = path.display().to_string().replace('\'', "''");
        format!("Add-Content -LiteralPath '{path}' -Value 'once'")
    }

    #[cfg(unix)]
    fn long_sleep_command() -> String {
        "sleep 30".into()
    }

    #[cfg(windows)]
    fn long_sleep_command() -> String {
        "Start-Sleep -Seconds 30".into()
    }

    #[cfg(unix)]
    fn short_sleep_command() -> String {
        "sleep 0.2".into()
    }

    #[cfg(windows)]
    fn short_sleep_command() -> String {
        "Start-Sleep -Milliseconds 200".into()
    }

    fn assert_one_line(path: &std::path::Path) {
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content.lines().collect::<Vec<_>>(), ["once"]);
    }

    #[cfg(unix)]
    fn create_forbidden_command(path: &std::path::Path) -> String {
        format!("printf forbidden > '{}'", path.display())
    }

    #[cfg(windows)]
    fn create_forbidden_command(path: &std::path::Path) -> String {
        let path = path.display().to_string().replace('\'', "''");
        format!("Set-Content -LiteralPath '{path}' -Value 'forbidden'")
    }

    #[tokio::test]
    async fn same_invite_reconnects_while_share_is_alive() {
        let state = tempfile::tempdir().unwrap();
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let invite = share.invitation().to_owned();
        assert!(crate::net::decode_invite(&invite).is_ok());

        let first = share.connect(&invite).await.unwrap();
        drop(first);
        let second = share.connect(&invite).await.unwrap();

        assert_eq!(second.session_id(), share.session_id());
        assert_eq!(share.invitation(), invite);
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn repeated_operation_id_executes_side_effect_once() {
        let state = tempfile::tempdir().unwrap();
        let output = state.path().join("side-effect.txt");
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let client = share.connect(share.invitation()).await.unwrap();
        let command = append_once_command(&output);
        let mut operation = request("op-once", command);
        operation.session_id = share.session_id().to_owned();

        let first = client.execute(operation.clone()).await.unwrap();
        let duplicate = client.execute(operation).await.unwrap();

        assert_eq!(first.record, duplicate.record);
        assert_eq!(first.record.state, OperationState::Succeeded);
        assert_one_line(&output);
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_revokes_invite_and_cancels_running_operation() {
        let state = tempfile::tempdir().unwrap();
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let invite = share.invitation().to_owned();
        let client = share.connect(&invite).await.unwrap();
        let mut operation = request("op-running", long_sleep_command());
        operation.session_id = share.session_id().to_owned();
        operation.timeout = Duration::from_millis(50);

        let running = client.execute(operation).await.unwrap();
        assert_eq!(running.record.state, OperationState::Running);
        share.shutdown().await.unwrap();

        assert!(share.connect(&invite).await.is_err());
        assert_eq!(
            share.operation_status("op-running").unwrap().state,
            OperationState::Cancelled
        );
    }

    #[tokio::test]
    async fn lost_reply_after_durable_result_returns_duplicate_without_reexecution() {
        let state = tempfile::tempdir().unwrap();
        let output = state.path().join("durable-once.txt");
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let command = append_once_command(&output);
        let mut operation = request("op-lost-reply", command);
        operation.session_id = share.session_id().to_owned();
        let client = share.connect(share.invitation()).await.unwrap();
        share.test_drop_next_operation_reply();

        assert!(client.execute(operation.clone()).await.is_err());
        let reconnected = share.connect(share.invitation()).await.unwrap();
        let duplicate = reconnected.execute(operation).await.unwrap();

        assert_eq!(duplicate.record.state, OperationState::Succeeded);
        assert_one_line(&output);
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn lost_running_reply_can_be_observed_after_reconnect() {
        let state = tempfile::tempdir().unwrap();
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let mut operation = request("op-running-drop", short_sleep_command());
        operation.session_id = share.session_id().to_owned();
        operation.timeout = Duration::from_millis(25);
        let client = share.connect(share.invitation()).await.unwrap();
        share.test_drop_next_operation_reply();

        assert!(client.execute(operation).await.is_err());
        let reconnected = share.connect(share.invitation()).await.unwrap();
        let first = reconnected
            .operation_status("op-running-drop")
            .await
            .unwrap();
        assert!(matches!(
            first.state,
            OperationState::Running | OperationState::Succeeded
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let final_record = reconnected
            .operation_status("op-running-drop")
            .await
            .unwrap();
        assert_eq!(final_record.state, OperationState::Succeeded);
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn abandoned_running_operation_is_interrupted_and_never_replayed() {
        use crate::net::protocol::{LeaseMeta, ShareSessionMeta, SESSION_SCHEMA};
        use crate::net::session_store::{SessionStore, StoreError};

        let state = tempfile::tempdir().unwrap();
        let old_id = "abandoned-session";
        let old_dir = state.path().join(old_id);
        let store = SessionStore::create_share(
            &old_dir,
            ShareSessionMeta {
                schema: SESSION_SCHEMA,
                session_id: old_id.into(),
                lease: LeaseMeta::default(),
                controller_token_hash: None,
            },
        )
        .unwrap();
        store
            .begin_operation("op-abandoned", "dangerous-side-effect")
            .unwrap();
        store.mark_running("op-abandoned").unwrap();
        drop(store);

        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let recovered = SessionStore::open(&old_dir).unwrap();
        assert_eq!(
            recovered.operation("op-abandoned").unwrap().state,
            OperationState::Interrupted
        );
        assert!(matches!(
            recovered.begin_operation("op-abandoned", "dangerous-side-effect"),
            Err(StoreError::Duplicate(record)) if record.state == OperationState::Interrupted
        ));
        drop(recovered);
        share.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_admission_before_waiting_for_inflight_start() {
        let state = tempfile::tempdir().unwrap();
        let output = state.path().join("must-not-run.txt");
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let lifecycle = share.inner.lifecycle.lock().await;
        let shutdown_share = share.clone();
        let shutdown = tokio::spawn(async move { shutdown_share.shutdown().await });
        while share.inner.active.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        let mut operation = request("op-after-shutdown", create_forbidden_command(&output));
        operation.session_id = share.session_id().to_owned();
        let inner = Arc::clone(&share.inner);
        let execute = tokio::spawn(async move { inner.execute(operation).await });
        drop(lifecycle);

        assert!(execute.await.unwrap().is_err());
        shutdown.await.unwrap().unwrap();
        assert!(!output.exists());
    }

    #[tokio::test]
    async fn dropping_owner_initiates_running_operation_cleanup() {
        let state = tempfile::tempdir().unwrap();
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let store = Arc::clone(&share.inner.store);
        let client = share.connect(share.invitation()).await.unwrap();
        let mut operation = request("op-owner-drop", long_sleep_command());
        operation.session_id = share.session_id().to_owned();
        operation.timeout = Duration::from_millis(25);
        assert_eq!(
            client.execute(operation).await.unwrap().record.state,
            OperationState::Running
        );

        drop(share);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if store.operation("op-owner-drop").unwrap().state == OperationState::Cancelled {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn aborting_shutdown_waiter_does_not_abort_cleanup() {
        let state = tempfile::tempdir().unwrap();
        let share = ShareService::start(state.path(), Arc::new(StdoutTerminalObserver))
            .await
            .unwrap();
        let store = Arc::clone(&share.inner.store);
        let client = share.connect(share.invitation()).await.unwrap();
        let mut operation = request("op-aborted-shutdown", long_sleep_command());
        operation.session_id = share.session_id().to_owned();
        operation.timeout = Duration::from_millis(25);
        client.execute(operation).await.unwrap();

        let waiter_share = share.clone();
        let waiter = tokio::spawn(async move { waiter_share.shutdown().await });
        while !share
            .inner
            .cleanup_started
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            tokio::task::yield_now().await;
        }
        waiter.abort();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if store.operation("op-aborted-shutdown").unwrap().state
                    == OperationState::Cancelled
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn unconfirmed_process_termination_is_interrupted_not_cancelled() {
        assert_eq!(shutdown_terminal_state(true).0, OperationState::Interrupted);
        assert_eq!(shutdown_terminal_state(false).0, OperationState::Cancelled);
    }
}
