//! Тулы «рук». Все мутирующие/исполняющие проходят через safety-гейт.
//!
//! Паттерн: чистая логика (`*_impl`, тестируется юнит-тестами с моком Confirmer)
//! плюс тонкая rmcp-обёртка. read/list/search — Low (без confirm, но secret-scoping
//! через blocked_patterns). write — Medium (confirm). run_shell — через `gate()`:
//! hardline даёт Deny, иначе подтверждение.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::audit::{self, Audit, AuditEntry, FileAudit};
use crate::net::protocol::{OperationRecord, OperationState};
use crate::net::{ControllerError, OperationRequest, SessionRegistry};
use crate::safety::{
    authorize, decide, gate, Action, ActionKind, Confirmer, GateError, Policy, StdinConfirmer,
    Verdict,
};

// ─── DTO ──────────────────────────────────────────────────────────────────

#[derive(Serialize, JsonSchema, Debug, Clone)]
pub struct DirEntryDTO {
    pub name: String,
    pub is_dir: bool,
}

#[derive(Serialize, JsonSchema, Debug, Clone)]
pub struct Hit {
    pub path: String,
    pub line: u32,
    pub text: String,
}

#[derive(Serialize, JsonSchema, Debug, Clone)]
pub struct ShellResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

// Обёртки-объекты: MCP требует root-тип outputSchema = object (не array).
#[derive(Serialize, JsonSchema)]
pub struct ListDirOutput {
    pub entries: Vec<DirEntryDTO>,
}
#[derive(Serialize, JsonSchema)]
pub struct SearchOutput {
    pub hits: Vec<Hit>,
}

#[derive(Serialize, JsonSchema)]
pub struct SessionConnectedOutput {
    pub session_id: String,
    pub connection: String,
    pub lease_expires_at_unix: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct SessionStatusOutput {
    pub connection: String,
    pub queue_len: usize,
    pub lease: LeaseOutput,
    pub last_operation: Option<OperationSummaryOutput>,
}

#[derive(Serialize, JsonSchema)]
pub struct LeaseOutput {
    pub controller_id: Option<String>,
    pub expires_at_unix: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct OperationSummaryOutput {
    pub operation_id: String,
    pub state: String,
    pub summary: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct JournalOutput {
    pub session_id: String,
    pub markdown: String,
}

#[derive(Serialize, JsonSchema)]
pub struct NoteAppendedOutput {
    pub session_id: String,
    pub appended: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct RemoteExecOutput {
    pub operation_id: String,
    pub state: OperationState,
    pub summary: String,
}

#[derive(Serialize, JsonSchema)]
pub struct OperationStatusOutput {
    pub operation_id: String,
    pub state: OperationState,
    pub summary: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct OperationOutputOutput {
    pub operation_id: String,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct SessionDisconnectedOutput {
    pub session_id: String,
    pub connection: String,
}

// ─── Чистая логика (тестируемая без MCP) ────────────────────────────────────

pub fn list_dir_impl(path: &Path) -> std::io::Result<Vec<DirEntryDTO>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let is_dir = entry.file_type()?.is_dir();
        out.push(DirEntryDTO {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir,
        });
    }
    Ok(out)
}

pub fn read_file_impl(
    path: &Path,
    policy: &Policy,
    confirmer: &dyn Confirmer,
    audit: &dyn Audit,
) -> Result<String, GateError> {
    let action = Action {
        kind: ActionKind::Read,
        path: Some(path.to_path_buf()),
        command: None,
    };
    let verdict = decide(&action, policy);
    audit::audit_decision(audit, &action, &verdict, false)?; // read → degrade
    if let Err(e) = authorize(verdict, &action, confirmer) {
        audit::audit_result(audit, &action, &format!("denied: {e:?}"));
        return Err(e);
    }
    let content = std::fs::read_to_string(path).map_err(|e| GateError::Io(e.to_string()))?;
    audit::audit_result(audit, &action, &format!("ok: {} bytes", content.len()));
    Ok(content)
}

pub fn write_file_impl(
    path: &Path,
    content: &str,
    policy: &Policy,
    confirmer: &dyn Confirmer,
    audit: &dyn Audit,
) -> Result<(), GateError> {
    let action = Action {
        kind: ActionKind::Write,
        path: Some(path.to_path_buf()),
        command: None,
    };
    let verdict = decide(&action, policy);
    audit::audit_decision(audit, &action, &verdict, true)?; // мутация → fail-closed
    if let Err(e) = authorize(verdict, &action, confirmer) {
        audit::audit_result(audit, &action, &format!("denied: {e:?}"));
        return Err(e);
    }
    std::fs::write(path, content).map_err(|e| GateError::Io(e.to_string()))?;
    audit::audit_result(audit, &action, &format!("ok: {} bytes written", content.len()));
    Ok(())
}

pub fn run_shell_impl(
    command: &str,
    policy: &Policy,
    confirmer: &dyn Confirmer,
    audit: &dyn Audit,
) -> Result<ShellResult, GateError> {
    let action = Action {
        kind: ActionKind::Exec,
        path: None,
        command: Some(command.to_string()),
    };
    let verdict = gate(command, policy);
    audit::audit_decision(audit, &action, &verdict, true)?; // мутация → fail-closed
    if let Err(e) = authorize(verdict, &action, confirmer) {
        audit::audit_result(audit, &action, &format!("denied: {e:?}"));
        return Err(e);
    }
    let output = shell(command)
        .output()
        .map_err(|e| GateError::Io(e.to_string()))?;
    let res = ShellResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    audit::audit_result(audit, &action, &format!("ok: code={}", res.code));
    Ok(res)
}

fn shell(command: &str) -> Command {
    if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    }
}

pub fn search_impl(root: &Path, query: &str, policy: &Policy) -> std::io::Result<Vec<Hit>> {
    const MAX_HITS: usize = 500;
    let mut hits = Vec::new();
    search_walk(root, query, policy, &mut hits, MAX_HITS)?;
    Ok(hits)
}

fn search_walk(
    dir: &Path,
    query: &str,
    policy: &Policy,
    hits: &mut Vec<Hit>,
    max: usize,
) -> std::io::Result<()> {
    if hits.len() >= max {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if matches!(name, ".git" | "node_modules" | "target") {
                    continue;
                }
            }
            search_walk(&path, query, policy, hits, max)?;
        } else if ft.is_file() {
            // secret-scoping: тот же гейт, что и read_file. Файлы, на которые
            // decide != Allow (blocked_patterns), не читаем и не показываем — иначе
            // поиск стал бы обходом запрета на чтение секретов.
            let action = Action {
                kind: ActionKind::Read,
                path: Some(path.clone()),
                command: None,
            };
            if !matches!(decide(&action, policy), Verdict::Allow) {
                continue;
            }
            // не-UTF8/бинарные файлы пропускаем
            if let Ok(content) = std::fs::read_to_string(&path) {
                for (i, line) in content.lines().enumerate() {
                    if line.contains(query) {
                        hits.push(Hit {
                            path: path.to_string_lossy().into_owned(),
                            line: (i + 1) as u32,
                            text: line.to_string(),
                        });
                        if hits.len() >= max {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// ─── MCP-параметры ──────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ListDirParams {
    /// Путь к директории.
    pub path: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct ReadFileParams {
    /// Путь к файлу.
    pub path: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct WriteFileParams {
    /// Путь к файлу.
    pub path: String,
    /// Содержимое.
    pub content: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Корневая директория поиска.
    pub root: String,
    /// Искомая подстрока.
    pub query: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct RunShellParams {
    /// Команда для исполнения.
    pub command: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct SessionConnectParams {
    pub invite: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct SessionIdParams {
    pub session_id: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct SessionNoteAppendParams {
    pub session_id: String,
    pub note: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct RemoteExecParams {
    pub session_id: String,
    pub operation_id: Option<String>,
    pub command: String,
    pub cwd: Option<PathBuf>,
    pub timeout_ms: Option<u64>,
}
#[derive(Deserialize, JsonSchema)]
pub struct OperationParams {
    pub session_id: String,
    pub operation_id: String,
}

// ─── MCP-сервер ─────────────────────────────────────────────────────────────

/// MCP-сервер «руки». Держит политику безопасности и канал подтверждения.
#[derive(Clone)]
pub struct HandsServer {
    // Читается макросом #[tool_handler]; анализатор dead-code не видит → глушим.
    #[allow(dead_code)]
    tool_router: ToolRouter<HandsServer>,
    policy: Policy,
    confirmer: Arc<dyn Confirmer>,
    audit: Arc<dyn Audit>,
    /// Релей A→B включён только на локальном `serve` (внешний мозг оркеструет B).
    /// На сетевом узле-B (`with`) выключен: B не должен звонить наружу (B→C-цепочки).
    relay_enabled: bool,
    sessions: Arc<SessionRegistry>,
}

#[tool_router]
impl HandsServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            policy: Policy::default(),
            confirmer: Arc::new(StdinConfirmer::default()),
            audit: Arc::new(FileAudit::new(audit::default_path())),
            relay_enabled: true,
            sessions: Arc::new(SessionRegistry::new(crate::paths::state_path("sessions"))),
        }
    }

    /// Сконструировать с явными политикой/каналом подтверждения/журналом.
    /// Используется удалёнными сессиями: вето владельца B + стрим в его терминал.
    pub fn with(policy: Policy, confirmer: Arc<dyn Confirmer>, audit: Arc<dyn Audit>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            policy,
            confirmer,
            audit,
            relay_enabled: false,
            sessions: Arc::new(SessionRegistry::new(crate::paths::state_path("sessions"))),
        }
    }

    #[cfg(test)]
    fn with_sessions_dir(sessions_dir: &Path) -> Self {
        let mut server = Self::new();
        server.sessions = Arc::new(SessionRegistry::new(sessions_dir));
        server
    }

    #[tool(
        name = "list_dir",
        description = "Список содержимого директории (имя + признак папки)."
    )]
    fn list_dir(
        &self,
        Parameters(ListDirParams { path }): Parameters<ListDirParams>,
    ) -> Result<Json<ListDirOutput>, ErrorData> {
        let action = Action {
            kind: ActionKind::Read,
            path: Some(PathBuf::from(&path)),
            command: None,
        };
        let verdict = decide(&action, &self.policy);
        let _ = audit::audit_decision(&*self.audit, &action, &verdict, false);
        if let Verdict::Deny(reason) = verdict {
            audit::audit_result(&*self.audit, &action, &format!("denied: {reason}"));
            return Err(ErrorData::invalid_request(reason, None));
        }
        let r = list_dir_impl(Path::new(&path));
        audit::audit_result(
            &*self.audit,
            &action,
            &match &r {
                Ok(v) => format!("ok: {} entries", v.len()),
                Err(e) => format!("error: {e}"),
            },
        );
        r.map(|entries| Json(ListDirOutput { entries }))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }

    #[tool(name = "read_file", description = "Прочитать текстовый файл.")]
    fn read_file(
        &self,
        Parameters(ReadFileParams { path }): Parameters<ReadFileParams>,
    ) -> Result<String, ErrorData> {
        read_file_impl(Path::new(&path), &self.policy, &*self.confirmer, &*self.audit)
            .map_err(gate_err)
    }

    #[tool(name = "search", description = "Поиск подстроки по файлам в директории.")]
    fn search(
        &self,
        Parameters(SearchParams { root, query }): Parameters<SearchParams>,
    ) -> Result<Json<SearchOutput>, ErrorData> {
        let action = Action {
            kind: ActionKind::Read,
            path: Some(PathBuf::from(&root)),
            command: None,
        };
        let verdict = decide(&action, &self.policy);
        let _ = audit::audit_decision(&*self.audit, &action, &verdict, false);
        if let Verdict::Deny(reason) = verdict {
            audit::audit_result(&*self.audit, &action, &format!("denied: {reason}"));
            return Err(ErrorData::invalid_request(reason, None));
        }
        let r = search_impl(Path::new(&root), &query, &self.policy);
        audit::audit_result(
            &*self.audit,
            &action,
            &match &r {
                Ok(v) => format!("ok: {} hits", v.len()),
                Err(e) => format!("error: {e}"),
            },
        );
        r.map(|hits| Json(SearchOutput { hits }))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }

    #[tool(
        name = "write_file",
        description = "Записать файл (мутация — требует подтверждения владельца)."
    )]
    fn write_file(
        &self,
        Parameters(WriteFileParams { path, content }): Parameters<WriteFileParams>,
    ) -> Result<String, ErrorData> {
        let bytes = content.len();
        write_file_impl(
            Path::new(&path),
            &content,
            &self.policy,
            &*self.confirmer,
            &*self.audit,
        )
        .map(|_| format!("записано {bytes} байт в {path}"))
        .map_err(gate_err)
    }

    #[tool(
        name = "run_shell",
        description = "Выполнить shell-команду через safety-гейт (опасное — запрет, мутации — подтверждение)."
    )]
    fn run_shell(
        &self,
        Parameters(RunShellParams { command }): Parameters<RunShellParams>,
    ) -> Result<Json<ShellResult>, ErrorData> {
        run_shell_impl(&command, &self.policy, &*self.confirmer, &*self.audit)
            .map(Json)
            .map_err(gate_err)
    }

    #[tool(name = "session_connect", description = "Connect to a shared remote session by invitation.")]
    async fn session_connect(
        &self,
        Parameters(SessionConnectParams { invite }): Parameters<SessionConnectParams>,
    ) -> Result<Json<SessionConnectedOutput>, ErrorData> {
        self.relay_guard()?;
        let controller = self.sessions.connect(&invite).await.map_err(controller_error)?;
        let status = controller.status().map_err(controller_error)?;
        let _ = self.audit.record(&AuditEntry::relay(&format!("connect:{}", status.session_id), "ok"));
        Ok(Json(SessionConnectedOutput {
            session_id: status.session_id,
            connection: "connected".into(),
            lease_expires_at_unix: status.lease.expires_at_unix,
        }))
    }

    #[tool(name = "session_status", description = "Return connection, queue, lease, and latest operation state.")]
    async fn session_status(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<Json<SessionStatusOutput>, ErrorData> {
        self.relay_guard()?;
        let status = self.sessions.get(&session_id).await.map_err(controller_error)?.status().map_err(controller_error)?;
        Ok(Json(SessionStatusOutput {
            connection: "connected".into(),
            queue_len: status.queue_len,
            lease: LeaseOutput {
                controller_id: status.lease.controller_id,
                expires_at_unix: status.lease.expires_at_unix,
            },
            last_operation: status.last_operation.as_ref().map(operation_summary),
        }))
    }

    #[tool(name = "session_journal", description = "Read the durable Markdown journal for a remote session.")]
    async fn session_journal(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<Json<JournalOutput>, ErrorData> {
        self.relay_guard()?;
        let controller = self.sessions.get(&session_id).await.map_err(controller_error)?;
        let path = controller.session_dir().join("journal.md");
        let markdown = match tokio::fs::read_to_string(&path).await {
            Ok(markdown) => markdown,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(storage_error(error.to_string())),
        };
        Ok(Json(JournalOutput { session_id, markdown }))
    }

    #[tool(name = "session_note_append", description = "Append a redacted timestamped note to the durable session journal.")]
    async fn session_note_append(
        &self,
        Parameters(SessionNoteAppendParams { session_id, note }): Parameters<SessionNoteAppendParams>,
    ) -> Result<Json<NoteAppendedOutput>, ErrorData> {
        self.relay_guard()?;
        let controller = self.sessions.get(&session_id).await.map_err(controller_error)?;
        let redacted = crate::tg::redact(&note);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let entry = format!("## {timestamp}\n\n{redacted}\n\n");
        append_private(&controller.session_dir().join("journal.md"), entry.as_bytes()).await?;
        Ok(Json(NoteAppendedOutput { session_id, appended: true }))
    }

    #[tool(name = "remote_exec", description = "Execute an unrestricted command in an addressed remote session.")]
    async fn remote_exec(
        &self,
        Parameters(params): Parameters<RemoteExecParams>,
    ) -> Result<Json<RemoteExecOutput>, ErrorData> {
        self.relay_guard()?;
        let controller = self.sessions.get(&params.session_id).await.map_err(controller_error)?;
        let operation_id = params.operation_id.unwrap_or_else(random_operation_id);
        let reply = controller.execute(OperationRequest {
            session_id: params.session_id,
            operation_id: operation_id.clone(),
            command: params.command,
            cwd: params.cwd,
            timeout: std::time::Duration::from_millis(params.timeout_ms.unwrap_or(30_000)),
        }).await.map_err(controller_error)?;
        Ok(Json(RemoteExecOutput {
            operation_id,
            state: reply.record.state,
            summary: reply.record.summary.unwrap_or_default(),
        }))
    }

    #[tool(name = "operation_status", description = "Return durable state for a remote operation.")]
    async fn operation_status(
        &self,
        Parameters(OperationParams { session_id, operation_id }): Parameters<OperationParams>,
    ) -> Result<Json<OperationStatusOutput>, ErrorData> {
        self.relay_guard()?;
        let record = self.sessions.get(&session_id).await.map_err(controller_error)?
            .operation_status(&operation_id).await.map_err(controller_error)?;
        Ok(Json(OperationStatusOutput {
            operation_id: record.id,
            state: record.state,
            summary: record.summary,
        }))
    }

    #[tool(name = "operation_output", description = "Return stdout and stderr captured for a remote operation.")]
    async fn operation_output(
        &self,
        Parameters(OperationParams { session_id, operation_id }): Parameters<OperationParams>,
    ) -> Result<Json<OperationOutputOutput>, ErrorData> {
        self.relay_guard()?;
        let record = self.sessions.get(&session_id).await.map_err(controller_error)?
            .operation_status(&operation_id).await.map_err(controller_error)?;
        let (stdout, stderr) = split_output(record.output.as_deref().unwrap_or_default());
        Ok(Json(OperationOutputOutput {
            operation_id: record.id,
            stdout,
            stderr,
            truncated: record.output_truncated || record.output_pruned,
        }))
    }

    #[tool(name = "session_disconnect", description = "Release and remove an addressed remote session connection.")]
    async fn session_disconnect(
        &self,
        Parameters(SessionIdParams { session_id }): Parameters<SessionIdParams>,
    ) -> Result<Json<SessionDisconnectedOutput>, ErrorData> {
        self.relay_guard()?;
        self.sessions.disconnect(&session_id).await.map_err(controller_error)?;
        let _ = self.audit.record(&AuditEntry::relay(&format!("disconnect:{session_id}"), "ok"));
        Ok(Json(SessionDisconnectedOutput { session_id, connection: "disconnected".into() }))
    }
}

impl HandsServer {
    /// Релей-тулы работают только на узле-A (`serve`). На узле-B (`listen`, `with`)
    /// они инертны — иначе B мог бы самовольно звонить наружу (цепочки A→B→C).
    fn relay_guard(&self) -> Result<(), ErrorData> {
        if !self.relay_enabled {
            return Err(ErrorData::invalid_request(
                "релей отключён на этом узле".to_string(),
                None,
            ));
        }
        Ok(())
    }
}

fn operation_summary(record: &OperationRecord) -> OperationSummaryOutput {
    OperationSummaryOutput {
        operation_id: record.id.clone(),
        state: operation_state(record.state),
        summary: record.summary.clone(),
    }
}

fn operation_state(state: OperationState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn random_operation_id() -> String {
    use rand::Rng;
    let suffix: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    format!("op-{suffix}")
}

fn split_output(output: &str) -> (String, String) {
    match output.split_once("\n[stderr]\n") {
        Some((stdout, stderr)) => (stdout.to_owned(), stderr.to_owned()),
        None => (output.to_owned(), String::new()),
    }
}

async fn append_private(path: &Path, bytes: &[u8]) -> Result<(), ErrorData> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|error| storage_error(error.to_string()))?;
    file.write_all(bytes)
        .await
        .map_err(|error| storage_error(error.to_string()))?;
    file.sync_all()
        .await
        .map_err(|error| storage_error(error.to_string()))?;
    #[cfg(unix)]
    tokio::fs::set_permissions(path, {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o600)
    })
    .await
    .map_err(|error| storage_error(error.to_string()))?;
    Ok(())
}

fn controller_error(error: ControllerError) -> ErrorData {
    let (code, internal) = match &error {
        ControllerError::Busy { .. } => ("session_busy", false),
        ControllerError::QueueFull => ("queue_full", false),
        ControllerError::Storage(_) | ControllerError::RemoteStorage(_) => {
            ("storage_unavailable", true)
        }
        ControllerError::UnknownInProgress { .. } => ("unknown_in_progress", true),
        ControllerError::Reconnecting => ("reconnecting", true),
        ControllerError::Remote(_) | ControllerError::Transport(_) | ControllerError::InvalidState(_) => {
            ("session_unavailable", true)
        }
    };
    let message = format!("{code}: {error}");
    let data = Some(serde_json::json!({ "code": code }));
    if internal {
        ErrorData::internal_error(message, data)
    } else {
        ErrorData::invalid_request(message, data)
    }
}

fn storage_error(message: String) -> ErrorData {
    ErrorData::internal_error(
        format!("storage_unavailable: {message}"),
        Some(serde_json::json!({ "code": "storage_unavailable" })),
    )
}

fn gate_err(e: GateError) -> ErrorData {
    match e {
        GateError::Denied(r) => ErrorData::invalid_request(r, None),
        GateError::Io(r) => ErrorData::internal_error(r, None),
    }
}

impl Default for HandsServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for HandsServer {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::protocol::OperationState;
    use crate::net::{ControllerError, ShareService};
    use crate::server::executor::{ExecResult, TerminalObserver};

    struct QuietObserver;
    impl TerminalObserver for QuietObserver {
        fn started(&self, _: &str) {}
        fn finished(&self, _: &ExecResult) {}
        fn failed(&self, _: &str, _: &str) {}
    }

    #[test]
    fn serve_lists_stable_session_tools() {
        let router = HandsServer::tool_router();
        let names: Vec<String> = router.list_all().iter().map(|tool| tool.name.to_string()).collect();
        for name in [
            "list_dir", "read_file", "search", "write_file", "run_shell",
            "session_connect", "session_status", "session_journal", "session_note_append",
            "remote_exec", "operation_status", "operation_output", "session_disconnect",
        ] {
            assert!(names.iter().any(|candidate| candidate == name), "missing {name}: {names:?}");
        }
        for legacy in ["mm_connect", "mm_remote_tools", "mm_remote_call", "mm_disconnect"] {
            assert!(!names.iter().any(|name| name == legacy), "legacy {legacy} remains: {names:?}");
        }
        assert_eq!(names.len(), 13, "5 local + 8 stable session tools: {names:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_exec_returns_operation_id_and_summary() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let share = ShareService::start(share_state.path(), Arc::new(QuietObserver)).await.unwrap();
        let server = HandsServer::with_sessions_dir(engineer_state.path());
        let connected = server.session_connect(Parameters(SessionConnectParams {
            invite: share.invitation().to_owned(),
        })).await.unwrap();

        let output = server.remote_exec(Parameters(RemoteExecParams {
            session_id: connected.0.session_id.clone(),
            operation_id: Some("tool-op-1".into()),
            command: "printf 'hello'".into(),
            cwd: None,
            timeout_ms: Some(5_000),
        })).await.unwrap();

        assert_eq!(output.0.operation_id, "tool-op-1");
        assert_eq!(output.0.state, OperationState::Succeeded);
        assert!(output.0.summary.contains("stdout=5B"), "{}", output.0.summary);
        let captured = server
            .operation_output(Parameters(OperationParams {
                session_id: connected.0.session_id.clone(),
                operation_id: "tool-op-1".into(),
            }))
            .await
            .unwrap();
        assert_eq!(captured.0.stdout, "hello");
        assert!(captured.0.stderr.is_empty());
        assert!(!captured.0.truncated);
        server.session_disconnect(Parameters(SessionIdParams {
            session_id: connected.0.session_id,
        })).await.unwrap();
        share.shutdown().await.unwrap();
    }

    #[test]
    fn busy_and_queue_full_are_structured_errors() {
        for (error, stable_code) in [
            (ControllerError::Busy { expires_at_unix: 42 }, "session_busy"),
            (ControllerError::QueueFull, "queue_full"),
        ] {
            let mapped = controller_error(error);
            assert_eq!(mapped.data.as_ref().and_then(|value| value.get("code")).and_then(|value| value.as_str()), Some(stable_code));
            assert!(mapped.message.contains(stable_code));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn note_append_survives_controller_restart_redacted() {
        let share_state = tempfile::tempdir().unwrap();
        let engineer_state = tempfile::tempdir().unwrap();
        let share = ShareService::start(share_state.path(), Arc::new(QuietObserver)).await.unwrap();
        let server = HandsServer::with_sessions_dir(engineer_state.path());
        let connected = server.session_connect(Parameters(SessionConnectParams {
            invite: share.invitation().to_owned(),
        })).await.unwrap().0;
        server.session_note_append(Parameters(SessionNoteAppendParams {
            session_id: connected.session_id.clone(),
            note: "TOKEN=super-secret-value".into(),
        })).await.unwrap();
        drop(server);

        let restarted = HandsServer::with_sessions_dir(engineer_state.path());
        let journal = restarted.session_journal(Parameters(SessionIdParams {
            session_id: connected.session_id.clone(),
        })).await.unwrap();
        assert!(journal.0.markdown.contains("TOKEN=***"), "{}", journal.0.markdown);
        assert!(!journal.0.markdown.contains("super-secret-value"));
        restarted.session_disconnect(Parameters(SessionIdParams {
            session_id: connected.session_id,
        })).await.unwrap();
        share.shutdown().await.unwrap();
    }
}
