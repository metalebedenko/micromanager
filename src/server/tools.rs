//! Тулы «рук». Все мутирующие/исполняющие проходят через safety-гейт.
//!
//! Паттерн: чистая логика (`*_impl`, тестируется юнит-тестами с моком Confirmer)
//! плюс тонкая rmcp-обёртка. read/list/search — Low (без confirm, но secret-scoping
//! через blocked_patterns). write — Medium (confirm). run_shell — через `gate()`:
//! hardline даёт Deny, иначе подтверждение.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;

use crate::net::McpSession;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::audit::{self, Audit, AuditEntry, FileAudit};
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

/// Статус релей-операции (`mm_disconnect`).
#[derive(Serialize, JsonSchema)]
pub struct RelayStatus {
    pub status: String,
}

/// Результат `mm_connect`: метка хоста B + сводка выданного им гранта (информативно).
#[derive(Serialize, JsonSchema)]
pub struct RelayConnected {
    pub host: String,
    pub grant: crate::net::GrantSummary,
}

/// Список имён тулов, предоставляемых B.
#[derive(Serialize, JsonSchema)]
pub struct RemoteToolsOutput {
    pub tools: Vec<String>,
}

/// Результат удалённого вызова тула B (человекочитаемый текст/JSON).
#[derive(Serialize, JsonSchema)]
pub struct RemoteCallOutput {
    pub output: String,
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
pub struct MmConnectParams {
    /// Код-приглашение (ticket) от компьютера B.
    pub ticket: String,
}
#[derive(Deserialize, JsonSchema)]
pub struct MmRemoteCallParams {
    /// Имя тула B (например list_dir, read_file, run_shell).
    pub tool: String,
    /// Аргументы тула — JSON-объект.
    pub args: serde_json::Value,
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
    /// Единственный слот удалённой B-сессии (одно подключение за раз).
    relay_session: Arc<AsyncMutex<Option<McpSession>>>,
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
            relay_session: Arc::new(AsyncMutex::new(None)),
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
            relay_session: Arc::new(AsyncMutex::new(None)),
        }
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

    // ─── Релей A→B (только на локальном `serve`; инертен на узле-B) ──────────

    #[tool(
        name = "mm_connect",
        description = "Подключиться к компьютеру B по коду-приглашению (ticket). Возвращает метку хоста и сводку гранта B. Одно подключение за раз — перед новым вызвать mm_disconnect."
    )]
    async fn mm_connect(
        &self,
        Parameters(MmConnectParams { ticket }): Parameters<MmConnectParams>,
    ) -> Result<Json<RelayConnected>, ErrorData> {
        self.relay_guard()?;
        let mut slot = self.relay_session.lock().await;
        if let Some(existing) = slot.as_ref() {
            // Guard ДО сети: занятый слот не трогаем, существующую сессию не подменяем.
            return Err(ErrorData::invalid_request(
                format!(
                    "уже подключено к {}, сначала mm_disconnect",
                    existing.host_label()
                ),
                None,
            ));
        }
        match McpSession::connect(&ticket).await {
            Ok(session) => {
                let host = session.host_label().to_string();
                let grant = session.grant().clone();
                let _ = self
                    .audit
                    .record(&AuditEntry::relay(&format!("connect:{host}"), "ok"));
                *slot = Some(session);
                Ok(Json(RelayConnected { host, grant }))
            }
            Err(e) => {
                let _ = self
                    .audit
                    .record(&AuditEntry::relay("connect", &format!("error: {e}")));
                Err(ErrorData::internal_error(
                    format!("подключение к B не удалось: {e}"),
                    None,
                ))
            }
        }
    }

    #[tool(
        name = "mm_remote_tools",
        description = "Список имён тулов, которые предоставляет подключённый компьютер B."
    )]
    async fn mm_remote_tools(&self) -> Result<Json<RemoteToolsOutput>, ErrorData> {
        self.relay_guard()?;
        let slot = self.relay_session.lock().await;
        let session = slot.as_ref().ok_or_else(|| {
            ErrorData::invalid_request("не подключено — сначала mm_connect".to_string(), None)
        })?;
        let host = session.host_label().to_string();
        match session.list_tool_names().await {
            Ok(tools) => {
                let _ = self.audit.record(&AuditEntry::relay(
                    &format!("{host}:list_tools"),
                    &format!("ok: {} tools", tools.len()),
                ));
                Ok(Json(RemoteToolsOutput { tools }))
            }
            Err(e) => {
                let _ = self
                    .audit
                    .record(&AuditEntry::relay(&format!("{host}:list_tools"), &format!("error: {e}")));
                Err(ErrorData::internal_error(
                    format!("не удалось получить тулы B: {e}"),
                    None,
                ))
            }
        }
    }

    #[tool(
        name = "mm_remote_call",
        description = "Выполнить тул компьютера B по имени с JSON-аргументами (объект). Действие проходит вето владельца B; результат возвращается как текст."
    )]
    async fn mm_remote_call(
        &self,
        Parameters(MmRemoteCallParams { tool, args }): Parameters<MmRemoteCallParams>,
    ) -> Result<Json<RemoteCallOutput>, ErrorData> {
        self.relay_guard()?;
        // Валидация ДО сети: McpSession::call_tool молча роняет не-объект в None.
        if !args.is_object() {
            return Err(ErrorData::invalid_request(
                "args должен быть JSON-объектом".to_string(),
                None,
            ));
        }
        let slot = self.relay_session.lock().await;
        let session = slot.as_ref().ok_or_else(|| {
            ErrorData::invalid_request("не подключено — сначала mm_connect".to_string(), None)
        })?;
        let host = session.host_label().to_string();
        match session.call_tool(&tool, args).await {
            Ok(output) => {
                let _ = self
                    .audit
                    .record(&AuditEntry::relay(&format!("{host}:{tool}"), "ok"));
                Ok(Json(RemoteCallOutput { output }))
            }
            Err(e) => {
                // Ошибка вызова / обрыв / отказ вето B → текст мозгу, не паника.
                let _ = self
                    .audit
                    .record(&AuditEntry::relay(&format!("{host}:{tool}"), &format!("error: {e}")));
                Err(ErrorData::internal_error(
                    format!("вызов тула B '{tool}' не удался: {e}"),
                    None,
                ))
            }
        }
    }

    #[tool(
        name = "mm_disconnect",
        description = "Закрыть активную удалённую сессию с компьютером B (идемпотентно)."
    )]
    async fn mm_disconnect(&self) -> Result<Json<RelayStatus>, ErrorData> {
        self.relay_guard()?;
        let taken = self.relay_session.lock().await.take();
        let status = if let Some(session) = taken {
            session.close().await;
            "сессия закрыта".to_string()
        } else {
            "нет активной сессии".to_string()
        };
        let _ = self.audit.record(&AuditEntry::relay("disconnect", &status));
        Ok(Json(RelayStatus { status }))
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
mod relay_tests {
    use super::*;
    use crate::audit::{AuditEntry, NullAudit};
    use std::sync::Mutex as StdMutex;

    /// Журнал, фиксирующий записи в память — для проверки релей-аудита.
    #[derive(Default)]
    struct RecordingAudit(StdMutex<Vec<AuditEntry>>);
    impl Audit for RecordingAudit {
        fn record(&self, entry: &AuditEntry) -> std::io::Result<()> {
            self.0.lock().unwrap().push(entry.clone());
            Ok(())
        }
    }
    impl RecordingAudit {
        fn entries(&self) -> Vec<AuditEntry> {
            self.0.lock().unwrap().clone()
        }
    }

    /// Локальный `serve` (new) включает релей; сетевой `listen` (with) — нет.
    /// Релей-тулы инертны на узле-B, чтобы B не звонил наружу (B→C-цепочки).
    #[test]
    fn relay_enabled_for_serve_disabled_for_listen() {
        let serve = HandsServer::new();
        assert!(serve.relay_enabled, "serve (new) должен включать релей");

        let listen = HandsServer::with(
            Policy::default(),
            Arc::new(StdinConfirmer::default()),
            Arc::new(NullAudit),
        );
        assert!(!listen.relay_enabled, "listen (with) должен выключать релей");
    }

    /// Без активной сессии `mm_disconnect` — идемпотентный успех (не ошибка), слот пуст.
    #[tokio::test]
    async fn mm_disconnect_idempotent_without_session() {
        let mut server = HandsServer::new();
        let rec = Arc::new(RecordingAudit::default());
        server.audit = rec.clone();

        let out = server.mm_disconnect().await.expect("disconnect без сессии — успех");
        assert!(out.0.status.contains("нет активной"), "статус: {}", out.0.status);
        assert!(server.relay_session.lock().await.is_none());
        assert!(
            rec.entries().iter().any(|e| e.kind == "relay"),
            "релей-аудит записан"
        );
    }

    /// С активной сессией `mm_disconnect` закрывает её и очищает слот.
    #[tokio::test(flavor = "multi_thread")]
    async fn mm_disconnect_closes_active_session() {
        let (session, b_task, _dir) = crate::net::loopback_session_with_probe().await;
        let server = HandsServer::new();
        *server.relay_session.lock().await = Some(session);

        let out = server.mm_disconnect().await.expect("disconnect закрывает сессию");
        assert!(out.0.status.contains("закрыт"), "статус: {}", out.0.status);
        assert!(
            server.relay_session.lock().await.is_none(),
            "слот очищен после disconnect"
        );
        b_task.abort();
    }

    /// На узле-B релей-тул `mm_connect` инертен: отказ (без сети).
    #[tokio::test]
    async fn mm_connect_refused_on_b_node() {
        let listen = HandsServer::with(
            Policy::default(),
            Arc::new(StdinConfirmer::default()),
            Arc::new(NullAudit),
        );
        let res = listen
            .mm_connect(Parameters(MmConnectParams {
                ticket: "anything".into(),
            }))
            .await;
        assert!(res.is_err(), "на узле-B mm_connect отключён");
        assert!(format!("{:?}", res.err().unwrap()).contains("отключ"));
    }

    /// При уже активной сессии `mm_connect` отказывает (без попытки сети — guard до connect),
    /// существующая сессия не тронута.
    #[tokio::test(flavor = "multi_thread")]
    async fn mm_connect_refuses_when_already_connected() {
        let (session, b_task, _dir) = crate::net::loopback_session_with_probe().await;
        let server = HandsServer::new();
        *server.relay_session.lock().await = Some(session);

        let res = server
            .mm_connect(Parameters(MmConnectParams {
                ticket: "ignored-ticket".into(),
            }))
            .await;
        assert!(res.is_err(), "повторный connect при активной сессии — ошибка");
        assert!(
            format!("{:?}", res.err().unwrap()).contains("уже подключено"),
            "ошибка должна предлагать mm_disconnect"
        );
        // существующая сессия не подменена
        assert!(server.relay_session.lock().await.is_some());

        let s = server.relay_session.lock().await.take().unwrap();
        s.close().await;
        b_task.abort();
    }

    /// Loopback: с активной сессией `mm_remote_tools` непуст (есть list_dir),
    /// `mm_remote_call("list_dir", {path})` возвращает листинг B (probe.txt).
    #[tokio::test(flavor = "multi_thread")]
    async fn mm_remote_tools_and_call_loopback() {
        let (session, b_task, dir) = crate::net::loopback_session_with_probe().await;
        let server = HandsServer::new();
        *server.relay_session.lock().await = Some(session);

        let tools = server.mm_remote_tools().await.expect("список тулов B");
        assert!(
            tools.0.tools.iter().any(|t| t == "list_dir"),
            "тулы B: {:?}",
            tools.0.tools
        );

        let out = server
            .mm_remote_call(Parameters(MmRemoteCallParams {
                tool: "list_dir".into(),
                args: serde_json::json!({ "path": dir.path().to_string_lossy() }),
            }))
            .await
            .expect("remote_call list_dir");
        assert!(out.0.output.contains("probe.txt"), "вывод B: {}", out.0.output);

        let s = server.relay_session.lock().await.take().unwrap();
        s.close().await;
        b_task.abort();
    }

    /// Success criterion #5: мутация на B через `mm_remote_call` под вето владельца B
    /// (No-confirmer) → ошибка мозгу как ErrorData, файл НЕ создан, транспорт A цел.
    #[tokio::test(flavor = "multi_thread")]
    async fn mm_remote_call_relays_b_owner_veto_as_error() {
        use crate::safety::{Action, Confirmer};
        struct No;
        impl Confirmer for No {
            fn confirm(&self, _: &Action) -> bool {
                false
            }
        }

        let (session, b_task, dir) =
            crate::net::loopback_session_with_confirmer(Arc::new(No)).await;
        let server = HandsServer::new();
        *server.relay_session.lock().await = Some(session);

        let target = dir.path().join("vetoed.txt");
        let res = server
            .mm_remote_call(Parameters(MmRemoteCallParams {
                tool: "write_file".into(),
                args: serde_json::json!({
                    "path": target.to_string_lossy(),
                    "content": "x"
                }),
            }))
            .await;
        assert!(res.is_err(), "вето владельца B → ошибка мозгу, не успех");
        assert!(!target.exists(), "вето владельца B: файл не создан на B");

        // транспорт A цел: следующий вызов всё ещё работает
        let still = server.mm_remote_tools().await;
        assert!(still.is_ok(), "сессия жива после отказа B");

        let s = server.relay_session.lock().await.take().unwrap();
        s.close().await;
        b_task.abort();
    }

    /// Без активной сессии оба тула отдают понятную ошибку «не подключено».
    #[tokio::test]
    async fn mm_remote_without_session_errors() {
        let server = HandsServer::new();
        assert!(server.mm_remote_tools().await.is_err());
        let res = server
            .mm_remote_call(Parameters(MmRemoteCallParams {
                tool: "list_dir".into(),
                args: serde_json::json!({ "path": "." }),
            }))
            .await;
        assert!(format!("{:?}", res.err().unwrap()).contains("не подключено"));
    }

    /// Не-объектный `args` отвергается ДО сети (McpSession иначе молча уронит его в None).
    #[tokio::test]
    async fn mm_remote_call_rejects_non_object_args() {
        let server = HandsServer::new();
        let res = server
            .mm_remote_call(Parameters(MmRemoteCallParams {
                tool: "list_dir".into(),
                args: serde_json::json!("строка-а-не-объект"),
            }))
            .await;
        assert!(res.is_err(), "не-объектный args → ошибка");
        assert!(format!("{:?}", res.err().unwrap()).contains("объект"));
    }

    /// Приёмка: `serve` регистрирует ровно 9 тулов — 5 локальных + 4 релейных.
    /// Тулы существуют и на узле-B (тот же тип), но там инертны (см. *_refused_on_b_node).
    #[test]
    fn serve_exposes_nine_tools_including_relay() {
        let router = HandsServer::tool_router();
        let names: Vec<String> = router.list_all().iter().map(|t| t.name.to_string()).collect();
        for n in [
            "list_dir",
            "read_file",
            "search",
            "write_file",
            "run_shell",
            "mm_connect",
            "mm_remote_tools",
            "mm_remote_call",
            "mm_disconnect",
        ] {
            assert!(names.iter().any(|x| x == n), "нет тула {n} в {names:?}");
        }
        assert_eq!(names.len(), 9, "ровно 9 тулов в serve: {names:?}");
    }

    /// На узле-B (`with`, relay_enabled=false) релей-тул инертен: отказ.
    #[tokio::test]
    async fn mm_disconnect_refused_on_b_node() {
        let listen = HandsServer::with(
            Policy::default(),
            Arc::new(StdinConfirmer::default()),
            Arc::new(NullAudit),
        );
        let res = listen.mm_disconnect().await;
        assert!(res.is_err(), "на узле-B релей отключён");
        let err = res.err().unwrap();
        assert!(
            format!("{err:?}").contains("отключ"),
            "ошибка должна говорить, что релей отключён: {err:?}"
        );
    }
}
