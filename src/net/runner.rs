//! Удалённый ToolRunner: мозг A гоняет тулы на B. Driver-поток с current-thread
//! tokio-рантаймом владеет соединением; sync-стороны шлют запросы через канал.

use std::future::Future;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::brain::{FunctionSpec, ToolRunner, ToolSpec};

/// Таймаут одного удалённого вызова тула.
pub const REMOTE_CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Абстракция «позвать тул на B» — реальный McpSession или мок в тестах.
pub trait McpCaller: Send + 'static {
    fn call(&self, name: String, args: Value) -> impl Future<Output = anyhow::Result<String>> + Send;
    fn close(self) -> impl Future<Output = ()> + Send;
}

/// Внутренний запрос от sync-стороны к driver-потоку.
struct Req {
    name: String,
    args: Value,
    reply: oneshot::Sender<String>,
}

/// Владелец удалённого раннера: держит driver-поток (current-thread runtime + соединение).
pub struct McpToolRunner {
    specs: Vec<ToolSpec>,
    tx: mpsc::UnboundedSender<Req>,
    stop: Option<oneshot::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
}

/// Лёгкий клонируемый хэндл к driver-у; реализует ToolRunner.
#[derive(Clone)]
pub struct McpHandle {
    specs: Vec<ToolSpec>,
    tx: mpsc::UnboundedSender<Req>,
}

impl McpToolRunner {
    /// Запустить driver с продакшн-таймаутом.
    pub fn start<C: McpCaller>(caller: C, specs: Vec<ToolSpec>) -> Self {
        Self::start_with_timeout(caller, specs, REMOTE_CALL_TIMEOUT)
    }

    /// Запустить driver с инъектируемым таймаутом (для тестов, приватный).
    fn start_with_timeout<C: McpCaller>(caller: C, specs: Vec<ToolSpec>, timeout: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Req>();
        let (stop, stop_rx) = oneshot::channel::<()>();
        let join = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("driver runtime");
            rt.block_on(driver_loop(caller, rx, stop_rx, Some(timeout)));
        });
        Self { specs, tx, stop: Some(stop), join: Some(join) }
    }

    /// Локальный раннер: in-process MCP-сессия (rmcp-клиент ↔ `HandsServer` по duplex)
    /// поднимается ВНУТРИ driver-потока — его current-thread рантайм держит И клиент,
    /// И сервер-задачу. Внешний рантайм не нужен → зови из любого sync-контекста
    /// (CLI `spawn_blocking`, TUI/Telegram-потоки). Метку источника несёт `audit`.
    /// Таймаут вызова — `None` (локально «зависнуть» можно лишь на confirmer, а у
    /// них свои TTL; `StdinConfirmer` намеренно ждёт владельца бесконечно — паритет).
    pub fn start_local(
        policy: crate::safety::Policy,
        confirmer: std::sync::Arc<dyn crate::safety::Confirmer>,
        audit: std::sync::Arc<dyn crate::audit::Audit>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Req>();
        let (stop, stop_rx) = oneshot::channel::<()>();
        let (specs_tx, specs_rx) = std::sync::mpsc::channel::<Vec<ToolSpec>>();
        let join = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("local driver runtime");
            rt.block_on(async move {
                let session = match super::local::LocalMcpSession::build(policy, confirmer, audit).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[micromanager] не удалось поднять локальные руки: {e}");
                        let _ = specs_tx.send(Vec::new());
                        return;
                    }
                };
                let specs = session.hands_specs().await.unwrap_or_default();
                let _ = specs_tx.send(specs);
                driver_loop(session, rx, stop_rx, None).await; // local: без внешнего таймаута
            });
        });
        let specs = specs_rx.recv().unwrap_or_default();
        Self { specs, tx, stop: Some(stop), join: Some(join) }
    }

    /// Получить клонируемый хэндл к driver-у.
    pub fn handle(&self) -> McpHandle {
        McpHandle { specs: self.specs.clone(), tx: self.tx.clone() }
    }

    /// Погасить driver: послать stop → цикл выходит → caller.close(); дождаться потока.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    /// Идемпотентная остановка: Option::take гарантирует отсутствие двойного send/join.
    fn stop_and_join(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for McpToolRunner {
    fn drop(&mut self) {
        self.stop_and_join(); // если shutdown не звали
    }
}

/// Общее тело driver-цикла: обрабатывает запросы тулов через `caller` до стопа,
/// затем `caller.close()`. Таймаут опциональный — remote `Some(120s)` (сеть может
/// зависнуть), local `None` (полагаемся на TTL самих confirmer-ов).
async fn driver_loop<C: McpCaller>(
    caller: C,
    mut rx: mpsc::UnboundedReceiver<Req>,
    mut stop_rx: oneshot::Receiver<()>,
    timeout: Option<Duration>,
) {
    loop {
        tokio::select! {
            // Явный стоп — выходим даже если живы клоны tx в хэндлах.
            // КРИТИЧНО: без этого shutdown() зависнет, если хэндлы переживают /disconnect.
            _ = &mut stop_rx => break,
            maybe = rx.recv() => match maybe {
                None => break, // все senders ушли (тоже валидный стоп)
                Some(req) => {
                    let fut = caller.call(req.name, req.args);
                    let out = match timeout {
                        Some(d) => match tokio::time::timeout(d, fut).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => format!("ошибка на компе друга: {e}"),
                            Err(_) => "ошибка: удалённый вызов превысил таймаут".to_string(),
                        },
                        None => match fut.await {
                            Ok(s) => s,
                            Err(e) => format!("ошибка: {e}"),
                        },
                    };
                    let _ = req.reply.send(out);
                }
            }
        }
    }
    caller.close().await;
}

/// Преобразует rmcp-тул B в наш ToolSpec для мозга A.
/// Поле `input_schema` — Arc<JsonObject>; клонируем в serde_json::Value::Object для FunctionSpec.
pub fn map_tool(t: &rmcp::model::Tool) -> ToolSpec {
    ToolSpec {
        kind: "function".to_string(),
        function: FunctionSpec {
            name: t.name.to_string(),
            description: t.description.as_ref().map(|d| d.to_string()).unwrap_or_default(),
            parameters: serde_json::Value::Object((*t.input_schema).clone()),
        },
    }
}

impl ToolRunner for McpHandle {
    fn specs(&self) -> Vec<ToolSpec> {
        self.specs.clone()
    }

    fn dispatch(&self, name: &str, args: &Value) -> String {
        let (reply, reply_rx) = oneshot::channel();
        if self.tx.send(Req { name: name.to_string(), args: args.clone(), reply }).is_err() {
            return "ошибка: удалённая сессия недоступна".to_string();
        }
        reply_rx.blocking_recv().unwrap_or_else(|_| "ошибка: удалённая сессия недоступна".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn start_local_round_trips_and_filters_specs() {
        use crate::safety::Policy;
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let runner = McpToolRunner::start_local(
            Policy::default(),
            Arc::new(crate::safety::DenyConfirmer),
            Arc::new(crate::audit::NullAudit),
        );
        let h = runner.handle();
        assert_eq!(h.specs().len(), 5, "ровно 5 hands-тулов");
        let out = h.dispatch("list_dir", &serde_json::json!({"path": dir.path().to_string_lossy()}));
        assert!(out.contains("probe.txt"), "list_dir round-trip: {out}");
        runner.shutdown(); // не виснет — сервер-задача гасится по close
    }

    #[test]
    fn local_runner_drives_agent_loop() {
        use crate::brain::run_agent;
        use crate::safety::Policy;
        use std::sync::Arc;
        let runner = McpToolRunner::start_local(
            Policy::default(),
            Arc::new(crate::safety::DenyConfirmer),
            Arc::new(crate::audit::NullAudit),
        );
        let brain = crate::brain::tests_support::two_step(); // list_dir → "готово"
        let ans = run_agent(&brain, &runner.handle(), "покажи файлы").unwrap();
        assert_eq!(ans, "готово", "финальный ответ мозга");
        runner.shutdown();
    }

    #[test]
    fn start_local_confirm_does_not_hang_driver() {
        use crate::safety::{Action, Confirmer, Policy};
        use std::sync::mpsc;
        use std::sync::Arc;
        // Confirmer блокируется на канале; ответ шлёт ДРУГОЙ OS-поток (имитация UI).
        struct ChanConfirmer {
            rx: std::sync::Mutex<mpsc::Receiver<bool>>,
        }
        impl Confirmer for ChanConfirmer {
            fn confirm(&self, _a: &Action) -> bool {
                self.rx.lock().unwrap().recv().unwrap_or(false)
            }
        }
        let (tx, rx) = mpsc::channel::<bool>();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("w.txt");
        let runner = McpToolRunner::start_local(
            Policy::default(),
            Arc::new(ChanConfirmer {
                rx: std::sync::Mutex::new(rx),
            }),
            Arc::new(crate::audit::NullAudit),
        );
        let h = runner.handle();
        let target2 = target.clone();
        let t = std::thread::spawn(move || {
            h.dispatch(
                "write_file",
                &serde_json::json!({"path": target2.to_string_lossy(), "content": "hi"}),
            )
        });
        // отвечаем «да» из этого потока — driver не должен висеть
        std::thread::sleep(std::time::Duration::from_millis(200));
        tx.send(true).unwrap();
        let _out = t.join().unwrap();
        assert!(target.exists(), "файл записан после подтверждения");
        runner.shutdown();
    }

    #[test]
    fn map_tool_translates_mcp_tool_to_spec() {
        use rmcp::model::Tool;
        let schema = serde_json::json!({"type":"object","properties":{"path":{"type":"string"}}});
        let obj = schema.as_object().unwrap().clone();
        let t = Tool::new("list_dir", "Список директории", Arc::new(obj));
        let spec = map_tool(&t);
        assert_eq!(spec.function.name, "list_dir");
        assert_eq!(spec.function.description, "Список директории");
        assert_eq!(spec.function.parameters["properties"]["path"]["type"], "string");
    }

    // Мок: считает вызовы, эхо-результат; close — флаг.
    struct MockCaller { calls: Arc<AtomicUsize>, closed: Arc<AtomicUsize> }
    impl McpCaller for MockCaller {
        async fn call(&self, name: String, _args: Value) -> anyhow::Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("вызвано:{name}"))
        }
        async fn close(self) { self.closed.fetch_add(1, Ordering::SeqCst); }
    }

    fn specs1() -> Vec<ToolSpec> {
        vec![ToolSpec { kind: "function".into(),
            function: crate::brain::FunctionSpec { name: "list_dir".into(), description: "d".into(),
                parameters: serde_json::json!({"type":"object"}) } }]
    }

    #[test]
    fn dispatch_round_trips_through_driver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let runner = McpToolRunner::start(
            MockCaller { calls: calls.clone(), closed: closed.clone() }, specs1());
        let h = runner.handle();
        assert_eq!(h.specs().len(), 1);
        let out = h.dispatch("list_dir", &serde_json::json!({"path":"."}));
        assert_eq!(out, "вызвано:list_dir");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // shutdown синхронно джойнит driver → caller.close() гарантированно вызван (h ещё жив — не виснет благодаря stop-каналу)
        runner.shutdown();
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatch_after_shutdown_returns_error_not_hang() {
        let calls = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let runner = McpToolRunner::start(
            MockCaller { calls: calls.clone(), closed: closed.clone() }, specs1());
        let h = runner.handle();
        runner.shutdown(); // джойнит; rx дропнут
        let out = h.dispatch("list_dir", &serde_json::json!({}));
        assert!(out.contains("недоступн") || out.contains("ошибка"), "got: {out}");
    }

    // Ошибка вызова в середине работы (обрыв) → текст ошибки мозгу, не паника.
    struct ErrCaller;
    impl McpCaller for ErrCaller {
        async fn call(&self, _n: String, _a: Value) -> anyhow::Result<String> {
            anyhow::bail!("соединение разорвано")
        }
        async fn close(self) {}
    }
    #[test]
    fn caller_error_returns_error_text() {
        let runner = McpToolRunner::start(ErrCaller, specs1());
        let h = runner.handle();
        let out = h.dispatch("list_dir", &serde_json::json!({}));
        assert!(out.contains("ошибка на компе друга"), "got: {out}");
        runner.shutdown();
    }

    // Мок, который зависает → проверяем, что таймаут driver-а отрабатывает (короткий, инъекцией).
    struct HangCaller;
    impl McpCaller for HangCaller {
        async fn call(&self, _n: String, _a: Value) -> anyhow::Result<String> {
            futures_timer_sleep().await; Ok("не должно дойти".into())
        }
        async fn close(self) {}
    }
    async fn futures_timer_sleep() { tokio::time::sleep(Duration::from_secs(3600)).await; }

    #[test]
    fn call_timeout_returns_error() {
        // короткий таймаут через приватный конструктор для теста
        let runner = McpToolRunner::start_with_timeout(HangCaller, specs1(), Duration::from_millis(80));
        let h = runner.handle();
        let out = h.dispatch("list_dir", &serde_json::json!({}));
        assert!(out.contains("таймаут") || out.contains("timeout"), "got: {out}");
        runner.shutdown();
    }
}
