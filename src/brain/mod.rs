//! Мозг: агент-цикл (tool-calling) на локальной LLM (Ollama), рулящий «руками».
//!
//! Принцип «сменный мозг»: `Brain` — абстракция (Ollama / мок / в будущем API).
//! Цикл: задача → LLM выбирает тулы → `ToolRunner` исполняет через настоящий MCP
//! (in-process локально / iroh удалённо) с safety+audit → результат обратно в LLM.

mod ollama;
mod openai;
mod routing;

pub use ollama::OllamaBrain;
pub use openai::OpenAiBrain;
pub use routing::RoutingBrain;

use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Можно ли слать Bearer-ключ на этот хост: https:// — всегда; http:// — только localhost.
pub(crate) fn host_allows_key(host: &str) -> bool {
    if host.strip_prefix("https://").is_some() {
        return true;
    }
    if let Some(rest) = host.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or("");
        let hostname = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
        return matches!(hostname, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    }
    false // схему не распознали — безопаснее отказать
}

/// Выбор бэкенда мозга. Lowercase в JSON для конфига.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Ollama,
    #[serde(rename = "openai")]
    OpenAi,
}

/// Профиль одного мозга для конфига роутера (primary/fallback): провайдер + endpoint.
/// `build()` — тонкая обёртка над `build_brain` (единый путь выбора провайдера,
/// сохраняет guard `host_allows_key`, без дублирования).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BrainProfile {
    pub provider: Provider,
    pub host: String,
    pub model: String,
    pub api_key: Option<String>,
}

// Ручной Debug: НЕ печатать api_key (иначе `{:?}`/`dbg!` слил бы ключ в логи).
impl std::fmt::Debug for BrainProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrainProfile")
            .field("provider", &self.provider)
            .field("host", &self.host)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "***"))
            .finish()
    }
}

impl BrainProfile {
    /// Полнота профиля: непустые host и model. `api_key` намеренно не входит
    /// (Ollama ключа не требует; нужный, но отсутствующий ключ ловится на уровне `chat`).
    pub fn is_complete(&self) -> bool {
        !self.host.trim().is_empty() && !self.model.trim().is_empty()
    }

    /// Построить мозг — тонкая обёртка над `build_brain` (тот же путь, что и везде).
    pub fn build(&self) -> Box<dyn Brain> {
        build_brain(self.provider, &self.host, &self.model, self.api_key.clone())
    }

    /// Как `build`, но для локального (Ollama) мозга применяет таймаут запроса
    /// (роутер: зависший демон → `Err` по таймауту → fallback). Cloud-провайдер —
    /// как `build` (спец-таймаут не нужен; реальная проверка — первый запрос).
    pub fn build_with_timeout(&self, secs: u64) -> Box<dyn Brain> {
        match self.provider {
            Provider::Ollama => Box::new(
                OllamaBrain::new(&self.host, &self.model)
                    .with_api_key(self.api_key.clone())
                    .with_timeout(secs),
            ),
            Provider::OpenAi => self.build(),
        }
    }
}

/// Единая точка выбора мозга: и TUI, и CLI строят мозг отсюда.
/// `host` — это база endpoint'а: для Ollama хост демона, для OpenAI — base_url (…/v1).
pub fn build_brain(
    provider: Provider,
    host: &str,
    model: &str,
    api_key: Option<String>,
) -> Box<dyn Brain> {
    match provider {
        Provider::Ollama => Box::new(OllamaBrain::new(host, model).with_api_key(api_key)),
        Provider::OpenAi => Box::new(OpenAiBrain::new(host, model, api_key.unwrap_or_default())),
    }
}

/// Дефолтная модель Ollama, единая для CLI и TUI. Совпадает с фолбэком `OllamaBrain::from_env`.
pub fn default_model() -> String {
    "gemma4:12b".to_string()
}

/// Сообщение диалога (формат Ollama /api/chat).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub role: String,
    #[serde(default)]
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl Message {
    pub fn system(c: &str) -> Self {
        Self::plain("system", c)
    }
    pub fn user(c: &str) -> Self {
        Self::plain("user", c)
    }
    pub fn tool(name: &str, result: &str) -> Self {
        Self::tool_with_id(name, None, result)
    }
    pub fn tool_with_id(name: &str, tool_call_id: Option<String>, result: &str) -> Self {
        Self {
            role: "tool".to_string(),
            content: result.to_string(),
            tool_name: Some(name.to_string()),
            tool_call_id,
            tool_calls: None,
        }
    }
    fn plain(role: &str, c: &str) -> Self {
        Self {
            role: role.to_string(),
            content: c.to_string(),
            tool_name: None,
            tool_call_id: None,
            tool_calls: None,
        }
    }
}

/// Вызов инструмента, который вернула LLM.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ToolCall {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub function: FunctionCall,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Описание инструмента для LLM (формат tools у Ollama).
#[derive(Serialize, Clone)]
pub struct ToolSpec {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: FunctionSpec,
}

#[derive(Serialize, Clone)]
pub struct FunctionSpec {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Абстракция мозга: один шаг диалога (LLM → ответ, возможно с tool_calls).
pub trait Brain: Send + Sync {
    fn chat(&self, messages: &[Message], tools: &[ToolSpec]) -> anyhow::Result<Message>;

    /// Лёгкий probe доступности перед стартом сессии (для роутера мозга).
    /// Дефолт `true`: cloud-мозги и моки доступны «по построению»; локальный
    /// Ollama переопределяет (пинг демона). Реальная проверка cloud — первый `chat`.
    fn health(&self) -> bool {
        true
    }
}

/// Точка диспатча тулов для agent-loop: и локально, и по сети — через `McpToolRunner`
/// (in-process MCP / iroh). Loop не знает, где исполняется тул.
pub trait ToolRunner: Send + Sync {
    fn specs(&self) -> Vec<ToolSpec>;
    fn dispatch(&self, name: &str, args: &serde_json::Value) -> String;
}

const MAX_STEPS: usize = 12;

const SYSTEM_PROMPT: &str = "Ты — micromanager, аккуратный помощник-исполнитель на компьютере владельца. \
У тебя есть инструменты для файлов и команд. Работай по шагам: вызывай инструменты, читай результаты, \
и когда задача выполнена — дай краткий ответ на русском. Часть действий защищена: мутации могут \
потребовать подтверждения владельца, катастрофичные команды будут отклонены — это нормально и правильно, \
не пытайся обходить защиту. Если инструмент вернул отказ — объясни это владельцу, не настаивай.";

/// Свежий разговор: только системная установка. TUI копит историю поверх.
pub fn new_conversation() -> Vec<Message> {
    vec![Message::system(SYSTEM_PROMPT)]
}

/// Агент-цикл поверх ПЕРЕДАННОЙ истории (`messages` уже оканчивается user-репликой).
/// Дописывает assistant/tool-сообщения. Перед каждым шагом проверяет `cancel`
/// (между шагами, не внутри HTTP-вызова): отмена → ранний выход с пометкой.
pub fn run_agent_with(
    brain: &dyn Brain,
    runner: &dyn ToolRunner,
    messages: &mut Vec<Message>,
    cancel: &AtomicBool,
) -> anyhow::Result<String> {
    let tools = runner.specs();
    for _ in 0..MAX_STEPS {
        if cancel.load(Ordering::SeqCst) {
            return Ok("⏹ задача отменена".to_string());
        }
        let reply = brain.chat(messages, &tools)?;
        let calls = reply.tool_calls.clone().unwrap_or_default();
        messages.push(reply.clone());

        if calls.is_empty() {
            return Ok(reply.content);
        }
        for call in calls {
            let result = runner.dispatch(&call.function.name, &call.function.arguments);
            messages.push(Message::tool_with_id(&call.function.name, call.id.clone(), &result));
        }
    }
    Ok("[агент достиг лимита шагов — задача не завершена]".to_string())
}

/// Одноразовый прогон по задаче (без сохранения истории). Обёртка над `run_agent_with`.
pub fn run_agent(brain: &dyn Brain, runner: &dyn ToolRunner, task: &str) -> anyhow::Result<String> {
    let mut messages = new_conversation();
    messages.push(Message::user(task));
    run_agent_with(brain, runner, &mut messages, &AtomicBool::new(false))
}

/// Переиспользуемые тест-моки мозга (доступны другим модулям крейта в тестах).
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Мозг: первый ход — tool_call `list_dir`, второй — финал «готово».
    pub(crate) struct TwoStepBrain {
        step: AtomicUsize,
    }
    impl Brain for TwoStepBrain {
        fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
            if self.step.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Message {
                    role: "assistant".into(),
                    content: String::new(),
                    tool_name: None,
                    tool_call_id: None,
                    tool_calls: Some(vec![ToolCall {
                        id: Some("c1".into()),
                        function: FunctionCall {
                            name: "list_dir".into(),
                            arguments: serde_json::json!({"path": "."}),
                        },
                    }]),
                })
            } else {
                Ok(Message {
                    role: "assistant".into(),
                    content: "готово".into(),
                    tool_name: None,
                    tool_call_id: None,
                    tool_calls: None,
                })
            }
        }
    }

    pub(crate) fn two_step() -> TwoStepBrain {
        TwoStepBrain {
            step: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
mod runner_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // Мок-runner: фиксирует, что dispatch позвали, и с каким тулом.
    struct MockRunner {
        calls: AtomicUsize,
        last: std::sync::Mutex<String>,
    }
    impl ToolRunner for MockRunner {
        fn specs(&self) -> Vec<ToolSpec> {
            vec![]
        }
        fn dispatch(&self, name: &str, _args: &serde_json::Value) -> String {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap() = name.to_string();
            "ок-результат".to_string()
        }
    }

    #[test]
    fn agent_loop_dispatches_through_toolrunner_trait() {
        let runner = MockRunner {
            calls: AtomicUsize::new(0),
            last: std::sync::Mutex::new(String::new()),
        };
        let brain = super::tests_support::two_step();
        let mut messages = new_conversation();
        messages.push(Message::user("задача"));
        let ans =
            run_agent_with(&brain, &runner, &mut messages, &AtomicBool::new(false)).unwrap();
        assert_eq!(ans, "готово");
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(*runner.last.lock().unwrap(), "list_dir");
    }
}

#[cfg(test)]
mod factory_tests {
    use super::*;

    #[test]
    fn provider_default_is_ollama() {
        assert_eq!(Provider::default(), Provider::Ollama);
    }

    #[test]
    fn brain_profile_debug_masks_api_key() {
        let p = BrainProfile {
            provider: Provider::OpenAi,
            host: "https://api.example.com".into(),
            model: "gpt".into(),
            api_key: Some("sk-super-secret-value".into()),
        };
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("sk-super-secret-value"), "ключ утёк в Debug: {dbg}");
        assert!(dbg.contains("***"), "ожидали маску: {dbg}");
    }

    #[test]
    fn provider_serde_lowercase() {
        assert_eq!(serde_json::to_string(&Provider::OpenAi).unwrap(), "\"openai\"");
        let p: Provider = serde_json::from_str("\"ollama\"").unwrap();
        assert_eq!(p, Provider::Ollama);
    }

    #[test]
    fn brain_health_defaults_true() {
        // Мозг без override health() — дефолт трейта должен давать true,
        // чтобы существующие реализации и моки не ломались.
        struct Bare;
        impl Brain for Bare {
            fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
                Ok(Message::system("x"))
            }
        }
        assert!(Bare.health(), "health() по умолчанию должен быть true");
    }

    #[test]
    fn brain_profile_is_complete() {
        // Полнота = непустые host и model (api_key намеренно не входит).
        assert!(!BrainProfile::default().is_complete(), "дефолтный профиль пуст");
        let p = BrainProfile {
            provider: Provider::Ollama,
            host: "http://h".into(),
            model: "m".into(),
            api_key: None,
        };
        assert!(p.is_complete());
        let no_model = BrainProfile {
            model: String::new(),
            ..p.clone()
        };
        assert!(!no_model.is_complete(), "без model — неполный");
    }

    #[test]
    fn brain_profile_build_delegates_without_panic() {
        let p = BrainProfile {
            provider: Provider::Ollama,
            host: "http://localhost:11434".into(),
            model: "m".into(),
            api_key: None,
        };
        let _ = p.build(); // тонкая обёртка над build_brain
        let _ = p.build_with_timeout(5); // local с таймаутом
    }

    #[test]
    fn build_brain_picks_implementation() {
        // Тип стирается за dyn Brain — проверяем, что фабрика не паникует и строит оба.
        let _o = build_brain(Provider::Ollama, "http://localhost:11434", "gemma4:12b", None);
        let _a = build_brain(Provider::OpenAi, "https://openrouter.ai/api/v1", "z-ai/glm-4.6", Some("k".into()));
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // Хелпер: assistant-сообщение (Message::plain приватный → строим литералом, все поля pub).
    fn assistant(text: &str) -> Message {
        Message {
            role: "assistant".into(),
            content: text.into(),
            tool_name: None,
            tool_call_id: None,
            tool_calls: None,
        }
    }

    // Мок: финальный ответ; считает, сколько сообщений видел в ПОСЛЕДНИЙ раз.
    struct EchoBrain {
        seen: AtomicUsize,
    }
    impl Brain for EchoBrain {
        fn chat(&self, messages: &[Message], _tools: &[ToolSpec]) -> anyhow::Result<Message> {
            self.seen.store(messages.len(), Ordering::SeqCst);
            Ok(assistant("ок"))
        }
    }

    // Плейсхолдер-раннер для тестов agent-loop, которым не важен результат тула
    // (проверяют поведение цикла / call_id-threading, не исполнение).
    struct NoopRunner;
    impl ToolRunner for NoopRunner {
        fn specs(&self) -> Vec<ToolSpec> {
            Vec::new()
        }
        fn dispatch(&self, _name: &str, _args: &serde_json::Value) -> String {
            "ок".to_string()
        }
    }
    fn mock_runner() -> NoopRunner {
        NoopRunner
    }

    #[test]
    fn run_agent_with_carries_prior_history() {
        let brain = EchoBrain {
            seen: AtomicUsize::new(0),
        };
        let disp = mock_runner();
        let cancel = AtomicBool::new(false);
        // история: system + прошлый user + прошлый assistant + новый user = 4
        let mut messages = new_conversation();
        messages.push(Message::user("первый вопрос"));
        messages.push(assistant("первый ответ"));
        messages.push(Message::user("второй вопрос"));
        let ans = run_agent_with(&brain, &disp, &mut messages, &cancel).unwrap();
        assert_eq!(ans, "ок");
        // мозг увидел всю историю (4), а не только [system, user]=2
        assert_eq!(brain.seen.load(Ordering::SeqCst), 4);
        // ответ ассистента дописан в историю → теперь 5
        assert_eq!(messages.len(), 5);
    }

    // Мок, который всегда зовёт тул (бесконечный цикл без отмены) — проверяем, что cancel рвёт.
    struct LoopBrain;
    impl Brain for LoopBrain {
        fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
            Ok(Message {
                role: "assistant".into(),
                content: String::new(),
                tool_name: None,
                tool_call_id: None,
                tool_calls: Some(vec![ToolCall {
                    id: None,
                    function: FunctionCall {
                        name: "list_dir".into(),
                        arguments: serde_json::json!({"path": "."}),
                    },
                }]),
            })
        }
    }

    #[test]
    fn cancel_stops_the_loop() {
        let disp = mock_runner();
        let cancel = AtomicBool::new(true); // уже отменено → цикл не должен делать шаги
        let mut messages = new_conversation();
        messages.push(Message::user("задача"));
        let ans = run_agent_with(&LoopBrain, &disp, &mut messages, &cancel).unwrap();
        assert_eq!(ans, "⏹ задача отменена");
    }

    #[test]
    fn run_agent_wrapper_still_works() {
        let brain = EchoBrain {
            seen: AtomicUsize::new(0),
        };
        let disp = mock_runner();
        let ans = run_agent(&brain, &disp, "задача").unwrap();
        assert_eq!(ans, "ок");
        assert_eq!(brain.seen.load(Ordering::SeqCst), 2); // [system, user]
    }

    #[test]
    fn tool_message_carries_optional_call_id() {
        let m = Message::tool_with_id("read_file", Some("call_42".into()), "ok");
        assert_eq!(m.tool_call_id.as_deref(), Some("call_42"));
        assert_eq!(m.tool_name.as_deref(), Some("read_file"));
    }

    #[test]
    fn ollama_serialization_omits_none_ids() {
        // Без id поля не должны появляться в JSON (совместимость с Ollama и session.json).
        let m = Message::user("привет");
        let j = serde_json::to_string(&m).unwrap();
        assert!(!j.contains("tool_call_id"), "got: {j}");
        let tc = ToolCall { id: None, function: FunctionCall { name: "x".into(), arguments: serde_json::json!({}) } };
        let j = serde_json::to_string(&tc).unwrap();
        assert!(!j.contains("\"id\""), "got: {j}");
    }

    #[test]
    fn loop_threads_call_id_into_tool_message() {
        // Мозг возвращает один tool_call c id, затем финал. tool-сообщение должно нести этот id.
        use std::sync::atomic::AtomicBool;
        struct OneCallBrain { step: std::sync::atomic::AtomicUsize }
        impl Brain for OneCallBrain {
            fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
                let n = self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    Ok(Message {
                        role: "assistant".into(), content: String::new(), tool_name: None,
                        tool_call_id: None,
                        tool_calls: Some(vec![ToolCall {
                            id: Some("call_7".into()),
                            function: FunctionCall { name: "list_dir".into(), arguments: serde_json::json!({"path":"."}) },
                        }]),
                    })
                } else {
                    Ok(Message { role: "assistant".into(), content: "готово".into(), tool_name: None, tool_call_id: None, tool_calls: None })
                }
            }
        }
        let brain = OneCallBrain { step: std::sync::atomic::AtomicUsize::new(0) };
        let disp = mock_runner();
        let mut messages = new_conversation();
        messages.push(Message::user("покажи файлы"));
        run_agent_with(&brain, &disp, &mut messages, &AtomicBool::new(false)).unwrap();
        let tool_msg = messages.iter().find(|m| m.role == "tool").expect("есть tool-сообщение");
        assert_eq!(tool_msg.tool_call_id.as_deref(), Some("call_7"));
    }
}
