//! Агент-цикл через настоящий MCP (in-process). Ядро тестируется
//! мок-мозгом (без Ollama); тулы исполняются реальным `HandsServer` по duplex.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use micromanager::audit::NullAudit;
use micromanager::brain::{run_agent, Brain, FunctionCall, Message, ToolCall, ToolSpec};
use micromanager::net::McpToolRunner;
use micromanager::safety::{Action, Confirmer, Policy};

struct Yes;
impl Confirmer for Yes {
    fn confirm(&self, _: &Action) -> bool {
        true
    }
}

/// Локальный MCP-раннер (rmcp-клиент ↔ in-process HandsServer) для тестов.
fn test_runner() -> McpToolRunner {
    McpToolRunner::start_local(Policy::default(), Arc::new(Yes), Arc::new(NullAudit))
}

/// Мок-мозг: 1-й шаг — просит list_dir; 2-й — отдаёт финальный ответ.
struct MockBrain {
    calls: AtomicUsize,
    path: String,
}
impl Brain for MockBrain {
    fn chat(&self, messages: &[Message], _tools: &[ToolSpec]) -> anyhow::Result<Message> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Ok(Message {
                role: "assistant".to_string(),
                content: String::new(),
                tool_name: None,
                tool_call_id: None,
                tool_calls: Some(vec![ToolCall {
                    id: None,
                    function: FunctionCall {
                        name: "list_dir".to_string(),
                        arguments: serde_json::json!({ "path": self.path }),
                    },
                }]),
            })
        } else {
            // на втором шаге агент должен был скормить результат тула
            assert!(
                messages.iter().any(|m| m.role == "tool"),
                "результат тула должен вернуться в диалог"
            );
            Ok(Message {
                role: "assistant".to_string(),
                content: "готово".to_string(),
                tool_name: None,
                tool_call_id: None,
                tool_calls: None,
            })
        }
    }
}

#[test]
fn agent_loop_executes_tool_then_finishes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.txt"), "1").unwrap();
    let brain = MockBrain {
        calls: AtomicUsize::new(0),
        path: dir.path().to_string_lossy().into_owned(),
    };
    let runner = test_runner();
    let answer = run_agent(&brain, &runner.handle(), "посмотри папку").unwrap();
    assert_eq!(answer, "готово");
    runner.shutdown();
}

#[test]
fn dispatch_list_dir_returns_entries() {
    use micromanager::brain::ToolRunner;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("y.txt"), "1").unwrap();
    let runner = test_runner();
    let out = runner.handle().dispatch(
        "list_dir",
        &serde_json::json!({ "path": dir.path().to_string_lossy() }),
    );
    assert!(out.contains("y.txt"), "got: {out}");
    runner.shutdown();
}

#[test]
fn dispatch_hardline_is_denied() {
    use micromanager::brain::ToolRunner;
    let runner = test_runner();
    let out = runner
        .handle()
        .dispatch("run_shell", &serde_json::json!({ "command": "rm -rf /" }));
    let low = out.to_lowercase();
    // hardline-команда не исполняется: ответ — отказ/ошибка (MCP-путь возвращает текст ошибки).
    assert!(
        low.contains("отказ") || low.contains("hardline") || low.contains("ошибк"),
        "hardline должна быть отклонена: {out}"
    );
    runner.shutdown();
}

#[test]
fn dispatch_unknown_tool_errors() {
    use micromanager::brain::ToolRunner;
    let runner = test_runner();
    let out = runner.handle().dispatch("nope", &serde_json::json!({}));
    let low = out.to_lowercase();
    // несуществующий тул → MCP-ошибка (не успешный результат).
    assert!(
        low.contains("ошибк") || low.contains("неизвестн") || low.contains("not found") || low.contains("unknown"),
        "неизвестный тул → ошибка: {out}"
    );
    runner.shutdown();
}
