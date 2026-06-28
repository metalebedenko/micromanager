//! Обёртка ToolRunner: дублирует удалённые tool-call'ы в панель действий TUI.

use serde_json::Value;

use crate::brain::{ToolRunner, ToolSpec};
use crate::net::McpHandle;
use crate::tui::event::AppEvent;

/// Обёртка-тройник: пересылает каждый tool-call во внутренний ToolRunner,
/// одновременно дублируя вызов и результат в канал событий TUI.
pub struct ActivityTee<R: ToolRunner> {
    pub inner: R,
    pub tx: std::sync::mpsc::Sender<AppEvent>,
}

/// Конкретный тип для удалённого узла.
pub type ActivityRunner = ActivityTee<McpHandle>;

impl<R: ToolRunner> ToolRunner for ActivityTee<R> {
    fn specs(&self) -> Vec<ToolSpec> {
        self.inner.specs()
    }

    fn dispatch(&self, name: &str, args: &Value) -> String {
        // Событие «до»: что отправляем на удалённый узел.
        let _ = self.tx.send(AppEvent::Activity(format!("→B: {name} {args}")));
        let out = self.inner.dispatch(name, args);
        // Событие «после»: усечённый ответ (не заливать панель гигантским JSON).
        let shown: String = out.chars().take(80).collect();
        let _ = self.tx.send(AppEvent::Activity(format!("←B: {shown}")));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Мок-раннер: возвращает детерминированный ответ без сети.
    struct MockInner;

    impl ToolRunner for MockInner {
        fn specs(&self) -> Vec<ToolSpec> {
            vec![]
        }
        fn dispatch(&self, name: &str, _a: &Value) -> String {
            format!("ОК:{name}")
        }
    }

    #[test]
    fn dispatch_tees_two_activity_events_and_returns_inner() {
        let (tx, rx) = std::sync::mpsc::channel();
        let tee = ActivityTee { inner: MockInner, tx };
        let out = tee.dispatch("list_dir", &serde_json::json!({"path":"."}));
        assert_eq!(out, "ОК:list_dir");
        let a = rx.recv().unwrap();
        let b = rx.recv().unwrap();
        assert!(matches!(a, AppEvent::Activity(s) if s.contains("→B") && s.contains("list_dir")));
        assert!(matches!(b, AppEvent::Activity(s) if s.contains("←B")));
    }
}
