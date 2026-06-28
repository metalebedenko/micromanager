//! Ручное управление руками без мозга (префикс `!` в TUI).
//!
//! Чистое ядро: распарсить «голую» команду и исполнить её ОДИН раз через
//! активный `ToolRunner` (локальный MCP-раннер или удалённый B). Safety
//! полностью на стороне runner-а (`dispatch` → тот же гейт, что у agent-loop)
//! — этот слой ничего не ослабляет, лишь маршрутизирует разобранный tool-call.

use crate::brain::ToolRunner;
use crate::command::{command_hint, route_command};

/// Результат прямой команды оператора.
#[derive(Debug, PartialEq, Eq)]
pub enum ManualOutcome {
    /// Команда распознана и исполнена — текст результата (или отказа) для чата.
    Done(String),
    /// Команда не распознана — подсказка; мозг и руки не трогаются.
    Hint(String),
}

/// Исполнить прямую команду через `runner`, минуя мозг.
/// `raw` — текст ПОСЛЕ `!` (напр. "ls /tmp"). `route_command` None → подсказка;
/// Some → ровно один `dispatch` (под safety/вето активного runner-а).
pub fn run_manual(runner: &dyn ToolRunner, raw: &str) -> ManualOutcome {
    match route_command(raw) {
        Some((name, args)) => ManualOutcome::Done(runner.dispatch(&name, &args)),
        None => ManualOutcome::Hint(command_hint()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brain::{ToolRunner, ToolSpec};
    use serde_json::Value;
    use std::sync::Mutex;

    /// Мок: записывает все вызовы dispatch, возвращает детерминированный ответ.
    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl ToolRunner for RecordingRunner {
        fn specs(&self) -> Vec<ToolSpec> {
            vec![]
        }
        fn dispatch(&self, name: &str, args: &Value) -> String {
            self.calls
                .lock()
                .unwrap()
                .push((name.to_string(), args.clone()));
            format!("ОК:{name}")
        }
    }

    #[test]
    fn recognized_command_dispatches_once_without_brain() {
        let runner = RecordingRunner::default();
        let out = run_manual(&runner, "ls /tmp");
        assert_eq!(out, ManualOutcome::Done("ОК:list_dir".into()));
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "list_dir");
        assert_eq!(calls[0].1, serde_json::json!({ "path": "/tmp" }));
    }

    #[test]
    fn unrecognized_command_returns_hint_and_does_not_dispatch() {
        let runner = RecordingRunner::default();
        let out = run_manual(&runner, "чтотопопало");
        match out {
            ManualOutcome::Hint(h) => assert!(h.contains("!ls")),
            other => panic!("ожидалась подсказка, получено {other:?}"),
        }
        assert!(runner.calls.lock().unwrap().is_empty());
    }
}
