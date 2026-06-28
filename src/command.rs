//! Разбор «голой» команды оператора в (имя_тула, аргументы).
//!
//! Единый источник правды для парсинга прямых команд — переиспользуется
//! Telegram-фронтом (raw-команды владельца) и TUI (префикс `!`, ручное
//! управление без мозга). Парсер чистый: `&str -> Option<(String, Value)>`,
//! без I/O и без safety — safety применяется ниже, при `ToolRunner::dispatch`.

use serde_json::{json, Value};

/// Разбирает строку-команду в `(имя_тула, JSON-аргументы)`.
/// Распознаёт: `list_dir`/`ls`, `read_file`/`cat`, `search`/`grep`,
/// `run_shell`/`sh`/`run`, `write_file`. Неизвестное/пустое → `None`.
pub fn route_command(text: &str) -> Option<(String, Value)> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let (cmd, rest) = split_first_word(text);
    let rest = rest.trim();
    match cmd.as_str() {
        "list_dir" | "ls" => {
            let path = if rest.is_empty() { "." } else { rest };
            Some(("list_dir".into(), json!({ "path": path })))
        }
        "read_file" | "cat" => Some(("read_file".into(), json!({ "path": rest }))),
        "search" | "grep" => {
            let (root, query) = split_first_word(rest);
            Some(("search".into(), json!({ "root": root, "query": query.trim() })))
        }
        "run_shell" | "sh" | "run" => Some(("run_shell".into(), json!({ "command": rest }))),
        "write_file" => {
            let (path, content) = split_first_word(rest);
            Some(("write_file".into(), json!({ "path": path, "content": content })))
        }
        _ => None,
    }
}

/// Подсказка оператору: какие прямые команды доступны (префикс `!` в TUI).
/// Показывается при пустой/нераспознанной команде после `!`.
pub fn command_hint() -> String {
    "Команды: !ls <путь> | !cat <файл> | !grep <корень> <строка> | \
     !sh <команда> | !write_file <файл> <текст>. Без ! — обычный запрос мозгу."
        .to_string()
}

/// Делит строку на первое слово и остаток (по первому пробельному символу).
pub fn split_first_word(s: &str) -> (String, String) {
    match s.trim().split_once(char::is_whitespace) {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (s.trim().to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn routes_list_dir_with_path() {
        assert_eq!(
            route_command("ls /tmp"),
            Some(("list_dir".into(), json!({ "path": "/tmp" })))
        );
        assert_eq!(
            route_command("list_dir /var"),
            Some(("list_dir".into(), json!({ "path": "/var" })))
        );
    }

    #[test]
    fn list_dir_defaults_to_dot() {
        assert_eq!(
            route_command("ls"),
            Some(("list_dir".into(), json!({ "path": "." })))
        );
    }

    #[test]
    fn routes_read_file_aliases() {
        assert_eq!(
            route_command("cat todo.txt"),
            Some(("read_file".into(), json!({ "path": "todo.txt" })))
        );
        assert_eq!(
            route_command("read_file a.rs"),
            Some(("read_file".into(), json!({ "path": "a.rs" })))
        );
    }

    #[test]
    fn routes_search_root_and_query() {
        assert_eq!(
            route_command("grep src TODO"),
            Some(("search".into(), json!({ "root": "src", "query": "TODO" })))
        );
    }

    #[test]
    fn routes_run_shell_takes_whole_rest() {
        assert_eq!(
            route_command("sh echo hello world"),
            Some(("run_shell".into(), json!({ "command": "echo hello world" })))
        );
        assert_eq!(
            route_command("run uname -a"),
            Some(("run_shell".into(), json!({ "command": "uname -a" })))
        );
    }

    #[test]
    fn routes_write_file_path_and_content() {
        assert_eq!(
            route_command("write_file out.txt привет мир"),
            Some(("write_file".into(), json!({ "path": "out.txt", "content": "привет мир" })))
        );
    }

    #[test]
    fn unknown_command_is_none() {
        assert_eq!(route_command("чтотопопало"), None);
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(route_command(""), None);
        assert_eq!(route_command("   "), None);
    }

    #[test]
    fn hint_lists_aliases_and_prefix() {
        let h = command_hint();
        assert!(h.contains("!ls"));
        assert!(h.contains("!sh"));
        assert!(h.contains("Без !"));
    }

    #[test]
    fn split_first_word_basic() {
        assert_eq!(split_first_word("ls /tmp"), ("ls".into(), "/tmp".into()));
        assert_eq!(split_first_word("solo"), ("solo".into(), String::new()));
        // trim() убирает края, split_once режет по ПЕРВОМУ пробелу —
        // внутренние пробелы остатка сохраняются (route_command тримит rest сам).
        assert_eq!(split_first_word("  a   b c "), ("a".into(), "  b c".into()));
    }
}
