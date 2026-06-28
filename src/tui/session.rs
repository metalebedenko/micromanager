//! Персистентность диалога TUI: история мозга (`Vec<Message>`) ↔ JSON-файл.

use std::path::{Path, PathBuf};

use crate::brain::Message;

/// Файл сессии в per-user state-dir.
pub fn session_path() -> PathBuf {
    crate::paths::state_path("session.json")
}

/// Сохранить историю диалога. Перезаписывает файл целиком.
pub fn save_session(path: &Path, messages: &[Message]) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(messages)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Загрузить историю. Нет файла / битый JSON → None (стартуем со свежего).
pub fn load_session(path: &Path) -> Option<Vec<Message>> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Один сохранённый чат: заголовок + полная история мозга.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct StoredChat {
    pub title: String,
    pub messages: Vec<Message>,
}

/// Все чаты TUI на диске: индекс активного + список.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct StoredSessions {
    pub active: usize,
    pub chats: Vec<StoredChat>,
}

/// Путь файла всех чатов в per-user state-dir.
pub fn sessions_path() -> PathBuf {
    crate::paths::state_path("sessions.json")
}

/// Сохранить все чаты. Перезаписывает файл целиком. Best-effort у вызывающего.
pub fn save_sessions(path: &Path, s: &StoredSessions) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Загрузить чаты. Приоритет: sessions.json → миграция legacy session.json → один пустой.
/// Гарантия на выходе: непустой `chats`, `active` в диапазоне (санитизация).
pub fn load_sessions(sessions_path: &Path, legacy_session_path: &Path) -> StoredSessions {
    // 1. новый формат
    if let Ok(text) = std::fs::read_to_string(sessions_path) {
        if let Ok(mut s) = serde_json::from_str::<StoredSessions>(&text) {
            sanitize(&mut s);
            return s;
        }
        // битый JSON → один пустой
        return one_empty();
    }
    // 2. миграция легаси (>1 сообщения, как в нынешнем load_session)
    if let Some(msgs) = load_session(legacy_session_path) {
        if msgs.len() > 1 {
            return StoredSessions {
                active: 0,
                chats: vec![StoredChat { title: crate::tui::app::derive_title(&msgs), messages: msgs }],
            };
        }
    }
    // 3. ничего → один пустой
    one_empty()
}

fn one_empty() -> StoredSessions {
    StoredSessions {
        active: 0,
        chats: vec![StoredChat { title: String::new(), messages: crate::brain::new_conversation() }],
    }
}

/// Непустой chats + active в диапазоне.
fn sanitize(s: &mut StoredSessions) {
    if s.chats.is_empty() {
        *s = one_empty();
        return;
    }
    if s.active >= s.chats.len() {
        s.active = s.chats.len() - 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brain::{new_conversation, Message};

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let mut msgs = new_conversation();
        msgs.push(Message::user("вопрос"));
        save_session(&path, &msgs).unwrap();
        let loaded = load_session(&path).expect("должно загрузиться");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].content, "вопрос");
    }

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_session(&dir.path().join("nope.json")).is_none());
    }

    #[test]
    fn load_corrupt_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load_session(&path).is_none());
    }

    #[test]
    fn save_then_load_sessions_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("sessions.json");
        let legacy = dir.path().join("session.json");
        let mut m0 = new_conversation();
        m0.push(Message::user("первый"));
        let mut m1 = new_conversation();
        m1.push(Message::user("второй"));
        let s = StoredSessions {
            active: 1,
            chats: vec![
                StoredChat { title: "t0".into(), messages: m0 },
                StoredChat { title: "t1".into(), messages: m1 },
            ],
        };
        save_sessions(&sp, &s).unwrap();
        let back = load_sessions(&sp, &legacy);
        assert_eq!(back.active, 1);
        assert_eq!(back.chats.len(), 2);
        assert_eq!(back.chats[1].title, "t1");
        assert_eq!(back.chats[1].messages.last().unwrap().content, "второй");
    }

    #[test]
    fn migrates_legacy_session_into_one_chat() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("sessions.json"); // не существует
        let legacy = dir.path().join("session.json");
        let mut msgs = new_conversation();
        msgs.push(Message::user("из легаси"));
        save_session(&legacy, &msgs).unwrap();
        let s = load_sessions(&sp, &legacy);
        assert_eq!(s.chats.len(), 1, "один чат из легаси");
        assert_eq!(s.active, 0);
        assert!(s.chats[0].messages.iter().any(|m| m.content == "из легаси"));
    }

    #[test]
    fn no_files_gives_one_empty_chat() {
        let dir = tempfile::tempdir().unwrap();
        let s = load_sessions(&dir.path().join("nope.json"), &dir.path().join("none.json"));
        assert_eq!(s.chats.len(), 1);
        assert_eq!(s.active, 0);
    }

    #[test]
    fn corrupt_sessions_gives_one_empty_chat() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("sessions.json");
        std::fs::write(&sp, "{не json").unwrap();
        let s = load_sessions(&sp, &dir.path().join("none.json"));
        assert_eq!(s.chats.len(), 1);
    }

    #[test]
    fn sanitizes_empty_chats_and_out_of_range_active() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("sessions.json");
        std::fs::write(&sp, r#"{"active":5,"chats":[]}"#).unwrap();
        let s = load_sessions(&sp, &dir.path().join("none.json"));
        assert_eq!(s.chats.len(), 1, "пустой chats → один пустой чат");
        assert!(s.active < s.chats.len(), "active в диапазоне");
    }
}
