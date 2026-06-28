//! Telegram-confirm с inline-кнопками + anti-replay.
//!
//! Инвариант: callback_data несёт непредсказуемый nonce, связанный с pending-
//! действием; кнопка одноразовая (resolve удаляет nonce) и с TTL. Нельзя нажать чужую/
//! устаревшую/угаданную. confirm() блокируется на ответе (в отдельной задаче) с fail-closed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::safety::{Action, Confirmer};

/// Решение владельца по inline-кнопке.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Разрешить один раз.
    Yes,
    /// Разрешить на всю сессию (доверие).
    All,
    /// Запретить.
    No,
}

/// callback_data = "<y|a|n>:<nonce>".
pub fn format_callback(d: Decision, nonce: &str) -> String {
    let p = match d {
        Decision::Yes => "y",
        Decision::All => "a",
        Decision::No => "n",
    };
    format!("{p}:{nonce}")
}

pub fn parse_callback(data: &str) -> Option<(Decision, String)> {
    let (p, nonce) = data.split_once(':')?;
    if nonce.is_empty() {
        return None;
    }
    let d = match p {
        "y" => Decision::Yes,
        "a" => Decision::All,
        "n" => Decision::No,
        _ => return None,
    };
    Some((d, nonce.to_string()))
}

fn nonce() -> String {
    use rand::Rng;
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Реестр ожидающих подтверждений: nonce → (время, канал ответа). Одноразовость = remove.
#[derive(Default)]
pub struct PendingConfirms {
    map: Mutex<HashMap<String, (Instant, std::sync::mpsc::Sender<Decision>)>>,
}

impl PendingConfirms {
    pub fn new() -> Self {
        Self::default()
    }

    /// Зарегистрировать ожидание; вернуть (nonce, приёмник решения).
    pub fn register(&self) -> (String, Receiver<Decision>) {
        let n = nonce();
        let (tx, rx) = channel();
        self.map.lock().unwrap().insert(n.clone(), (Instant::now(), tx));
        (n, rx)
    }

    /// Доставить решение по nonce. true — если nonce был валиден (одноразово). Повтор/чужой → false (no-op).
    pub fn resolve(&self, nonce: &str, d: Decision) -> bool {
        match self.map.lock().unwrap().remove(nonce) {
            Some((_, tx)) => {
                let _ = tx.send(d);
                true
            }
            None => false,
        }
    }

    /// Снять незакрытое ожидание (по таймауту/ошибке отправки).
    pub fn cancel(&self, nonce: &str) {
        self.map.lock().unwrap().remove(nonce);
    }

    /// Удалить протухшие (TTL) ожидания.
    pub fn sweep(&self, ttl: Duration) {
        self.map
            .lock()
            .unwrap()
            .retain(|_, (t, _)| t.elapsed() < ttl);
    }

    #[cfg(test)]
    fn any_nonce(&self) -> Option<String> {
        self.map.lock().unwrap().keys().next().cloned()
    }
}

/// Канал отправки inline-кнопок (sync, вызывается из блокирующего confirm). Мок в тестах.
pub trait ButtonSender: Send + Sync {
    fn send_confirm(
        &self,
        chat_id: i64,
        text: &str,
        nonce: &str,
        dangerous: bool,
    ) -> anyhow::Result<()>;
}

fn describe(action: &Action) -> String {
    action
        .command
        .clone()
        .or_else(|| action.path.as_ref().map(|p| p.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

/// Confirmer через Telegram inline-кнопки. Блокируется на ответе с TTL (fail-closed).
/// Доверие-на-сессию (кнопка «На сессию»); опасное — отдельный запрос, доверием не покрыто.
pub struct TelegramConfirmer {
    chat_id: i64,
    pending: std::sync::Arc<PendingConfirms>,
    sender: Box<dyn ButtonSender>,
    ttl: Duration,
    trusted: AtomicBool,
}

impl TelegramConfirmer {
    pub fn new(
        chat_id: i64,
        pending: std::sync::Arc<PendingConfirms>,
        sender: Box<dyn ButtonSender>,
        ttl: Duration,
    ) -> Self {
        Self {
            chat_id,
            pending,
            sender,
            ttl,
            trusted: AtomicBool::new(false),
        }
    }

    fn ask(&self, action: &Action, dangerous: bool) -> Option<Decision> {
        let (n, rx) = self.pending.register();
        let text = describe(action);
        if self
            .sender
            .send_confirm(self.chat_id, &text, &n, dangerous)
            .is_err()
        {
            self.pending.cancel(&n);
            return None;
        }
        match rx.recv_timeout(self.ttl) {
            Ok(d) => Some(d),
            Err(_) => {
                self.pending.cancel(&n);
                None // таймаут → fail-closed
            }
        }
    }
}

impl Confirmer for TelegramConfirmer {
    fn confirm(&self, action: &Action) -> bool {
        if self.trusted.load(Ordering::SeqCst) {
            return true;
        }
        match self.ask(action, false) {
            Some(Decision::Yes) => true,
            Some(Decision::All) => {
                self.trusted.store(true, Ordering::SeqCst);
                true
            }
            Some(Decision::No) | None => false,
        }
    }

    fn confirm_dangerous(&self, action: &Action, _reason: &str) -> bool {
        // опасное: только явное Yes; «на сессию» НЕ покрывает катастрофу
        matches!(self.ask(action, true), Some(Decision::Yes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn callback_roundtrip() {
        for d in [Decision::Yes, Decision::All, Decision::No] {
            let s = format_callback(d, "abc123");
            assert_eq!(parse_callback(&s), Some((d, "abc123".to_string())));
        }
        assert_eq!(parse_callback("z:abc"), None);
        assert_eq!(parse_callback("y:"), None);
        assert_eq!(parse_callback("garbage"), None);
    }

    #[test]
    fn resolve_is_one_time_and_routes() {
        let p = PendingConfirms::new();
        let (n, rx) = p.register();
        assert!(p.resolve(&n, Decision::Yes));
        assert_eq!(rx.recv().unwrap(), Decision::Yes);
        // повтор того же nonce → no-op (одноразовость / anti-replay)
        assert!(!p.resolve(&n, Decision::Yes));
        // чужой/угаданный nonce → no-op
        assert!(!p.resolve("ghost", Decision::Yes));
    }

    struct OkSender;
    impl ButtonSender for OkSender {
        fn send_confirm(&self, _: i64, _: &str, _: &str, _: bool) -> anyhow::Result<()> {
            Ok(())
        }
    }
    struct FailSender;
    impl ButtonSender for FailSender {
        fn send_confirm(&self, _: i64, _: &str, _: &str, _: bool) -> anyhow::Result<()> {
            anyhow::bail!("нет сети")
        }
    }

    fn act() -> Action {
        Action {
            kind: crate::safety::ActionKind::Exec,
            path: None,
            command: Some("echo hi".into()),
        }
    }

    #[test]
    fn confirm_blocks_until_resolved_yes() {
        let p = Arc::new(PendingConfirms::new());
        let c = TelegramConfirmer::new(1, p.clone(), Box::new(OkSender), Duration::from_secs(5));
        let h = std::thread::spawn(move || c.confirm(&act()));
        // дождаться регистрации pending и разрешить
        let n = loop {
            if let Some(n) = p.any_nonce() {
                break n;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(p.resolve(&n, Decision::Yes));
        assert!(h.join().unwrap());
    }

    #[test]
    fn all_sets_session_trust() {
        let p = Arc::new(PendingConfirms::new());
        let c = TelegramConfirmer::new(1, p.clone(), Box::new(OkSender), Duration::from_secs(5));
        // первый confirm с «All» в отдельном потоке
        let p2 = p.clone();
        let n = std::thread::spawn(move || {
            let n = loop {
                if let Some(n) = p2.any_nonce() {
                    break n;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            p2.resolve(&n, Decision::All)
        });
        assert!(c.confirm(&act()));
        n.join().unwrap();
        // теперь доверие на сессию → confirm не блокируется (sender не нужен)
        assert!(c.confirm(&act()));
    }

    #[test]
    fn timeout_is_fail_closed() {
        let p = Arc::new(PendingConfirms::new());
        let c = TelegramConfirmer::new(1, p, Box::new(OkSender), Duration::from_millis(50));
        assert!(!c.confirm(&act())); // никто не ответил → deny
    }

    #[test]
    fn send_failure_is_fail_closed() {
        let p = Arc::new(PendingConfirms::new());
        let c = TelegramConfirmer::new(1, p, Box::new(FailSender), Duration::from_secs(5));
        assert!(!c.confirm(&act()));
    }

    #[test]
    fn dangerous_not_covered_by_session_trust() {
        let p = Arc::new(PendingConfirms::new());
        let c = TelegramConfirmer::new(1, p.clone(), Box::new(OkSender), Duration::from_millis(50));
        // «All» по обычному не должен авто-разрешать опасное (оно всегда спрашивает; таймаут→deny)
        assert!(!c.confirm_dangerous(&act(), "hardline: x"));
    }
}
