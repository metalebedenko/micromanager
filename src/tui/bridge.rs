//! Канальные швы между фоновым агент-потоком и UI:
//! `ChannelConfirmer` (impl Confirmer) и `ChannelAudit` (impl Audit).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Sender};
use std::time::Duration;

use crate::safety::{Action, Confirmer};
use crate::tui::event::{AppEvent, ConfirmRequest};

/// Confirmer, проксирующий запрос в UI по каналу и блокирующийся на ответе.
/// Fail-closed: таймаут/закрытый канал/ошибка отправки → false. Доверие-на-сессию
/// покрывает только обычные мутации, не dangerous (как у Telegram/StdinConfirmer).
pub struct ChannelConfirmer {
    tx: Sender<AppEvent>,
    timeout: Duration,
    trusted: std::sync::Arc<AtomicBool>,
}

impl ChannelConfirmer {
    pub fn new(tx: Sender<AppEvent>, timeout: Duration) -> Self {
        Self {
            tx,
            timeout,
            trusted: std::sync::Arc::new(AtomicBool::new(false)),
        }
    }

    /// Отметить «доверять до конца сессии» (ответ «На сессию»).
    pub fn trust_session(&self) {
        self.trusted.store(true, Ordering::SeqCst);
    }

    fn ask(&self, prompt: String, dangerous: bool) -> bool {
        let (reply_tx, reply_rx) = sync_channel::<bool>(1);
        let req = ConfirmRequest {
            prompt,
            dangerous,
            reply: reply_tx,
            // делимся СВОИМ флагом доверия — ответ «На сессию» поставит его точечно.
            trust: self.trusted.clone(),
        };
        if self.tx.send(AppEvent::Confirm(req)).is_err() {
            return false; // UI исчез — fail-closed
        }
        matches!(reply_rx.recv_timeout(self.timeout), Ok(true))
    }
}

/// Краткое человекочитаемое описание действия для модалки.
fn describe(action: &Action) -> String {
    let what = action
        .command
        .clone()
        .or_else(|| action.path.as_ref().map(|p| p.display().to_string()))
        .unwrap_or_default();
    format!("{:?}: {what}", action.kind)
}

impl Confirmer for ChannelConfirmer {
    fn confirm(&self, action: &Action) -> bool {
        if self.trusted.load(Ordering::SeqCst) {
            return true;
        }
        self.ask(format!("Подтвердить {}?", describe(action)), false)
    }

    fn confirm_dangerous(&self, action: &Action, reason: &str) -> bool {
        // Доверие игнорируется; отдельная громкая модалка.
        self.ask(
            format!(
                "⚠ ОПАСНО: {}\nПричина: {reason}\nВсё равно выполнить?",
                describe(action)
            ),
            true,
        )
    }
}

/// Форвард `Confirmer` через `Arc`: цикл держит общий `Arc<ChannelConfirmer>` (зовёт
/// `trust_session`), а исполнитель получает его как `Arc<dyn Confirmer>` в `HandsServer`.
impl Confirmer for std::sync::Arc<ChannelConfirmer> {
    fn confirm(&self, action: &Action) -> bool {
        (**self).confirm(action)
    }
    fn confirm_dangerous(&self, action: &Action, reason: &str) -> bool {
        (**self).confirm_dangerous(action, reason)
    }
}

use crate::audit::{Audit, AuditEntry};

/// Audit-приёмник, пересылающий каждую запись в UI как строку панели активности.
/// `prefix` — метка источника (напр. `"A→ "` для удалённого, `"ты→ "` для своих `!`).
pub struct ChannelAudit {
    tx: Sender<AppEvent>,
    prefix: String,
}

impl ChannelAudit {
    pub fn new(tx: Sender<AppEvent>) -> Self {
        Self {
            tx,
            prefix: String::new(),
        }
    }

    /// С меткой источника в начале строки панели.
    pub fn labeled(tx: Sender<AppEvent>, prefix: &str) -> Self {
        Self {
            tx,
            prefix: prefix.to_string(),
        }
    }
}

impl Audit for ChannelAudit {
    fn record(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let tag = if entry.verdict.is_empty() {
            entry.kind.clone()
        } else {
            entry.verdict.clone()
        };
        let line = format!("{}{} {} {}", self.prefix, tag, entry.action, entry.result)
            .trim_end()
            .to_string();
        // UI исчез — не ошибка журналирования (fail-closed решают confirmer/файл-аудит).
        let _ = self.tx.send(AppEvent::Activity(line));
        Ok(())
    }
}

/// Журнал в два приёмника: primary (fail-closed, напр. файл) + secondary (best-effort, напр. панель).
pub struct DualAudit {
    primary: Box<dyn Audit>,
    secondary: Box<dyn Audit>,
}

impl DualAudit {
    pub fn new(primary: Box<dyn Audit>, secondary: Box<dyn Audit>) -> Self {
        Self { primary, secondary }
    }
}

impl Audit for DualAudit {
    fn record(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let _ = self.secondary.record(entry); // best-effort
        self.primary.record(entry) // fail-closed зависит от primary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::{Action, ActionKind, Confirmer};
    use crate::tui::event::AppEvent;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    fn write_action() -> Action {
        Action {
            kind: ActionKind::Write,
            path: Some(PathBuf::from("/tmp/x")),
            command: None,
        }
    }

    #[test]
    fn labeled_audit_prefixes_activity() {
        use crate::audit::AuditEntry;
        let (tx, rx) = mpsc::channel();
        let a = ChannelAudit::labeled(tx, "A→ ");
        let entry = AuditEntry {
            ts: String::new(),
            kind: "decision".into(),
            action: "Exec echo".into(),
            verdict: "allow".into(),
            result: String::new(),
        };
        a.record(&entry).unwrap();
        if let AppEvent::Activity(line) = rx.recv().unwrap() {
            assert!(line.starts_with("A→ "), "строка должна нести префикс источника: {line}");
        } else {
            panic!("ожидался Activity");
        }
    }

    #[test]
    fn trust_flag_in_request_marks_this_confirmer() {
        use std::sync::atomic::Ordering;
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let c = ChannelConfirmer::new(tx, Duration::from_secs(5));
        let action = write_action();
        // UI-имитация: получить запрос, «нажать a» = выставить trust-флаг + ответить true.
        let h = std::thread::spawn(move || {
            if let AppEvent::Confirm(req) = rx.recv().unwrap() {
                req.trust.store(true, Ordering::SeqCst);
                req.reply.send(true).unwrap();
            }
        });
        assert!(c.confirm(&action), "ответ true → разрешено");
        h.join().unwrap();
        // доверие выставлено → следующий confirm НЕ шлёт запрос (некому отвечать), но true.
        assert!(c.confirm(&action), "после доверия — без запроса true");
    }

    #[test]
    fn confirm_resolves_yes_from_ui() {
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let confirmer = ChannelConfirmer::new(tx, Duration::from_secs(2));
        // имитируем UI в отдельном потоке: получить запрос и ответить «да»
        let ui = std::thread::spawn(move || {
            if let Ok(AppEvent::Confirm(req)) = rx.recv() {
                assert!(!req.dangerous);
                req.reply.send(true).unwrap();
            }
        });
        assert!(confirmer.confirm(&write_action()));
        ui.join().unwrap();
    }

    #[test]
    fn confirm_times_out_to_false() {
        let (tx, _rx) = mpsc::channel::<AppEvent>(); // _rx висит, никто не отвечает
        let confirmer = ChannelConfirmer::new(tx, Duration::from_millis(50));
        assert!(!confirmer.confirm(&write_action())); // fail-closed
    }

    #[test]
    fn session_trust_skips_prompt() {
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let confirmer = ChannelConfirmer::new(tx, Duration::from_secs(2));
        confirmer.trust_session();
        // никакого UI-ответчика нет, но trust → сразу true, без отправки запроса
        assert!(confirmer.confirm(&write_action()));
        assert!(rx.try_recv().is_err()); // запрос НЕ отправлялся
    }

    #[test]
    fn dangerous_ignores_trust_and_flags_request() {
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let confirmer = ChannelConfirmer::new(tx, Duration::from_secs(2));
        confirmer.trust_session(); // не должно влиять на dangerous
        let ui = std::thread::spawn(move || {
            if let Ok(AppEvent::Confirm(req)) = rx.recv() {
                assert!(req.dangerous);
                req.reply.send(false).unwrap();
            }
        });
        assert!(!confirmer.confirm_dangerous(&write_action(), "rm -rf /"));
        ui.join().unwrap();
    }

    #[test]
    fn arc_confirmer_forwards() {
        let (tx, _rx) = mpsc::channel::<AppEvent>();
        let confirmer = std::sync::Arc::new(ChannelConfirmer::new(tx, Duration::from_millis(50)));
        let dyn_ref: &dyn Confirmer = &confirmer;
        assert!(!dyn_ref.confirm(&write_action())); // fail-closed через Arc
    }

    #[test]
    fn audit_forwards_entry_to_activity() {
        use crate::audit::{Audit, AuditEntry};
        use crate::safety::Verdict;
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let sink = ChannelAudit::new(tx);
        let entry = AuditEntry::decision(&write_action(), &Verdict::Allow);
        sink.record(&entry).unwrap();
        match rx.recv().unwrap() {
            AppEvent::Activity(line) => assert!(line.contains("Write")),
            _ => panic!("ожидался Activity"),
        }
    }

    #[test]
    fn dual_audit_writes_both_and_returns_primary() {
        use crate::audit::{Audit, AuditEntry, NullAudit};
        use crate::safety::Verdict;
        let (tx, rx) = mpsc::channel::<AppEvent>();
        // primary = NullAudit (Ok), secondary = ChannelAudit (в канал)
        let dual = DualAudit::new(Box::new(NullAudit), Box::new(ChannelAudit::new(tx)));
        let entry = AuditEntry::decision(&write_action(), &Verdict::Allow);
        dual.record(&entry).unwrap(); // primary Ok
        // secondary доставил в канал
        assert!(matches!(rx.recv().unwrap(), AppEvent::Activity(_)));
    }
}
