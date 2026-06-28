//! Отчёты владельцу в Telegram: стрим действий A → TG владельца B.
//! Raw-режим (без LLM). Перед отправкой — secret-redaction: не лить секреты в TG.

use crate::audit::{Audit, AuditEntry};

/// Замаскировать вероятные секреты в тексте ПЕРЕД отправкой в Telegram.
/// Эвристично и намеренно «пере-маскирует» (безопаснее лишний раз скрыть). Spec §7 — известно неполно.
pub fn redact(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut mask_next = false;
    for tok in text.split_whitespace() {
        if mask_next {
            out.push("***".to_string());
            mask_next = false;
            continue;
        }
        // key=value / key:value c секрет-подобным ключом → маскируем значение
        if let Some((k, _)) = tok.split_once(['=', ':']) {
            if is_secretish(k) {
                out.push(format!("{k}=***"));
                continue;
            }
        }
        // флаг вида --password (значение в следующем токене)
        if is_secretish(tok) && tok.starts_with('-') {
            out.push(tok.to_string());
            mask_next = true;
            continue;
        }
        // длинный непрозрачный блоб (base64/hex/токен) → маскируем
        if looks_secret_blob(tok) {
            out.push("***".to_string());
            continue;
        }
        out.push(tok.to_string());
    }
    out.join(" ")
}

fn is_secretish(k: &str) -> bool {
    let kl = k.trim_start_matches('-').to_ascii_lowercase();
    ["password", "passwd", "pwd", "secret", "token", "key", "credential", "auth"]
        .iter()
        .any(|n| kl.contains(n))
}

fn looks_secret_blob(t: &str) -> bool {
    t.len() >= 24
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_'))
}

/// Человеко-ориентированная (но сырая) строка отчёта из записи журнала.
pub fn format_report(e: &AuditEntry) -> String {
    let icon = match e.kind.as_str() {
        "decision" => "•",
        "result" => "→",
        _ => "·",
    };
    let verdict = if e.verdict.is_empty() {
        String::new()
    } else {
        format!(" [{}]", e.verdict)
    };
    let result = if e.result.is_empty() {
        String::new()
    } else {
        format!(" {}", e.result)
    };
    format!("{icon} {}{verdict}{result}", e.action)
}

/// Sync-канал отправки текстового отчёта (мок в тестах / blocking reqwest в проде).
pub trait ReportSink: Send + Sync {
    fn report(&self, chat_id: i64, text: &str) -> anyhow::Result<()>;
}

/// Audit-декоратор: дублирует поток действий владельцу в Telegram (с redaction).
/// Оборачивает inner-журнал (напр. fail-closed файл); сам — best-effort.
pub struct TelegramReportAudit {
    inner: Box<dyn Audit>,
    sink: std::sync::Arc<dyn ReportSink>,
    chat_id: i64,
}

impl TelegramReportAudit {
    pub fn new(inner: Box<dyn Audit>, sink: std::sync::Arc<dyn ReportSink>, chat_id: i64) -> Self {
        Self {
            inner,
            sink,
            chat_id,
        }
    }
}

impl Audit for TelegramReportAudit {
    fn record(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let line = redact(&format_report(entry));
        let _ = self.sink.report(self.chat_id, &line); // best-effort, не влияет на fail-closed
        self.inner.record(entry) // fail-closed зависит от inner
    }
}

/// Прод-sink: blocking reqwest sendMessage. HTTP выполняется на чистом std-потоке —
/// `report()` зовётся из sync tool-handler, который может крутиться на async-worker
/// tokio; `reqwest::blocking` из-под ambient-рантайма паникует «runtime within runtime».
/// Клиент строится ВНУТРИ потока (как ReqwestButtonSender).
pub struct ReqwestReportSink {
    token: String,
}

impl ReqwestReportSink {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl ReportSink for ReqwestReportSink {
    fn report(&self, chat_id: i64, text: &str) -> anyhow::Result<()> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let body = serde_json::json!({ "chat_id": chat_id, "text": text });
        std::thread::spawn(move || -> anyhow::Result<()> {
            reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?
                .post(url)
                .json(&body)
                .send()?
                .error_for_status()?;
            Ok(())
        })
        .join()
        .map_err(|_| anyhow::anyhow!("report-поток HTTP паниковал"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::{Action, ActionKind, Verdict};
    use std::sync::Mutex;

    #[test]
    fn redact_masks_password_flag() {
        let r = redact("run_shell mysqldump --password hunter2 db");
        assert!(!r.contains("hunter2"), "пароль не должен утечь: {r}");
        assert!(r.contains("***"));
    }

    #[test]
    fn redact_masks_key_value() {
        assert!(redact("TOKEN=abcdef123456").contains("***"));
        assert!(redact("api_key=zzz").contains("***"));
        assert!(!redact("API_SECRET=topsecretvalue").contains("topsecretvalue"));
    }

    #[test]
    fn redact_masks_long_blob_keeps_paths() {
        assert!(redact("AAAAAAAAAAAAAAAAAAAAAAAAAAAA").contains("***")); // 28 alnum → blob
        let p = redact("list_dir /home/user/documents/file.txt");
        assert!(p.contains("/home/user/documents/file.txt"), "путь не маскируем: {p}");
    }

    struct CapSink(std::sync::Arc<Mutex<Vec<(i64, String)>>>);
    impl ReportSink for CapSink {
        fn report(&self, chat_id: i64, text: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().push((chat_id, text.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn report_sink_does_not_panic_in_async_runtime() {
        // Регресс: reqwest::blocking из-под ambient tokio-рантайма не должен паниковать
        // (HTTP вынесен в std::thread). Сетевая ошибка к невалидному токену — ожидаема, не паника.
        let sink = ReqwestReportSink::new("123:invalid-token-for-test");
        let _ = sink.report(1, "hello"); // Err по сети — ок; главное, нет паники рантайма
    }

    #[test]
    fn report_audit_streams_redacted_and_delegates_inner() {
        use crate::audit::NullAudit;
        let captured = std::sync::Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let audit = TelegramReportAudit::new(
            Box::new(NullAudit),
            std::sync::Arc::new(CapSink(captured.clone())),
            42,
        );
        let action = Action {
            kind: ActionKind::Exec,
            path: None,
            command: Some("mysqldump --password hunter2".into()),
        };
        audit.record(&AuditEntry::decision(&action, &Verdict::Ask)).unwrap();

        let sent = captured.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 42);
        assert!(!sent[0].1.contains("hunter2"), "секрет не в TG: {}", sent[0].1);
        assert!(sent[0].1.contains("***"));
    }
}
