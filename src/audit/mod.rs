//! Audit-log: журнал всех действий (решение + результат) в JSON-lines.
//!
//! Fail-closed: для мутирующего действия невозможность записать решение в журнал =
//! Deny (действие не исполняется). Для read (Low) — degrade-режим с алертом в stderr.

use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::safety::{Action, GateError, Verdict};

/// Запись журнала (одна строка JSON).
#[derive(Serialize, Debug, Clone)]
pub struct AuditEntry {
    /// Unix-время в миллисекундах (строкой).
    pub ts: String,
    /// "decision" | "result".
    pub kind: String,
    /// Краткое описание действия (вид + путь/команда).
    pub action: String,
    /// Вердикт для decision: allow/ask/deny (для result — пусто).
    pub verdict: String,
    /// Детали: причина deny / итог исполнения (для decision allow/ask — пусто).
    pub result: String,
}

impl AuditEntry {
    pub fn decision(action: &Action, verdict: &Verdict) -> Self {
        let (label, detail) = match verdict {
            Verdict::Allow => ("allow", String::new()),
            Verdict::Ask => ("ask", String::new()),
            Verdict::ConfirmDangerous(r) => ("dangerous", r.clone()),
            Verdict::Deny(r) => ("deny", r.clone()),
        };
        Self {
            ts: now_ms(),
            kind: "decision".to_string(),
            action: describe(action),
            verdict: label.to_string(),
            result: detail,
        }
    }

    /// Запись события удалённой сессии A→B.
    /// У релея нет локального `Action`+`Verdict` — решение принимает владелец B.
    /// `action` — метка вида `"<host>:<tool>"`, `result` — исход (ok/ошибка).
    pub fn relay(action: &str, result: &str) -> Self {
        Self {
            ts: now_ms(),
            kind: "relay".to_string(),
            action: action.to_string(),
            verdict: String::new(),
            result: result.to_string(),
        }
    }

    pub fn result(action: &Action, result: &str) -> Self {
        Self {
            ts: now_ms(),
            kind: "result".to_string(),
            action: describe(action),
            verdict: String::new(),
            result: result.to_string(),
        }
    }
}

fn describe(a: &Action) -> String {
    let what = a
        .command
        .clone()
        .or_else(|| a.path.as_ref().map(|p| p.display().to_string()))
        .unwrap_or_default();
    format!("{:?}: {what}", a.kind)
}

fn now_ms() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

/// Приёмник журнала. Реализации: FileAudit (прод), NullAudit (тесты).
pub trait Audit: Send + Sync {
    fn record(&self, entry: &AuditEntry) -> std::io::Result<()>;
}

/// Файловый журнал JSON-lines с простой ротацией (1 бэкап при превышении размера).
pub struct FileAudit {
    path: PathBuf,
    max_bytes: u64,
}

impl FileAudit {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_bytes: 5_000_000,
        }
    }
}

impl Audit for FileAudit {
    fn record(&self, entry: &AuditEntry) -> std::io::Result<()> {
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() >= self.max_bytes {
                let _ = std::fs::rename(&self.path, self.path.with_extension("1"));
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string());
        writeln!(f, "{line}")
    }
}

/// Заглушка для тестов, где audit не под проверкой. Никогда не падает.
pub struct NullAudit;
impl Audit for NullAudit {
    fn record(&self, _entry: &AuditEntry) -> std::io::Result<()> {
        Ok(())
    }
}

/// Записать РЕШЕНИЕ. Fail-closed: если запись провалилась и действие мутирующее —
/// вернуть Deny (исполнять нельзя, пока решение не зафиксировано). Для read — degrade.
pub fn audit_decision(
    audit: &dyn Audit,
    action: &Action,
    verdict: &Verdict,
    mutating: bool,
) -> Result<(), GateError> {
    if let Err(e) = audit.record(&AuditEntry::decision(action, verdict)) {
        if mutating {
            return Err(GateError::Denied(format!(
                "audit недоступен — fail-closed (мутация не исполнена): {e}"
            )));
        }
        eprintln!("[micromanager] audit degrade (read), действие исполнено без записи: {e}");
    }
    Ok(())
}

/// Записать РЕЗУЛЬТАТ (best-effort: уже исполнено/отказано, журнал не блокирует).
pub fn audit_result(audit: &dyn Audit, action: &Action, result: &str) {
    let _ = audit.record(&AuditEntry::result(action, result));
}

/// Путь журнала по умолчанию (per-user state-dir).
pub fn default_path() -> PathBuf {
    crate::paths::state_path("audit.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Релей-событие (connect/remote_call/disconnect) не имеет локального Action+Verdict
    /// — решение принято на B. `relay()` пишет плоскую запись kind="relay" без вердикта.
    #[test]
    fn relay_entry_has_relay_kind_and_no_verdict() {
        let e = AuditEntry::relay("host42:list_dir", "ok: 3 entries");
        assert_eq!(e.kind, "relay");
        assert_eq!(e.action, "host42:list_dir");
        assert_eq!(e.result, "ok: 3 entries");
        assert!(e.verdict.is_empty(), "у релея нет локального вердикта");
        assert!(!e.ts.is_empty(), "ts проставлен");
    }
}
