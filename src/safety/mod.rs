//! Safety-гейт: классификация + решение allow/deny/ask перед каждым действием.
//! Философия: fail-closed (неизвестное → deny), право вето у владельца машины.
//!
//! Слои (полностью собираются к задаче 5):
//!   0. anti-bypass-парсер — развернуть обёртки, разбить цепочки
//!   1. hardline-blocklist — неперебиваемый Deny
//!   2. risk-классификация (здесь) — Low/Medium/High/Critical
//!   3. confirm-гейт (здесь) — Low→Allow, иначе→Ask, fail-closed

pub mod blocklist;
pub mod parser;
mod policy;
mod risk;

pub use policy::{wildcard_match, Policy};
pub use risk::{classify, Risk};

use std::path::PathBuf;

/// Вид действия, который собирается выполнить тул.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Read,
    Write,
    Exec,
    Delete,
    Network,
}

/// Действие на оценку safety-гейтом.
#[derive(Debug, Clone)]
pub struct Action {
    pub kind: ActionKind,
    pub path: Option<PathBuf>,
    pub command: Option<String>,
}

/// Вердикт гейта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Исполнять без подтверждения (только Low).
    Allow,
    /// Требуется подтверждение владельца (Medium+).
    Ask,
    /// Катастрофичное, но owner включил override (allow_dangerous): требует ОТДЕЛЬНОГО
    /// громкого подтверждения; не покрывается «доверием на сессию». Строка — причина.
    ConfirmDangerous(String),
    /// Запрещено; строка — причина (для audit и ответа клиенту).
    Deny(String),
}

/// Решение по действию (без hardline/parser — те подключаются в задачах 4-5).
pub fn decide(action: &Action, policy: &Policy) -> Verdict {
    if let Some(path) = &action.path {
        // 0. Path-scope гранта: действие вне allowed_paths → Deny.
        if !policy.path_in_scope(path) {
            return Verdict::Deny("путь вне разрешённого scope гранта".to_string());
        }
        // 1. Запретные паттерны на путь — Deny даже для read (secret-scoping).
        let s = path.to_string_lossy();
        for pat in &policy.blocked_patterns {
            if wildcard_match(pat, &s) {
                return Verdict::Deny(format!("путь матчит запретный паттерн '{pat}'"));
            }
        }
    }

    // 2. Risk-гейт, fail-closed: только Low авто-аллоу.
    match classify(action) {
        Risk::Low => Verdict::Allow,
        Risk::Medium | Risk::High | Risk::Critical => Verdict::Ask,
    }
}

/// Полный гейт для shell-команды: парсер → hardline → blocked_patterns → risk.
/// Используется тулом run_shell. Собирает все слои безопасности.
///
/// - hardline (по сырой команде и по каждому сегменту) → Deny, неперебиваемо
/// - нераспарсиваемое → Deny (fail-closed)
/// - сегмент матчит blocked_patterns → Deny
/// - иначе команда = Exec (High) → Ask (подтверждение владельца)
pub fn gate(command: &str, policy: &Policy) -> Verdict {
    // 0. Грант запрещает произвольные команды → Deny весь run_shell.
    if !policy.allow_shell {
        return Verdict::Deny("выполнение команд запрещено грантом (allow_shell=false)".to_string());
    }
    // helper: hardline → Deny (по умолчанию) или ConfirmDangerous (если owner-override).
    let hardline_verdict = |reason: &str| -> Verdict {
        if policy.allow_dangerous {
            Verdict::ConfirmDangerous(format!("hardline: {reason}"))
        } else {
            Verdict::Deny(format!("hardline: {reason}"))
        }
    };
    // 1. hardline по сырой команде (fork-бомба и прочее, что спанит всю строку).
    if let Some(reason) = blocklist::is_hardline(command) {
        return hardline_verdict(reason);
    }
    // 2. разбор на эффективные сегменты; нераспарсиваемое → Deny.
    let segments = match parser::segments(command) {
        Ok(s) => s,
        Err(_) => return Verdict::Deny("команда не распарсена (fail-closed)".to_string()),
    };
    // 3. каждый сегмент: hardline → Deny/ConfirmDangerous; запретный паттерн → Deny.
    for seg in &segments {
        if let Some(reason) = blocklist::is_hardline(seg) {
            return hardline_verdict(reason);
        }
        for pat in &policy.blocked_patterns {
            if wildcard_match(pat, seg) {
                return Verdict::Deny(format!("сегмент матчит запретный паттерн '{pat}'"));
            }
        }
    }
    // 4. обычная shell-команда = Exec (High) → требует подтверждения.
    Verdict::Ask
}

/// Ошибка авторизации действия гейтом (для тулов).
#[derive(Debug, Clone)]
pub enum GateError {
    /// Запрещено (hardline / не подтверждено / запретный паттерн). Строка — причина.
    Denied(String),
    /// Ошибка ввода-вывода при исполнении уже разрешённого действия.
    Io(String),
}

/// Применить вердикт: Allow→ок, Deny→Denied, Ask→спросить confirmer (нет→Denied).
pub fn authorize(
    verdict: Verdict,
    action: &Action,
    confirmer: &dyn Confirmer,
) -> Result<(), GateError> {
    match verdict {
        Verdict::Allow => Ok(()),
        Verdict::Deny(reason) => Err(GateError::Denied(reason)),
        Verdict::Ask => {
            if confirmer.confirm(action) {
                Ok(())
            } else {
                Err(GateError::Denied("действие не подтверждено владельцем".to_string()))
            }
        }
        Verdict::ConfirmDangerous(reason) => {
            if confirmer.confirm_dangerous(action, &reason) {
                Ok(())
            } else {
                Err(GateError::Denied(format!("опасное не подтверждено: {reason}")))
            }
        }
    }
}

/// Канал подтверждения. Инъектируется в тулы; в тестах — мок.
pub trait Confirmer: Send + Sync {
    /// Подтвердить обычную мутацию (Ask). Fail-closed: сомнение/таймаут/закрытый канал → false.
    fn confirm(&self, action: &Action) -> bool;

    /// Подтвердить КАТАСТРОФИЧНОЕ действие (hardline при allow_dangerous). Отдельный громкий
    /// запрос; не покрывается «доверием на сессию». По умолчанию — отказ (безопасно).
    fn confirm_dangerous(&self, _action: &Action, _reason: &str) -> bool {
        false
    }
}

/// Confirmer, отклоняющий любые мутации. Для каналов без confirm (напр. Telegram,
/// пока нет inline-кнопок) — мутации deny, read-тулы (Allow) проходят.
pub struct DenyConfirmer;
impl Confirmer for DenyConfirmer {
    fn confirm(&self, _action: &Action) -> bool {
        false
    }
}

fn describe_action(action: &Action) -> String {
    action
        .command
        .clone()
        .or_else(|| action.path.as_ref().map(|p| p.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

fn read_stdin_line() -> Option<String> {
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    Some(line.trim().to_ascii_lowercase())
}

/// Confirm через stdin/stderr с «доверием на сессию» (ответ `a` → дальше не спрашивает).
/// Катастрофичное (confirm_dangerous) всегда спрашивает отдельно, доверие его не покрывает.
#[derive(Default)]
pub struct StdinConfirmer {
    trusted: std::sync::atomic::AtomicBool,
}

impl Confirmer for StdinConfirmer {
    fn confirm(&self, action: &Action) -> bool {
        use std::io::Write;
        use std::sync::atomic::Ordering;
        if self.trusted.load(Ordering::SeqCst) {
            return true;
        }
        eprint!(
            "[micromanager] подтвердить {:?} «{}»? [y]es / [a]ll(на сессию) / [N]o ",
            action.kind,
            describe_action(action)
        );
        let _ = std::io::stderr().flush();
        match read_stdin_line() {
            None => false,
            Some(ans) => match ans.as_str() {
                "a" | "all" | "все" | "всё" => {
                    self.trusted.store(true, Ordering::SeqCst);
                    true
                }
                "y" | "yes" | "да" => true,
                _ => false,
            },
        }
    }

    fn confirm_dangerous(&self, action: &Action, reason: &str) -> bool {
        use std::io::Write;
        eprint!(
            "\n[micromanager] ‼ ОПАСНОЕ ({reason}): {:?} «{}»\n  Это НЕОБРАТИМО. Подтвердить? [yes-точно/N] ",
            action.kind,
            describe_action(action)
        );
        let _ = std::io::stderr().flush();
        // требуем полное "yes-точно" — не случайный y
        matches!(read_stdin_line().as_deref(), Some("yes-точно"))
    }
}
