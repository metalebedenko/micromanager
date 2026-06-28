//! Классификация риска действия по 4 тирам OWASP.

use super::{Action, ActionKind};

/// Уровень риска. Авто-апрув — только Low (см. `decide`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Чтение/листинг — обратимо, безопасно.
    Low,
    /// Запись/внешние API — обратимо, но меняет состояние.
    Medium,
    /// Удаление/исполнение произвольной команды — высокий blast radius.
    High,
    /// Необратимое/катастрофичное (присваивается правилами hardline).
    Critical,
}

/// Базовая классификация по виду действия. Hardline-паттерны
/// могут поднять вердикт до Deny отдельно, до этой классификации.
pub fn classify(action: &Action) -> Risk {
    match action.kind {
        ActionKind::Read => Risk::Low,
        ActionKind::Write | ActionKind::Network => Risk::Medium,
        ActionKind::Delete | ActionKind::Exec => Risk::High,
    }
}
