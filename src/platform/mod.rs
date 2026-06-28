//! Определение текущей ОС и выбор платформенных команд.
//! Hardline-blocklist (safety::blocklist) активен для ВСЕХ ОС всегда —
//! управляемая машина B может быть любой; платформа влияет лишь на выбор шелла.

/// Поддерживаемые платформы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
    Macos,
    Other,
}

/// Текущая ОС, на которой исполняется micromanager.
pub fn current() -> Os {
    match std::env::consts::OS {
        "windows" => Os::Windows,
        "linux" => Os::Linux,
        "macos" => Os::Macos,
        _ => Os::Other,
    }
}
