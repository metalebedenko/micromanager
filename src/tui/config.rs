//! Персистентность настроек TUI: `Settings` ↔ JSON-файл.

use std::path::{Path, PathBuf};

use crate::tui::settings::Settings;

pub fn config_path() -> PathBuf {
    crate::paths::state_path("config.json")
}

pub fn save_config(path: &Path, settings: &Settings) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Конфиг может хранить API-ключ → права только владельцу (0600 на Unix).
    write_private(path, json.as_bytes())
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // Windows: файл в профиле пользователя; полагаемся на ACL профиля по умолчанию.
    std::fs::write(path, data)
}

pub fn load_config(path: &Path) -> Option<Settings> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::settings::Settings;

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let s = Settings {
            model: "zzz".into(),
            ..Default::default()
        };
        save_config(&path, &s).unwrap();
        let loaded = load_config(&path).expect("должно загрузиться");
        assert_eq!(loaded.model, "zzz");
    }

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_config(&dir.path().join("nope.json")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        save_config(&path, &Settings::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600); // только владелец читает/пишет
    }
}
