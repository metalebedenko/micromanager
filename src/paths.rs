//! Единое расположение файлов состояния micromanager.
//! По умолчанию — платформенная per-user папка (`BaseDirs::data_dir()/micromanager`);
//! `MM_STATE_DIR` переопределяет; нет HOME → CWD (`.`). Одноразовая миграция легаси
//! `./micromanager.<name>` из CWD в state-dir.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Значение `MM_STATE_DIR`, если задано и непусто (пустое = не задано).
fn env_state_dir() -> Option<OsString> {
    std::env::var_os("MM_STATE_DIR").filter(|d| !d.is_empty())
}

/// Чистый резолвер каталога состояния (без чтения env — для тестов).
fn resolve_state_dir(env_override: Option<OsString>) -> PathBuf {
    if let Some(d) = env_override {
        return PathBuf::from(d);
    }
    directories::BaseDirs::new()
        .map(|b| b.data_dir().join("micromanager"))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Каталог состояния (production): из env `MM_STATE_DIR` или платформенный.
pub fn state_dir() -> PathBuf {
    resolve_state_dir(env_state_dir())
}

/// Создать каталог (рекурсивно) + 0700 на Unix. Best-effort.
fn ensure_dir(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
}

/// Путь к `name` в `dir` с миграцией легаси `legacy_dir/micromanager.<name>`.
/// Каталог создаётся. Если target нет, а легаси есть — `rename` (best-effort).
/// Чистая: работает по ЯВНЫМ каталогам, без env/CWD.
fn state_path_in(dir: &Path, legacy_dir: &Path, name: &str) -> PathBuf {
    ensure_dir(dir);
    let target = dir.join(name);
    if !target.exists() {
        let legacy = legacy_dir.join(format!("micromanager.{name}"));
        if legacy.exists() {
            if let Err(e) = std::fs::rename(&legacy, &target) {
                eprintln!("[micromanager] миграция {legacy:?} → {target:?} не удалась: {e}");
            }
        }
    }
    target
}

/// Путь к файлу состояния `name`. **Чистый резолвер** — БЕЗ побочек (не создаёт
/// каталог, не мигрирует). Создание каталога и миграция — один раз в `init()` при
/// старте `main`. Это важно: иначе любой тест, дёргающий path-функцию, сорил бы в
/// реальную per-user папку (и мог бы мигрировать файлы из CWD).
pub fn state_path(name: &str) -> PathBuf {
    state_dir().join(name)
}

/// Все файлы состояния (для одноразовой миграции легаси в `init`).
const STATE_FILES: &[&str] = &[
    "identity.json",
    "allowlist.json",
    "peers.json",
    "audit.log",
    "session.json",
    "config.json",
    "hosts.json",
];

/// Один раз при старте `main`: создать state-dir (0700) и, при ДЕФОЛТНОМ расположении
/// (без `MM_STATE_DIR`), мигрировать легаси `./micromanager.<name>` из CWD. Идемпотентно
/// (после переноса легаси нет → no-op; target существует → не перезаписываем).
/// Тесты НЕ зовут `init` → реальная папка не трогается, миграция не запускается.
pub fn init() {
    let dir = state_dir();
    ensure_dir(&dir);
    if env_state_dir().is_none() {
        for name in STATE_FILES {
            let _ = state_path_in(&dir, Path::new("."), name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_path_is_pure_join() {
        // Чистый резолвер: ровно state_dir()/name, без побочек (каталог не создаётся).
        assert_eq!(state_path("config.json"), state_dir().join("config.json"));
    }

    #[test]
    fn resolve_uses_env_override() {
        let p = resolve_state_dir(Some(OsString::from("/tmp/mm_x")));
        assert_eq!(p, PathBuf::from("/tmp/mm_x"));
    }

    #[test]
    fn resolve_default_is_nonempty_micromanager_or_cwd() {
        let p = resolve_state_dir(None);
        let s = p.to_string_lossy();
        assert!(s.contains("micromanager") || s == ".", "дефолтный путь: {s}");
    }

    #[test]
    fn ensure_dir_creates_nested() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("a/b/c");
        ensure_dir(&dir);
        assert!(dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "каталог состояния должен быть 0700");
        }
    }

    #[test]
    fn state_path_in_migrates_legacy() {
        let state = tempfile::tempdir().unwrap();
        let legacy = tempfile::tempdir().unwrap();
        std::fs::write(legacy.path().join("micromanager.config.json"), b"CONTENT").unwrap();
        let p = state_path_in(state.path(), legacy.path(), "config.json");
        assert_eq!(p, state.path().join("config.json"));
        assert_eq!(std::fs::read(&p).unwrap(), b"CONTENT");
        assert!(!legacy.path().join("micromanager.config.json").exists(), "легаси перенесён");
    }

    #[test]
    fn state_path_in_no_legacy_returns_target_uncreated() {
        let state = tempfile::tempdir().unwrap();
        let legacy = tempfile::tempdir().unwrap();
        let p = state_path_in(state.path(), legacy.path(), "x.json");
        assert_eq!(p, state.path().join("x.json"));
        assert!(!p.exists(), "файл не создаётся пустым — только путь");
    }

    #[test]
    fn state_path_in_keeps_existing_target() {
        let state = tempfile::tempdir().unwrap();
        let legacy = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("config.json"), b"TARGET").unwrap();
        std::fs::write(legacy.path().join("micromanager.config.json"), b"LEGACY").unwrap();
        let p = state_path_in(state.path(), legacy.path(), "config.json");
        assert_eq!(std::fs::read(&p).unwrap(), b"TARGET", "свежий target не перезаписан легаси");
    }

    #[test]
    fn state_path_in_same_dir_renames_in_place() {
        // Фолбэк-режим: legacy_dir == state_dir (оба CWD). Переименование на месте.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("micromanager.config.json"), b"C").unwrap();
        let p = state_path_in(dir.path(), dir.path(), "config.json");
        assert_eq!(p, dir.path().join("config.json"));
        assert_eq!(std::fs::read(&p).unwrap(), b"C");
        assert!(!dir.path().join("micromanager.config.json").exists());
    }
}
