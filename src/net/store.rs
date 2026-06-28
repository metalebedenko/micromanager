//! Общие хелперы персиста state-файлов (identity/allowlist/peers): атомарная запись
//! с приватными правами (0600 на Unix) и форс-ужесточение прав существующего файла.

use std::io;
use std::path::{Path, PathBuf};

/// Постоянная iroh-личность (приватный ключ, 0600) в per-user state-dir.
pub(crate) fn identity_path() -> PathBuf {
    crate::paths::state_path("identity.json")
}
/// allowlist спаренных друзей стороны B (опт-ин `--remember`).
pub(crate) fn allowlist_path() -> PathBuf {
    crate::paths::state_path("allowlist.json")
}
/// Запомненные B стороны A (для `connect --resume`).
pub(crate) fn peers_path() -> PathBuf {
    crate::paths::state_path("peers.json")
}

/// Записать файл атомарно и приватно: temp-файл (0600) + `rename`. Полуфайла не бывает —
/// при краше остаётся либо старый целый, либо новый целый. Для приватных данных (ключ).
pub(crate) fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    write_tmp_0600(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(unix)]
fn write_tmp_0600(tmp: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(tmp)?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_tmp_0600(tmp: &Path, data: &[u8]) -> io::Result<()> {
    // Windows: полагаемся на ACL профиля пользователя.
    std::fs::write(tmp, data)
}

/// Если файл существует с правами шире 0600 (Unix) — принудительно ужесточить до 0600.
/// Для приватного ключа: «только warning» недостаточно, ключ компрометируется навсегда.
#[cfg(unix)]
pub(crate) fn ensure_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            eprintln!("[micromanager] {path:?}: права {mode:o} шире 0600 — ужесточаю до 0600");
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn ensure_0600(_path: &Path) {}
