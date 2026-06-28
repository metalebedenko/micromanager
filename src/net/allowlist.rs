//! Персист allowlist стороны B (опт-ин `listen --remember`): id спаренных друзей
//! в `micromanager.allowlist.json`. Формат зафиксирован: `["<z32>"]` (EndpointId
//! через `to_string`/`FromStr`) — стабильный долгоживущий контракт файла.

use std::collections::HashSet;
use std::path::Path;

use iroh::EndpointId;

use super::store::write_private;

/// Загрузить allowlist. Нет файла / битый / чужой формат → ПУСТОЙ (fail-closed:
/// доверия аннулированы, друзья перепарятся по секрету) + WARN. Никогда не паника, не fail-open.
pub(crate) fn load(path: &Path) -> HashSet<EndpointId> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    match serde_json::from_str::<Vec<String>>(&text) {
        Ok(list) => list.iter().filter_map(|s| s.parse::<EndpointId>().ok()).collect(),
        Err(_) => {
            eprintln!("[micromanager] {path:?}: allowlist повреждён — старт с ПУСТЫМ (fail-closed)");
            HashSet::new()
        }
    }
}

/// Сохранить allowlist атомарно как `["<z32>"]`. Best-effort: ошибка записи → лог, не паника.
pub(crate) fn save(path: &Path, ids: &HashSet<EndpointId>) {
    let list: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
    if let Ok(json) = serde_json::to_string(&list) {
        if let Err(e) = write_private(path, json.as_bytes()) {
            eprintln!("[micromanager] не удалось сохранить allowlist {path:?}: {e}");
        }
    }
}

/// Забыть друга (отзыв доступа стороны B). `prefix=None` → забыть всех; `Some(p)` →
/// убрать тех, чей id (z32) начинается с `p`. Возвращает число удалённых.
pub(crate) fn forget(path: &Path, prefix: Option<&str>) -> usize {
    let before = load(path);
    let after: HashSet<EndpointId> = match prefix {
        None => HashSet::new(),
        Some(p) => before
            .iter()
            .filter(|id| !id.to_string().starts_with(p))
            .copied()
            .collect(),
    };
    let removed = before.len() - after.len();
    if after.is_empty() {
        let _ = std::fs::remove_file(path);
    } else {
        save(path, &after);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    #[test]
    fn forget_all_and_by_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("al.json");
        let a = id();
        let set: HashSet<_> = std::iter::once(a).collect();
        save(&path, &set);
        // префикс не совпал → 0 удалено
        assert_eq!(forget(&path, Some("zzzz")), 0);
        assert!(load(&path).contains(&a));
        // совпал префикс id → удалён
        let pfx = &a.to_string()[..6];
        assert_eq!(forget(&path, Some(pfx)), 1);
        assert!(load(&path).is_empty());
        // forget all на пустом → 0, не паника
        assert_eq!(forget(&path, None), 0);
    }

    #[test]
    fn save_load_roundtrip_z32_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("al.json");
        let a = id();
        let mut set = HashSet::new();
        set.insert(a);
        save(&path, &set);
        // формат файла — массив z32-строк
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains(&a.to_string()), "файл хранит z32-id: {raw}");
        // загрузка возвращает тот же id
        assert!(load(&path).contains(&a));
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&dir.path().join("nope.json")).is_empty());
    }

    #[test]
    fn corrupt_file_fail_closed_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("al.json");
        std::fs::write(&path, "{не массив строк}").unwrap();
        assert!(load(&path).is_empty(), "битый allowlist → пустой (fail-closed)");
    }
}
