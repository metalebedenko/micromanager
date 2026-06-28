//! Сторона A: запомненные B (опт-ин персист). `peers.json` хранит адрес+метку+время
//! НЕСКОЛЬКИХ известных B, чтобы `connect --resume` выбрал нужного без нового кода.
//! Дедуп по EndpointId. Формат — список (обратная совместимость со старым `[{addr,label}]`).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};

use super::store::write_private;

/// Известный B: адрес для дозвона + метка (короткий id хоста) + время последнего использования.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KnownPeer {
    pub addr: EndpointAddr,
    pub label: String,
    /// Unix-секунды. `#[serde(default)]` → старый формат без поля читается как 0.
    #[serde(default)]
    pub last_used_unix: u64,
}

/// Текущее unix-время в секундах; сбой часов → 0 (не паника).
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Загрузить список запомненных B. Нет файла / битый → пустой (не паника).
pub(crate) fn load(path: &Path) -> Vec<KnownPeer> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<KnownPeer>>(&s).ok())
        .unwrap_or_default()
}

/// Запомнить/обновить B. Дедуп по `addr.id`: существующий → обновить addr+label+last_used;
/// новый → добавить. Время = сейчас. Атомарно, best-effort.
pub(crate) fn remember(path: &Path, addr: EndpointAddr, label: String) {
    let mut list = load(path);
    let now = now_unix();
    if let Some(existing) = list.iter_mut().find(|kp| kp.addr.id == addr.id) {
        existing.addr = addr;
        existing.label = label;
        existing.last_used_unix = now;
    } else {
        list.push(KnownPeer { addr, label, last_used_unix: now });
    }
    write_list(path, &list);
}

/// Запомненные B, свежие сверху (для меню и resume-выбора).
pub(crate) fn list_recent(path: &Path) -> Vec<KnownPeer> {
    let mut list = load(path);
    list.sort_by_key(|b| std::cmp::Reverse(b.last_used_unix));
    list
}

/// Обновить last_used у записи с данным id (после успешного resume). Best-effort, no-op если нет.
pub(crate) fn touch(path: &Path, id: &EndpointId) {
    let mut list = load(path);
    if let Some(kp) = list.iter_mut().find(|kp| &kp.addr.id == id) {
        kp.last_used_unix = now_unix();
        write_list(path, &list);
    }
}

/// Забыть B. `prefix=None` → забыть всех; `Some(p)` → убрать тех, чья метка/`id`
/// начинается с `p`. Возвращает, сколько записей удалено.
pub(crate) fn forget(path: &Path, prefix: Option<&str>) -> usize {
    let before = load(path);
    let after: Vec<KnownPeer> = match prefix {
        None => Vec::new(),
        Some(p) => before
            .iter()
            .filter(|kp| !kp.label.starts_with(p) && !kp.addr.id.to_string().starts_with(p))
            .cloned()
            .collect(),
    };
    let removed = before.len() - after.len();
    if after.is_empty() {
        let _ = std::fs::remove_file(path);
    } else {
        write_list(path, &after);
    }
    removed
}

/// Кандидаты после фильтра по префиксу + правило «1 vs много».
pub(crate) enum Selection {
    One(KnownPeer),
    Menu(Vec<KnownPeer>),
    Empty,
}

/// Итог выбора с применением chooser к Menu.
pub(crate) enum Resolved {
    Chosen(KnownPeer),
    Empty,
    Cancelled,
}

/// Совпадает ли запись с `who` как префикс метки или z32-id.
fn matches_prefix(kp: &KnownPeer, p: &str) -> bool {
    kp.label.starts_with(p) || kp.addr.id.to_string().starts_with(p)
}

/// Чистый отбор кандидатов. `who=None` → все; `Some(p)` → префикс метки/id.
/// Точное полное совпадение метки/id выигрывает (даёт One, даже если это префикс других).
/// Порядок входного среза (свежие-сверху) сохраняется.
pub(crate) fn select_peer(peers: &[KnownPeer], who: Option<&str>) -> Selection {
    let candidates: Vec<KnownPeer> = match who {
        None => peers.to_vec(),
        Some(p) => {
            // точное совпадение метки/id → однозначно оно
            if let Some(exact) = peers.iter().find(|kp| kp.label == p || kp.addr.id.to_string() == p) {
                return Selection::One(exact.clone());
            }
            peers.iter().filter(|kp| matches_prefix(kp, p)).cloned().collect()
        }
    };
    match candidates.len() {
        0 => Selection::Empty,
        1 => Selection::One(candidates.into_iter().next().unwrap()),
        _ => Selection::Menu(candidates),
    }
}

/// `select_peer` + разбор Menu через chooser (0-based индекс в переданном свежие-сверху срезе).
pub(crate) fn resolve(
    peers: &[KnownPeer],
    who: Option<&str>,
    chooser: impl FnOnce(&[KnownPeer]) -> Option<usize>,
) -> Resolved {
    match select_peer(peers, who) {
        Selection::Empty => Resolved::Empty,
        Selection::One(p) => Resolved::Chosen(p),
        Selection::Menu(v) => match chooser(&v) {
            Some(i) if i < v.len() => Resolved::Chosen(v[i].clone()),
            _ => Resolved::Cancelled,
        },
    }
}

fn write_list(path: &Path, peers: &[KnownPeer]) {
    if let Ok(json) = serde_json::to_string(peers) {
        if let Err(e) = write_private(path, json.as_bytes()) {
            eprintln!("[micromanager] не удалось сохранить peers {path:?}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::presets;
    use iroh::Endpoint;

    async fn an_addr() -> EndpointAddr {
        let e = Endpoint::builder(presets::Minimal).bind().await.unwrap();
        let addr = e.addr();
        e.close().await;
        addr
    }

    /// Детерминированный EndpointAddr из свежего ключа (без сети).
    fn dummy_addr() -> EndpointAddr {
        EndpointAddr::from(iroh::SecretKey::generate().public())
    }

    #[tokio::test]
    async fn remember_two_distinct_keeps_both() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        remember(&path, an_addr().await, "host-a".into());
        remember(&path, an_addr().await, "host-b".into());
        assert_eq!(load(&path).len(), 2, "две разные машины → две записи");
    }

    #[tokio::test]
    async fn remember_same_id_dedups_and_updates_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let addr = an_addr().await;
        remember(&path, addr.clone(), "old".into());
        remember(&path, addr.clone(), "new".into());
        let list = load(&path);
        assert_eq!(list.len(), 1, "тот же id → одна запись");
        assert_eq!(list[0].label, "new", "label обновлён");
    }

    #[test]
    fn list_recent_sorts_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let a = KnownPeer { addr: dummy_addr(), label: "older".into(), last_used_unix: 100 };
        let b = KnownPeer { addr: dummy_addr(), label: "newer".into(), last_used_unix: 200 };
        write_list(&path, &[a, b]);
        let sorted = list_recent(&path);
        assert_eq!(sorted[0].label, "newer", "свежие сверху");
        assert_eq!(sorted[1].label, "older");
    }

    #[test]
    fn old_format_without_timestamp_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let kp = KnownPeer { addr: dummy_addr(), label: "legacy".into(), last_used_unix: 777 };
        let full = serde_json::to_value(vec![&kp]).unwrap();
        let mut arr = full.as_array().unwrap().clone();
        let obj = arr[0].as_object_mut().unwrap();
        obj.remove("last_used_unix"); // имитируем старый файл без поля
        std::fs::write(&path, serde_json::to_string(&arr).unwrap()).unwrap();
        let list = load(&path);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].last_used_unix, 0, "нет поля → 0");
        assert_eq!(list[0].label, "legacy");
    }

    #[test]
    fn touch_updates_existing_noop_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let kp = KnownPeer { addr: dummy_addr(), label: "x".into(), last_used_unix: 1 };
        let id = kp.addr.id;
        write_list(&path, &[kp]);
        let before = now_unix();
        touch(&path, &id);
        // сравниваем со снимком ДО touch (не с now_unix() после — иначе same-second flaky)
        assert!(load(&path)[0].last_used_unix >= before, "last_used подтянулся к сейчас");
        // несуществующий id → no-op, не паника
        let other = iroh::SecretKey::generate().public();
        let snap = std::fs::read_to_string(&path).unwrap();
        touch(&path, &other);
        assert_eq!(snap, std::fs::read_to_string(&path).unwrap(), "чужой id → файл не тронут");
    }

    #[test]
    fn forget_all_and_by_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        write_list(&path, &[KnownPeer { addr: dummy_addr(), label: "friend-1".into(), last_used_unix: 5 }]);
        assert_eq!(forget(&path, Some("frie")), 1, "совпал префикс метки");
        assert!(load(&path).is_empty());
        assert_eq!(forget(&path, None), 0, "forget all на пустом → 0");
    }

    fn peer(label: &str, t: u64) -> KnownPeer {
        KnownPeer { addr: dummy_addr(), label: label.into(), last_used_unix: t }
    }

    #[test]
    fn select_empty_one_menu() {
        assert!(matches!(select_peer(&[], None), Selection::Empty));
        let a = peer("host-a", 10);
        assert!(matches!(select_peer(std::slice::from_ref(&a), None), Selection::One(_)));
        let b = peer("host-b", 20);
        let two = [a.clone(), b];
        match select_peer(&two, None) {
            Selection::Menu(v) => assert_eq!(v.len(), 2),
            _ => panic!("ожидалось Menu"),
        }
    }

    #[test]
    fn select_by_prefix() {
        let two = [peer("host-a", 10), peer("host-b", 20)];
        assert!(matches!(select_peer(&two, Some("host-a")), Selection::One(_)));
        assert!(matches!(select_peer(&two, Some("host")), Selection::Menu(_)));
        assert!(matches!(select_peer(&two, Some("zzz")), Selection::Empty));
    }

    #[test]
    fn select_exact_match_wins_over_prefix() {
        // "host-a" — точное совпадение и одновременно префикс "host-ab"
        let two = [peer("host-a", 10), peer("host-ab", 20)];
        match select_peer(&two, Some("host-a")) {
            Selection::One(p) => assert_eq!(p.label, "host-a", "точное совпадение выигрывает"),
            _ => panic!("ожидалось One(host-a)"),
        }
    }

    #[test]
    fn resolve_chosen_empty_cancelled() {
        assert!(matches!(resolve(&[], None, |_| Some(0)), Resolved::Empty));
        let one = [peer("solo", 1)];
        match resolve(&one, None, |_| panic!("chooser не должен вызываться при One")) {
            Resolved::Chosen(p) => assert_eq!(p.label, "solo"),
            _ => panic!("ожидалось Chosen"),
        }
        let two = [peer("a", 1), peer("b", 2)];
        match resolve(&two, None, |_| Some(1)) {
            Resolved::Chosen(p) => assert_eq!(p.label, "b", "0-based индекс 1 = второй"),
            _ => panic!("ожидалось Chosen(b)"),
        }
        assert!(matches!(resolve(&two, None, |_| None), Resolved::Cancelled));
    }
}
