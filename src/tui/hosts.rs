//! Персист журнала прошлых удалённых подключений (информационный; reconnect невозможен — код одноразовый).

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HostLogEntry {
    pub host_label: String,
    pub connected_at_unix: u64,
}

pub fn hosts_path() -> PathBuf { crate::paths::state_path("hosts.json") }

pub fn load_hosts(path: &Path) -> Vec<HostLogEntry> {
    std::fs::read_to_string(path).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_hosts(path: &Path, log: &[HostLogEntry]) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(log)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.json");
        let log = vec![HostLogEntry { host_label: "abc123".into(), connected_at_unix: 1000 }];
        save_hosts(&p, &log).unwrap();
        assert_eq!(load_hosts(&p), log);
    }
    #[test]
    fn missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_hosts(&dir.path().join("nope.json")).is_empty());
    }
    #[test]
    fn corrupt_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.json");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(load_hosts(&p).is_empty());
    }
}
