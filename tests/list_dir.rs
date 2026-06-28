//! Тул list_dir: тестируем чистую логику (rmcp-обёртка тонкая;
//! интеграция «MCP-клиент коннектится» проверяется в acceptance-тесте).

use micromanager::server::tools::list_dir_impl;

#[test]
fn list_dir_returns_entries() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "hi").unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();

    let mut entries = list_dir_impl(dir.path()).unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "file.txt");
    assert!(!entries[0].is_dir);
    assert_eq!(entries[1].name, "sub");
    assert!(entries[1].is_dir);
}

#[test]
fn list_dir_missing_path_errors() {
    let res = list_dir_impl(std::path::Path::new("/no/such/path/xyz123"));
    assert!(res.is_err());
}
