//! Audit-log + fail-closed.

use micromanager::audit::FileAudit;
use micromanager::safety::{Action, Confirmer, GateError, Policy};
use micromanager::server::tools::{read_file_impl, run_shell_impl};

struct Yes;
impl Confirmer for Yes {
    fn confirm(&self, _: &Action) -> bool {
        true
    }
}

#[test]
fn allowed_exec_is_recorded_with_verdict_and_result() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let audit = FileAudit::new(&log);

    let _ = run_shell_impl("echo hi", &Policy::default(), &Yes, &audit).unwrap();

    let content = std::fs::read_to_string(&log).unwrap();
    assert!(content.contains("echo hi"), "действие в логе");
    assert!(content.contains("\"verdict\":\"ask\""), "вердикт в логе");
    assert!(content.contains("code=0"), "результат в логе");
}

#[test]
fn mutating_with_unwritable_audit_is_denied_and_not_executed() {
    let dir = tempfile::tempdir().unwrap();
    // лог в несуществующей поддиректории → запись провалится
    let log = dir.path().join("no_such_subdir").join("audit.log");
    let audit = FileAudit::new(&log);

    let marker = dir.path().join("marker.txt");
    let cmd = format!("echo x > {}", marker.display());
    let r = run_shell_impl(&cmd, &Policy::default(), &Yes, &audit);

    assert!(
        matches!(r, Err(GateError::Denied(_))),
        "fail-closed: мутация при недоступном audit → Denied"
    );
    assert!(!marker.exists(), "команда НЕ должна была исполниться");
}

#[test]
fn read_with_unwritable_audit_still_executes_degraded() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.txt");
    std::fs::write(&f, "data").unwrap();
    let log = dir.path().join("no_such_subdir").join("audit.log");
    let audit = FileAudit::new(&log);

    // read → degrade: исполняется несмотря на недоступный журнал
    let s = read_file_impl(&f, &Policy::default(), &Yes, &audit).unwrap();
    assert_eq!(s, "data");
}
