//! Приёмочный тест: интеграция стека in-process (руки + safety + audit).
//! Покрывает: read-only (allow), мутация с подтверждением, hardline-блок,
//! и что КАЖДОЕ действие попадает в audit-log с вердиктом.
//! (Сетевой stdio-путь с rmcp проверяется отдельно сырым JSON-RPC; здесь —
//!  интеграция safety+audit+тулов, т.к. confirm-по-stdio даст TUI фазы 1b.)

use micromanager::audit::FileAudit;
use micromanager::safety::{Action, Confirmer, Policy};
use micromanager::server::tools::{read_file_impl, run_shell_impl, write_file_impl};

struct Owner;
impl Confirmer for Owner {
    fn confirm(&self, _: &Action) -> bool {
        true
    }
}

#[test]
fn phase1_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let audit = FileAudit::new(&log);
    let policy = Policy::default();

    // 1. read-only → allow, исполняется
    let src = dir.path().join("src.txt");
    std::fs::write(&src, "content").unwrap();
    assert_eq!(
        read_file_impl(&src, &policy, &Owner, &audit).unwrap(),
        "content"
    );

    // 2. мутация с подтверждением → исполняется
    let dst = dir.path().join("out.txt");
    write_file_impl(&dst, "hello", &policy, &Owner, &audit).unwrap();
    assert_eq!(std::fs::read_to_string(&dst).unwrap(), "hello");

    // 3. hardline → запрет, не исполнено
    assert!(run_shell_impl("rm -rf /", &policy, &Owner, &audit).is_err());

    // 4. всё в audit-логе с вердиктами allow/ask/deny + причина hardline
    let log_content = std::fs::read_to_string(&log).unwrap();
    assert!(log_content.contains("\"verdict\":\"allow\""), "read → allow");
    assert!(log_content.contains("\"verdict\":\"ask\""), "write → ask");
    assert!(log_content.contains("\"verdict\":\"deny\""), "hardline → deny");
    assert!(log_content.contains("hardline"), "причина deny зафиксирована");
}
