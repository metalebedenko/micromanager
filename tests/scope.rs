//! Capability-грант: path-scope + запрет команд.

use micromanager::safety::{authorize, decide, gate, Action, ActionKind, Confirmer, Policy, Verdict};
use std::path::PathBuf;

fn scoped(dir: &std::path::Path, allow_shell: bool) -> Policy {
    Policy {
        allowed_paths: vec![dir.to_path_buf()],
        blocked_patterns: vec![],
        allow_shell,
        allow_dangerous: false,
    }
}

fn read(path: PathBuf) -> Action {
    Action {
        kind: ActionKind::Read,
        path: Some(path),
        command: None,
    }
}

#[test]
fn path_scope_allows_inside_denies_outside() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ok.txt"), "x").unwrap();
    let policy = scoped(dir.path(), true);

    assert!(matches!(
        decide(&read(dir.path().join("ok.txt")), &policy),
        Verdict::Allow
    ));
    assert!(matches!(
        decide(&read(PathBuf::from("/etc/hosts")), &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn path_traversal_escape_denied() {
    let dir = tempfile::tempdir().unwrap();
    let policy = scoped(dir.path(), true);
    // ../ резолвится наружу scope → Deny (канонизация анти-traversal)
    let escape = read(dir.path().join("../../../../etc/hosts"));
    assert!(matches!(decide(&escape, &policy), Verdict::Deny(_)));
}

#[test]
fn no_shell_grant_denies_run_shell() {
    let dir = tempfile::tempdir().unwrap();
    let policy = scoped(dir.path(), false);
    assert!(matches!(gate("echo hi", &policy), Verdict::Deny(_)));
}

#[test]
fn shell_allowed_by_default() {
    assert!(matches!(gate("echo hi", &Policy::default()), Verdict::Ask));
}

#[test]
fn empty_scope_allows_any_path() {
    // дефолт (локальный) — без path-ограничений
    assert!(matches!(
        decide(&read(PathBuf::from("/etc/hosts")), &Policy::default()),
        Verdict::Allow
    ));
}

// ─── owner-override опасного + доверие на сессию ───

#[test]
fn dangerous_blocked_by_default_but_confirmable_with_override() {
    // по умолчанию hardline — Deny (неперебиваемо)
    assert!(matches!(gate("rm -rf /", &Policy::default()), Verdict::Deny(_)));
    // с owner-override → не Deny, а ConfirmDangerous (громкое подтверждение)
    let overridden = Policy {
        allow_dangerous: true,
        ..Policy::default()
    };
    assert!(matches!(
        gate("rm -rf /", &overridden),
        Verdict::ConfirmDangerous(_)
    ));
    // даже спрятанное в обёртку → ConfirmDangerous под override
    assert!(matches!(
        gate(r#"powershell -c "Remove-Item -Recurse -Force C:\""#, &overridden),
        Verdict::ConfirmDangerous(_)
    ));
}

struct DangerYes;
impl Confirmer for DangerYes {
    fn confirm(&self, _: &Action) -> bool {
        false
    }
    fn confirm_dangerous(&self, _: &Action, _: &str) -> bool {
        true
    }
}
struct PlainConfirmer;
impl Confirmer for PlainConfirmer {
    fn confirm(&self, _: &Action) -> bool {
        true
    } // confirm_dangerous — дефолт (false)
}

#[test]
fn authorize_dangerous_needs_explicit_dangerous_consent() {
    let action = Action {
        kind: ActionKind::Exec,
        path: None,
        command: Some("rm -rf /".into()),
    };
    let v = || Verdict::ConfirmDangerous("hardline: x".into());
    // явное согласие на опасное → ок
    assert!(authorize(v(), &action, &DangerYes).is_ok());
    // обычный confirmer (без согласия на опасное) → отказ, даже если confirm()=true
    assert!(authorize(v(), &action, &PlainConfirmer).is_err());
}
