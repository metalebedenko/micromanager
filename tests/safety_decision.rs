//! Safety-ядро: классификация риска + решение allow/ask/deny.
//! (Anti-bypass-парсер и hardline-blocklist подключаются в задачах 4-5.)

use micromanager::safety::{classify, decide, Action, ActionKind, Policy, Risk, Verdict};

fn act(kind: ActionKind) -> Action {
    Action {
        kind,
        path: Some("/tmp/x".into()),
        command: None,
    }
}

#[test]
fn read_is_low_and_allowed() {
    let a = act(ActionKind::Read);
    assert_eq!(classify(&a), Risk::Low);
    assert!(matches!(decide(&a, &Policy::default()), Verdict::Allow));
}

#[test]
fn write_is_medium_and_asks() {
    let a = act(ActionKind::Write);
    assert_eq!(classify(&a), Risk::Medium);
    assert!(matches!(decide(&a, &Policy::default()), Verdict::Ask));
}

#[test]
fn delete_is_high_and_asks() {
    let a = act(ActionKind::Delete);
    assert_eq!(classify(&a), Risk::High);
    assert!(matches!(decide(&a, &Policy::default()), Verdict::Ask));
}

#[test]
fn exec_is_high_and_asks() {
    let a = Action {
        kind: ActionKind::Exec,
        path: None,
        command: Some("echo hi".into()),
    };
    assert_eq!(classify(&a), Risk::High);
    assert!(matches!(decide(&a, &Policy::default()), Verdict::Ask));
}

#[test]
fn blocked_pattern_path_is_denied_even_for_read() {
    // Секретные файлы не отдаём даже на read, если путь матчит blocked_patterns.
    let policy = Policy {
        allowed_paths: vec![],
        allow_shell: true,
        allow_dangerous: false,
        blocked_patterns: vec!["*.env".into(), "*secret*".into()],
    };
    let a = Action {
        kind: ActionKind::Read,
        path: Some("/home/u/.env".into()),
        command: None,
    };
    assert!(matches!(decide(&a, &policy), Verdict::Deny(_)));
}
