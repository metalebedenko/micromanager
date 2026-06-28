//! Тулы read/search/write/run_shell через safety-гейт.
//! Подтверждение инъектируется моком (Yes/No).

use micromanager::audit::NullAudit;
use micromanager::safety::{Action, Confirmer, GateError, Policy};
use micromanager::server::tools::{read_file_impl, run_shell_impl, search_impl, write_file_impl};

struct Yes;
impl Confirmer for Yes {
    fn confirm(&self, _: &Action) -> bool {
        true
    }
}
struct No;
impl Confirmer for No {
    fn confirm(&self, _: &Action) -> bool {
        false
    }
}

#[test]
fn read_returns_content() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.txt");
    std::fs::write(&p, "hello").unwrap();
    assert_eq!(
        read_file_impl(&p, &Policy::default(), &Yes, &NullAudit).unwrap(),
        "hello"
    );
}

#[test]
fn read_blocked_pattern_denied() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("secret.txt");
    std::fs::write(&p, "x").unwrap();
    let policy = Policy {
        allowed_paths: vec![],
        allow_shell: true,
        allow_dangerous: false,
        blocked_patterns: vec!["*secret*".into()],
    };
    assert!(matches!(
        read_file_impl(&p, &policy, &Yes, &NullAudit),
        Err(GateError::Denied(_))
    ));
}

#[test]
fn write_requires_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("new.txt");
    // без подтверждения — запрет, файл НЕ создан
    assert!(matches!(
        write_file_impl(&p, "data", &Policy::default(), &No, &NullAudit),
        Err(GateError::Denied(_))
    ));
    assert!(!p.exists());
    // с подтверждением — записано
    write_file_impl(&p, "data", &Policy::default(), &Yes, &NullAudit).unwrap();
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "data");
}

#[test]
fn run_shell_hardline_denied_not_executed() {
    assert!(matches!(
        run_shell_impl("rm -rf /", &Policy::default(), &Yes, &NullAudit),
        Err(GateError::Denied(_))
    ));
}

#[test]
fn run_shell_safe_executes_with_confirm() {
    let r = run_shell_impl("echo hi", &Policy::default(), &Yes, &NullAudit).unwrap();
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("hi"));
}

#[test]
fn run_shell_denied_without_confirm() {
    assert!(matches!(
        run_shell_impl("echo hi", &Policy::default(), &No, &NullAudit),
        Err(GateError::Denied(_))
    ));
}

#[test]
fn search_finds_matches() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), "alpha\nbeta needle\ngamma").unwrap();
    let hits = search_impl(dir.path(), "needle", &Policy::default()).unwrap();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].text.contains("needle"));
    assert_eq!(hits[0].line, 2);
}

#[test]
fn search_skips_secret_scoped_files() {
    // secret-scoping: поиск НЕ должен возвращать строки из заблокированных файлов
    // (иначе обход запрета на чтение секретов через search).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("public.txt"), "needle here").unwrap();
    std::fs::write(dir.path().join("api.env"), "SECRET=needle").unwrap();
    let policy = Policy {
        allowed_paths: vec![],
        allow_shell: true,
        allow_dangerous: false,
        blocked_patterns: vec!["*.env".into()],
    };
    let hits = search_impl(dir.path(), "needle", &policy).unwrap();
    assert_eq!(hits.len(), 1, "должен найтись только public.txt, не api.env");
    assert!(hits[0].path.ends_with("public.txt"));
}
