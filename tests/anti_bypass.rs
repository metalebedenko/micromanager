//! Anti-bypass-парсер: ловит обходы name-based gating —
//! обёртки-интерпретаторы, цепочки, подстановки команд.

use micromanager::safety::parser::segments;

#[test]
fn unwraps_powershell_wrapper() {
    let s = segments(r#"powershell -c "Remove-Item -Recurse -Force C:\x""#).unwrap();
    assert!(s.iter().any(|c| c.contains("Remove-Item")));
    assert!(!s.iter().any(|c| c.starts_with("powershell")));
}

#[test]
fn splits_chains_into_segments() {
    let s = segments("git status && rm -rf /tmp/x").unwrap();
    assert_eq!(s.len(), 2);
    assert!(s[1].contains("rm -rf"));
}

#[test]
fn splits_pipes_and_semicolons() {
    let s = segments("cat a | sh ; echo done").unwrap();
    assert!(s.len() >= 3);
}

#[test]
fn nested_wrapper_unwrapped() {
    let s = segments(r#"bash -c "powershell -c 'del x'""#).unwrap();
    assert!(s.iter().any(|c| c.contains("del")));
}

#[test]
fn extracts_command_substitution() {
    // $(...) и backticks — тоже исполняемые команды, должны попасть в сегменты.
    let s = segments("echo $(rm -rf /tmp/x)").unwrap();
    assert!(s.iter().any(|c| c.contains("rm -rf")));
    let s2 = segments("echo `mkfs /dev/sda`").unwrap();
    assert!(s2.iter().any(|c| c.contains("mkfs")));
}

#[test]
fn cmd_slash_c_unwrapped() {
    let s = segments(r#"cmd /c "del /f /s /q C:\""#).unwrap();
    assert!(s.iter().any(|c| c.contains("del /f")));
}

#[test]
fn unbalanced_quotes_unparseable() {
    assert!(segments(r#"echo "unterminated"#).is_err());
}

#[test]
fn deep_nesting_unparseable() {
    // защита от обфускации глубокой вложенностью подстановок → fail-closed
    let bomb = format!("{}x{}", "$(".repeat(8), ")".repeat(8));
    assert!(segments(&bomb).is_err());
}
