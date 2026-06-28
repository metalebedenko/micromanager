//! Hardline-blocklist + gate(): неперебиваемый блок катастроф,
//! в т.ч. спрятанных в обёртки/цепочки. Оба набора (*nix и Windows) всегда активны.

use micromanager::safety::{gate, Policy, Verdict};

fn denied(cmd: &str) -> bool {
    matches!(gate(cmd, &Policy::default()), Verdict::Deny(_))
}

#[test]
fn nix_hardline_blocked() {
    for c in [
        "rm -rf /",
        "rm -fr /",
        "rm --recursive --force /",
        ":(){ :|:& };:",
        "mkfs.ext4 /dev/sda",
        "dd if=/dev/zero of=/dev/sda",
        "/bin/rm -rf /",
    ] {
        assert!(denied(c), "должно блокироваться: {c}");
    }
}

#[test]
fn windows_hardline_blocked() {
    for c in [
        "format C:",
        "del /f /s /q C:\\",
        "diskpart",
        "Remove-Item -Recurse -Force C:\\",
        "bcdedit /delete",
    ] {
        assert!(denied(c), "должно блокироваться: {c}");
    }
}

#[test]
fn hardline_via_wrapper_and_chain_blocked() {
    assert!(denied(r#"powershell -c "Remove-Item -Recurse -Force C:\""#));
    assert!(denied("echo ok && rm -rf /"));
    assert!(denied("ls ; dd if=/dev/zero of=/dev/sda"));
}

#[test]
fn hardline_quote_escape_bypass_blocked() {
    // Класс A: снятие кавычек/escape перед матчингом.
    for c in [
        r"\rm -rf /etc",
        "'rm' -rf /",
        r#""rm" -rf /etc"#,
        "r''m -rf /etc",
        r#"rm -rf "/etc""#,
        r#"dd if=/dev/zero of="/dev/sda""#,
        r#""mkfs.ext4" /dev/sda"#,
        "rm -rf ${HOME}",
        r#""format" c:"#,
    ] {
        assert!(denied(c), "класс A должен блокироваться: {c}");
    }
}

#[test]
fn hardline_prefix_wrapper_bypass_blocked() {
    // Класс B: раскрытие argv-префикс-обёрток, в т.ч. опции-с-аргументом.
    for c in [
        "sudo rm -rf /etc",
        "env FOO=bar rm -rf /",
        "nice mkfs.ext4 /dev/sda",
        "timeout 5 rm -rf /etc",
        "eval rm -rf /etc",
        "sudo -u root rm -rf /",
        "timeout -s KILL 5 rm -rf /etc",
        "env -u PATH rm -rf /etc",
    ] {
        assert!(denied(c), "класс B должен блокироваться: {c}");
    }
}

#[test]
fn hardline_newline_separator_bypass_blocked() {
    // Класс D: перевод строки/CR — тоже разделитель команд.
    assert!(denied("ls\nrm -rf /etc"));
    assert!(denied("true\nmkfs.ext4 /dev/sda"));
    assert!(denied("echo hi\rrm -rf /etc"));
}

#[test]
fn hardline_path_depth_moderate_blocked() {
    // Класс C (умеренный): глоб под критичным top-level + резолв в корень.
    for c in [
        "rm -rf /etc/*",
        "rm -rf /bin/*",
        "rm -rf /var/*",
        "rm -rf /.",
        "rm -rf /etc/..",
    ] {
        assert!(denied(c), "класс C должен блокироваться: {c}");
    }
    // Умеренный режим: глубокие пользовательские пути под /var — НЕ Deny (легит-операции).
    for c in ["rm -rf /var/cache/app", "rm -rf /home/user/x", "rm -rf /opt/app/logs"] {
        assert!(matches!(gate(c, &Policy::default()), Verdict::Ask), "должно быть Ask: {c}");
    }
}

#[test]
fn hardline_class_e_blocked() {
    // Класс E (fail-closed): подстановки, here-string, scan интерпретатора, find, xargs, redirect.
    for c in [
        "bash <(rm -rf /etc)",
        "wc -l <(rm -rf /etc)",
        "bash <<< 'rm -rf /'",
        r#"python3 -c "import os; os.system('rm -rf /')""#,
        r#"perl -e 'system("rm -rf /etc")'"#,
        "find / -delete",
        "find /etc -delete",
        "echo /etc | xargs rm -rf",
        "cat /dev/zero > /dev/sda",
    ] {
        assert!(denied(c), "класс E должен блокироваться: {c}");
    }
}

#[test]
fn class_e_keeps_legit_as_ask() {
    // scan/find не должны ложно блокировать безобидный код/поиск.
    for c in [
        r#"python3 -c "print(1)""#,
        "find . -name '*.rs'",
        "cat /dev/zero > /tmp/out",
    ] {
        assert!(!matches!(gate(c, &Policy::default()), Verdict::Deny(_)), "не должно быть Deny: {c}");
    }
}

#[test]
fn prefix_wrapper_keeps_legit_as_ask() {
    // Префиксы не должны давать false-positive на легитимных командах.
    for c in ["nice -n 10 cargo build", "timeout 30 cargo test", "sudo ls -la"] {
        assert!(matches!(gate(c, &Policy::default()), Verdict::Ask), "должно быть Ask: {c}");
    }
}

#[test]
fn unparseable_denied() {
    let bomb = format!("{}x{}", "$(".repeat(8), ")".repeat(8));
    assert!(denied(&bomb));
    assert!(denied(r#"echo "unterminated"#));
}

#[test]
fn ordinary_command_is_not_denied_but_asks() {
    // обычная команда — не Deny, а Ask (требует подтверждения)
    assert!(matches!(gate("echo hello", &Policy::default()), Verdict::Ask));
    assert!(matches!(gate("ls -la", &Policy::default()), Verdict::Ask));
}

#[test]
fn blocked_pattern_in_command_denied() {
    let policy = Policy {
        allowed_paths: vec![],
        allow_shell: true,
        allow_dangerous: false,
        blocked_patterns: vec!["*secret*".into()],
    };
    assert!(matches!(gate("cat /etc/secret.txt", &policy), Verdict::Deny(_)));
}
