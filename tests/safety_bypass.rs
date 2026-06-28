//! Регресс-таблица safety-байпаса: опасные команды и их обёртки через настоящий gate().
//! Источник правды против рецидива (никакая обёртка не должна пробить hardline).
//!
//! Гейтинг по классам из DONE; SAFE-векторы ассертим всегда (не должны стать Deny).

use micromanager::safety::{gate, Policy, Verdict};

const TABLE: &str = include_str!("fixtures/bypass-vectors.tsv");

/// Классы, фиксы которых уже внедрены. Расширяется по мере этапов (1: A,B,D; 2: C; 3: E).
const DONE: &[&str] = &["BASE", "A", "B", "C", "D", "E"];

/// Раскрыть escape-последовательности RAW: `\n`→LF, `\r`→CR, `\t`→TAB, `\\`→`\`.
/// Walker (не цепочка replace), чтобы литеральный `\\rm` не схлопывался в CR+m.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn is_deny(v: &Verdict) -> bool {
    matches!(v, Verdict::Deny(_) | Verdict::ConfirmDangerous(_))
}

fn deny_reason(v: &Verdict) -> String {
    match v {
        Verdict::Deny(r) | Verdict::ConfirmDangerous(r) => r.clone(),
        _ => String::new(),
    }
}

#[test]
fn bypass_table_regression() {
    let policy = Policy::default();
    let mut failures: Vec<String> = Vec::new();
    let mut pending: Vec<String> = Vec::new();

    for (i, line) in TABLE.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        assert!(cols.len() >= 3, "строка {}: плохой формат: {:?}", i + 1, line);
        let (class, expect, raw) = (cols[0], cols[1], unescape(cols[2]));
        let reason_tag = cols.get(3).copied().unwrap_or("");

        let v = gate(&raw, &policy);
        let deny = is_deny(&v);

        if class == "SAFE" {
            // легит-контроль: НИКОГДА не Deny, на всех этапах
            if deny {
                failures.push(format!("[SAFE→DENY!] {raw}  ::  {}", deny_reason(&v)));
            }
            continue;
        }
        // DENY-классы
        if !DONE.contains(&class) {
            if !deny {
                pending.push(format!("[{class} pending] {raw}"));
            }
            continue;
        }
        assert_eq!(expect, "DENY", "DENY-класс {class}, но EXPECT={expect}");
        if !deny {
            failures.push(format!("[{class} НЕ заблокирован!] {raw}"));
        } else if !reason_tag.is_empty() {
            // regress-by-mechanism (актуально для E, когда войдёт в DONE)
            let r = deny_reason(&v).to_lowercase();
            if !r.contains(reason_tag) {
                failures.push(format!("[{class} причина не '{reason_tag}': '{r}'] {raw}"));
            }
        }
    }

    if !pending.is_empty() {
        eprintln!(
            "=== PENDING (ожидаемый остаток до этапов 2-3): {} ===",
            pending.len()
        );
        for p in &pending {
            eprintln!("  {p}");
        }
    }
    assert!(
        failures.is_empty(),
        "БАЙПАС/регресс ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
