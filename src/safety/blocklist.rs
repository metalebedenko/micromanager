//! Hardline-blocklist — неперебиваемый список катастрофичных команд.
//! Срабатывает ДО approval-слоя, без override. Оба набора (*nix и Windows)
//! активны всегда: управляемая машина B может быть любой ОС.
//!
//! Детекторы работают по токенам (whitespace-split, lowercase), с basename имени.
//! Цель — ловить НЕОБРАТИМОЕ (уничтожение данных/диска/boot), не мешая обычной работе
//! (она и так проходит через confirm-гейт). Узкие, а не широкие паттерны → меньше
//! false-positive; обычные мутации остаются на Ask, а не Deny.

/// Вернуть Some(причина), если сегмент/команда совпали с hardline-паттерном.
pub fn is_hardline(seg: &str) -> Option<&'static str> {
    if is_fork_bomb(seg) {
        return Some("fork-бомба");
    }
    let tokens = norm_tokens(seg);
    if tokens.is_empty() {
        return None;
    }
    let name = cmd_name(&tokens);

    // --- *nix ---
    if is_rm_rf(&tokens) {
        return Some("rm -rf на корневой/системный путь");
    }
    if name.starts_with("mkfs") && tokens.len() >= 2 {
        return Some("mkfs — форматирование файловой системы");
    }
    if name == "dd" && tokens.iter().any(|t| t.starts_with("of=/dev/")) {
        return Some("dd на дисковое устройство");
    }
    if name == "wipefs" && tokens.iter().any(|t| t.contains("/dev/")) {
        return Some("wipefs на устройстве");
    }

    // --- Класс E (fail-closed): код интерпретаторов, find/xargs/redirect ---
    // scan: script-язык с -c/-e, тело содержит катастрофичную подстроку (нельзя распарсить
    // язык полноценно → консервативно блокируем по подстроке, возможны осознанные FP).
    if SCRIPT_LANGS.contains(&name) {
        if let Some(body) = inline_code_body(&tokens) {
            if scan_catastrophe(body) {
                return Some("scan — код интерпретатора содержит катастрофичную команду");
            }
        }
    }
    // find ... -delete на системном/корневом пути.
    if name == "find"
        && tokens.iter().any(|t| t == "-delete")
        && tokens.iter().any(|t| dangerous_nix_target(t))
    {
        return Some("find -delete на системном пути");
    }
    // xargs запускает rm с рекурсией+force (цель приходит из stdin — динамична, опасна).
    if name == "xargs" && rm_recursive_force(&tokens) {
        return Some("xargs запускает rm -rf");
    }
    // redirect перезаписи в дисковое устройство (`> /dev/sda`).
    if redirect_to_disk(&tokens) {
        return Some("redirect — перезапись дискового устройства");
    }

    // --- Windows ---
    if name == "format" {
        return Some("format — форматирование диска");
    }
    if name == "diskpart" {
        return Some("diskpart — разметка диска");
    }
    if name == "bcdedit" {
        return Some("bcdedit — изменение boot-конфигурации");
    }
    if (name == "del" || name == "erase" || name == "rd" || name == "rmdir")
        && tokens.iter().any(|t| t == "/s")
        && tokens.iter().any(|t| dangerous_win_target(t))
    {
        return Some("рекурсивное удаление на корне диска");
    }
    if name == "remove-item" || name == "ri" {
        let rec = tokens.iter().any(|t| t.starts_with("-rec"));
        let force = tokens.iter().any(|t| t.starts_with("-fo") || t == "-f");
        if rec && force && tokens.iter().any(|t| dangerous_win_target(t)) {
            return Some("Remove-Item -Recurse -Force на корне диска");
        }
    }
    if name == "reg"
        && tokens.get(1).map(|t| t == "delete").unwrap_or(false)
        && tokens
            .iter()
            .any(|t| t.starts_with("hklm") || t.starts_with("hkey_local_machine"))
    {
        return Some("reg delete в HKLM");
    }

    None
}

fn norm_tokens(seg: &str) -> Vec<String> {
    // Снять кавычки/escape (anti-bypass класс A), затем лоуэркейс. Несбалансированное →
    // пустой Vec → is_hardline=None → parser::segments вернёт Unparseable → Deny (fail-closed).
    match crate::safety::parser::canon_tokens(seg) {
        Ok(toks) => toks.into_iter().map(|t| t.to_ascii_lowercase()).collect(),
        Err(_) => Vec::new(),
    }
}

fn cmd_name(tokens: &[String]) -> &str {
    tokens
        .first()
        .map(|t| t.rsplit(['/', '\\']).next().unwrap_or(t))
        .unwrap_or("")
}

/// Fork-бомба: функция, тело которой (в `(){ ... }`) пайпит и бэкграундит саму себя.
fn is_fork_bomb(seg: &str) -> bool {
    let s: String = seg.chars().filter(|c| !c.is_whitespace()).collect();
    if let Some(idx) = s.find("(){") {
        if let Some(close) = s[idx + 3..].find('}') {
            let body = &s[idx + 3..idx + 3 + close];
            return body.contains('|') && body.contains('&');
        }
    }
    false
}

fn is_rm_rf(tokens: &[String]) -> bool {
    if cmd_name(tokens) != "rm" {
        return false;
    }
    let (mut rec, mut force) = (false, false);
    let mut targets: Vec<&str> = Vec::new();
    for t in &tokens[1..] {
        if t == "--recursive" {
            rec = true;
        } else if t == "--force" {
            force = true;
        } else if t.starts_with("--") {
            // прочие длинные опции игнорируем
        } else if let Some(flags) = t.strip_prefix('-') {
            if flags.contains('r') {
                rec = true;
            }
            if flags.contains('f') {
                force = true;
            }
        } else {
            targets.push(t);
        }
    }
    rec && force && targets.iter().any(|t| dangerous_nix_target(t))
}

const NIX_CRITICAL_TOP: &[&str] = &[
    "etc", "usr", "bin", "sbin", "boot", "lib", "lib64", "var", "sys", "dev", "proc", "root", "opt",
];

/// Script-языки, чей `-c`/`-e`-код нельзя распарсить как шелл (scan по подстроке).
const SCRIPT_LANGS: &[&str] = &["python", "python3", "perl", "ruby", "node", "deno"];

/// Тело inline-кода интерпретатора: токен после `-c`/`-e`/`-E`/`--eval`/`--command`.
fn inline_code_body(tokens: &[String]) -> Option<&str> {
    for i in 0..tokens.len() {
        if matches!(tokens[i].as_str(), "-c" | "-e" | "-E" | "--eval" | "--command") {
            return tokens.get(i + 1).map(|s| s.as_str());
        }
    }
    None
}

/// Консервативный scan тела на катастрофичную подстроку (body уже lowercased).
/// Возможны осознанные FP (литерал `print('rm -rf /')`) — зафиксировано тестом и планом.
fn scan_catastrophe(body: &str) -> bool {
    const PAT: &[&str] = &[
        "rm -rf /",
        "rm -fr /",
        "rm -r -f /",
        "rm -f -r /",
        "mkfs",
        "wipefs",
        "dd if=/dev/",
        "> /dev/sd",
        ">/dev/sd",
    ];
    PAT.iter().any(|p| body.contains(p))
}

/// Есть ли в токенах `rm` с рекурсией И force (цель не важна — для xargs она из stdin).
fn rm_recursive_force(tokens: &[String]) -> bool {
    if !tokens.iter().any(|t| cmd_name_of(t) == "rm") {
        return false;
    }
    let (mut rec, mut force) = (false, false);
    for t in tokens {
        if t == "--recursive" {
            rec = true;
        } else if t == "--force" {
            force = true;
        } else if let Some(flags) = t.strip_prefix('-') {
            if !flags.starts_with('-') {
                if flags.contains('r') {
                    rec = true;
                }
                if flags.contains('f') {
                    force = true;
                }
            }
        }
    }
    rec && force
}

fn cmd_name_of(t: &str) -> &str {
    t.rsplit(['/', '\\']).next().unwrap_or(t)
}

/// `> /dev/sda` / `>>/dev/nvme0n1` — перезапись дискового устройства (не null/zero/tty).
fn redirect_to_disk(tokens: &[String]) -> bool {
    for (i, t) in tokens.iter().enumerate() {
        // слитная форма: `>/dev/sda`
        let after_redir = t.trim_start_matches('>');
        if after_redir.len() < t.len() && !after_redir.is_empty() {
            if is_disk_device(after_redir) {
                return true;
            }
        } else if t == ">" || t == ">>" {
            // раздельная форма: `> /dev/sda`
            if let Some(next) = tokens.get(i + 1) {
                if is_disk_device(next) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_disk_device(t: &str) -> bool {
    let Some(dev) = t.strip_prefix("/dev/") else {
        return false;
    };
    matches!(
        dev.get(..2),
        Some("sd") | Some("hd") | Some("vd")
    ) || dev.starts_with("nvme")
        || dev.starts_with("xvd")
        || dev.starts_with("mmcblk")
        || dev.starts_with("disk")
}

fn dangerous_nix_target(t: &str) -> bool {
    let trimmed = t.trim_end_matches('/');
    if t == "/" || t == "/*" {
        return true;
    }
    if matches!(trimmed, "~" | "$home" | "$home/*" | "${home}" | "${home}/*") || t == "~/*" {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix('/') {
        let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
        // Класс C (умеренный): глоб НЕПОСРЕДСТВЕННО под критичным top-level — `/etc/*`.
        if comps.len() >= 2 && NIX_CRITICAL_TOP.contains(&comps[0]) && comps[1] == "*" {
            return true;
        }
        // Лексическая нормализация `.`/`..` (без глобов): `/etc/..`→/, `/.`→/, `/usr/../etc`→/etc.
        let mut norm: Vec<&str> = Vec::new();
        for c in &comps {
            match *c {
                "." => {}
                ".." => {
                    norm.pop();
                }
                other => norm.push(other),
            }
        }
        // Резолв в корень (`/.`, `/etc/..`) — катастрофа.
        if norm.is_empty() {
            return true;
        }
        // Одиночный критичный top-level (`/etc`, `/usr/../etc`) — катастрофа.
        // Глубже (`/var/cache/app`) — обычный confirm (умеренный режим, не Deny).
        if norm.len() == 1 && NIX_CRITICAL_TOP.contains(&norm[0]) {
            return true;
        }
    }
    false
}

fn dangerous_win_target(t: &str) -> bool {
    let t = t.trim_end_matches(['\\', '/']).to_ascii_lowercase();
    // корень диска вида "c:"
    if t.len() == 2 && t.ends_with(':') && t.as_bytes()[0].is_ascii_alphabetic() {
        return true;
    }
    matches!(
        t.as_str(),
        "" | "%systemdrive%" | "%windir%" | "c:\\windows" | "c:\\windows\\system32"
    )
}
