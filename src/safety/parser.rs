//! Anti-bypass-парсер команд. Цель: не дать обойти name-based gating через
//! обёртки-интерпретаторы, цепочки и подстановки. Каждая «эффективная» команда
//! должна попасть в отдельный сегмент и быть проверена (hardline/risk).
//!
//! Fail-closed: нераспарсиваемое (несбалансированные кавычки/скобки, слишком
//! глубокая вложенность) → `Err(ParseError::Unparseable)` → caller трактует как Deny.

/// Ошибка парсинга. Любая → Deny на стороне гейта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Обфускация / несбалансированный синтаксис / превышена глубина.
    Unparseable,
}

/// Предел рекурсии (обёртки + подстановки) — защита от обфускации.
const MAX_DEPTH: usize = 6;

/// Развернуть команду в плоский список эффективных сегментов для классификации.
pub fn segments(command: &str) -> Result<Vec<String>, ParseError> {
    let mut out = Vec::new();
    parse_into(command, 0, &mut out)?;
    if out.is_empty() {
        return Err(ParseError::Unparseable);
    }
    Ok(out)
}

fn parse_into(command: &str, depth: usize, out: &mut Vec<String>) -> Result<(), ParseError> {
    if depth > MAX_DEPTH {
        return Err(ParseError::Unparseable);
    }
    for seg in split_chain(command)? {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        if let Some(inner) = unwrap_wrapper(seg)? {
            // обёртка-интерпретатор: проверяем то, что РЕАЛЬНО исполнится
            parse_into(&inner, depth + 1, out)?;
        } else {
            out.push(seg.to_string());
            // подстановки команд внутри сегмента — тоже исполняемые
            for sub in extract_substitutions(seg) {
                parse_into(&sub, depth + 1, out)?;
            }
        }
    }
    Ok(())
}

/// Разбить по операторам цепочек (`&&`, `||`, `;`, `|`, `&`), уважая кавычки,
/// backticks и `$(...)`-подстановки (внутри них не режем).
fn split_chain(s: &str) -> Result<Vec<String>, ParseError> {
    let chars: Vec<char> = s.chars().collect();
    let mut segs = Vec::new();
    let mut cur = String::new();
    let (mut in_s, mut in_d, mut bt) = (false, false, false);
    let mut paren: i32 = 0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' && !in_d && !bt {
            in_s = !in_s;
            cur.push(c);
            i += 1;
            continue;
        }
        if c == '"' && !in_s && !bt {
            in_d = !in_d;
            cur.push(c);
            i += 1;
            continue;
        }
        if c == '`' && !in_s && !in_d {
            bt = !bt;
            cur.push(c);
            i += 1;
            continue;
        }
        if !in_s && !in_d && !bt {
            if c == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
                paren += 1;
                cur.push('$');
                cur.push('(');
                i += 2;
                continue;
            }
            if paren > 0 && c == '(' {
                paren += 1;
                cur.push(c);
                i += 1;
                continue;
            }
            if paren > 0 && c == ')' {
                paren -= 1;
                cur.push(c);
                i += 1;
                continue;
            }
            if paren == 0 {
                // перевод строки — тоже разделитель команд (класс D anti-bypass).
                if c == '\n' || c == '\r' {
                    push_seg(&mut segs, &mut cur);
                    i += 1;
                    continue;
                }
                if c == '&' && i + 1 < chars.len() && chars[i + 1] == '&' {
                    push_seg(&mut segs, &mut cur);
                    i += 2;
                    continue;
                }
                if c == '|' && i + 1 < chars.len() && chars[i + 1] == '|' {
                    push_seg(&mut segs, &mut cur);
                    i += 2;
                    continue;
                }
                if c == ';' || c == '|' || c == '&' {
                    push_seg(&mut segs, &mut cur);
                    i += 1;
                    continue;
                }
            }
        }
        cur.push(c);
        i += 1;
    }
    if in_s || in_d || bt || paren != 0 {
        return Err(ParseError::Unparseable);
    }
    push_seg(&mut segs, &mut cur);
    Ok(segs)
}

fn push_seg(segs: &mut Vec<String>, cur: &mut String) {
    let t = cur.trim();
    if !t.is_empty() {
        segs.push(t.to_string());
    }
    cur.clear();
}

/// Токенизация с учётом кавычек (кавычки снимаются, `\`-escape вне кавычек снимается).
/// Несбалансированные кавычки → Err. Соседние сегменты склеиваются (`r''m` → `rm`).
fn tokenize(s: &str) -> Result<Vec<String>, ParseError> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let (mut in_s, mut in_d) = (false, false);
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            // shell-escape вне кавычек: снять `\`, взять следующий символ литералом
            // (`\rm` → `rm`, `/et\c` → `/etc`). В одинарных кавычках `\` литерален.
            '\\' if !in_s && !in_d => {
                if let Some(n) = it.next() {
                    cur.push(n);
                    has = true;
                }
            }
            '\'' if !in_d => {
                in_s = !in_s;
                has = true;
            }
            '"' if !in_s => {
                in_d = !in_d;
                has = true;
            }
            c if c.is_whitespace() && !in_s && !in_d => {
                if has {
                    tokens.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if in_s || in_d {
        return Err(ParseError::Unparseable);
    }
    if has {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Каноническая токенизация сегмента для hardline-матчинга: снимает кавычки и
/// `\`-escape, склеивает соседние части. НЕ лоуэркейсит (кейс-нормализацию делает
/// `blocklist::norm_tokens`). Несбалансированные кавычки → Err (caller трактует как Deny).
pub fn canon_tokens(seg: &str) -> Result<Vec<String>, ParseError> {
    tokenize(seg)
}

/// Если сегмент — вызов известного интерпретатора с `-c`/`/c`-командой,
/// вернуть Some(внутренняя команда). `-EncodedCommand` → Err (fail-closed).
fn unwrap_wrapper(seg: &str) -> Result<Option<String>, ParseError> {
    let toks = tokenize(seg)?;
    if toks.is_empty() {
        return Ok(None);
    }
    let cmd0 = basename(&toks[0]).to_ascii_lowercase();
    let cmd0 = cmd0.strip_suffix(".exe").unwrap_or(&cmd0);

    // argv-префикс-обёртки (sudo/env/eval/…): отбросить обёртку и её опции, проверять
    // то, что РЕАЛЬНО исполнится (класс B anti-bypass). Развёртка рекурсивна (parse_into).
    if is_prefix_wrapper(cmd0) {
        if cmd0 == "eval" {
            // eval STRING — аргумент целиком есть команда; ре-парсим хвост после `eval`.
            return Ok(remainder_after_tokens(seg, 1));
        }
        let skip = prefix_skip(cmd0, &toks);
        return Ok(remainder_after_tokens(seg, skip));
    }

    let is_pwsh = matches!(cmd0, "powershell" | "pwsh");
    let is_cmd = cmd0 == "cmd";
    // POSIX-шеллы: исполняют и `-c CMD`, и here-string `<<< CMD`.
    let is_shell = matches!(cmd0, "bash" | "sh" | "zsh" | "dash" | "ash" | "ksh");
    // Script-языки (python/perl/node/…) НЕ разворачиваем тут: их `-c`/`-e`-код невозможно
    // полноценно распарсить как шелл → scan тела на катастрофу в blocklist::is_hardline.

    if is_pwsh {
        for t in &toks[1..] {
            let tl = t.to_ascii_lowercase();
            if tl == "-encodedcommand" || tl == "-enc" || tl == "-ec" || tl == "-e" {
                return Err(ParseError::Unparseable); // base64 — не пропускаем вслепую
            }
        }
        // -Command (и его аббревиатуры -c/-co/-com...), -c
        if let Some(arg) = arg_after(&toks, |t| t.len() >= 2 && "-command".starts_with(t)) {
            return Ok(Some(arg));
        }
        return Ok(None);
    }
    if is_cmd {
        if let Some(arg) = arg_after(&toks, |t| t == "/c" || t == "/k") {
            return Ok(Some(arg));
        }
        return Ok(None);
    }
    if is_shell {
        if let Some(arg) = arg_after(&toks, |t| t == "-c") {
            return Ok(Some(arg));
        }
        // here-string: `bash <<< 'rm -rf /'` — операнд исполняется как скрипт.
        if let Some(arg) = arg_after(&toks, |t| t == "<<<") {
            return Ok(Some(arg));
        }
        return Ok(None);
    }
    Ok(None)
}

/// Вернуть токен, следующий за первым флагом, удовлетворяющим предикату
/// (флаг сравнивается в нижнем регистре).
fn arg_after<F: Fn(&str) -> bool>(toks: &[String], is_flag: F) -> Option<String> {
    for i in 0..toks.len() {
        if is_flag(&toks[i].to_ascii_lowercase()) {
            return toks.get(i + 1).cloned();
        }
    }
    None
}

fn basename(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

/// Argv-префикс-обёртки: не интерпретаторы, а команды, после которых идёт ДРУГАЯ команда.
fn is_prefix_wrapper(cmd0: &str) -> bool {
    matches!(
        cmd0,
        "sudo"
            | "doas"
            | "env"
            | "nice"
            | "ionice"
            | "timeout"
            | "nohup"
            | "setsid"
            | "stdbuf"
            | "command"
            | "exec"
            | "time"
            | "eval"
    )
}

/// Сколько ведущих токенов отбросить, чтобы добраться до реальной команды после префикса.
/// Учитывает опции-С-аргументом (`sudo -u root`, `env -u VAR`, `timeout -s SIG`) и
/// первый bare-аргумент `timeout` (DURATION). Жадно, но не съедает имя команды.
fn prefix_skip(cmd0: &str, toks: &[String]) -> usize {
    // опции, забирающие СЛЕДУЮЩИЙ токен как аргумент (раздельная форма)
    let arg_taking: &[&str] = match cmd0 {
        "sudo" | "doas" => &["-u", "-g", "-p", "-c", "-h", "-r", "-t", "--user", "--group"],
        "env" => &["-u", "--unset"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p", "-u"],
        "timeout" => &["-s", "--signal", "-k", "--kill-after"],
        "stdbuf" => &["-i", "-o", "-e", "--input", "--output", "--error"],
        _ => &[],
    };
    let mut timeout_duration_pending = cmd0 == "timeout";
    let mut i = 1; // отбрасываем сам префикс
    while i < toks.len() {
        let t = &toks[i];
        let tl = t.to_ascii_lowercase();
        // env VAR=val присвоения
        if cmd0 == "env" && !t.starts_with('-') && t.contains('=') {
            i += 1;
            continue;
        }
        if t.starts_with('-') {
            i += 1;
            // раздельная форма опции-с-аргументом (-u root); слитная (-c3, -oL) — без доп. токена
            if arg_taking.contains(&tl.as_str()) && i < toks.len() {
                i += 1;
            }
            continue;
        }
        // bare-токен
        if timeout_duration_pending {
            timeout_duration_pending = false; // первый non-flag у timeout — это DURATION
            i += 1;
            continue;
        }
        break; // дошли до имени реальной команды
    }
    i
}

/// Вернуть СЫРОЙ остаток сегмента после первых `n` токенов (whitespace-разделённых,
/// с уважением кавычек) — сохраняя исходное квотирование для корректного ре-парса
/// вложенных интерпретаторов (`sudo bash -c "rm -rf /"`). None — если ничего не осталось.
fn remainder_after_tokens(seg: &str, n: usize) -> Option<String> {
    let chars: Vec<char> = seg.chars().collect();
    let (mut in_s, mut in_d) = (false, false);
    let mut i = 0;
    let mut count = 0;
    while count < n {
        while i < chars.len() && chars[i].is_whitespace() && !in_s && !in_d {
            i += 1;
        }
        if i >= chars.len() {
            return None;
        }
        while i < chars.len() {
            let c = chars[i];
            if c == '\'' && !in_d {
                in_s = !in_s;
                i += 1;
                continue;
            }
            if c == '"' && !in_s {
                in_d = !in_d;
                i += 1;
                continue;
            }
            if c.is_whitespace() && !in_s && !in_d {
                break;
            }
            i += 1;
        }
        count += 1;
    }
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    if i >= chars.len() {
        None
    } else {
        Some(chars[i..].iter().collect())
    }
}

/// Извлечь содержимое подстановок `$(...)`/`<(...)`/`>(...)` (с вложенностью) и `` `...` ``.
/// Внутри одинарных кавычек подстановка не выполняется — пропускаем.
fn extract_substitutions(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut subs = Vec::new();
    let (mut in_s, mut in_d) = (false, false);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' && !in_d {
            in_s = !in_s;
            i += 1;
            continue;
        }
        if c == '"' && !in_s {
            in_d = !in_d;
            i += 1;
            continue;
        }
        if !in_s {
            // $(...), а также process substitution <(...) / >(...) — содержимое исполняется.
            if (c == '$' || c == '<' || c == '>') && i + 1 < chars.len() && chars[i + 1] == '(' {
                let mut depth = 1;
                let start = i + 2;
                let mut j = start;
                while j < chars.len() && depth > 0 {
                    match chars[j] {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if depth == 0 {
                    subs.push(chars[start..j].iter().collect());
                    i = j + 1;
                    continue;
                }
            }
            if c == '`' {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != '`' {
                    j += 1;
                }
                if j < chars.len() {
                    subs.push(chars[start..j].iter().collect());
                    i = j + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    subs
}
