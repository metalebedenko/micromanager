//! Политика безопасности: scoped allowlist + blocked-паттерны.
//! Принцип OWASP: НЕ `allowed_commands:'*'`, а явный scope.

/// Конфиг политики. Дефолт (локальный): без path-scope, shell разрешён.
/// Удалённый грант сужает: allowed_paths + allow_shell.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Разрешённые пути (scope). Пусто = ограничение по путям не задано;
    /// иначе path-действие должно быть ВНУТРИ одного из них (иначе Deny).
    pub allowed_paths: Vec<std::path::PathBuf>,
    /// Запретные glob-паттерны (`*.env`, `*.key`, `*secret*`) — Deny даже на read.
    pub blocked_patterns: Vec<String>,
    /// Разрешён ли run_shell. false → произвольные команды запрещены (только файловые тулы).
    pub allow_shell: bool,
    /// Owner-override: true → hardline не блокирует, а требует ГРОМКОГО подтверждения
    /// владельца (для «я доверяю, мне правда надо: реестр/диск/boot»). По умолч. false.
    pub allow_dangerous: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            blocked_patterns: Vec::new(),
            allow_shell: true,
            allow_dangerous: false,
        }
    }
}

impl Policy {
    /// Проверить, что путь лежит ВНУТРИ allowed_paths (если scope задан).
    /// Канонизация резолвит `..` и симлинки (анти-traversal). Несуществующий
    /// файл (write) — канонизируем родителя + имя.
    pub fn path_in_scope(&self, path: &std::path::Path) -> bool {
        if self.allowed_paths.is_empty() {
            return true;
        }
        let canon = canonicalize_lenient(path);
        self.allowed_paths.iter().any(|base| {
            canonicalize_lenient(base)
                .map(|b| canon.as_ref().map(|c| c.starts_with(&b)).unwrap_or(false))
                .unwrap_or(false)
        })
    }
}

/// Канонизировать путь; если не существует — канонизировать родителя и доклеить имя.
fn canonicalize_lenient(path: &std::path::Path) -> Option<std::path::PathBuf> {
    if let Ok(c) = path.canonicalize() {
        return Some(c);
    }
    let parent = path.parent()?;
    let name = path.file_name()?;
    parent.canonicalize().ok().map(|p| p.join(name))
}

/// Простое glob-сопоставление: поддерживает `*` (любые символы).
/// `*.env` → текст оканчивается на `.env`; `*secret*` → содержит `secret`.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    // Нет '*' — точное совпадение.
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // Якорь в начало.
            if !text[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if i == parts.len() - 1 {
            // Якорь в конец.
            return text[pos..].ends_with(part);
        } else {
            // Середина: найти подстроку после pos.
            match text[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}
