//! Pairing + auth. Одноразовый секрет в коде-приглашении + allowlist
//! по криптографической идентичности узла (iroh верифицирует EndpointId).
//!
//! Поток: A открывает поток → шлёт MM/<ver> <secret>\n → B сверяет версию + секрет
//! → отвечает OK {json}/NO/VERS <ver>. Только после OK обе стороны переходят к MCP.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use iroh::EndpointId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::GrantSummary;

/// Версия pairing-протокола. Бампать при ЛЮБОЙ смене формата провода рукопожатия.
/// v1 = первая версия с явным обменом версией (MM/<ver> ... + VERS-ответ).
pub const PROTOCOL_VERSION: u16 = 1;

/// Лимит неверных попыток секрета: после превышения секрет инвалидируется
/// (защита-в-глубину от перебора; легит предъявляет верный секрет с первой попытки).
pub(crate) const MAX_SECRET_ATTEMPTS: u32 = 20;

/// TTL pairing-секрета по умолчанию для пользовательских точек (listen/share): окно,
/// в течение которого приглашение действительно. Реконнект по allowlist TTL не подчинён.
pub const PAIRING_SECRET_TTL_SECS: u64 = 1800; // 30 минут

/// Сравнение в постоянное время (по совпавшей длине): не утекать позицию расхождения
/// тайминг-сайдканалом. Длина секрета фиксирована, её раскрытие не значимо.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Привратник стороны B: одноразовый секрет + allowlist спаренных узлов.
/// При `persist_path = Some` allowlist грузится из файла на старте и дописывается
/// при новом паринге (опт-ин `listen --remember`) — друг переживает рестарт B.
pub struct Gatekeeper {
    secret: String,
    secret_consumed: AtomicBool,
    failed_attempts: AtomicU32,
    created: Instant,
    ttl: Option<Duration>,
    allowed: Mutex<HashSet<EndpointId>>,
    persist_path: Option<PathBuf>,
}

impl Gatekeeper {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            secret_consumed: AtomicBool::new(false),
            failed_attempts: AtomicU32::new(0),
            created: Instant::now(),
            ttl: None,
            allowed: Mutex::new(HashSet::new()),
            persist_path: None,
        }
    }

    /// Как `new`, но с персистом allowlist в `path`: грузит спаренные id на старте
    /// (битый файл → пустой, fail-closed), дописывает файл при новом паринге.
    pub fn with_persist(secret: impl Into<String>, path: PathBuf) -> Self {
        let allowed = super::allowlist::load(&path);
        Self {
            secret: secret.into(),
            secret_consumed: AtomicBool::new(false),
            failed_attempts: AtomicU32::new(0),
            created: Instant::now(),
            ttl: None,
            allowed: Mutex::new(allowed),
            persist_path: Some(path),
        }
    }

    /// Задать TTL секрета (0 = без лимита). Реконнект по allowlist TTL не подчинён.
    pub fn with_ttl(mut self, secs: u64) -> Self {
        self.ttl = (secs != 0).then(|| Duration::from_secs(secs));
        self
    }

    /// Истёк ли TTL секрета.
    fn secret_expired(&self) -> bool {
        self.ttl.is_some_and(|ttl| self.created.elapsed() > ttl)
    }

    /// Пустить ли узел: уже в allowlist, либо предъявил неиспользованный секрет
    /// (тогда секрет «сгорает» и узел добавляется в allowlist + персист). Иначе — нет.
    pub fn authorize(&self, remote: EndpointId, presented: &str) -> bool {
        if self.allowed.lock().unwrap().contains(&remote) {
            return true;
        }
        // Дальше — только путь одноразового pairing-секрета.
        if self.secret_consumed.load(Ordering::SeqCst) {
            return false; // сгорел/инвалидирован (использован, лимит попыток или TTL)
        }
        if self.secret_expired() {
            self.secret_consumed.store(true, Ordering::SeqCst);
            return false;
        }
        // Пустой presented безопасен: generate_secret() всегда непустой → reconnect-A
        // пускается ТОЛЬКО через allowlist выше, а не сюда.
        if presented.is_empty() {
            return false;
        }
        if !ct_eq(presented.as_bytes(), self.secret.as_bytes()) {
            // неверная попытка: счётчик; при превышении лимита — инвалидировать секрет.
            if self.failed_attempts.fetch_add(1, Ordering::SeqCst) + 1 >= MAX_SECRET_ATTEMPTS {
                self.secret_consumed.store(true, Ordering::SeqCst);
            }
            return false;
        }
        // Верный секрет: атомарно «сжечь» через CAS — ровно ОДИН проходит даже при гонке
        // параллельных сессий (без TOCTOU между load и store).
        if self
            .secret_consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let mut allowed = self.allowed.lock().unwrap();
            allowed.insert(remote);
            if let Some(path) = &self.persist_path {
                super::allowlist::save(path, &allowed); // best-effort
            }
            return true;
        }
        false
    }

    /// Тест-хелпер: состарить секрет на `secs` (для проверки TTL без реального ожидания).
    #[cfg(test)]
    fn test_age(mut self, secs: u64) -> Self {
        self.created = self
            .created
            .checked_sub(Duration::from_secs(secs))
            .unwrap_or(self.created);
        self
    }
}

/// Сгенерировать криптослучайный pairing-секрет (24 символа alnum).
pub fn generate_secret() -> String {
    use rand::Rng;
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

const MAX_LINE: usize = 512;

/// Прочитать одну строку (до '\n') побайтно — чтобы НЕ захватить байты MCP,
/// которые пойдут по тому же потоку после рукопожатия.
async fn read_line<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<String> {
    let mut buf = Vec::new();
    loop {
        let b = r.read_u8().await?;
        if b == b'\n' {
            break;
        }
        buf.push(b);
        if buf.len() > MAX_LINE {
            anyhow::bail!("рукопожатие: строка слишком длинная");
        }
    }
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

/// Разобрать client-hello B-стороной: "MM/<ver> <secret>" → Some((ver, secret));
/// "MM/<ver>" без секрета → Some((ver, "")) — ПУСТОЙ секрет для reconnect по allowlist
/// (read_line срезает хвостовой пробел, поэтому "MM/1 " приходит как "MM/1"); legacy
/// без префикса "MM/" или нечисловая версия → None.
pub(crate) fn parse_client_hello(line: &str) -> Option<(u16, String)> {
    let rest = line.trim().strip_prefix("MM/")?;
    match rest.split_once(' ') {
        Some((ver_str, secret)) => {
            let ver: u16 = ver_str.parse().ok()?;
            Some((ver, secret.trim().to_string()))
        }
        None => {
            // нет пробела → версия без секрета = пустой секрет (reconnect)
            let ver: u16 = rest.trim().parse().ok()?;
            Some((ver, String::new()))
        }
    }
}

/// Исход рукопожатия глазами A.
#[derive(Debug, PartialEq)]
pub enum HandshakeOutcome {
    Ok(GrantSummary),
    VersionMismatch { peer: u16 },
    Rejected,
}

/// Разобрать ответ B A-стороной.
pub(crate) fn parse_server_reply(line: &str) -> HandshakeOutcome {
    let line = line.trim();
    if line == "OK" {
        return HandshakeOutcome::Ok(GrantSummary::default());
    }
    if let Some(rest) = line.strip_prefix("OK ") {
        return HandshakeOutcome::Ok(serde_json::from_str(rest.trim()).unwrap_or_default());
    }
    if let Some(rest) = line.strip_prefix("VERS ") {
        if let Ok(peer) = rest.trim().parse::<u16>() {
            return HandshakeOutcome::VersionMismatch { peer };
        }
    }
    HandshakeOutcome::Rejected // "NO" и всё прочее (включая голый VERS без числа)
}

/// B-сторона рукопожатия: прочитать секрет, проверить версию, авторизовать, ответить OK {json}/NO/VERS.
pub async fn server_handshake<R, W>(
    recv: &mut R,
    send: &mut W,
    gk: &Gatekeeper,
    remote: EndpointId,
    grant: &GrantSummary,
) -> Result<bool>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let line = read_line(recv).await?;
    match parse_client_hello(&line) {
        None => {
            // legacy/мусорный клиент без MM/<ver>
            eprintln!("[handshake] отклонено: несовместимо старая версия клиента (нет MM/<версии>)");
            send.write_all(format!("VERS {PROTOCOL_VERSION}\n").as_bytes()).await?;
            send.flush().await?;
            Ok(false)
        }
        Some((ver, _)) if ver != PROTOCOL_VERSION => {
            eprintln!("[handshake] отклонено: версии несовместимы (клиент v{ver}, мы v{PROTOCOL_VERSION})");
            send.write_all(format!("VERS {PROTOCOL_VERSION}\n").as_bytes()).await?;
            send.flush().await?;
            Ok(false)
        }
        Some((_, secret)) => {
            let ok = gk.authorize(remote, &secret);
            if ok {
                send.write_all(
                    format!("OK {}\n", serde_json::to_string(grant).unwrap_or_else(|_| "{}".into()))
                        .as_bytes(),
                )
                .await?;
            } else {
                send.write_all(b"NO\n").await?;
            }
            send.flush().await?;
            Ok(ok)
        }
    }
}

/// A-сторона рукопожатия: предъявить MM/<ver> + секрет, дождаться OK/NO/VERS.
pub async fn client_handshake<R, W>(
    send: &mut W,
    recv: &mut R,
    secret: &str,
) -> Result<HandshakeOutcome>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    send.write_all(format!("MM/{PROTOCOL_VERSION} {secret}\n").as_bytes()).await?;
    send.flush().await?;
    let resp = read_line(recv).await?;
    Ok(parse_server_reply(&resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    #[test]
    fn secret_authorizes_once_then_allowlist() {
        let gk = Gatekeeper::new("abc");
        let (a, b) = (id(), id());
        assert!(gk.authorize(a, "abc"), "первый паринг по секрету");
        assert!(gk.authorize(a, "wrong"), "A уже в allowlist");
        assert!(!gk.authorize(b, "abc"), "секрет сгорел → B мимо");
        assert!(!gk.authorize(b, "wrong"));
    }

    #[test]
    fn wrong_secret_rejected() {
        let gk = Gatekeeper::new("abc");
        assert!(!gk.authorize(id(), "nope"));
    }

    #[test]
    fn secret_invalidated_after_attempt_limit() {
        // Защита-в-глубину: после лимита неверных попыток секрет сгорает.
        let gk = Gatekeeper::new("right-secret");
        for _ in 0..MAX_SECRET_ATTEMPTS {
            assert!(!gk.authorize(id(), "wrong"));
        }
        assert!(
            !gk.authorize(id(), "right-secret"),
            "после лимита попыток даже верный секрет не пускает"
        );
    }

    #[test]
    fn expired_secret_rejected() {
        // TTL: просроченное приглашение не пускает, даже с верным секретом.
        let gk = Gatekeeper::new("sec").with_ttl(60).test_age(120);
        assert!(!gk.authorize(id(), "sec"), "секрет протух по TTL");
        // А свежий с тем же TTL — пускает.
        let fresh = Gatekeeper::new("sec").with_ttl(60);
        assert!(fresh.authorize(id(), "sec"));
    }

    #[test]
    fn ttl_zero_means_no_expiry() {
        let gk = Gatekeeper::new("sec").with_ttl(0).test_age(100_000);
        assert!(gk.authorize(id(), "sec"), "ttl=0 → без лимита времени");
    }

    #[test]
    fn allowlist_reconnect_not_subject_to_ttl() {
        // Реконнект по allowlist не подчинён TTL секрета (друг уже доверенный).
        let gk = Gatekeeper::new("sec").with_ttl(60);
        let a = id();
        assert!(gk.authorize(a, "sec"), "первый паринг");
        let gk_aged = gk.test_age(120); // секрет давно протух
        assert!(gk_aged.authorize(a, ""), "вернувшийся A пускается по allowlist пустым секретом");
    }

    #[test]
    fn generate_secret_is_never_empty() {
        // Фундамент безопасности пустого-секрет-реконнекта: пустой presented != секрет.
        assert!(!generate_secret().is_empty());
        assert_eq!(generate_secret().len(), 24);
    }

    #[test]
    fn persisted_allowlist_lets_returning_node_in_with_empty_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("al.json");
        let a = id();

        // Первый «запуск» B: A парится по секрету → персист в файл.
        let gk = Gatekeeper::with_persist("sec-1", path.clone());
        assert!(gk.authorize(a, "sec-1"), "паринг по секрету");

        // «Рестарт» B: новый Gatekeeper из того же файла, НОВЫЙ секрет.
        let gk2 = Gatekeeper::with_persist("sec-2-new", path.clone());
        assert!(gk2.authorize(a, ""), "вернувшийся A пускается из allowlist пустым секретом");
        assert!(!gk2.authorize(id(), ""), "неизвестный узел пустым секретом — нет");
        assert!(!gk2.authorize(id(), "sec-1"), "старый сгоревший секрет — нет");
    }

    #[test]
    fn corrupt_persisted_allowlist_is_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("al.json");
        std::fs::write(&path, "мусор не массив").unwrap();
        let a = id();
        let gk = Gatekeeper::with_persist("sec", path);
        assert!(!gk.authorize(a, ""), "битый allowlist → пусто → пустой секрет не пускает");
    }

    // --- Тесты parse_client_hello ---

    #[test]
    fn parse_client_hello_versioned() {
        assert_eq!(parse_client_hello("MM/1 abc"), Some((1, "abc".to_string())));
        assert_eq!(
            parse_client_hello("MM/7 secret24chars"),
            Some((7, "secret24chars".to_string()))
        );
    }

    #[test]
    fn parse_client_hello_empty_secret_for_reconnect() {
        // "MM/1" без секрета (read_line срезал хвостовой пробел) → пустой секрет.
        assert_eq!(parse_client_hello("MM/1"), Some((1, String::new())));
        assert_eq!(parse_client_hello("MM/1 "), Some((1, String::new())));
    }

    #[test]
    fn parse_client_hello_legacy_or_garbage_is_none() {
        assert_eq!(parse_client_hello("plainsecret"), None); // legacy (нет MM/)
        assert_eq!(parse_client_hello("MM/abc x"), None);    // версия не u16
        assert_eq!(parse_client_hello("MM/abc"), None);      // версия не u16 (без секрета)
        assert_eq!(parse_client_hello(""), None);
    }

    // --- Тесты parse_server_reply (замена parse_handshake_reply) ---

    #[test]
    fn parse_ok_without_json_defaults() {
        assert_eq!(parse_server_reply("OK"), HandshakeOutcome::Ok(GrantSummary::default()));
    }

    #[test]
    fn parse_ok_with_bad_json_defaults() {
        assert_eq!(
            parse_server_reply("OK {не json"),
            HandshakeOutcome::Ok(GrantSummary::default())
        );
    }

    #[test]
    fn parse_no_returns_rejected() {
        assert_eq!(parse_server_reply("NO"), HandshakeOutcome::Rejected);
        assert_eq!(parse_server_reply("чепуха"), HandshakeOutcome::Rejected);
    }

    #[test]
    fn parse_ok_with_json_parses() {
        let g = GrantSummary { allow_shell: true, ttl_secs: Some(7), ..Default::default() };
        let line = format!("OK {}", serde_json::to_string(&g).unwrap());
        assert_eq!(parse_server_reply(&line), HandshakeOutcome::Ok(g));
    }

    #[test]
    fn parse_server_reply_branches() {
        assert_eq!(parse_server_reply("OK"), HandshakeOutcome::Ok(GrantSummary::default()));
        let g = GrantSummary { allow_shell: true, ttl_secs: Some(5), ..Default::default() };
        assert_eq!(
            parse_server_reply(&format!("OK {}", serde_json::to_string(&g).unwrap())),
            HandshakeOutcome::Ok(g)
        );
        assert_eq!(
            parse_server_reply("OK {bad"),
            HandshakeOutcome::Ok(GrantSummary::default())
        ); // кривой json → дефолт
        assert_eq!(
            parse_server_reply("VERS 3"),
            HandshakeOutcome::VersionMismatch { peer: 3 }
        );
        assert_eq!(parse_server_reply("VERS xyz"), HandshakeOutcome::Rejected);
        assert_eq!(parse_server_reply("NO"), HandshakeOutcome::Rejected);
        assert_eq!(parse_server_reply("чепуха"), HandshakeOutcome::Rejected);
    }

    // --- Migrated duplex tests ---

    #[tokio::test]
    async fn handshake_carries_grant() {
        use tokio::io::duplex;
        let grant = GrantSummary {
            allowed_paths: vec!["/tmp".into()],
            allow_shell: true,
            allow_dangerous: false,
            ttl_secs: Some(120),
        };
        let gk = Gatekeeper::new("sec");
        let (a, b) = duplex(4096);
        let id = iroh::SecretKey::generate().public();
        let g2 = grant.clone();
        // B-сторона
        let bt = tokio::spawn(async move {
            let (mut br, mut bw) = tokio::io::split(b);
            server_handshake(&mut br, &mut bw, &gk, id, &g2).await.unwrap()
        });
        // A-сторона
        let (mut ar, mut aw) = tokio::io::split(a);
        let got = client_handshake(&mut aw, &mut ar, "sec").await.unwrap();
        assert!(bt.await.unwrap());
        assert_eq!(got, HandshakeOutcome::Ok(grant));
    }

    #[tokio::test]
    async fn handshake_reject_returns_none() {
        use tokio::io::duplex;
        let gk = Gatekeeper::new("right");
        let (a, b) = duplex(4096);
        let id = iroh::SecretKey::generate().public();
        let bt = tokio::spawn(async move {
            let (mut br, mut bw) = tokio::io::split(b);
            server_handshake(&mut br, &mut bw, &gk, id, &Default::default())
                .await
                .unwrap()
        });
        let (mut ar, mut aw) = tokio::io::split(a);
        let got = client_handshake(&mut aw, &mut ar, "WRONG").await.unwrap();
        assert!(!bt.await.unwrap());
        assert_eq!(got, HandshakeOutcome::Rejected);
    }

    // --- Новый тест: B отвечает VERS на legacy-первую-строку ---

    #[tokio::test]
    async fn server_replies_vers_on_legacy_first_line() {
        use tokio::io::{duplex, split, AsyncWriteExt};
        let gk = Gatekeeper::new("sec");
        let id = iroh::SecretKey::generate().public();
        let (a, b) = duplex(4096);
        let (ar, mut aw) = split(a);
        let (mut br, mut bw) = split(b);
        // A шлёт LEGACY первую строку (без MM/) — старый клиент
        let at = tokio::spawn(async move {
            aw.write_all(b"plainsecret\n").await.unwrap();
            aw.flush().await.unwrap();
            // прочитать ответ B
            let mut ar = ar;
            let line = super::read_line(&mut ar).await.unwrap();
            line
        });
        let ok = server_handshake(&mut br, &mut bw, &gk, id, &Default::default()).await.unwrap();
        let reply = at.await.unwrap();
        assert!(!ok);
        assert!(reply.starts_with("VERS "), "got: {reply}");
    }

    // --- Дополнительный тест: B отвечает VERS на version-mismatch (MM/<ver≠1>) ---

    #[tokio::test]
    async fn server_replies_vers_on_version_mismatch() {
        use tokio::io::{duplex, split, AsyncWriteExt};
        let gk = Gatekeeper::new("sec");
        let id = iroh::SecretKey::generate().public();
        let (a, b) = duplex(4096);
        let (ar, mut aw) = split(a);
        let (mut br, mut bw) = split(b);
        // A шлёт MM/<version≠PROTOCOL_VERSION>
        let at = tokio::spawn(async move {
            // версия 99 — заведомо не равна PROTOCOL_VERSION (1)
            aw.write_all(b"MM/99 sec\n").await.unwrap();
            aw.flush().await.unwrap();
            let mut ar = ar;
            let line = super::read_line(&mut ar).await.unwrap();
            line
        });
        let ok = server_handshake(&mut br, &mut bw, &gk, id, &Default::default()).await.unwrap();
        let reply = at.await.unwrap();
        assert!(!ok);
        assert!(reply.starts_with("VERS "), "got: {reply}");
    }
}
