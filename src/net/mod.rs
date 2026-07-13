//! Сетевой слой: «руки» B по iroh, оркестратор A — клиент.
//! MCP поверх iroh-bidi-потока (мост iroh ↔ rmcp transport).

mod allowlist;
// pub(crate): TUI-экран «поделиться своим ПК» (src/tui/share.rs) переиспользует
// эти примитивы (handshake/идентичность/store/serve_hands_with), как и headless listen.
pub(crate) mod auth;
mod connect;
mod grant;
pub(crate) mod identity;
pub(crate) mod keyfile;
mod listen;
mod local;
mod peers;
pub mod protocol;
mod remote;
mod runner;
pub(crate) mod session;
pub mod session_store;
pub(crate) mod store;

pub use auth::{Gatekeeper, HandshakeOutcome, PROTOCOL_VERSION};
pub use connect::run_connect;
pub use grant::GrantSummary;
pub use listen::run_listen;
pub use peers::KnownPeer;
pub use remote::McpSession;
pub(crate) use remote::short_id;
#[cfg(test)]
pub(crate) use remote::{loopback_session_with_confirmer, loopback_session_with_probe};
pub use runner::{map_tool, McpCaller, McpHandle, McpToolRunner};
pub use session::{Grant, ReportTo};

use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

/// Отозвать доверие (`forget`): убрать запомненных B (A-сторона, `peers.json`) и
/// друзей из allowlist (B-сторона, `allowlist.json`). `prefix=None` → всех; `Some(p)`
/// → по префиксу id/метки. Возвращает `(забыто_B_на_A, забыто_друзей_на_B)`.
pub fn forget(prefix: Option<&str>) -> (usize, usize) {
    let on_a = peers::forget(&store::peers_path(), prefix);
    let on_b = allowlist::forget(&store::allowlist_path(), prefix);
    (on_a, on_b)
}

/// ALPN протокола micromanager поверх iroh.
pub const ALPN: &[u8] = b"micromanager/mcp/0";

/// Код-приглашение: адрес узла B + одноразовый pairing-секрет.
/// `remember` (опт-ин персист): B пометил «помнить этого друга» (`listen --remember`).
/// `#[serde(default)]` → старые коды без поля читаются как `remember=false`.
#[derive(Serialize, Deserialize)]
pub struct Invite {
    pub addr: EndpointAddr,
    pub secret: String,
    #[serde(default)]
    pub remember: bool,
}

/// Префикс компактного кода-приглашения. Тело — base64url(JSON) без паддинга.
const INVITE_PREFIX: &str = "mm_";

/// Кодирует инвайт в один paste-safe токен `mm_<base64url(json)>`: без кавычек,
/// скобок и пробелов — выживает в мессенджерах и выделяется двойным кликом.
pub fn encode_invite(inv: &Invite) -> String {
    use base64::Engine;
    let json = serde_json::to_string(inv).unwrap_or_default();
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    format!("{INVITE_PREFIX}{body}")
}

/// Декодирует инвайт. Принимает оба формата:
/// - новый токен `mm_<base64url(json)>` — любые пробелы/переносы внутри игнорируются
///   (устойчив к артефактам ручного копирования из терминала);
/// - легаси сырой JSON `{...}` — обратная совместимость со старыми кодами.
pub fn decode_invite(s: &str) -> anyhow::Result<Invite> {
    let t = s.trim();
    if let Some(body) = t.strip_prefix(INVITE_PREFIX) {
        use base64::Engine;
        let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body.as_bytes())
            .map_err(|e| anyhow::anyhow!("битый код-приглашение (base64): {e}"))?;
        Ok(serde_json::from_slice(&bytes)?)
    } else {
        Ok(serde_json::from_str(t)?)
    }
}

#[cfg(test)]
mod tests {
    use super::auth::{client_handshake, server_handshake, Gatekeeper, HandshakeOutcome};
    use super::ALPN;
    use crate::audit::NullAudit;
    use crate::safety::{Action, Confirmer, Policy};
    use crate::server::tools::HandsServer;
    use iroh::endpoint::presets;
    use iroh::Endpoint;
    use rmcp::model::CallToolRequestParams;
    use rmcp::ServiceExt;
    use std::sync::Arc;

    struct No;
    impl Confirmer for No {
        fn confirm(&self, _: &Action) -> bool {
            false
        }
    }
    struct Yes;
    impl Confirmer for Yes {
        fn confirm(&self, _: &Action) -> bool {
            true
        }
    }

    async fn call(
        client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
        tool: &str,
        args: serde_json::Value,
    ) -> String {
        let mut p = CallToolRequestParams::new(tool.to_string());
        p.arguments = args.as_object().cloned();
        format!("{:?}", client.peer().call_tool(p).await)
    }

    /// Персист-личность (`listen --remember`) даёт СТАБИЛЬНЫЙ EndpointId между «рестартами»:
    /// тот же ключ из файла → тот же id эндпоинта. Ядро механизма постоянного доступа.
    #[tokio::test]
    async fn persisted_identity_gives_stable_endpoint_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let sk1 = super::identity::load_or_create(&path).unwrap();
        let e1 = Endpoint::builder(presets::Minimal).secret_key(sk1).bind().await.unwrap();
        let id1 = e1.id();
        e1.close().await;
        // «рестарт»: тот же ключ из файла
        let sk2 = super::identity::load_or_create(&path).unwrap();
        let e2 = Endpoint::builder(presets::Minimal).secret_key(sk2).bind().await.unwrap();
        let id2 = e2.id();
        e2.close().await;
        assert_eq!(id1, id2, "тот же ключ из файла → тот же EndpointId между рестартами");
    }

    /// Код-приглашение кодируется в paste-safe токен `mm_…`, переживает roundtrip,
    /// терпит пробелы/переносы от ручного копирования и принимает легаси-JSON.
    #[tokio::test]
    async fn invite_token_roundtrip_legacy_and_paste_safe() {
        let b = Endpoint::builder(presets::Minimal).bind().await.unwrap();
        let inv = super::Invite {
            addr: b.addr(),
            secret: "s".into(),
            remember: true,
        };

        // новый формат — компактный токен без спецсимволов
        let enc = super::encode_invite(&inv);
        assert!(enc.starts_with("mm_"), "инвайт кодируется как токен mm_…, got {enc}");
        assert!(
            !enc.contains(['{', '}', '"', ' ', '\n']),
            "токен paste-safe (ни скобок, ни кавычек, ни пробелов): {enc}"
        );
        assert!(super::decode_invite(&enc).unwrap().remember, "remember=true пережил roundtrip");

        // устойчивость к пробелам/переносам, вставленным при ручном копировании из терминала
        let mangled = format!("  {} \n {}  ", &enc[..10], &enc[10..]);
        assert_eq!(
            super::decode_invite(&mangled).unwrap().secret,
            "s",
            "пробелы/переносы внутри токена игнорируются"
        );

        // легаси: сырой JSON без поля remember → default false (обратная совместимость)
        let raw_json = serde_json::to_string(&inv).unwrap();
        let mut obj: serde_json::Value = serde_json::from_str(&raw_json).unwrap();
        obj.as_object_mut().unwrap().remove("remember");
        let old = serde_json::to_string(&obj).unwrap();
        assert!(!super::decode_invite(&old).unwrap().remember, "легаси JSON без remember → false");
        b.close().await;
    }

    /// PC-PC симуляция с pairing: A проходит рукопожатие по секрету и вызывает руки B.
    #[tokio::test]
    async fn paired_a_connects_and_calls_remote_list_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let secret = "test-secret-123";

        // B: эндпоинт + привратник; на подключение — рукопожатие, затем руки.
        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b_addr = b.addr();
        let gk = Arc::new(Gatekeeper::new(secret));
        let b_task = tokio::spawn(async move {
            let conn = b.accept().await.expect("incoming").await.expect("conn");
            let remote = conn.remote_id();
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            let ok = server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
                .await
                .expect("handshake");
            assert!(ok, "B должен авторизовать верный секрет");
            let svc = HandsServer::new().serve((recv, send)).await.expect("serve");
            svc.waiting().await.ok();
        });

        // A: дозвон → рукопожатие → MCP → list_dir у B.
        let a = Endpoint::bind(presets::Minimal).await.unwrap();
        let conn = a.connect(b_addr, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let ok = client_handshake(&mut send, &mut recv, secret).await.unwrap();
        assert!(matches!(ok, HandshakeOutcome::Ok(_)), "A должен получить OK");

        let client = ().serve((recv, send)).await.unwrap();
        let mut param = CallToolRequestParams::new("list_dir");
        param.arguments = serde_json::json!({ "path": dir.path().to_string_lossy() })
            .as_object()
            .cloned();
        let result = client.peer().call_tool(param).await.unwrap();
        assert!(
            format!("{result:?}").contains("probe.txt"),
            "удалённый list_dir должен вернуть probe.txt"
        );

        client.cancel().await.ok();
        a.close().await;
        b_task.abort();
    }

    /// Удалённый гость ограничен path-scope гранта — внутри ок, снаружи отказ.
    #[tokio::test]
    async fn remote_list_dir_respects_path_scope() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let scope = dir.path().to_path_buf();
        let secret = "s";

        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b_addr = b.addr();
        let gk = Arc::new(Gatekeeper::new(secret));
        let b_task = tokio::spawn(async move {
            let conn = b.accept().await.unwrap().await.unwrap();
            let remote = conn.remote_id();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
                .await
                .unwrap();
            let policy = Policy {
                allowed_paths: vec![scope],
                blocked_patterns: vec![],
                allow_shell: false,
                allow_dangerous: false,
            };
            let svc = HandsServer::with(policy, Arc::new(Yes), Arc::new(NullAudit))
                .serve((recv, send))
                .await
                .unwrap();
            svc.waiting().await.ok();
        });

        let a = Endpoint::bind(presets::Minimal).await.unwrap();
        let conn = a.connect(b_addr, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let _ = client_handshake(&mut send, &mut recv, secret).await.unwrap();
        let client = ().serve((recv, send)).await.unwrap();

        // внутри scope — видно
        let inside = call(&client, "list_dir", serde_json::json!({"path": dir.path().to_string_lossy()})).await;
        assert!(inside.contains("probe.txt"), "внутри scope должно работать");
        // снаружи scope — отказ
        let outside = call(&client, "list_dir", serde_json::json!({"path": "/etc"})).await;
        assert!(
            outside.contains("scope") || outside.to_lowercase().contains("error"),
            "вне scope должно быть отказано: {outside}"
        );

        client.cancel().await.ok();
        a.close().await;
        b_task.abort();
    }

    /// Удалённая мутация при вето владельца B (No-confirmer) НЕ исполняется.
    #[tokio::test]
    async fn remote_mutation_denied_when_owner_vetoes() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("should_not_exist.txt");
        let secret = "s";

        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b_addr = b.addr();
        let gk = Arc::new(Gatekeeper::new(secret));
        let b_task = tokio::spawn(async move {
            let conn = b.accept().await.unwrap().await.unwrap();
            let remote = conn.remote_id();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
                .await
                .unwrap();
            // владелец B ветирует всё (No); журнал не важен
            let svc = HandsServer::with(Policy::default(), Arc::new(No), Arc::new(NullAudit))
                .serve((recv, send))
                .await
                .unwrap();
            svc.waiting().await.ok();
        });

        let a = Endpoint::bind(presets::Minimal).await.unwrap();
        let conn = a.connect(b_addr, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let _ = client_handshake(&mut send, &mut recv, secret).await.unwrap();
        let client = ().serve((recv, send)).await.unwrap();

        let mut param = CallToolRequestParams::new("write_file");
        param.arguments = serde_json::json!({ "path": target.to_string_lossy(), "content": "x" })
            .as_object()
            .cloned();
        // вызов может вернуть tool-ошибку или is_error — главное, файл НЕ создан
        let _ = client.peer().call_tool(param).await;
        assert!(
            !target.exists(),
            "вето владельца B: удалённая запись не должна была исполниться"
        );

        client.cancel().await.ok();
        a.close().await;
        b_task.abort();
    }
}
