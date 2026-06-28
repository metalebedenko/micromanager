//! Фоновая серверная задача экрана «поделиться своим ПК»: поднять iroh-эндпоинт,
//! принимать друзей A, мост к «рукам» под вето владельца. В отличие от headless
//! `listen`, поток действий A и запрос вето идут в TUI-каналы (`ChannelConfirmer`/
//! `ChannelAudit`), а не в stdout/stdin. Safety-ядро не трогается — общий `serve_hands_with`.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::Endpoint;

use crate::audit::{Audit, FileAudit};
use crate::net::auth::{generate_secret, server_handshake};
use crate::net::session::serve_hands_with;
use crate::net::{
    encode_invite, identity, short_id, store, Gatekeeper, Grant, GrantSummary, Invite, ALPN,
};
use crate::safety::Confirmer;
use crate::tui::bridge::{ChannelAudit, ChannelConfirmer, DualAudit};
use crate::tui::event::AppEvent;

/// Поднять шеринг: эмитит `ShareInvite` с кодом, принимает A до сигнала `stop`.
/// `remember` (опт-ин) → стабильная личность + персист allowlist (как `listen --remember`).
/// `confirm_timeout` — TTL вето в TUI (нет ответа → fail-closed deny).
pub async fn run_share(
    grant: Grant,
    remember: bool,
    tx: std::sync::mpsc::Sender<AppEvent>,
    confirm_timeout: Duration,
    stop: tokio::sync::oneshot::Receiver<()>,
) {
    // Прод: реальная сеть (N0) + опц. стабильная личность для `remember`.
    let builder = Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()]);
    let builder = if remember {
        let key = match identity::load_or_create(&store::identity_path()) {
            Ok(k) => k,
            Err(e) => {
                let _ = tx.send(AppEvent::ShareError(format!("identity: {e}")));
                return;
            }
        };
        builder.secret_key(key)
    } else {
        builder
    };
    let endpoint = match builder.bind().await {
        Ok(e) => e,
        Err(e) => {
            let _ = tx.send(AppEvent::ShareError(format!("bind: {e}")));
            return;
        }
    };
    let secret = generate_secret();
    let gatekeeper = Arc::new(
        if remember {
            Gatekeeper::with_persist(secret.clone(), store::allowlist_path())
        } else {
            Gatekeeper::new(secret.clone())
        }
        .with_ttl(crate::net::auth::PAIRING_SECRET_TTL_SECS),
    );
    run_share_loop(endpoint, secret, remember, gatekeeper, grant, tx, confirm_timeout, stop).await;
}

/// Ядро шеринга поверх готового эндпоинта (preset выбирает caller: прод N0 /
/// тест Minimal): эмитит код-приглашение, accept-loop против `stop`, каждого A —
/// в `handle_peer`. Эндпоинт закрывается на стопе.
#[allow(clippy::too_many_arguments)]
async fn run_share_loop(
    endpoint: Endpoint,
    secret: String,
    remember: bool,
    gatekeeper: Arc<Gatekeeper>,
    grant: Grant,
    tx: std::sync::mpsc::Sender<AppEvent>,
    confirm_timeout: Duration,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let summary = GrantSummary {
        allowed_paths: grant
            .policy
            .allowed_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        allow_shell: grant.policy.allow_shell,
        allow_dangerous: grant.policy.allow_dangerous,
        ttl_secs: grant.ttl.map(|d| d.as_secs()),
    };
    let invite = Invite {
        addr: endpoint.addr(),
        secret,
        remember,
    };
    let _ = tx.send(AppEvent::ShareInvite(encode_invite(&invite)));

    loop {
        tokio::select! {
            _ = &mut stop => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let gk = gatekeeper.clone();
                let grant = grant.clone();
                let tx = tx.clone();
                let summary = summary.clone();
                tokio::spawn(async move {
                    let _ = handle_peer(incoming, gk, grant, tx, summary, confirm_timeout).await;
                });
            }
        }
    }
    endpoint.close().await;
    let _ = tx.send(AppEvent::ShareStopped);
}

/// Обслужить одного A: рукопожатие → `serve_hands_with` с канальными вето/аудитом.
/// Поток действий помечается `A→`; вето идёт в модалку TUI (`ChannelConfirmer`).
/// Аудит fail-closed на primary `FileAudit`; панель (best-effort) — secondary.
async fn handle_peer(
    incoming: iroh::endpoint::Incoming,
    gk: Arc<Gatekeeper>,
    grant: Grant,
    tx: std::sync::mpsc::Sender<AppEvent>,
    summary: GrantSummary,
    confirm_timeout: Duration,
) -> anyhow::Result<()> {
    let conn = incoming.await?;
    let remote = conn.remote_id();
    let label = short_id(&remote);
    let (mut send, mut recv) = conn.accept_bi().await?;
    if !server_handshake(&mut recv, &mut send, &gk, remote, &summary).await? {
        // неавторизован (неверный секрет / не в allowlist) — молча закрыть
        return Ok(());
    }
    let _ = tx.send(AppEvent::SharePeerConnected(label.clone()));

    let confirmer: Arc<dyn Confirmer> = Arc::new(ChannelConfirmer::new(tx.clone(), confirm_timeout));
    let audit: Arc<dyn Audit> = Arc::new(DualAudit::new(
        Box::new(FileAudit::new(crate::audit::default_path())),
        Box::new(ChannelAudit::labeled(tx.clone(), "A→ ")),
    ));
    let res = serve_hands_with(recv, send, label.clone(), grant, confirmer, audit).await;
    let _ = tx.send(AppEvent::SharePeerGone(label));
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::event::AppEvent;
    use std::time::Duration;

    // multi_thread: тест блокируется на std-mpsc `rx.recv()`, а `run_share_loop` —
    // спавненная задача; на current_thread они бы взаимно заблокировались.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_share_emits_invite_and_peer_then_stops() {
        let (tx, rx) = std::sync::mpsc::channel::<AppEvent>();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let grant = crate::tui::settings::Settings::default().to_grant();
        // Тест поднимает Minimal-эндпоинт (оффлайн loopback), как в net-тестах;
        // прод-`run_share` сделал бы то же на N0.
        let secret = "s".to_string();
        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let gk = Arc::new(Gatekeeper::new(secret.clone()));
        let task = tokio::spawn(run_share_loop(
            b,
            secret,
            false,
            gk,
            grant,
            tx,
            Duration::from_secs(5),
            stop_rx,
        ));

        // дождаться кода-приглашения
        let code = loop {
            match rx.recv().unwrap() {
                AppEvent::ShareInvite(c) => break c,
                AppEvent::ShareError(e) => panic!("bind error: {e}"),
                _ => {}
            }
        };

        // A подключается по коду (Minimal-эндпоинт, как в loopback-тестах net).
        let inv = crate::net::decode_invite(&code).unwrap();
        let a = Endpoint::bind(presets::Minimal).await.unwrap();
        let conn = a.connect(inv.addr, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let _ = crate::net::auth::client_handshake(&mut send, &mut recv, &inv.secret)
            .await
            .unwrap();
        let _client = rmcp::ServiceExt::serve((), (recv, send)).await.unwrap();

        // должен прийти SharePeerConnected
        let mut saw_peer = false;
        for _ in 0..50 {
            if let Ok(AppEvent::SharePeerConnected(_)) = rx.recv_timeout(Duration::from_millis(200))
            {
                saw_peer = true;
                break;
            }
        }
        assert!(saw_peer, "ожидался SharePeerConnected");

        // стоп → ShareStopped
        stop_tx.send(()).unwrap();
        let mut saw_stop = false;
        for _ in 0..50 {
            if let Ok(AppEvent::ShareStopped) = rx.recv_timeout(Duration::from_millis(200)) {
                saw_stop = true;
                break;
            }
        }
        assert!(saw_stop, "ожидался ShareStopped");
        a.close().await;
        task.await.ok();
    }
}
