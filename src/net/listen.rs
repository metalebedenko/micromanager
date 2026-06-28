//! Сторона B («управляемый»): поднять iroh-эндпоинт, печатать код-приглашение
//! с одноразовым секретом, на подключение A — рукопожатие (auth) → мост к «рукам».

use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::Endpoint;

use super::auth::{generate_secret, server_handshake, Gatekeeper};
use super::session::{serve_hands, Grant, ReportTo};
use super::{encode_invite, identity, store, Invite, ALPN};

/// `remember=true` (опт-ин `listen --remember`): стабильная личность (персист ключа),
/// персист allowlist и `Invite.remember=true` — друг переподключится после рестарта B
/// без нового кода. `false` — эфемерно, как раньше (дефолт).
pub async fn run_listen(grant: Grant, report: Option<ReportTo>, remember: bool) -> Result<()> {
    let builder = Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()]);
    let builder = if remember {
        // постоянный ключ → стабильный EndpointId между рестартами
        builder.secret_key(identity::load_or_create(&store::identity_path())?)
    } else {
        builder
    };
    let endpoint = builder.bind().await?;
    let addr = endpoint.addr();

    let secret = generate_secret();
    let gatekeeper = Arc::new(
        if remember {
            Gatekeeper::with_persist(secret.clone(), store::allowlist_path())
        } else {
            Gatekeeper::new(secret.clone())
        }
        .with_ttl(super::auth::PAIRING_SECRET_TTL_SECS),
    );
    let invite = Invite { addr, secret, remember };
    if remember {
        eprintln!("[micromanager] --remember: помню этого друга после рестарта (allowlist+ключ персистятся); отозвать — `micromanager forget`.");
    }

    println!("=== micromanager: руки доступны по iroh ===");
    println!(
        "Код-приглашение (передай оркестратору A; одноразовый):\n{}",
        encode_invite(&invite)
    );
    // показать владельцу, что именно он выдаёт
    let scope = if grant.policy.allowed_paths.is_empty() {
        "весь диск".to_string()
    } else {
        format!("{:?}", grant.policy.allowed_paths)
    };
    let shell = if grant.policy.allow_shell { "разрешены" } else { "ЗАПРЕЩЕНЫ" };
    let ttl = grant
        .ttl
        .map(|d| format!("{}s", d.as_secs()))
        .unwrap_or_else(|| "без лимита".to_string());
    let danger = if grant.policy.allow_dangerous {
        " ‼ ОПАСНЫЕ команды РАЗРЕШЕНЫ (каждая — с громким подтверждением)"
    } else {
        ""
    };
    eprintln!("[micromanager] ГРАНТ: пути={scope}, команды {shell}, TTL={ttl}.{danger}");
    eprintln!("[micromanager] B слушает. Пускаю только предъявившего секрет; дальше — по allowlist. Ctrl-C чтобы остановить.");

    if report.is_some() {
        eprintln!("[micromanager] отчёты о действиях дублируются в Telegram владельца.");
    }
    while let Some(incoming) = endpoint.accept().await {
        let gk = gatekeeper.clone();
        let grant = grant.clone();
        let report = report.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(incoming, gk, grant, report).await {
                eprintln!("[micromanager] сессия завершена: {e}");
            }
        });
    }
    Ok(())
}

async fn handle(
    incoming: iroh::endpoint::Incoming,
    gk: Arc<Gatekeeper>,
    grant: Grant,
    report: Option<ReportTo>,
) -> Result<()> {
    let conn = incoming.await?;
    let remote = conn.remote_id();
    let (mut send, mut recv) = conn.accept_bi().await?;

    let summary = crate::net::GrantSummary {
        allowed_paths: grant.policy.allowed_paths.iter().map(|p| p.display().to_string()).collect(),
        allow_shell: grant.policy.allow_shell,
        allow_dangerous: grant.policy.allow_dangerous,
        ttl_secs: grant.ttl.map(|d| d.as_secs()),
    };
    if !server_handshake(&mut recv, &mut send, &gk, remote, &summary).await? {
        eprintln!("[micromanager] ОТКАЗ: неавторизованный узел {remote} (неверный секрет / не в allowlist)");
        return Ok(());
    }
    eprintln!("[micromanager] авторизован {remote} — отдаю руки под вето владельца. Действия — ниже; Ctrl-C чтобы оборвать всё.");

    serve_hands(recv, send, format!("{remote}"), grant, report).await?;
    eprintln!("[micromanager] {remote} отключился");
    Ok(())
}
