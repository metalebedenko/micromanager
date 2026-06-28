//! Сторона A («оркестратор»): по коду дозвониться до B, пройти рукопожатие (секрет),
//! затем говорить MCP (rmcp-клиент) и вызвать руки B. Milestone 1-2.

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::Endpoint;
use rmcp::model::CallToolRequestParams;
use rmcp::ServiceExt;

use super::auth::{client_handshake, HandshakeOutcome, PROTOCOL_VERSION};
use super::{decode_invite, ALPN};

pub async fn run_connect(ticket: &str, path: &str) -> Result<()> {
    let invite = decode_invite(ticket)?;
    let endpoint = Endpoint::bind(presets::N0).await?;

    eprintln!("[micromanager] дозваниваюсь до B {} по iroh…", invite.addr.id);
    let conn = endpoint.connect(invite.addr, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    // рукопожатие: предъявить одноразовый секрет, проверить версии
    match client_handshake(&mut send, &mut recv, &invite.secret).await? {
        HandshakeOutcome::Ok(_) => {}
        HandshakeOutcome::VersionMismatch { peer } => anyhow::bail!(
            "версии протокола несовместимы: вы v{}, B v{peer} — обновите micromanager на обеих сторонах",
            PROTOCOL_VERSION
        ),
        HandshakeOutcome::Rejected => anyhow::bail!(
            "B отклонил подключение: неверный код, либо несовместимо старая версия B — обновите обе стороны"
        ),
    }
    eprintln!("[micromanager] авторизован у B, открываю MCP");

    // мост: rmcp-клиент поверх iroh-потока
    let client = ().serve((recv, send)).await?;

    let tools = client.peer().list_tools(Default::default()).await?;
    let names: Vec<_> = tools.tools.iter().map(|t| t.name.as_ref()).collect();
    println!("Руки B предоставляют тулы: {names:?}");

    let args = serde_json::json!({ "path": path });
    let mut param = CallToolRequestParams::new("list_dir");
    param.arguments = args.as_object().cloned();
    let result = client.peer().call_tool(param).await?;
    println!("list_dir(\"{path}\") у B →\n{result:#?}");

    client.cancel().await?;
    endpoint.close().await;
    Ok(())
}
