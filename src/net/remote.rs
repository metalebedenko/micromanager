//! Постоянная удалённая сессия к B (rmcp-клиент поверх iroh). Переиспользуется
//! CLI `connect` и Telegram-фронтом: дозвон по коду + вызовы тулов B.

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde_json::Value;

use super::auth::{client_handshake, HandshakeOutcome, PROTOCOL_VERSION};
use super::{decode_invite, identity, peers, store, GrantSummary, ALPN};
use crate::net::runner::McpCaller;

pub(crate) fn short_id(node_id: &iroh::EndpointId) -> String {
    node_id.to_string().chars().take(12).collect()
}

/// Связать A-эндпоинт. `persistent=true` (remember-флоу) — со стабильным ключом из
/// `identity.json` (B запомнит наш id); иначе эфемерный, как при одноразовом коннекте.
async fn bind_endpoint(persistent: bool) -> Result<Endpoint> {
    let builder = Endpoint::builder(presets::N0);
    let builder = if persistent {
        builder.secret_key(identity::load_or_create(&store::identity_path())?)
    } else {
        builder
    };
    Ok(builder.bind().await?)
}

/// Живое соединение A→B: держит iroh-эндпоинт и MCP-клиента к рукам B.
pub struct McpSession {
    endpoint: Endpoint,
    client: RunningService<RoleClient, ()>,
    grant: GrantSummary,
    host_label: String,
}

impl McpSession {
    /// Дозвониться до B по коду-приглашению: iroh-connect → рукопожатие (секрет) → MCP-клиент.
    /// Если `Invite.remember` — A использует СТАБИЛЬНУЮ личность (чтобы B её запомнил) и
    /// сохраняет B в `peers.json` (для `connect --resume` без нового кода).
    pub async fn connect(invite: &str) -> Result<Self> {
        let inv = decode_invite(invite)?;
        let endpoint = bind_endpoint(inv.remember).await?;
        let session = Self::dial(endpoint, inv.addr.clone(), &inv.secret).await?;
        if inv.remember {
            peers::remember(&store::peers_path(), inv.addr.clone(), session.host_label.clone());
        }
        Ok(session)
    }

    /// Реконнект к ЗАПОМНЕННОМУ B (опт-ин персист): дозвон по сохранённому адресу
    /// с ПУСТЫМ секретом, СТАБИЛЬНОЙ личностью. B пускает по allowlist (Gatekeeper
    /// проверяет allowlist первым). Не в allowlist (доступ отозван/B не помнил) → отказ.
    pub async fn reconnect(addr: EndpointAddr) -> Result<Self> {
        let endpoint = bind_endpoint(true).await?;
        Self::dial(endpoint, addr, "").await
    }

    /// `connect --resume [--host P]`: выбрать запомненного B и переподключиться.
    /// Выбор (resolve) — чистый; единственный сетевой шаг — reconnect. chooser инъецируется
    /// (прод — stdin-меню; тест — стаб). После успеха — touch (свежесть для сортировки меню).
    pub async fn resume(
        who: Option<&str>,
        chooser: impl FnOnce(&[peers::KnownPeer]) -> Option<usize>,
    ) -> Result<Self> {
        let path = store::peers_path();
        match peers::resolve(&peers::list_recent(&path), who, chooser) {
            peers::Resolved::Empty => anyhow::bail!(
                "нет запомненного B (или нет совпадений с --host) — сначала `connect <код>` к узлу с `listen --remember`"
            ),
            peers::Resolved::Cancelled => anyhow::bail!("выбор хоста отменён"),
            peers::Resolved::Chosen(p) => {
                let session = Self::reconnect(p.addr.clone()).await?;
                peers::touch(&path, &p.addr.id);
                Ok(session)
            }
        }
    }

    /// Общий путь connect/reconnect: iroh-connect → рукопожатие → MCP-клиент.
    async fn dial(endpoint: Endpoint, addr: EndpointAddr, secret: &str) -> Result<Self> {
        let conn = endpoint.connect(addr, ALPN).await?;
        let host_label = short_id(&conn.remote_id());
        let (mut send, mut recv) = conn.open_bi().await?;
        let grant = match client_handshake(&mut send, &mut recv, secret).await? {
            HandshakeOutcome::Ok(g) => g,
            HandshakeOutcome::VersionMismatch { peer } => anyhow::bail!(
                "версии протокола несовместимы: вы v{}, B v{peer} — обновите micromanager на обеих сторонах",
                PROTOCOL_VERSION
            ),
            HandshakeOutcome::Rejected => anyhow::bail!(
                "B отклонил подключение: неверный код / доступ отозван / несовместимая версия — получи новый код-приглашение"
            ),
        };
        let client = ().serve((recv, send)).await?;
        Ok(Self { endpoint, client, grant, host_label })
    }

    pub fn grant(&self) -> &GrantSummary { &self.grant }
    pub fn host_label(&self) -> &str { &self.host_label }

    /// Имена тулов, которые предоставляет B.
    pub async fn list_tool_names(&self) -> Result<Vec<String>> {
        let t = self.client.peer().list_tools(Default::default()).await?;
        Ok(t.tools.iter().map(|t| t.name.to_string()).collect())
    }

    /// Вызвать тул B по сети; вернуть человекочитаемый текст результата.
    pub async fn call_tool(&self, name: &str, args: Value) -> Result<String> {
        let mut p = CallToolRequestParams::new(name.to_string());
        p.arguments = args.as_object().cloned();
        let r = self.client.peer().call_tool(p).await?;
        Ok(format_result(&r))
    }

    /// Корректно закрыть сессию.
    pub async fn close(self) {
        let _ = self.client.cancel().await;
        self.endpoint.close().await;
    }

    /// Полные описания тулов B (для построения tool-specs мозга A).
    pub async fn list_tools_full(&self) -> Result<Vec<rmcp::model::Tool>> {
        Ok(self.client.peer().list_tools(Default::default()).await?.tools)
    }
}

impl McpCaller for McpSession {
    async fn call(&self, name: String, args: Value) -> anyhow::Result<String> {
        self.call_tool(&name, args).await
    }

    async fn close(self) {
        McpSession::close(self).await
    }
}

/// Тест-сеем: поднять loopback-сессию A→B (Minimal preset, оффлайн) с `probe.txt`
/// в директории B. Возвращает живую `McpSession` + хэндл B-задачи + tempdir.
/// Даёт hand-built сессию в обход сетевого `connect` (N0, не тестируется оффлайн) —
/// используется релей-тестами `server::tools` (тест-сеем сессии в обход сети).
#[cfg(test)]
pub(crate) async fn loopback_session_with_probe(
) -> (McpSession, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    // Read-only probe: confirmer не вызывается (list_dir/list_tools — Allow).
    loopback_session_with_confirmer(std::sync::Arc::new(
        crate::safety::StdinConfirmer::default(),
    ))
    .await
}

/// Как `loopback_session_with_probe`, но B-сторона использует заданный `confirmer` —
/// чтобы тестировать вето владельца B через релей (мутация на B под No-confirmer).
/// B поднимается как сетевой узел (`with` → relay_enabled=false, NullAudit — без побочного файла).
#[cfg(test)]
pub(crate) async fn loopback_session_with_confirmer(
    confirmer: std::sync::Arc<dyn crate::safety::Confirmer>,
) -> (McpSession, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    use super::auth::{server_handshake, Gatekeeper};
    use super::{encode_invite, Invite};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
    let secret = "s";

    let b = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let invite = encode_invite(&Invite {
        addr: b.addr(),
        secret: secret.to_string(),
        remember: false,
    });
    let gk = Arc::new(Gatekeeper::new(secret));
    let b_task = tokio::spawn(async move {
        let conn = b.accept().await.unwrap().await.unwrap();
        let remote = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
            .await
            .unwrap();
        crate::server::tools::HandsServer::with(
            crate::safety::Policy::default(),
            confirmer,
            Arc::new(crate::audit::NullAudit),
        )
        .serve((recv, send))
        .await
        .unwrap()
        .waiting()
        .await
        .ok();
    });

    let a = Endpoint::bind(presets::Minimal).await.unwrap();
    let inv = decode_invite(&invite).unwrap();
    let conn = a.connect(inv.addr, ALPN).await.unwrap();
    let host_label = short_id(&conn.remote_id());
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let grant = match client_handshake(&mut send, &mut recv, &inv.secret).await.unwrap() {
        HandshakeOutcome::Ok(g) => g,
        _ => panic!("loopback handshake должен дать Ok"),
    };
    let client = ().serve((recv, send)).await.unwrap();
    (
        McpSession {
            endpoint: a,
            client,
            grant,
            host_label,
        },
        b_task,
        dir,
    )
}

pub(crate) fn format_result(r: &CallToolResult) -> String {
    if let Some(sc) = &r.structured_content {
        return serde_json::to_string(sc).unwrap_or_default();
    }
    serde_json::to_string(&r.content).unwrap_or_else(|_| format!("{r:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::auth::{server_handshake, Gatekeeper};
    use crate::net::{encode_invite, Invite};
    use crate::server::tools::HandsServer;
    use iroh::endpoint::presets;
    use std::sync::Arc;

    /// Loopback NL-over-remote: мок-мозг вызывает list_dir через McpToolRunner → McpSession → B в процессе.
    #[tokio::test(flavor = "multi_thread")]
    async fn nl_over_remote_loopback() {
        // Та же подготовка B, что в remote_session_calls_b_tool
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let secret = "s";

        let b = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![crate::net::ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let invite = encode_invite(&Invite {
            addr: b.addr(),
            secret: secret.to_string(),
            remember: false,
        });
        let gk = std::sync::Arc::new(crate::net::auth::Gatekeeper::new(secret));
        let b_task = tokio::spawn(async move {
            let conn = b.accept().await.unwrap().await.unwrap();
            let remote = conn.remote_id();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            crate::net::auth::server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
                .await
                .unwrap();
            crate::server::tools::HandsServer::new()
                .serve((recv, send))
                .await
                .unwrap()
                .waiting()
                .await
                .ok();
        });

        // A: подключиться как в remote_session_calls_b_tool (Minimal preset вручную)
        let a = iroh::Endpoint::bind(iroh::endpoint::presets::Minimal).await.unwrap();
        let inv = crate::net::decode_invite(&invite).unwrap();
        let conn = a.connect(inv.addr, crate::net::ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        assert!(matches!(crate::net::auth::client_handshake(&mut send, &mut recv, &inv.secret).await.unwrap(), crate::net::auth::HandshakeOutcome::Ok(_)));
        let client_svc = rmcp::ServiceExt::serve((), (recv, send)).await.unwrap();
        let session = McpSession { endpoint: a, client: client_svc, grant: Default::default(), host_label: "test".into() };

        // Получить specs живьём с B
        let tools = session.list_tools_full().await.unwrap();
        let specs: Vec<_> = tools.iter().map(crate::net::runner::map_tool).collect();
        assert!(specs.iter().any(|s| s.function.name == "list_dir"), "list_dir должен быть в specs");

        // Мок-мозг: ход 1 → tool_call list_dir(probe-dir), ход 2 → финал "готово"
        use crate::brain::{Brain, FunctionCall, Message, ToolCall, ToolSpec};
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        struct MockBrain { step: AtomicUsize, probe_path: String }
        impl Brain for MockBrain {
            fn chat(&self, _msgs: &[Message], _tools: &[ToolSpec]) -> anyhow::Result<Message> {
                let s = self.step.fetch_add(1, Ordering::SeqCst);
                if s == 0 {
                    // вернуть tool_call list_dir
                    Ok(Message {
                        role: "assistant".into(),
                        content: String::new(),
                        tool_name: None,
                        tool_call_id: None,
                        tool_calls: Some(vec![ToolCall {
                            id: Some("call_1".into()),
                            function: FunctionCall {
                                name: "list_dir".into(),
                                arguments: serde_json::json!({ "path": self.probe_path }),
                            },
                        }]),
                    })
                } else {
                    Ok(Message {
                        role: "assistant".into(),
                        content: "готово".into(),
                        tool_name: None,
                        tool_call_id: None,
                        tool_calls: None,
                    })
                }
            }
        }

        let probe_path = dir.path().to_string_lossy().to_string();
        let brain = MockBrain { step: AtomicUsize::new(0), probe_path };
        let runner = crate::net::McpToolRunner::start(session, specs);
        let h = runner.handle();

        // run_agent_with — sync, запускаем в spawn_blocking чтобы не блокировать tokio worker
        let (ans, msgs) = tokio::task::spawn_blocking(move || {
            let mut msgs = crate::brain::new_conversation();
            msgs.push(Message::user("покажи файлы"));
            let ans = crate::brain::run_agent_with(&brain, &h, &mut msgs, &std::sync::atomic::AtomicBool::new(false))?;
            Ok::<_, anyhow::Error>((ans, msgs))
        }).await.unwrap().unwrap();

        assert!(ans.contains("готово") || ans.contains("probe.txt"), "ответ: {ans}");
        // доказываем, что удалённый list_dir реально отработал: в истории есть tool-сообщение с probe.txt
        assert!(
            msgs.iter().any(|m| m.role == "tool" && m.content.contains("probe.txt")),
            "ожидали tool-результат с probe.txt в истории, got: {msgs:?}"
        );

        runner.shutdown();
        b_task.abort();
    }

    /// Реконнект через персист-allowlist: A заранее в allowlist B → дозвон с ПУСТЫМ
    /// секретом → B пускает по allowlist → list_dir работает. (Проверяет механизм
    /// пустого-секрет-реконнекта; сам `McpSession::reconnect` — N0, живая приёмка.)
    #[tokio::test]
    async fn reconnect_via_persisted_allowlist_empty_secret() {
        use crate::net::auth::{client_handshake, server_handshake, Gatekeeper, HandshakeOutcome};
        use crate::net::ALPN;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let allow_path = dir.path().join("allowlist.json");

        // A-эндпоинт первым — нужен его id, чтобы предзаписать в allowlist B.
        let a = Endpoint::bind(presets::Minimal).await.unwrap();
        let a_id = a.addr().id;
        let set: std::collections::HashSet<_> = std::iter::once(a_id).collect();
        crate::net::allowlist::save(&allow_path, &set);

        // B с персистом: грузит A из файла; секрет НОВЫЙ (как после рестарта).
        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b_addr = b.addr();
        let gk = Arc::new(Gatekeeper::with_persist("fresh-secret", allow_path));
        let b_task = tokio::spawn(async move {
            let conn = b.accept().await.unwrap().await.unwrap();
            let remote = conn.remote_id();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
                .await
                .unwrap();
            HandsServer::new()
                .serve((recv, send))
                .await
                .unwrap()
                .waiting()
                .await
                .ok();
        });

        // A дозванивается с ПУСТЫМ секретом.
        let conn = a.connect(b_addr, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        assert!(
            matches!(
                client_handshake(&mut send, &mut recv, "").await.unwrap(),
                HandshakeOutcome::Ok(_)
            ),
            "пустой секрет + id в allowlist → OK"
        );
        let client = ().serve((recv, send)).await.unwrap();
        let session = McpSession {
            endpoint: a,
            client,
            grant: Default::default(),
            host_label: "test".into(),
        };
        let out = session
            .call_tool("list_dir", serde_json::json!({ "path": dir.path().to_string_lossy() }))
            .await
            .unwrap();
        assert!(out.contains("probe.txt"), "реконнект-A получил руки B: {out}");

        session.close().await;
        b_task.abort();
    }

    /// Loopback: A через McpSession вызывает list_dir у B.
    #[tokio::test]
    async fn remote_session_calls_b_tool() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let secret = "s";

        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let invite = encode_invite(&Invite {
            addr: b.addr(),
            secret: secret.to_string(),
            remember: false,
        });
        let gk = Arc::new(Gatekeeper::new(secret));
        let b_task = tokio::spawn(async move {
            let conn = b.accept().await.unwrap().await.unwrap();
            let remote = conn.remote_id();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
                .await
                .unwrap();
            HandsServer::new()
                .serve((recv, send))
                .await
                .unwrap()
                .waiting()
                .await
                .ok();
        });

        // A: connect через McpSession (Minimal preset для оффлайн-loopback в тесте).
        // McpSession::connect использует preset N0; для теста соберём вручную аналог:
        let a = Endpoint::bind(presets::Minimal).await.unwrap();
        let inv = decode_invite(&invite).unwrap();
        let conn = a.connect(inv.addr, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        assert!(matches!(client_handshake(&mut send, &mut recv, &inv.secret).await.unwrap(), HandshakeOutcome::Ok(_)));
        let client = ().serve((recv, send)).await.unwrap();
        let session = McpSession {
            endpoint: a,
            client,
            grant: Default::default(),
            host_label: "test".into(),
        };

        let out = session
            .call_tool(
                "list_dir",
                serde_json::json!({ "path": dir.path().to_string_lossy() }),
            )
            .await
            .unwrap();
        assert!(out.contains("probe.txt"), "got: {out}");

        session.close().await;
        b_task.abort();
    }
}
