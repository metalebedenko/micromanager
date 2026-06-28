//! In-process MCP-сессия: локальный мозг говорит со своими руками через настоящий
//! rmcp (клиент ↔ `HandsServer` по `tokio::io::duplex`), как удалёнка — но без сети.
//! Тот же safety-гейт/вето/аудит, что и MCP-путь; убирает дублирующий in-process диспатч.

use std::sync::Arc;

use anyhow::Result;
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde_json::Value;

use crate::audit::Audit;
use crate::brain::ToolSpec;
use crate::net::map_tool;
use crate::net::remote::format_result;
use crate::net::runner::McpCaller;
use crate::safety::{Confirmer, Policy};
use crate::server::tools::HandsServer;

/// 5 hands-тулов, которые видит локальный мозг (релей-mm_* фильтруются).
const HANDS_TOOLS: &[&str] = &["list_dir", "read_file", "search", "write_file", "run_shell"];

pub struct LocalMcpSession {
    client: RunningService<RoleClient, ()>,
    server_task: tokio::task::JoinHandle<()>,
}

impl LocalMcpSession {
    /// Поднять in-process MCP-сессию. ВЫЗЫВАТЬ внутри tokio-рантайма (нужен `spawn`).
    pub async fn build(
        policy: Policy,
        confirmer: Arc<dyn Confirmer>,
        audit: Arc<dyn Audit>,
    ) -> Result<Self> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server_io);
        let server = HandsServer::with(policy, confirmer, audit);
        let server_task = tokio::spawn(async move {
            if let Ok(svc) = server.serve((sr, sw)).await {
                let _ = svc.waiting().await;
            }
        });
        let (cr, cw) = tokio::io::split(client_io);
        let client = ().serve((cr, cw)).await?;
        Ok(Self { client, server_task })
    }

    pub async fn call_tool(&self, name: &str, args: Value) -> Result<String> {
        let mut p = CallToolRequestParams::new(name.to_string());
        p.arguments = args.as_object().cloned();
        let r = self.client.peer().call_tool(p).await?;
        Ok(format_result(&r))
    }

    /// Специи ТОЛЬКО hands-тулов (релей-mm_* отфильтрованы) — для tool-calling мозга.
    pub async fn hands_specs(&self) -> Result<Vec<ToolSpec>> {
        let tools = self.client.peer().list_tools(Default::default()).await?.tools;
        Ok(tools
            .iter()
            .filter(|t| HANDS_TOOLS.contains(&t.name.as_ref()))
            .map(map_tool)
            .collect())
    }
}

impl McpCaller for LocalMcpSession {
    async fn call(&self, name: String, args: Value) -> anyhow::Result<String> {
        self.call_tool(&name, args).await
    }
    async fn close(self) {
        let _ = self.client.cancel().await;
        self.server_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Audit, AuditEntry};
    use std::sync::Mutex;

    struct RecAudit(Arc<Mutex<usize>>);
    impl Audit for RecAudit {
        fn record(&self, _e: &AuditEntry) -> std::io::Result<()> {
            *self.0.lock().unwrap() += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn local_session_calls_list_dir_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let n = Arc::new(Mutex::new(0usize));
        let s = LocalMcpSession::build(
            Policy::default(),
            Arc::new(crate::safety::DenyConfirmer),
            Arc::new(RecAudit(n.clone())),
        )
        .await
        .unwrap();
        let out = s
            .call_tool("list_dir", serde_json::json!({"path": dir.path().to_string_lossy()}))
            .await
            .unwrap();
        assert!(out.contains("probe.txt"), "list_dir видит probe.txt: {out}");
        assert!(*n.lock().unwrap() > 0, "аудит получил записи");
        s.close().await;
    }

    #[tokio::test]
    async fn write_file_denied_by_confirmer_not_written() {
        // паритет с прежним прямым диспатчем: мутация под Deny-confirmer не исполняется.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nope.txt");
        let s = LocalMcpSession::build(
            Policy::default(),
            Arc::new(crate::safety::DenyConfirmer),
            Arc::new(crate::audit::NullAudit),
        )
        .await
        .unwrap();
        // При вето сервер возвращает MCP-ошибку (Err) ЛИБО Ok с текстом отказа —
        // в обоих случаях мутация НЕ исполнена. Ключевой инвариант: файл не создан.
        let res = s
            .call_tool(
                "write_file",
                serde_json::json!({"path": target.to_string_lossy(), "content": "x"}),
            )
            .await;
        assert!(!target.exists(), "при вето файл НЕ создан");
        // Ok с текстом отказа ИЛИ Err (MCP-ошибка) — оба корректный отказ (раннер превратит Err в строку).
        if let Ok(out) = res {
            let lo = out.to_lowercase();
            assert!(
                lo.contains("отказ") || lo.contains("deny") || lo.contains("error"),
                "Ok-ответ должен быть отказом: {out}"
            );
        }
        s.close().await;
    }

    #[tokio::test]
    async fn hands_specs_are_exactly_five_no_relay() {
        let s = LocalMcpSession::build(
            Policy::default(),
            Arc::new(crate::safety::DenyConfirmer),
            Arc::new(crate::audit::NullAudit),
        )
        .await
        .unwrap();
        let specs = s.hands_specs().await.unwrap();
        let names: Vec<String> = specs.iter().map(|x| x.function.name.clone()).collect();
        assert_eq!(names.len(), 5, "ровно 5 hands-тулов, got: {names:?}");
        assert!(!names.iter().any(|n| n.starts_with("mm_")), "без релей-тулов: {names:?}");
        for t in HANDS_TOOLS {
            assert!(names.iter().any(|n| n == t), "есть {t}");
        }
        s.close().await;
    }
}
