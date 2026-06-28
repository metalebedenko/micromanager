//! MCP-сервер «руки» (rmcp). Регистрирует тулы и обслуживает MCP-клиента по stdio.

pub mod tools;

use rmcp::{transport::stdio, ServiceExt};

/// Поднять MCP-сервер по stdio и работать до закрытия клиентом.
/// Подключается любой MCP-клиент (локальная LLM или внешний агент).
pub async fn run_stdio() -> anyhow::Result<()> {
    let service = tools::HandsServer::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
