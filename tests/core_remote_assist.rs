use std::sync::Arc;
use std::time::Duration;

use micromanager::net::protocol::OperationState;
use micromanager::net::{OperationRequest, SessionController, ShareService};
use micromanager::server::executor::{ExecResult, TerminalObserver};
use rmcp::model::CallToolRequestParams;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::ServiceExt;

struct QuietObserver;

impl TerminalObserver for QuietObserver {
    fn started(&self, _: &str) {}
    fn finished(&self, _: &ExecResult) {}
    fn failed(&self, _: &str, _: &str) {}
}

#[cfg(unix)]
fn append_command(path: &std::path::Path) -> String {
    format!("printf 'once\\n' >> '{}'", path.display())
}

#[cfg(windows)]
fn append_command(path: &std::path::Path) -> String {
    let path = path.display().to_string().replace('\'', "''");
    format!("Add-Content -LiteralPath '{path}' -Value 'once'")
}

#[cfg(unix)]
fn stdout_command() -> &'static str {
    "printf 'stdio-ok'"
}

#[cfg(windows)]
fn stdout_command() -> &'static str {
    "Write-Output -NoNewline 'stdio-ok'"
}

async fn resume_after_lock_release(session_dir: &std::path::Path) -> SessionController {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match SessionController::resume(session_dir).await {
                Ok(controller) => break controller,
                Err(micromanager::net::ControllerError::Storage(
                    micromanager::net::session_store::StoreError::Locked,
                )) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => panic!("session resume failed: {error}"),
            }
        }
    })
    .await
    .expect("session store lock must be released after controller drop")
}

mod core_remote_assist {
    use super::*;

    pub mod share {
        use super::*;

        #[tokio::test(flavor = "multi_thread")]
        async fn public_invite_reconnect_and_exactly_once_operation() {
            let state = tempfile::tempdir().unwrap();
            let output = state.path().join("acceptance.txt");
            let service = ShareService::start(state.path(), Arc::new(QuietObserver))
                .await
                .unwrap();
            let invite = service.invitation().to_owned();
            let first = service.connect(&invite).await.unwrap();
            drop(first);
            let reconnected = service.connect(&invite).await.unwrap();
            let operation = OperationRequest {
                session_id: reconnected.session_id().to_owned(),
                operation_id: "acceptance-op-1".into(),
                command: append_command(&output),
                cwd: None,
                timeout: Duration::from_secs(5),
            };

            let completed = reconnected.execute(operation.clone()).await.unwrap();
            let duplicate = reconnected.execute(operation).await.unwrap();

            assert_eq!(completed.record, duplicate.record);
            assert_eq!(completed.record.state, OperationState::Succeeded);
            assert_eq!(
                std::fs::read_to_string(output)
                    .unwrap()
                    .lines()
                    .collect::<Vec<_>>(),
                ["once"]
            );
            service.shutdown().await.unwrap();
            assert!(service.connect(&invite).await.is_err());
        }
    }

    pub mod controller {
        use super::*;

        #[tokio::test(flavor = "multi_thread")]
        async fn public_controller_resumes_durable_session_and_operation_status() {
            let share_state = tempfile::tempdir().unwrap();
            let engineer_state = tempfile::tempdir().unwrap();
            let output = share_state.path().join("controller-acceptance.txt");
            let service = ShareService::start(share_state.path(), Arc::new(QuietObserver))
                .await
                .unwrap();
            let controller =
                SessionController::connect(engineer_state.path(), service.invitation())
                    .await
                    .unwrap();
            let operation = OperationRequest {
                session_id: String::new(),
                operation_id: "controller-acceptance-op-1".into(),
                command: append_command(&output),
                cwd: None,
                timeout: Duration::from_secs(5),
            };

            let completed = controller.execute(operation).await.unwrap();
            let session_dir = controller.session_dir().to_owned();
            drop(controller);
            let resumed = resume_after_lock_release(&session_dir).await;
            let restored = resumed
                .operation_status("controller-acceptance-op-1")
                .await
                .unwrap();

            assert_eq!(restored, completed.record);
            assert_eq!(restored.state, OperationState::Succeeded);
            assert_eq!(
                std::fs::read_to_string(output)
                    .unwrap()
                    .lines()
                    .collect::<Vec<_>>(),
                ["once"]
            );
            resumed.disconnect().await.unwrap();
            service.shutdown().await.unwrap();
        }
    }

    pub mod mcp {
        use super::*;

        async fn call(
            client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
            tool: &str,
            arguments: serde_json::Value,
        ) -> serde_json::Value {
            let mut params = CallToolRequestParams::new(tool.to_owned());
            params.arguments = arguments.as_object().cloned();
            client
                .peer()
                .call_tool(params)
                .await
                .unwrap()
                .structured_content
                .expect("stable tools return object structured content")
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn stable_session_tools_work_through_real_stdio_mcp() {
            let share_state = tempfile::tempdir().unwrap();
            let engineer_state = tempfile::tempdir().unwrap();
            let share = ShareService::start(share_state.path(), Arc::new(QuietObserver))
                .await
                .unwrap();
            let transport = TokioChildProcess::new(
                tokio::process::Command::new(env!("CARGO_BIN_EXE_micromanager")).configure(|cmd| {
                    cmd.arg("serve").env("MM_STATE_DIR", engineer_state.path());
                }),
            )
            .unwrap();
            let client = ().serve(transport).await.unwrap();

            let tools = client.list_all_tools().await.unwrap();
            for name in [
                "session_connect",
                "session_status",
                "session_journal",
                "session_note_append",
                "remote_exec",
                "operation_status",
                "operation_output",
                "session_disconnect",
            ] {
                let tool = tools.iter().find(|tool| tool.name == name).unwrap();
                assert_eq!(tool.input_schema.get("type").and_then(|value| value.as_str()), Some("object"));
                assert_eq!(tool.output_schema.as_ref().and_then(|schema| schema.get("type")).and_then(|value| value.as_str()), Some("object"));
            }

            let connected = call(&client, "session_connect", serde_json::json!({
                "invite": share.invitation(),
            })).await;
            let session_id = connected["session_id"].as_str().unwrap().to_owned();
            assert_eq!(connected["connection"], "connected");

            let executed = call(&client, "remote_exec", serde_json::json!({
                "session_id": session_id,
                "operation_id": "stdio-op-1",
                "command": stdout_command(),
                "timeout_ms": 5000,
            })).await;
            assert_eq!(executed["operation_id"], "op-00000000000000000001");
            assert_eq!(executed["state"], "succeeded");
            let canonical_operation_id = executed["operation_id"].as_str().unwrap();

            let status = call(&client, "operation_status", serde_json::json!({
                "session_id": session_id,
                "operation_id": canonical_operation_id,
            })).await;
            assert_eq!(status["state"], "succeeded");

            let disconnected = call(&client, "session_disconnect", serde_json::json!({
                "session_id": session_id,
            })).await;
            assert_eq!(disconnected["connection"], "disconnected");

            client.cancel().await.unwrap();
            share.shutdown().await.unwrap();
        }
    }
}
