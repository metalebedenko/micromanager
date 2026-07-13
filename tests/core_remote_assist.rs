use std::sync::Arc;
use std::time::Duration;

use micromanager::net::protocol::OperationState;
use micromanager::net::{OperationRequest, SessionController, ShareService};
use micromanager::server::executor::{ExecResult, TerminalObserver};

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

mod core_remote_assist {
    use super::*;

    pub mod share {
        use super::*;

        #[tokio::test]
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

        #[tokio::test]
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
            let resumed = SessionController::resume(&session_dir).await.unwrap();
            let restored = resumed
                .operation_status("controller-acceptance-op-1")
                .await
                .unwrap();

            assert_eq!(restored, completed.record);
            assert_eq!(restored.state, OperationState::Succeeded);
            assert_eq!(std::fs::read_to_string(output).unwrap(), "once\n");
            resumed.disconnect().await.unwrap();
            service.shutdown().await.unwrap();
        }
    }
}
