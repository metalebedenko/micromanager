use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SESSION_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseMeta {
    pub controller_id: Option<String>,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireLease {
    pub controller_id: String,
    pub resume_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub controller_id: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineerSessionMeta {
    pub schema: u32,
    pub session_id: String,
    pub peer: String,
    pub invite: String,
    pub controller_resume_token: String,
    pub lease: LeaseMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareSessionMeta {
    pub schema: u32,
    pub session_id: String,
    pub lease: LeaseMeta,
    pub controller_token_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", content = "meta", rename_all = "snake_case")]
pub enum SessionMeta {
    Engineer(EngineerSessionMeta),
    Share(ShareSessionMeta),
}

impl SessionMeta {
    pub fn schema(&self) -> u32 {
        match self {
            Self::Engineer(meta) => meta.schema,
            Self::Share(meta) => meta.schema,
        }
    }

    pub fn session_id(&self) -> &str {
        match self {
            Self::Engineer(meta) => &meta.session_id,
            Self::Share(meta) => &meta.session_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Interrupted,
}

impl OperationState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Interrupted
        )
    }

    fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Running | Self::Cancelled)
                | (
                    Self::Running,
                    Self::Succeeded | Self::Failed | Self::Cancelled | Self::Interrupted
                )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: String,
    #[serde(default)]
    pub request_key: Option<String>,
    pub command: String,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub remote_timeout_ms: u64,
    #[serde(default)]
    pub dispatched: bool,
    pub state: OperationState,
    pub summary: Option<String>,
    pub output: Option<String>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    pub output_truncated: bool,
    pub output_pruned: bool,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub finished_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationCapture {
    pub output: String,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

impl OperationRecord {
    pub fn queued(id: impl Into<String>, command: impl Into<String>, now_unix: u64) -> Self {
        Self {
            id: id.into(),
            request_key: None,
            command: command.into(),
            cwd: None,
            remote_timeout_ms: 0,
            dispatched: false,
            state: OperationState::Queued,
            summary: None,
            output: None,
            stdout: String::new(),
            stderr: String::new(),
            output_truncated: false,
            output_pruned: false,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
            finished_at_unix: None,
        }
    }

    pub fn transition(&mut self, next: OperationState, now_unix: u64) -> Result<(), ProtocolError> {
        if !self.state.can_transition_to(next) {
            return Err(ProtocolError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        self.updated_at_unix = now_unix;
        if next.is_terminal() {
            self.finished_at_unix = Some(now_unix);
        }
        Ok(())
    }

    pub fn finish(
        &mut self,
        terminal: OperationState,
        summary: impl Into<String>,
        output: impl Into<String>,
        now_unix: u64,
    ) -> Result<(), ProtocolError> {
        if !terminal.is_terminal() {
            return Err(ProtocolError::NotTerminal(terminal));
        }
        self.transition(terminal, now_unix)?;
        self.summary = Some(summary.into());
        self.output = Some(output.into());
        Ok(())
    }

    pub fn finish_detailed(
        &mut self,
        terminal: OperationState,
        summary: impl Into<String>,
        capture: OperationCapture,
        now_unix: u64,
    ) -> Result<(), ProtocolError> {
        self.finish(terminal, summary, capture.output, now_unix)?;
        self.stdout = capture.stdout;
        self.stderr = capture.stderr;
        self.output_truncated = capture.truncated;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidTransition {
        from: OperationState,
        to: OperationState,
    },
    NotTerminal(OperationState),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid operation transition {from:?} -> {to:?}")
            }
            Self::NotTerminal(state) => write!(formatter, "{state:?} is not terminal"),
        }
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::{OperationRecord, OperationState, ProtocolError};

    fn queued() -> OperationRecord {
        OperationRecord::queued("op-1", "echo ok", 10)
    }

    #[test]
    fn operation_follows_the_only_valid_happy_path() {
        let mut operation = queued();

        operation.transition(OperationState::Running, 20).unwrap();
        operation
            .finish(OperationState::Succeeded, "ok", "full output", 30)
            .unwrap();

        assert_eq!(operation.state, OperationState::Succeeded);
        assert_eq!(operation.summary.as_deref(), Some("ok"));
        assert_eq!(operation.output.as_deref(), Some("full output"));
        assert_eq!(operation.finished_at_unix, Some(30));
    }

    #[test]
    fn terminal_operation_cannot_be_reopened() {
        let mut operation = queued();
        operation.transition(OperationState::Running, 20).unwrap();
        operation
            .finish(OperationState::Interrupted, "connection lost", "", 30)
            .unwrap();

        let error = operation
            .transition(OperationState::Running, 40)
            .unwrap_err();

        assert_eq!(
            error,
            ProtocolError::InvalidTransition {
                from: OperationState::Interrupted,
                to: OperationState::Running,
            }
        );
    }

    #[test]
    fn interrupted_round_trips_through_json() {
        let mut operation = queued();
        operation.transition(OperationState::Running, 20).unwrap();
        operation
            .finish(OperationState::Interrupted, "restart", "partial", 30)
            .unwrap();

        let json = serde_json::to_vec(&operation).unwrap();
        let restored: OperationRecord = serde_json::from_slice(&json).unwrap();

        assert_eq!(restored, operation);
    }

    #[test]
    fn legacy_operation_without_stream_fields_deserializes() {
        let mut value = serde_json::to_value(queued()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("request_key");
        object.remove("stdout");
        object.remove("stderr");

        let restored: OperationRecord = serde_json::from_value(value).unwrap();

        assert_eq!(restored.request_key, None);
        assert!(restored.stdout.is_empty());
        assert!(restored.stderr.is_empty());
    }
}
