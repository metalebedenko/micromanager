use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;

use super::protocol::ProtocolError;
pub use super::protocol::{
    EngineerSessionMeta, LeaseMeta, OperationRecord, OperationState, SessionMeta, ShareSessionMeta,
    SESSION_SCHEMA,
};
use super::store::write_private;

pub const MAX_QUEUED_OPERATIONS: usize = 100;
pub const MAX_OPERATION_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_SESSION_OUTPUT_BYTES: usize = 50 * 1024 * 1024;

#[derive(Debug)]
pub enum StoreError {
    Corrupt { path: PathBuf, message: String },
    UnsupportedSchema(u64),
    Locked,
    Unavailable { path: PathBuf, message: String },
    AlreadyExists(PathBuf),
    Duplicate(Box<OperationRecord>),
    QueueFull,
    OperationNotFound(String),
    InvalidTransition(ProtocolError),
    RoleMismatch,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt { path, message } => {
                write!(
                    formatter,
                    "corrupt session store at {}: {message}",
                    path.display()
                )
            }
            Self::UnsupportedSchema(schema) => write!(formatter, "unsupported schema {schema}"),
            Self::Locked => formatter.write_str("session store is locked by another process"),
            Self::Unavailable { path, message } => {
                write!(
                    formatter,
                    "session store unavailable at {}: {message}",
                    path.display()
                )
            }
            Self::AlreadyExists(path) => {
                write!(
                    formatter,
                    "session store already exists at {}",
                    path.display()
                )
            }
            Self::Duplicate(record) => write!(formatter, "duplicate operation {}", record.id),
            Self::QueueFull => formatter.write_str("operation queue is full"),
            Self::OperationNotFound(id) => write!(formatter, "operation {id} not found"),
            Self::InvalidTransition(error) => error.fmt(formatter),
            Self::RoleMismatch => formatter.write_str("session metadata role or id does not match"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ProtocolError> for StoreError {
    fn from(value: ProtocolError) -> Self {
        Self::InvalidTransition(value)
    }
}

#[derive(Debug, Default)]
struct StoreState {
    operations: HashMap<String, OperationRecord>,
    output_bytes: usize,
    failure: Option<String>,
}

#[derive(Debug)]
pub struct SessionStore {
    dir: PathBuf,
    meta_path: PathBuf,
    _lock: File,
    state: Mutex<StoreState>,
}

impl SessionStore {
    pub fn create_engineer(dir: &Path, meta: EngineerSessionMeta) -> Result<Self, StoreError> {
        Self::create_with_meta(dir, SessionMeta::Engineer(meta))
    }

    pub fn create_share(dir: &Path, meta: ShareSessionMeta) -> Result<Self, StoreError> {
        Self::create_with_meta(dir, SessionMeta::Share(meta))
    }

    fn create_with_meta(dir: &Path, meta: SessionMeta) -> Result<Self, StoreError> {
        validate_meta(&meta, dir)?;
        ensure_private_dir(dir)?;
        let lock = acquire_lock(dir)?;
        let engineer_path = dir.join("engineer-meta.json");
        let share_path = dir.join("share-meta.json");
        if engineer_path.exists() || share_path.exists() {
            read_meta(dir)?;
            return Err(StoreError::AlreadyExists(dir.to_path_buf()));
        }
        let meta_path = meta_path(dir, &meta);
        let bytes = serde_json::to_vec(&meta).map_err(|error| StoreError::Corrupt {
            path: meta_path.clone(),
            message: error.to_string(),
        })?;
        write_private(&meta_path, &bytes).map_err(|error| unavailable(&meta_path, error))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            meta_path,
            _lock: lock,
            state: Mutex::new(StoreState::default()),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        if !dir.is_dir() {
            return Err(StoreError::Unavailable {
                path: dir.to_path_buf(),
                message: "session directory does not exist".into(),
            });
        }
        let lock = acquire_lock(dir)?;
        let (meta_path, meta) = read_meta(dir)?;
        validate_meta(&meta, dir)?;
        let state = load_ledger(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            meta_path,
            _lock: lock,
            state: Mutex::new(state),
        })
    }

    pub fn load_meta(&self) -> Result<SessionMeta, StoreError> {
        let (_, meta) = read_meta(&self.dir)?;
        Ok(meta)
    }

    pub fn save_meta(&self, meta: &SessionMeta) -> Result<(), StoreError> {
        let mut state = self.lock_state()?;
        ensure_writable(&state, &self.dir)?;
        validate_meta(meta, &self.dir)?;
        if meta_path(&self.dir, meta) != self.meta_path {
            return Err(StoreError::RoleMismatch);
        }
        let bytes = serde_json::to_vec(meta).map_err(|error| StoreError::Corrupt {
            path: self.meta_path.clone(),
            message: error.to_string(),
        })?;
        if let Err(error) = write_private(&self.meta_path, &bytes) {
            let error = unavailable(&self.meta_path, error);
            state.failure = Some(error.to_string());
            return Err(error);
        }
        Ok(())
    }

    pub fn begin_operation(&self, id: &str, command: &str) -> Result<OperationRecord, StoreError> {
        let mut state = self.lock_state()?;
        ensure_writable(&state, &self.dir)?;
        if let Some(existing) = state.operations.get(id) {
            return Err(StoreError::Duplicate(Box::new(existing.clone())));
        }
        let queued = state
            .operations
            .values()
            .filter(|record| record.state == OperationState::Queued)
            .count();
        if queued >= MAX_QUEUED_OPERATIONS {
            return Err(StoreError::QueueFull);
        }
        let record = OperationRecord::queued(id, command, now_unix());
        self.append_or_poison(&mut state, &record)?;
        state.operations.insert(id.to_owned(), record.clone());
        Ok(record)
    }

    pub fn mark_running(&self, id: &str) -> Result<OperationRecord, StoreError> {
        let mut state = self.lock_state()?;
        ensure_writable(&state, &self.dir)?;
        self.prune_outputs(
            &mut state,
            MAX_SESSION_OUTPUT_BYTES - MAX_OPERATION_OUTPUT_BYTES,
        )?;
        let mut record = state
            .operations
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::OperationNotFound(id.to_owned()))?;
        record.transition(OperationState::Running, now_unix())?;
        self.append_or_poison(&mut state, &record)?;
        state.operations.insert(id.to_owned(), record.clone());
        Ok(record)
    }

    pub fn finish_operation(
        &self,
        id: &str,
        terminal: OperationState,
        summary: &str,
        output: &str,
    ) -> Result<OperationRecord, StoreError> {
        let mut state = self.lock_state()?;
        ensure_writable(&state, &self.dir)?;
        let mut record = state
            .operations
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::OperationNotFound(id.to_owned()))?;
        let (output, truncated) = clip_utf8(output, MAX_OPERATION_OUTPUT_BYTES);
        record.finish(terminal, summary, output, now_unix())?;
        record.output_truncated = truncated;
        self.append_or_poison(&mut state, &record)?;
        if let Some(previous) = state.operations.insert(id.to_owned(), record.clone()) {
            state.output_bytes = state.output_bytes.saturating_sub(output_len(&previous));
        }
        state.output_bytes += output_len(&record);
        self.prune_outputs(&mut state, MAX_SESSION_OUTPUT_BYTES)?;
        Ok(state.operations.get(id).cloned().unwrap_or(record))
    }

    pub fn operation(&self, id: &str) -> Result<OperationRecord, StoreError> {
        self.lock_state()?
            .operations
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::OperationNotFound(id.to_owned()))
    }

    pub fn total_output_bytes(&self) -> usize {
        self.lock_state()
            .map(|state| state.output_bytes)
            .unwrap_or_default()
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, StoreState>, StoreError> {
        self.state.lock().map_err(|_| StoreError::Unavailable {
            path: self.dir.clone(),
            message: "session state lock was poisoned".into(),
        })
    }

    fn append_operation(&self, record: &OperationRecord) -> Result<(), StoreError> {
        let path = self.dir.join("operations.jsonl");
        let mut bytes = serde_json::to_vec(record).map_err(|error| StoreError::Corrupt {
            path: path.clone(),
            message: error.to_string(),
        })?;
        bytes.push(b'\n');
        let mut file = open_private_append(&path)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| unavailable(&path, error))
    }

    fn append_or_poison(
        &self,
        state: &mut StoreState,
        record: &OperationRecord,
    ) -> Result<(), StoreError> {
        if let Err(error) = self.append_operation(record) {
            state.failure = Some(error.to_string());
            return Err(error);
        }
        Ok(())
    }

    fn prune_outputs(&self, state: &mut StoreState, target: usize) -> Result<(), StoreError> {
        if state.output_bytes <= target {
            return Ok(());
        }
        let mut candidates: Vec<_> = state
            .operations
            .values()
            .filter(|record| record.state.is_terminal() && record.output.is_some())
            .map(|record| {
                (
                    record.finished_at_unix.unwrap_or(u64::MAX),
                    record.created_at_unix,
                    record.id.clone(),
                )
            })
            .collect();
        candidates.sort();
        for (_, _, id) in candidates {
            if state.output_bytes <= target {
                break;
            }
            let mut record =
                state
                    .operations
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| StoreError::Corrupt {
                        path: self.dir.join("operations.jsonl"),
                        message: format!("operation {id} disappeared during pruning"),
                    })?;
            state.output_bytes = state.output_bytes.saturating_sub(output_len(&record));
            record.output = None;
            record.output_pruned = true;
            record.updated_at_unix = now_unix();
            self.append_or_poison(state, &record)?;
            state.operations.insert(id, record);
        }
        Ok(())
    }
}

fn validate_meta(meta: &SessionMeta, dir: &Path) -> Result<(), StoreError> {
    if u64::from(meta.schema()) != u64::from(SESSION_SCHEMA) {
        return Err(StoreError::UnsupportedSchema(u64::from(meta.schema())));
    }
    let dir_id = dir.file_name().and_then(|name| name.to_str());
    if dir_id != Some(meta.session_id()) {
        return Err(StoreError::RoleMismatch);
    }
    Ok(())
}

fn meta_path(dir: &Path, meta: &SessionMeta) -> PathBuf {
    match meta {
        SessionMeta::Engineer(_) => dir.join("engineer-meta.json"),
        SessionMeta::Share(_) => dir.join("share-meta.json"),
    }
}

fn read_meta(dir: &Path) -> Result<(PathBuf, SessionMeta), StoreError> {
    let engineer = dir.join("engineer-meta.json");
    let share = dir.join("share-meta.json");
    let path = match (engineer.exists(), share.exists()) {
        (true, false) => engineer.clone(),
        (false, true) => share,
        (false, false) => {
            return Err(StoreError::Corrupt {
                path: dir.to_path_buf(),
                message: "session metadata is missing".into(),
            })
        }
        (true, true) => {
            return Err(StoreError::Corrupt {
                path: dir.to_path_buf(),
                message: "both engineer and share metadata exist".into(),
            })
        }
    };
    let bytes = std::fs::read(&path).map_err(|error| unavailable(&path, error))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| StoreError::Corrupt {
            path: path.clone(),
            message: error.to_string(),
        })?;
    let schema = value
        .get("meta")
        .and_then(|meta| meta.get("schema"))
        .or_else(|| value.get("schema"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| StoreError::Corrupt {
            path: path.clone(),
            message: "metadata schema is missing or not an unsigned integer".into(),
        })?;
    if schema != u64::from(SESSION_SCHEMA) {
        return Err(StoreError::UnsupportedSchema(schema));
    }
    let meta = if path == engineer {
        serde_json::from_slice::<SessionMeta>(&bytes).or_else(|_| {
            serde_json::from_slice::<EngineerSessionMeta>(&bytes).map(SessionMeta::Engineer)
        })
    } else {
        serde_json::from_slice::<SessionMeta>(&bytes)
            .or_else(|_| serde_json::from_slice::<ShareSessionMeta>(&bytes).map(SessionMeta::Share))
    }
    .map_err(|error| StoreError::Corrupt {
        path: path.clone(),
        message: error.to_string(),
    })?;
    let role_matches = matches!(
        (&meta, path == engineer),
        (SessionMeta::Engineer(_), true) | (SessionMeta::Share(_), false)
    );
    if !role_matches {
        return Err(StoreError::Corrupt {
            path,
            message: "metadata role does not match its filename".into(),
        });
    }
    Ok((path, meta))
}

fn ensure_private_dir(dir: &Path) -> Result<(), StoreError> {
    std::fs::create_dir_all(dir).map_err(|error| unavailable(dir, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| unavailable(dir, error))?;
    }
    Ok(())
}

fn acquire_lock(dir: &Path) -> Result<File, StoreError> {
    let path = dir.join("session.lock");
    let file = open_private_file(&path, false)?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(StoreError::Locked),
        Err(error) => Err(unavailable(&path, error)),
    }
}

fn open_private_append(path: &Path) -> Result<File, StoreError> {
    open_private_file(path, true)
}

fn open_private_file(path: &Path, append: bool) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).append(append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|error| unavailable(path, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| unavailable(path, error))?;
    }
    Ok(file)
}

fn load_ledger(dir: &Path) -> Result<StoreState, StoreError> {
    let path = dir.join("operations.jsonl");
    if !path.exists() {
        return Ok(StoreState::default());
    }
    let mut file = open_private_file(&path, false)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| unavailable(&path, error))?;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        let committed_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        bytes.truncate(committed_len);
        file.set_len(committed_len as u64)
            .and_then(|()| file.seek(SeekFrom::End(0)).map(|_| ()))
            .and_then(|()| file.sync_all())
            .map_err(|error| unavailable(&path, error))?;
    }
    let mut state = StoreState::default();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let record: OperationRecord =
            serde_json::from_slice(line).map_err(|error| StoreError::Corrupt {
                path: path.clone(),
                message: format!("line {}: {error}", index + 1),
            })?;
        validate_ledger_record(&path, index + 1, state.operations.get(&record.id), &record)?;
        if let Some(previous) = state.operations.insert(record.id.clone(), record.clone()) {
            state.output_bytes = state.output_bytes.saturating_sub(output_len(&previous));
        }
        state.output_bytes += output_len(&record);
    }
    if state.output_bytes > MAX_SESSION_OUTPUT_BYTES {
        return Err(StoreError::Corrupt {
            path,
            message: "stored output exceeds the session budget".into(),
        });
    }
    Ok(state)
}

fn validate_ledger_record(
    path: &Path,
    line: usize,
    previous: Option<&OperationRecord>,
    next: &OperationRecord,
) -> Result<(), StoreError> {
    let valid = valid_record_snapshot(next)
        && match previous {
            None => next.state == OperationState::Queued,
            Some(previous) if previous.state.is_terminal() && next.state == previous.state => {
                previous.command == next.command
                    && previous.created_at_unix == next.created_at_unix
                    && next.updated_at_unix >= previous.updated_at_unix
                    && previous.output.is_some()
                    && next.output.is_none()
                    && next.output_pruned
            }
            Some(previous) => {
                let mut expected = previous.clone();
                expected
                    .transition(next.state, next.updated_at_unix)
                    .is_ok()
                    && expected.state == next.state
                    && previous.command == next.command
                    && previous.created_at_unix == next.created_at_unix
                    && next.updated_at_unix >= previous.updated_at_unix
            }
        };
    if valid {
        Ok(())
    } else {
        Err(StoreError::Corrupt {
            path: path.to_path_buf(),
            message: format!("invalid operation transition on line {line}"),
        })
    }
}

fn valid_record_snapshot(record: &OperationRecord) -> bool {
    if record.id.is_empty()
        || record.updated_at_unix < record.created_at_unix
        || output_len(record) > MAX_OPERATION_OUTPUT_BYTES
    {
        return false;
    }
    match record.state {
        OperationState::Queued | OperationState::Running => {
            record.summary.is_none()
                && record.output.is_none()
                && !record.output_truncated
                && !record.output_pruned
                && record.finished_at_unix.is_none()
        }
        state if state.is_terminal() => {
            record.summary.is_some()
                && record.finished_at_unix == Some(record.updated_at_unix)
                && ((!record.output_pruned && record.output.is_some())
                    || (record.output_pruned && record.output.is_none()))
        }
        _ => false,
    }
}

fn output_len(record: &OperationRecord) -> usize {
    record.output.as_deref().map_or(0, str::len)
}

fn ensure_writable(state: &StoreState, dir: &Path) -> Result<(), StoreError> {
    if let Some(message) = &state.failure {
        return Err(StoreError::Unavailable {
            path: dir.to_path_buf(),
            message: format!("store is fail-closed after a write error: {message}"),
        });
    }
    Ok(())
}

fn clip_utf8(value: &str, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value.to_owned(), false);
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unavailable(path: &Path, error: std::io::Error) -> StoreError {
    StoreError::Unavailable {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::{
        EngineerSessionMeta, LeaseMeta, OperationState, SessionMeta, SessionStore,
        ShareSessionMeta, StoreError, MAX_OPERATION_OUTPUT_BYTES, MAX_QUEUED_OPERATIONS,
        MAX_SESSION_OUTPUT_BYTES, SESSION_SCHEMA,
    };

    fn engineer_meta(session_id: &str) -> EngineerSessionMeta {
        EngineerSessionMeta {
            schema: SESSION_SCHEMA,
            session_id: session_id.to_owned(),
            peer: "peer-1".into(),
            invite: "secret-invite".into(),
            controller_resume_token: "plain-resume-token".into(),
            lease: LeaseMeta::default(),
        }
    }

    fn share_meta(session_id: &str) -> ShareSessionMeta {
        ShareSessionMeta {
            schema: SESSION_SCHEMA,
            session_id: session_id.to_owned(),
            lease: LeaseMeta::default(),
            controller_token_hash: Some("hash-only".into()),
        }
    }

    fn finish(store: &SessionStore, id: &str, output: &str) {
        store.mark_running(id).unwrap();
        store
            .finish_operation(id, OperationState::Succeeded, "ok", output)
            .unwrap();
    }

    #[test]
    fn share_store_reopens_and_second_writer_is_locked() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_share(&dir, share_meta("session-1")).unwrap();

        assert!(matches!(SessionStore::open(&dir), Err(StoreError::Locked)));
        drop(store);

        let reopened = SessionStore::open(&dir).unwrap();
        assert!(matches!(
            reopened.load_meta().unwrap(),
            SessionMeta::Share(_)
        ));
    }

    #[test]
    fn share_metadata_contains_only_the_token_hash() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_share(&dir, share_meta("session-1")).unwrap();

        let bytes = std::fs::read_to_string(dir.join("share-meta.json")).unwrap();

        assert!(bytes.contains("hash-only"));
        assert!(!bytes.contains("secret-invite"));
        assert!(!bytes.contains("plain-resume-token"));
        drop(store);
    }

    #[cfg(unix)]
    #[test]
    fn session_directory_and_secret_metadata_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let _store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let meta_mode = std::fs::metadata(dir.join("engineer-meta.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(meta_mode, 0o600);
    }

    #[test]
    fn corrupt_schema_one_metadata_is_rejected_without_recreation() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engineer-meta.json");
        std::fs::write(&path, br#"{"schema":1,"session_id":"session-1"}"#).unwrap();

        let error = SessionStore::open(&dir).unwrap_err();

        assert!(matches!(error, StoreError::Corrupt { .. }));
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            r#"{"schema":1,"session_id":"session-1"}"#
        );
    }

    #[test]
    fn oversized_schema_number_never_wraps_to_supported_version() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("engineer-meta.json"),
            br#"{"schema":4294967297,"session_id":"session-1"}"#,
        )
        .unwrap();

        assert!(matches!(
            SessionStore::open(&dir),
            Err(StoreError::UnsupportedSchema(4_294_967_297))
        ));
    }

    #[test]
    fn metadata_role_must_match_its_filename() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        std::fs::create_dir_all(&dir).unwrap();
        let wrong_role = SessionMeta::Share(share_meta("session-1"));
        std::fs::write(
            dir.join("engineer-meta.json"),
            serde_json::to_vec(&wrong_role).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            SessionStore::open(&dir),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn duplicate_returns_the_terminal_interrupted_record() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        store.begin_operation("op-1", "echo ok").unwrap();
        store.mark_running("op-1").unwrap();
        store
            .finish_operation("op-1", OperationState::Interrupted, "restart", "partial")
            .unwrap();

        let error = store.begin_operation("op-1", "echo ok").unwrap_err();

        assert!(matches!(
            error,
            StoreError::Duplicate(record) if record.state == OperationState::Interrupted
        ));
    }

    #[test]
    fn queue_accepts_one_hundred_and_rejects_the_next() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();

        for index in 0..MAX_QUEUED_OPERATIONS {
            store
                .begin_operation(&format!("op-{index}"), "echo queued")
                .unwrap();
        }

        assert!(matches!(
            store.begin_operation("overflow", "echo no"),
            Err(StoreError::QueueFull)
        ));
    }

    #[test]
    fn output_is_clipped_at_one_mebibyte_on_a_utf8_boundary() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        store.begin_operation("op-1", "echo large").unwrap();
        let output = format!("{}é", "x".repeat(MAX_OPERATION_OUTPUT_BYTES));

        finish(&store, "op-1", &output);

        let record = store.operation("op-1").unwrap();
        assert_eq!(record.output.unwrap().len(), MAX_OPERATION_OUTPUT_BYTES);
        assert!(record.output_truncated);
    }

    #[test]
    fn session_budget_prunes_old_completed_output_but_keeps_metadata() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        let output = "x".repeat(MAX_OPERATION_OUTPUT_BYTES);
        let operation_count = MAX_SESSION_OUTPUT_BYTES / MAX_OPERATION_OUTPUT_BYTES + 1;

        for index in 0..operation_count {
            let id = format!("op-{index:03}");
            store.begin_operation(&id, "echo large").unwrap();
            finish(&store, &id, &output);
        }

        let oldest = store.operation("op-000").unwrap();
        let newest = store
            .operation(&format!("op-{:03}", operation_count - 1))
            .unwrap();
        assert_eq!(oldest.state, OperationState::Succeeded);
        assert!(oldest.output.is_none());
        assert!(oldest.output_pruned);
        assert_eq!(
            newest.output.as_deref().map(str::len),
            Some(MAX_OPERATION_OUTPUT_BYTES)
        );
        assert!(store.total_output_bytes() <= MAX_SESSION_OUTPUT_BYTES);
    }

    #[test]
    fn torn_final_ledger_line_is_removed_on_reopen() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        store.begin_operation("op-1", "echo ok").unwrap();
        drop(store);
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("operations.jsonl"))
            .unwrap()
            .write_all(br#"{"id":"torn"#)
            .unwrap();

        let reopened = SessionStore::open(&dir).unwrap();

        assert_eq!(
            reopened.operation("op-1").unwrap().state,
            OperationState::Queued
        );
        assert!(!std::fs::read_to_string(dir.join("operations.jsonl"))
            .unwrap()
            .contains("torn"));
    }

    #[test]
    fn corruption_before_the_final_line_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        store.begin_operation("op-1", "echo ok").unwrap();
        drop(store);
        let ledger = dir.join("operations.jsonl");
        let valid = std::fs::read_to_string(&ledger).unwrap();
        std::fs::write(&ledger, format!("broken\n{valid}")).unwrap();

        assert!(matches!(
            SessionStore::open(&dir),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn semantically_impossible_ledger_record_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        store.begin_operation("op-1", "echo ok").unwrap();
        drop(store);
        let ledger = dir.join("operations.jsonl");
        let line = std::fs::read_to_string(&ledger).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        value["output"] = serde_json::Value::String("impossible while queued".into());
        std::fs::write(
            &ledger,
            format!("{}\n", serde_json::to_string(&value).unwrap()),
        )
        .unwrap();

        assert!(matches!(
            SessionStore::open(&dir),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn append_failure_poisoning_blocks_later_operations() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        let ledger = dir.join("operations.jsonl");
        std::fs::create_dir(&ledger).unwrap();

        assert!(matches!(
            store.begin_operation("op-1", "echo no"),
            Err(StoreError::Unavailable { .. })
        ));
        std::fs::remove_dir(&ledger).unwrap();

        assert!(matches!(
            store.begin_operation("op-2", "echo still-no"),
            Err(StoreError::Unavailable { .. })
        ));
        assert!(!ledger.exists());
    }

    #[test]
    fn concurrent_duplicate_begin_has_exactly_one_winner() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store =
            Arc::new(SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.begin_operation("same-id", "echo once")
            }));
        }
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StoreError::Duplicate(_))))
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_metadata_update_keeps_the_last_valid_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session-1");
        let store = SessionStore::create_engineer(&dir, engineer_meta("session-1")).unwrap();
        let mut changed = engineer_meta("session-1");
        changed.peer = "peer-2".into();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = store.save_meta(&SessionMeta::Engineer(changed));

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert!(matches!(
            store.load_meta().unwrap(),
            SessionMeta::Engineer(meta) if meta.peer == "peer-1"
        ));
        assert!(matches!(
            store.begin_operation("op-after-failure", "echo no"),
            Err(StoreError::Unavailable { .. })
        ));
    }
}
