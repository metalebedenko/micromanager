use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

pub const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(1_800);
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: String,
    pub cwd: Option<PathBuf>,
    pub timeout: Duration,
}

impl ExecRequest {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            cwd: None,
            timeout: DEFAULT_EXEC_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output: String,
    pub output_truncated: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitOutcome {
    Finished(ExecResult),
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    EmptyCommand,
    InvalidCwd(PathBuf),
    HomeUnavailable,
    InvalidTimeout(Duration),
    RuntimeUnavailable,
    Spawn(String),
    Wait(String),
    Shutdown(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => formatter.write_str("command must not be empty"),
            Self::InvalidCwd(path) => write!(
                formatter,
                "cwd must be an absolute existing directory: {}",
                path.display()
            ),
            Self::HomeUnavailable => {
                formatter.write_str("share user's home directory is unavailable")
            }
            Self::InvalidTimeout(timeout) => write!(
                formatter,
                "timeout must be between 1 second and {} seconds, got {:?}",
                MAX_EXEC_TIMEOUT.as_secs(),
                timeout
            ),
            Self::RuntimeUnavailable => {
                formatter.write_str("executor requires an active Tokio runtime")
            }
            Self::Spawn(message) => write!(formatter, "command spawn failed: {message}"),
            Self::Wait(message) => write!(formatter, "command wait failed: {message}"),
            Self::Shutdown(message) => write!(formatter, "command shutdown failed: {message}"),
        }
    }
}

impl std::error::Error for ExecError {}

pub trait TerminalObserver: Send + Sync {
    fn started(&self, command: &str);
    fn finished(&self, result: &ExecResult);
    fn failed(&self, command: &str, error: &str);
}

#[derive(Debug, Default)]
pub struct StdoutTerminalObserver;

impl TerminalObserver for StdoutTerminalObserver {
    fn started(&self, command: &str) {
        println!("$ {command}\n[run]");
    }

    fn finished(&self, result: &ExecResult) {
        println!("{}", result.summary);
    }

    fn failed(&self, command: &str, error: &str) {
        eprintln!("$ {command}\n[error] {error}");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedOutput {
    pub text: String,
    pub truncated: bool,
}

#[derive(Clone)]
pub struct Executor {
    inner: Arc<ExecutorInner>,
}

struct ExecutorInner {
    observer: Arc<dyn TerminalObserver>,
    active: Mutex<HashMap<u64, Arc<RunningProcess>>>,
    next_id: AtomicU64,
}

struct RunningProcess {
    child: tokio::sync::Mutex<Child>,
    pid: u32,
}

pub struct RunningCommand {
    id: u64,
    command: String,
    timeout: Duration,
    process: Arc<RunningProcess>,
    stdout: Option<JoinHandle<std::io::Result<Captured>>>,
    stderr: Option<JoinHandle<std::io::Result<Captured>>>,
    stdout_captured: Option<Captured>,
    stderr_captured: Option<Captured>,
    completed: Option<ExecResult>,
    failure: Option<ExecError>,
    inner: Weak<ExecutorInner>,
}

struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

impl Executor {
    pub fn new(observer: Arc<dyn TerminalObserver>) -> Self {
        Self {
            inner: Arc::new(ExecutorInner {
                observer,
                active: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    pub fn start(&self, request: ExecRequest) -> Result<RunningCommand, ExecError> {
        match self.start_inner(request.clone()) {
            Ok(running) => Ok(running),
            Err(error) => {
                self.inner
                    .observer
                    .failed(&request.command, &error.to_string());
                Err(error)
            }
        }
    }

    fn start_inner(&self, request: ExecRequest) -> Result<RunningCommand, ExecError> {
        if request.command.trim().is_empty() {
            return Err(ExecError::EmptyCommand);
        }
        if request.timeout.is_zero() || request.timeout > MAX_EXEC_TIMEOUT {
            return Err(ExecError::InvalidTimeout(request.timeout));
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| ExecError::RuntimeUnavailable)?;
        let cwd = validate_cwd(request.cwd.as_deref())?;
        let mut command = build_command(&request.command);
        command
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command
            .spawn()
            .map_err(|error| ExecError::Spawn(error.to_string()))?;
        let pid = child
            .id()
            .ok_or_else(|| ExecError::Spawn("spawned process has no pid".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecError::Spawn("stdout pipe unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ExecError::Spawn("stderr pipe unavailable".into()))?;
        let process = Arc::new(RunningProcess {
            child: tokio::sync::Mutex::new(child),
            pid,
        });
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner
            .active
            .lock()
            .map_err(|_| ExecError::Spawn("active process registry was poisoned".into()))?
            .insert(id, Arc::clone(&process));
        self.inner.observer.started(&request.command);
        Ok(RunningCommand {
            id,
            command: request.command,
            timeout: request.timeout,
            process,
            stdout: Some(runtime.spawn(read_limited(stdout, MAX_OUTPUT_BYTES))),
            stderr: Some(runtime.spawn(read_limited(stderr, MAX_OUTPUT_BYTES))),
            stdout_captured: None,
            stderr_captured: None,
            completed: None,
            failure: None,
            inner: Arc::downgrade(&self.inner),
        })
    }

    pub async fn shutdown(&self) -> Result<(), ExecError> {
        let processes: Vec<_> = self
            .inner
            .active
            .lock()
            .map_err(|_| ExecError::Shutdown("active process registry was poisoned".into()))?
            .values()
            .cloned()
            .collect();
        for process in processes {
            terminate_process_group(&process).await?;
        }
        self.inner
            .active
            .lock()
            .map_err(|_| ExecError::Shutdown("active process registry was poisoned".into()))?
            .clear();
        Ok(())
    }
}

impl RunningCommand {
    pub async fn wait(&mut self) -> Result<WaitOutcome, ExecError> {
        if let Some(result) = &self.completed {
            return Ok(WaitOutcome::Finished(result.clone()));
        }
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let deadline = tokio::time::Instant::now() + self.timeout;
        let status = match tokio::time::timeout_at(deadline, self.wait_status()).await {
            Ok(status) => status?,
            Err(_) => return Ok(WaitOutcome::TimedOut),
        };
        match tokio::time::timeout_at(deadline, self.finish_with_status(status)).await {
            Ok(result) => result.map(WaitOutcome::Finished),
            Err(_) => Ok(WaitOutcome::TimedOut),
        }
    }

    pub async fn wait_for_completion(&mut self) -> Result<ExecResult, ExecError> {
        if let Some(result) = &self.completed {
            return Ok(result.clone());
        }
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let status = match self.wait_status().await {
            Ok(status) => status,
            Err(error) => return self.record_completion(Err(error)),
        };
        self.finish_with_status(status).await
    }

    async fn wait_status(&self) -> Result<std::process::ExitStatus, ExecError> {
        loop {
            let status = self
                .process
                .child
                .lock()
                .await
                .try_wait()
                .map_err(|error| ExecError::Wait(error.to_string()))?;
            if let Some(status) = status {
                return Ok(status);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn finish_with_status(
        &mut self,
        status: std::process::ExitStatus,
    ) -> Result<ExecResult, ExecError> {
        let completion = self.collect_captures(status.code()).await;
        self.record_completion(completion)
    }

    fn record_completion(
        &mut self,
        completion: Result<ExecResult, ExecError>,
    ) -> Result<ExecResult, ExecError> {
        if let Some(inner) = self.inner.upgrade() {
            if let Ok(mut active) = inner.active.lock() {
                active.remove(&self.id);
            }
            match &completion {
                Ok(result) => inner.observer.finished(result),
                Err(error) => inner.observer.failed(&self.command, &error.to_string()),
            }
        }
        match completion {
            Ok(result) => {
                self.completed = Some(result.clone());
                Ok(result)
            }
            Err(error) => {
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }

    async fn collect_captures(&mut self, exit_code: Option<i32>) -> Result<ExecResult, ExecError> {
        if self.stdout_captured.is_none() {
            self.stdout_captured = Some(join_capture(&mut self.stdout, "stdout").await?);
            self.stdout.take();
        }
        if self.stderr_captured.is_none() {
            self.stderr_captured = Some(join_capture(&mut self.stderr, "stderr").await?);
            self.stderr.take();
        }
        let stdout = self.stdout_captured.take().ok_or_else(|| {
            ExecError::Wait("stdout capture disappeared before result assembly".into())
        })?;
        let stderr = self.stderr_captured.take().ok_or_else(|| {
            ExecError::Wait("stderr capture disappeared before result assembly".into())
        })?;
        Ok(build_result(exit_code, stdout, stderr))
    }
}

#[cfg(unix)]
pub(crate) fn shell_argv(command: &str) -> [&str; 3] {
    ["/bin/sh", "-lc", command]
}

#[cfg(windows)]
pub(crate) fn shell_argv(command: &str) -> [&str; 5] {
    [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        command,
    ]
}

#[cfg(unix)]
fn build_command(command: &str) -> Command {
    let [program, first, second] = shell_argv(command);
    let mut process = Command::new(program);
    process.args([first, second]);
    process
}

#[cfg(windows)]
fn build_command(command: &str) -> Command {
    let [program, first, second, third, fourth] = shell_argv(command);
    let mut process = Command::new(program);
    process.args([first, second, third, fourth]);
    process
}

#[cfg(not(any(unix, windows)))]
compile_error!("remote executor supports only Unix and Windows targets");

pub(crate) fn validate_cwd(cwd: Option<&Path>) -> Result<PathBuf, ExecError> {
    let cwd = match cwd {
        Some(path) => path.to_path_buf(),
        None => directories::BaseDirs::new()
            .map(|dirs| dirs.home_dir().to_path_buf())
            .ok_or(ExecError::HomeUnavailable)?,
    };
    if !cwd.is_absolute() || !cwd.is_dir() {
        return Err(ExecError::InvalidCwd(cwd));
    }
    Ok(cwd)
}

pub(crate) fn sanitize_and_clip(raw: &[u8], max_bytes: usize) -> SanitizedOutput {
    let decoded = String::from_utf8_lossy(raw);
    let redacted = redact_preserving_whitespace(&decoded);
    clip_with_ellipsis(&redacted, max_bytes)
}

fn redact_preserving_whitespace(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut mask_next = false;
    while cursor < text.len() {
        let rest = &text[cursor..];
        let whitespace_len = rest
            .char_indices()
            .take_while(|(_, character)| character.is_whitespace())
            .map(|(_, character)| character.len_utf8())
            .sum::<usize>();
        if whitespace_len > 0 {
            output.push_str(&rest[..whitespace_len]);
            cursor += whitespace_len;
            continue;
        }
        let rest = &text[cursor..];
        let token_len = rest
            .char_indices()
            .take_while(|(_, character)| !character.is_whitespace())
            .map(|(_, character)| character.len_utf8())
            .sum::<usize>();
        let token = &rest[..token_len];
        if mask_next {
            output.push_str("***");
            mask_next = false;
        } else if let Some(redacted) = redact_key_value(token) {
            output.push_str(&redacted);
        } else if token.starts_with('-') && is_secretish(token) {
            output.push_str(token);
            mask_next = true;
        } else if looks_secret_blob(token) {
            output.push_str("***");
        } else {
            output.push_str(token);
        }
        cursor += token_len;
    }
    output
}

fn redact_key_value(token: &str) -> Option<String> {
    let separator = token.find(['=', ':'])?;
    let key = &token[..separator];
    if !is_secretish(key) {
        return None;
    }
    Some(format!("{}{}***", key, &token[separator..=separator]))
}

fn is_secretish(key: &str) -> bool {
    let key = key
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "private_key",
        "credential",
        "auth",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn looks_secret_blob(token: &str) -> bool {
    !Path::new(token).is_absolute()
        && token.len() >= 24
        && token.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=' | '_')
        })
}

fn clip_with_ellipsis(text: &str, max_bytes: usize) -> SanitizedOutput {
    if text.len() <= max_bytes {
        return SanitizedOutput {
            text: text.to_owned(),
            truncated: false,
        };
    }
    let ellipsis = "…";
    if max_bytes < ellipsis.len() {
        return SanitizedOutput {
            text: String::new(),
            truncated: true,
        };
    }
    let mut end = max_bytes - ellipsis.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut clipped = text[..end].to_owned();
    clipped.push_str(ellipsis);
    SanitizedOutput {
        text: clipped,
        truncated: true,
    }
}

async fn read_limited<R>(mut reader: R, limit: usize) -> std::io::Result<Captured>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&chunk[..retained]);
        truncated |= retained < count;
    }
    Ok(Captured { bytes, truncated })
}

async fn join_capture(
    task: &mut Option<JoinHandle<std::io::Result<Captured>>>,
    stream: &str,
) -> Result<Captured, ExecError> {
    task.as_mut()
        .ok_or_else(|| ExecError::Wait(format!("{stream} capture is unavailable")))?
        .await
        .map_err(|error| ExecError::Wait(format!("{stream} capture task failed: {error}")))?
        .map_err(|error| ExecError::Wait(format!("{stream} read failed: {error}")))
}

fn build_result(exit_code: Option<i32>, stdout: Captured, stderr: Captured) -> ExecResult {
    let stdout_sanitized = sanitize_and_clip(&stdout.bytes, MAX_OUTPUT_BYTES);
    let stderr_sanitized = sanitize_and_clip(&stderr.bytes, MAX_OUTPUT_BYTES);
    let mut combined = stdout_sanitized.text.clone();
    if !stderr_sanitized.text.is_empty() {
        if !combined.is_empty() {
            combined.push_str("\n[stderr]\n");
        }
        combined.push_str(&stderr_sanitized.text);
    }
    let output = clip_with_ellipsis(&combined, MAX_OUTPUT_BYTES);
    let output_truncated = stdout.truncated
        || stderr.truncated
        || stdout_sanitized.truncated
        || stderr_sanitized.truncated
        || output.truncated;
    let label = if exit_code == Some(0) { "ok" } else { "error" };
    let code = exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".into());
    let summary = format!(
        "[{label}] exit={code}; stdout={}B stderr={}B{}",
        stdout_sanitized.text.len(),
        stderr_sanitized.text.len(),
        if output_truncated {
            "; output clipped"
        } else {
            ""
        }
    );
    ExecResult {
        exit_code,
        stdout: stdout_sanitized.text,
        stderr: stderr_sanitized.text,
        output: output.text,
        output_truncated,
        summary,
    }
}

#[cfg(unix)]
async fn terminate_process_group(process: &RunningProcess) -> Result<(), ExecError> {
    let pid = i32::try_from(process.pid)
        .map_err(|_| ExecError::Shutdown(format!("pid {} does not fit i32", process.pid)))?;
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(ExecError::Shutdown(error.to_string()));
        }
    }
    let mut child = process.child.lock().await;
    let _ = child.start_kill();
    child
        .wait()
        .await
        .map_err(|error| ExecError::Shutdown(error.to_string()))?;
    Ok(())
}

#[cfg(windows)]
async fn terminate_process_group(process: &RunningProcess) -> Result<(), ExecError> {
    let status = Command::new("taskkill")
        .args(["/PID", &process.pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|error| ExecError::Shutdown(error.to_string()))?;
    let mut child = process.child.lock().await;
    let _ = child.start_kill();
    let reaped = child.wait().await.is_ok();
    if status.success() || reaped {
        Ok(())
    } else {
        Err(ExecError::Shutdown(format!(
            "taskkill exited with {status}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        sanitize_and_clip, validate_cwd, ExecRequest, ExecResult, Executor, TerminalObserver,
        WaitOutcome, MAX_EXEC_TIMEOUT, MAX_OUTPUT_BYTES,
    };

    #[derive(Default)]
    struct RecordingObserver(Mutex<Vec<String>>);

    impl TerminalObserver for RecordingObserver {
        fn started(&self, command: &str) {
            self.0.lock().unwrap().push(format!("run:{command}"));
        }

        fn finished(&self, result: &ExecResult) {
            self.0
                .lock()
                .unwrap()
                .push(format!("done:{}", result.summary));
        }

        fn failed(&self, command: &str, error: &str) {
            self.0
                .lock()
                .unwrap()
                .push(format!("error:{command}:{error}"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_shell_is_sh_login_command() {
        let argv = super::shell_argv("echo ok");
        assert_eq!(argv, ["/bin/sh", "-lc", "echo ok"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_shell_is_noninteractive_powershell() {
        let argv = super::shell_argv("Write-Output ok");
        assert_eq!(
            argv,
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Write-Output ok",
            ]
        );
    }

    #[test]
    fn invalid_cwd_is_rejected_before_spawn() {
        let relative = PathBuf::from("relative");
        assert!(validate_cwd(Some(&relative)).is_err());
        let missing = std::env::temp_dir().join("mm-definitely-missing-cwd");
        assert!(validate_cwd(Some(&missing)).is_err());
    }

    #[test]
    fn output_is_utf8_redacted_and_clipped() {
        let raw = b"token=abc\xff AAAAAAAAAAAAAAAAAAAAAAAAAAAA trailing";

        let sanitized = sanitize_and_clip(raw, 18);

        assert!(!sanitized.text.contains("abc"));
        assert!(!sanitized.text.contains("AAAAAAAA"));
        assert!(sanitized.text.contains("***"));
        assert!(sanitized.text.contains('…'));
        assert!(sanitized.text.len() <= 18);
        assert!(sanitized.truncated);
    }

    #[test]
    fn redaction_keeps_long_absolute_paths_visible() {
        let path = "/Users/sergeylebedenko/Documents/project";

        let sanitized = sanitize_and_clip(path.as_bytes(), 200);

        assert_eq!(sanitized.text, path);
        assert!(!sanitized.truncated);
    }

    #[test]
    fn timeout_above_thirty_minutes_is_rejected() {
        let request = ExecRequest {
            command: "echo no".into(),
            cwd: None,
            timeout: MAX_EXEC_TIMEOUT + Duration::from_secs(1),
        };
        let executor = Executor::new(Arc::new(RecordingObserver::default()));

        assert!(executor.start(request).is_err());
    }

    #[test]
    fn start_without_tokio_runtime_returns_an_error_instead_of_panicking() {
        let executor = Executor::new(Arc::new(RecordingObserver::default()));

        let result = executor.start(ExecRequest::new("echo no-runtime"));

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_smoke_runs_in_requested_directory() {
        let cwd = tempfile::tempdir().unwrap();
        let observer = Arc::new(RecordingObserver::default());
        let executor = Executor::new(observer.clone());
        let mut running = executor
            .start(ExecRequest {
                command: "printf 'mm-executor:%s' \"$PWD\"".into(),
                cwd: Some(cwd.path().to_path_buf()),
                timeout: Duration::from_secs(5),
            })
            .unwrap();

        let result = match running.wait().await.unwrap() {
            WaitOutcome::Finished(result) => result,
            WaitOutcome::TimedOut => panic!("smoke command timed out"),
        };

        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.contains("mm-executor:"));
        assert!(result
            .stdout
            .contains(cwd.path().to_string_lossy().as_ref()));
        assert!(!result
            .summary
            .contains(cwd.path().to_string_lossy().as_ref()));
        assert_eq!(observer.0.lock().unwrap().len(), 2);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_smoke_runs_powershell() {
        let observer = Arc::new(RecordingObserver::default());
        let executor = Executor::new(observer);
        let mut running = executor
            .start(ExecRequest {
                command: "Write-Output mm-executor".into(),
                cwd: None,
                timeout: Duration::from_secs(5),
            })
            .unwrap();

        let result = match running.wait().await.unwrap() {
            WaitOutcome::Finished(result) => result,
            WaitOutcome::TimedOut => panic!("smoke command timed out"),
        };
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.contains("mm-executor"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_keeps_one_running_handle_without_spawning_twice() {
        let cwd = tempfile::tempdir().unwrap();
        let marker = cwd.path().join("marker");
        let command = format!(
            "printf x >> '{}'; sleep 0.15; printf y >> '{}'",
            marker.display(),
            marker.display()
        );
        let observer = Arc::new(RecordingObserver::default());
        let executor = Executor::new(observer.clone());
        let mut running = executor
            .start(ExecRequest {
                command,
                cwd: Some(cwd.path().to_path_buf()),
                timeout: Duration::from_millis(20),
            })
            .unwrap();

        assert!(matches!(
            running.wait().await.unwrap(),
            WaitOutcome::TimedOut
        ));
        let result = running.wait_for_completion().await.unwrap();

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "xy");
        let events = observer.0.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("run:"))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("done:"))
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_while_draining_output_keeps_capture_handles_for_retry() {
        let executor = Executor::new(Arc::new(RecordingObserver::default()));
        let mut running = executor
            .start(ExecRequest {
                command: "true".into(),
                cwd: None,
                timeout: Duration::from_millis(20),
            })
            .unwrap();
        running.stdout = Some(tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(super::Captured {
                bytes: b"late-output".to_vec(),
                truncated: false,
            })
        }));

        assert!(matches!(
            running.wait().await.unwrap(),
            WaitOutcome::TimedOut
        ));
        let result = running.wait_for_completion().await.unwrap();

        assert_eq!(result.stdout, "late-output");
        assert_eq!(result.exit_code, Some(0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capture_failure_is_reported_and_removed_from_the_active_registry() {
        let observer = Arc::new(RecordingObserver::default());
        let executor = Executor::new(observer.clone());
        let mut running = executor
            .start(ExecRequest {
                command: "sleep 0.05".into(),
                cwd: None,
                timeout: Duration::from_secs(2),
            })
            .unwrap();
        running.stdout.as_ref().unwrap().abort();

        assert!(running.wait_for_completion().await.is_err());

        let events = observer.0.lock().unwrap();
        assert!(events.iter().any(|event| event.starts_with("error:")));
        assert!(executor.inner.active.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_terminates_the_active_process_group() {
        let observer = Arc::new(RecordingObserver::default());
        let executor = Executor::new(observer);
        let mut running = executor
            .start(ExecRequest {
                command: "sleep 30 & wait".into(),
                cwd: None,
                timeout: Duration::from_secs(30),
            })
            .unwrap();

        executor.shutdown().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), running.wait_for_completion())
            .await
            .expect("process group survived shutdown")
            .unwrap();

        assert_ne!(result.exit_code, Some(0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_still_owns_a_process_after_its_wait_handle_is_dropped() {
        let executor = Executor::new(Arc::new(RecordingObserver::default()));
        let running = executor
            .start(ExecRequest {
                command: "sleep 30".into(),
                cwd: None,
                timeout: Duration::from_secs(30),
            })
            .unwrap();
        let pid = i32::try_from(running.process.pid).unwrap();
        drop(running);

        executor.shutdown().await.unwrap();

        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "dropped wait handle orphaned pid {pid}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn combined_output_is_capped_at_one_mebibyte() {
        let observer = Arc::new(RecordingObserver::default());
        let executor = Executor::new(observer);
        let mut running = executor
            .start(ExecRequest {
                command: format!(
                    "yes x | head -c {}; yes y | head -c {} >&2",
                    MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES
                ),
                cwd: None,
                timeout: Duration::from_secs(10),
            })
            .unwrap();

        let result = running.wait_for_completion().await.unwrap();

        assert!(result.output.len() <= MAX_OUTPUT_BYTES);
        assert!(result.output_truncated);
    }
}
