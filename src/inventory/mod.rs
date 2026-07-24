use crate::model::SoftwareEntry;
use std::time::Duration;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// Command output is capped so a runaway or malicious package-manager output
/// cannot exhaust memory (Plan.md §14 "bounded memory when parsing collector
/// output").
// Only Linux/macOS collectors shell out to external commands; the Windows
// collector reads the registry directly, so these items are legitimately
// unused when compiling for Windows.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

const DEFAULT_COLLECTOR_TIMEOUT: Duration = Duration::from_secs(20);

/// Result of running every collector available on this platform. A single
/// collector's failure never aborts the whole run — it becomes a warning
/// instead (Plan.md §10 "partial inventory is preferable to a crash").
#[derive(Debug, Default)]
pub struct CollectorResult {
    pub entries: Vec<SoftwareEntry>,
    pub warnings: Vec<String>,
}

impl CollectorResult {
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    fn merge(&mut self, mut other: CollectorResult) {
        self.entries.append(&mut other.entries);
        self.warnings.append(&mut other.warnings);
    }
}

/// Runs every collector supported on the current OS and merges the results.
pub async fn collect_all() -> CollectorResult {
    collect_all_with_timeout(DEFAULT_COLLECTOR_TIMEOUT).await
}

pub async fn collect_all_with_timeout(timeout: Duration) -> CollectorResult {
    #[cfg(target_os = "linux")]
    {
        linux::collect(timeout).await
    }
    #[cfg(target_os = "windows")]
    {
        windows::collect(timeout).await
    }
    #[cfg(target_os = "macos")]
    {
        macos::collect(timeout).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = timeout;
        CollectorResult {
            entries: Vec::new(),
            warnings: vec![
                "software collection is not supported on this operating system".to_string(),
            ],
        }
    }
}

/// Outcome of attempting to run an external collector command.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) enum CommandRunError {
    /// The binary doesn't exist on this system — the collector is simply not
    /// applicable here, not a failure worth a warning.
    NotFound,
    Other(String),
}

/// Runs `program` with a timeout and a bounded-size, no-shell-interpolation
/// argument list (Plan.md §10.1/§14).
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) async fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, CommandRunError> {
    use std::process::Stdio;

    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CommandRunError::NotFound)
        }
        Err(error) => {
            return Err(CommandRunError::Other(format!(
                "failed to start {program}: {error}"
            )))
        }
    };

    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| CommandRunError::Other(format!("{program} timed out after {timeout:?}")))?
        .map_err(|error| {
            CommandRunError::Other(format!("failed to read {program} output: {error}"))
        })?;

    if !output.status.success() {
        return Err(CommandRunError::Other(format!(
            "{program} exited with status {}",
            output.status
        )));
    }

    if output.stdout.len() > MAX_OUTPUT_BYTES {
        return Err(CommandRunError::Other(format!(
            "{program} output exceeded {MAX_OUTPUT_BYTES} bytes"
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Trims a raw field and returns `None` for blank values, so collectors
/// consistently omit rather than guess unknown data (Plan.md §7).
pub(crate) fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
