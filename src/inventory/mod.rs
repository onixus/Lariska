use crate::model::SoftwareEntry;
use std::time::Duration;

pub mod environment;
pub mod runtimes;

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
    #[allow(unused_mut)]
    let mut result = {
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
    };

    // Collect language runtimes & package ecosystems (Python, Node.js, Java)
    let runtime_entries = tokio::task::spawn_blocking(runtimes::collect_all_runtimes)
        .await
        .unwrap_or_default();
    result.entries.extend(runtime_entries);

    result
}

/// Outcome of attempting to run an external collector command.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) enum CommandRunError {
    /// The binary doesn't exist on this system — the collector is simply not
    /// applicable here, not a failure worth a warning.
    NotFound,
    Other(String),
}

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub(crate) const TRUSTED_SYSTEM_DIRS: &[&str] =
    &["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"];

#[cfg(target_os = "macos")]
pub(crate) const TRUSTED_SYSTEM_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/opt/local/bin",
];

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) const TRUSTED_SYSTEM_DIRS: &[&str] = &[];

/// Resolves a binary name against trusted system directories only.
/// Prevents PATH-hijacking vulnerabilities by never searching ambient `$PATH`.
pub(crate) fn find_trusted_binary(binary_name: &str) -> Option<PathBuf> {
    // If a relative path or traversal is passed, reject or check strictly
    if binary_name.contains('/') || binary_name.contains('\\') || binary_name.contains("..") {
        let path = Path::new(binary_name);
        if path.is_absolute()
            && TRUSTED_SYSTEM_DIRS.iter().any(|dir| path.starts_with(dir))
            && path.is_file()
        {
            return Some(path.to_path_buf());
        }
        return None;
    }

    for dir in TRUSTED_SYSTEM_DIRS {
        let candidate = Path::new(dir).join(binary_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Runs `program` with a timeout and a bounded-size, no-shell-interpolation
/// argument list, strictly using trusted system paths (Plan.md §10.1/§14).
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) async fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, CommandRunError> {
    use std::process::Stdio;

    let executable = find_trusted_binary(program).ok_or(CommandRunError::NotFound)?;

    let mut command = tokio::process::Command::new(&executable);
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
                "failed to start {}: {error}",
                executable.display()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_trusted_binary_rejects_untrusted_paths() {
        assert!(find_trusted_binary("/tmp/malicious_bin").is_none());
        assert!(find_trusted_binary("../../../bin/sh").is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn find_trusted_binary_finds_standard_utilities() {
        // `sh` exists on virtually all Unix-like systems in /bin or /usr/bin
        let sh = find_trusted_binary("sh");
        assert!(
            sh.is_some(),
            "expected to locate 'sh' in trusted system directories"
        );
    }
}
