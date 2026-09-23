use crate::model::SoftwareEntry;
use std::time::{Duration, Instant};

pub mod environment;
pub mod runtimes;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// Command output is capped while it is being read so a runaway or malicious
/// package manager cannot exhaust memory before the limit is checked.
// Only Linux/macOS collectors shell out to external commands; the Windows
// collector reads the registry directly, so these items are legitimately
// unused when compiling for Windows.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Individual package metadata files are tiny in normal installations. Keep a
/// generous ceiling while refusing a corrupt/sparse file that would otherwise
/// create a large allocation on an endpoint.
pub(crate) const MAX_METADATA_FILE_BYTES: usize = 512 * 1024;

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
    let started = Instant::now();
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

    // Runtime metadata is filesystem-bound and synchronous. Keep it off the
    // async runtime, but deliberately run only one blocking task at a time: a
    // short scan with low peak I/O is preferable to three ecosystems racing
    // over the endpoint disk.
    let runtime_entries = tokio::task::spawn_blocking(runtimes::collect_all_runtimes)
        .await
        .unwrap_or_default();
    result.entries.extend(runtime_entries);

    tracing::debug!(
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        entries = result.entries.len(),
        warnings = result.warnings.len(),
        "inventory collection completed"
    );

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
    // If a relative path or traversal is passed, reject or check strictly.
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
///
/// The output limit is enforced while reading, not after `wait_with_output`
/// has already allocated it. A timed-out or overflowing collector is killed
/// and reaped before this function returns, so it cannot keep consuming host
/// resources in the background.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) async fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, CommandRunError> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    let executable = find_trusted_binary(program).ok_or(CommandRunError::NotFound)?;

    let mut command = tokio::process::Command::new(&executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
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

    let captured = tokio::time::timeout(timeout, async {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CommandRunError::Other(format!("failed to capture {program} stdout")))?;
        let mut stdout = stdout.take((MAX_OUTPUT_BYTES + 1) as u64);
        let mut bytes = Vec::with_capacity(64 * 1024);
        stdout.read_to_end(&mut bytes).await.map_err(|error| {
            CommandRunError::Other(format!("failed to read {program} output: {error}"))
        })?;

        if bytes.len() > MAX_OUTPUT_BYTES {
            let _ = child.kill().await;
            return Err(CommandRunError::Other(format!(
                "{program} output exceeded {MAX_OUTPUT_BYTES} bytes"
            )));
        }

        let status = child.wait().await.map_err(|error| {
            CommandRunError::Other(format!("failed to wait for {program}: {error}"))
        })?;
        Ok::<_, CommandRunError>((status, bytes))
    })
    .await;

    let (status, stdout) = match captured {
        Ok(result) => result?,
        Err(_) => {
            // `kill` also waits on Tokio, which prevents a zombie on Unix.
            let _ = child.kill().await;
            return Err(CommandRunError::Other(format!(
                "{program} timed out after {timeout:?}"
            )));
        }
    };

    if !status.success() {
        return Err(CommandRunError::Other(format!(
            "{program} exited with status {status}"
        )));
    }

    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Reads a small text metadata file without ever allocating more than the
/// configured ceiling. Invalid UTF-8 is decoded lossily because package names
/// are still useful, while an oversized file is ignored as corrupt input.
pub(crate) fn read_text_file_limited(path: &Path) -> Option<String> {
    use std::fs::File;
    use std::io::Read;

    let file = File::open(path).ok()?;
    let mut reader = file.take((MAX_METADATA_FILE_BYTES + 1) as u64);
    let mut bytes = Vec::with_capacity(4 * 1024);
    reader.read_to_end(&mut bytes).ok()?;
    if bytes.len() > MAX_METADATA_FILE_BYTES {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
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
    use std::fs;

    #[test]
    fn find_trusted_binary_rejects_untrusted_paths() {
        assert!(find_trusted_binary("/tmp/malicious_bin").is_none());
        assert!(find_trusted_binary("../../../bin/sh").is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn find_trusted_binary_finds_standard_utilities() {
        // `sh` exists on virtually all Unix-like systems in /bin or /usr/bin.
        let sh = find_trusted_binary("sh");
        assert!(
            sh.is_some(),
            "expected to locate 'sh' in trusted system directories"
        );
    }

    #[test]
    fn metadata_reader_refuses_oversized_files() {
        let path =
            std::env::temp_dir().join(format!("lariska-metadata-limit-{}", std::process::id()));
        fs::write(&path, vec![b'x'; MAX_METADATA_FILE_BYTES + 1])
            .expect("test metadata should be written");

        assert!(read_text_file_limited(&path).is_none());

        fs::remove_file(path).ok();
    }
}
