//! Acting on what the server decided (Shapoclyack #358).
//!
//! The heartbeat response carries two kinds of instruction: settings an
//! operator chose for this agent, and a build it should be running. This module
//! is what turns them into behaviour — new intervals without a restart, a new
//! log level without a restart, and a verified binary swap with one.
//!
//! **What is deliberately not settable from the server.** `server_url`, the
//! provisioning key file, the state directory and `allow_plain_http` come from
//! the local configuration and from nowhere else. An agent that accepted a new
//! `server_url` over the network could be told to report somewhere else by
//! whoever reached that network, and the instruction would arrive through the
//! very channel being used to say it. The API refuses to store such a policy;
//! this module would ignore one anyway.
//!
//! **Why an upgrade is refused over plain HTTP.** A build and its digest both
//! travel over the same connection, so plain HTTP means an attacker who can
//! rewrite the response can rewrite both and the check proves nothing. Against
//! a lab stand that is a real inconvenience and `allow_insecure_updates` exists
//! for it, but it is off by default and says what it is.

use crate::config::Config;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The settings the running agent uses, as opposed to the ones it started with.
///
/// Published through a `watch` channel: the heartbeat and inventory loops hold
/// receivers and rebuild their tickers when it changes, which is what makes a
/// new interval take effect on the next tick instead of the next restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Runtime {
    pub heartbeat_interval: Duration,
    pub inventory_interval: Duration,
}

impl Runtime {
    pub fn from_config(config: &Config) -> Self {
        Self {
            heartbeat_interval: config.heartbeat_interval,
            inventory_interval: config.inventory_interval,
        }
    }
}

/// What the server sent on one heartbeat. Every field is optional: a response
/// that says nothing is a server with no policy, which must leave the agent
/// exactly as it is rather than reset it to defaults.
#[derive(Debug, Default, Deserialize)]
pub struct ManagedDirective {
    #[serde(default)]
    pub managed_settings: Option<ManagedSettings>,
    #[serde(default)]
    pub managed_revision: Option<u64>,
    #[serde(default)]
    pub managed_update: Option<ManagedUpdate>,
    #[serde(default)]
    pub managed_update_blocked: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct ManagedSettings {
    #[serde(default)]
    pub heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    pub inventory_interval_secs: Option<u64>,
    #[serde(default)]
    pub log_level: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ManagedUpdate {
    pub version: String,
    pub platform: String,
    pub sha256: String,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    /// Path on the API, not a whole URL: the agent joins it to its own
    /// `server_url` so a response cannot send it to a different host.
    pub url: String,
}

/// The build this binary was compiled for, as the target triple the server
/// stores releases under.
///
/// Composed from `cfg!` rather than read from an environment variable at build
/// time: `TARGET` is not set for a plain `cargo build`, and a value that is
/// present in CI and absent locally is a value that disagrees with itself.
pub fn target_triple() -> String {
    let arch = std::env::consts::ARCH;

    if cfg!(target_os = "windows") {
        let env = if cfg!(target_env = "msvc") { "msvc" } else { "gnu" };
        return format!("{arch}-pc-windows-{env}");
    }
    if cfg!(target_os = "macos") {
        return format!("{arch}-apple-darwin");
    }
    if cfg!(target_os = "linux") {
        let env = if cfg!(target_env = "musl") { "musl" } else { "gnu" };
        return format!("{arch}-unknown-linux-{env}");
    }
    format!("{arch}-unknown-{}", std::env::consts::OS)
}

/// Applies the settings half of a directive, returning the revision now in
/// force.
///
/// `applied` is what this process has already acted on. A server repeats its
/// decision on every heartbeat, so without that comparison an agent would
/// re-apply and re-log the same policy every minute.
pub fn apply_settings(
    directive: &ManagedDirective,
    applied: Option<u64>,
    runtime: &tokio::sync::watch::Sender<Runtime>,
) -> Option<u64> {
    let revision = directive.managed_revision?;
    if applied == Some(revision) {
        return applied;
    }
    let Some(settings) = directive.managed_settings.as_ref() else {
        return Some(revision);
    };

    let mut next = *runtime.borrow();
    if let Some(secs) = settings.heartbeat_interval_secs {
        next.heartbeat_interval = Duration::from_secs(secs);
    }
    if let Some(secs) = settings.inventory_interval_secs {
        next.inventory_interval = Duration::from_secs(secs);
    }
    if let Some(level) = settings.log_level.as_deref() {
        crate::telemetry::set_log_level(level);
    }

    // `send_replace`, not `send`: `send` fails when every receiver has been
    // dropped, and would then leave the published settings at their old value
    // while reporting nothing. The loops are the receivers, so that is the
    // shutdown path -- but "no one is listening" must not turn into "the
    // setting silently did not change".
    if next != *runtime.borrow() {
        runtime.send_replace(next);
    }
    tracing::info!(
        revision,
        heartbeat_secs = next.heartbeat_interval.as_secs(),
        inventory_secs = next.inventory_interval.as_secs(),
        log_level = settings.log_level.as_deref().unwrap_or("unchanged"),
        "applied managed settings"
    );
    Some(revision)
}

/// Why an update was not carried out. Separated from a plain error string so
/// the refusals that are *policy* read as policy in the log rather than as
/// something that went wrong.
#[derive(Debug)]
pub enum UpdateOutcome {
    /// Swapped in; the process must exit so the supervisor starts the new one.
    Staged { version: String },
    Refused(String),
    Failed(String),
}

/// Downloads, verifies and swaps in the build the server named.
///
/// The order matters: download to a temporary file, check its digest, only then
/// touch the installed binary, and keep the previous one beside it. A partial
/// download or a digest mismatch leaves the running installation untouched.
pub async fn apply_update(
    update: &ManagedUpdate,
    config: &Config,
    token: &str,
    http: &reqwest::Client,
) -> UpdateOutcome {
    if !config.server_url.starts_with("https://") && !config.allow_insecure_updates {
        return UpdateOutcome::Refused(format!(
            "refusing to install {} over plain HTTP: the build and the digest that \
             vouches for it would travel on the same unprotected connection, so the \
             check proves nothing. Set allow_insecure_updates = true to override on a \
             lab stand.",
            update.version
        ));
    }

    if update.platform != target_triple() {
        return UpdateOutcome::Refused(format!(
            "server offered a build for {} and this agent is {}",
            update.platform,
            target_triple()
        ));
    }

    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return UpdateOutcome::Failed(format!("cannot locate the running binary: {error}"))
        }
    };

    let url = format!(
        "{}{}",
        config.server_url.trim_end_matches('/'),
        update.url
    );
    let response = match http
        .get(&url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(300))
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return UpdateOutcome::Failed(format!("download failed: {error}")),
    };
    if !response.status().is_success() {
        return UpdateOutcome::Failed(format!("download failed: HTTP {}", response.status()));
    }
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => return UpdateOutcome::Failed(format!("download failed: {error}")),
    };

    let digest = sha256_hex(&bytes);
    if !digest.eq_ignore_ascii_case(&update.sha256) {
        return UpdateOutcome::Failed(format!(
            "downloaded build does not match the digest the server published \
             (expected {}, got {digest}); nothing was replaced",
            update.sha256
        ));
    }

    match swap_binary(&current_exe, &bytes, &update.version, &config.state_dir) {
        Ok(()) => UpdateOutcome::Staged {
            version: update.version.clone(),
        },
        Err(error) => UpdateOutcome::Failed(error),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Puts the new binary where the old one was.
///
/// Windows will not let a running executable be overwritten, but it will let it
/// be *renamed* — which is why the previous build is moved aside rather than
/// deleted, and why this works at all while the process is running. Keeping it
/// is not only a technicality: it is what an operator restores by hand if the
/// new build cannot start, and this is a machine nobody is standing next to.
fn swap_binary(
    current_exe: &Path,
    bytes: &[u8],
    version: &str,
    state_dir: &Path,
) -> Result<(), String> {
    let staging = state_dir.join(format!("lariska-{version}.new"));
    std::fs::write(&staging, bytes)
        .map_err(|error| format!("cannot write {}: {error}", staging.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755));
    }

    install_staged(current_exe, &staging)
}

/// Moves the running binary aside and puts the staged one in its place.
///
/// Split from the staging above so the restore path has a seam a test can
/// reach: it is the branch that decides whether a machine nobody is standing
/// next to still has a working agent after a failed upgrade, and a branch like
/// that should not be reasoned about only on paper.
fn install_staged(current_exe: &Path, staging: &Path) -> Result<(), String> {
    let previous = with_suffix(current_exe, ".old");
    // A leftover from an earlier upgrade would make the rename fail on Windows,
    // where renaming onto an existing file is an error.
    let _ = std::fs::remove_file(&previous);
    std::fs::rename(current_exe, &previous).map_err(|error| {
        format!(
            "cannot move the running binary aside ({} -> {}): {error}",
            current_exe.display(),
            previous.display()
        )
    })?;

    if let Err(error) = std::fs::rename(staging, current_exe) {
        // Put back what was there. An installation left with no binary at all
        // is the one outcome worse than a failed upgrade.
        let _ = std::fs::rename(&previous, current_exe);
        return Err(format!(
            "cannot install the new binary ({} -> {}): {error}; the previous build was restored",
            staging.display(),
            current_exe.display()
        ));
    }

    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Shared handle the loops read their intervals from.
pub type RuntimeWatch = Arc<tokio::sync::watch::Sender<Runtime>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(runtime: Runtime) -> tokio::sync::watch::Sender<Runtime> {
        tokio::sync::watch::channel(runtime).0
    }

    fn base() -> Runtime {
        Runtime {
            heartbeat_interval: Duration::from_secs(60),
            inventory_interval: Duration::from_secs(3600),
        }
    }

    #[test]
    fn a_response_that_says_nothing_changes_nothing() {
        let sender = watch(base());
        let applied = apply_settings(&ManagedDirective::default(), None, &sender);
        assert_eq!(applied, None);
        assert_eq!(*sender.borrow(), base());
    }

    #[test]
    fn settings_are_applied_once_per_revision() {
        let sender = watch(base());
        let directive = ManagedDirective {
            managed_revision: Some(7),
            managed_settings: Some(ManagedSettings {
                heartbeat_interval_secs: Some(30),
                inventory_interval_secs: None,
                log_level: None,
            }),
            ..ManagedDirective::default()
        };

        let applied = apply_settings(&directive, None, &sender);
        assert_eq!(applied, Some(7));
        assert_eq!(sender.borrow().heartbeat_interval, Duration::from_secs(30));
        // Untouched by a policy that did not mention it.
        assert_eq!(sender.borrow().inventory_interval, Duration::from_secs(3600));

        // The server repeats itself on every beat; the agent must not.
        let again = apply_settings(&directive, applied, &sender);
        assert_eq!(again, Some(7));
    }

    #[test]
    fn the_triple_names_this_build() {
        let triple = target_triple();
        assert!(triple.starts_with(std::env::consts::ARCH), "{triple}");
        if cfg!(target_os = "windows") {
            assert!(triple.contains("pc-windows"), "{triple}");
        }
    }

    #[test]
    fn a_failed_install_puts_the_previous_binary_back() {
        let dir = tempdir();
        let exe = dir.join("lariska");
        std::fs::write(&exe, b"old build").unwrap();

        // The staged file is gone by the time the install runs -- whatever the
        // cause on a real machine (antivirus, a cleaner, a full disk), the
        // agent has already moved its own binary aside and must put it back.
        let error = install_staged(&exe, &dir.join("never-written")).unwrap_err();

        assert!(error.contains("previous build was restored"), "{error}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");
    }

    #[test]
    fn a_staging_failure_never_touches_the_installed_binary() {
        let dir = tempdir();
        let exe = dir.join("lariska");
        std::fs::write(&exe, b"old build").unwrap();
        // A directory where the staged file should be written.
        std::fs::create_dir_all(dir.join("lariska-9.9.9.new")).unwrap();

        let error = swap_binary(&exe, b"new build", "9.9.9", &dir).unwrap_err();

        assert!(error.contains("cannot write"), "{error}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");
    }

    fn config_for(server_url: &str, allow_insecure: bool) -> Config {
        Config {
            server_url: server_url.to_string(),
            provisioning_key_file: std::env::temp_dir().join("key"),
            state_dir: std::env::temp_dir(),
            inventory_interval: Duration::from_secs(3600),
            heartbeat_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(5),
            tls_ca_file: None,
            log_level: "info".to_string(),
            allow_plain_http: true,
            allow_insecure_updates: allow_insecure,
            inventory_full_refresh_interval: Duration::from_secs(86_400),
            max_spool_entries: 200,
        }
    }

    fn offered(platform: &str) -> ManagedUpdate {
        ManagedUpdate {
            version: "9.9.9".to_string(),
            platform: platform.to_string(),
            sha256: "0".repeat(64),
            size_bytes: Some(1),
            url: "/api/endpoint/agent/releases/9.9.9/x/download".to_string(),
        }
    }

    /// The refusal that makes the whole mechanism safe to have.
    ///
    /// Over plain HTTP the build and the digest that vouches for it travel on
    /// the same connection, so whoever can rewrite one can rewrite both and the
    /// verification proves nothing. Refused before anything is downloaded, and
    /// reported as a *decision* rather than as a failure.
    #[tokio::test]
    async fn an_upgrade_over_plain_http_is_refused_before_anything_is_fetched() {
        let config = config_for("http://stand.invalid:8080", false);
        let outcome = apply_update(
            &offered(&target_triple()),
            &config,
            "token",
            &reqwest::Client::new(),
        )
        .await;

        match outcome {
            UpdateOutcome::Refused(reason) => {
                assert!(reason.contains("plain HTTP"), "{reason}");
                assert!(reason.contains("allow_insecure_updates"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A build for another platform is refused rather than run.
    ///
    /// The server looks an upgrade up by (version, platform) and should never
    /// offer the wrong one, but "the server should not" is not a reason for the
    /// thing that executes the binary to skip the check.
    #[tokio::test]
    async fn a_build_for_another_platform_is_refused() {
        let config = config_for("https://stand.invalid:8443", false);
        let outcome = apply_update(
            &offered("sparc64-unknown-none"),
            &config,
            "token",
            &reqwest::Client::new(),
        )
        .await;

        match outcome {
            UpdateOutcome::Refused(reason) => {
                assert!(reason.contains("sparc64-unknown-none"), "{reason}");
                assert!(reason.contains(&target_triple()), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_successful_swap_keeps_the_previous_build_beside_it() {
        let dir = tempdir();
        let exe = dir.join("lariska");
        std::fs::write(&exe, b"old build").unwrap();

        swap_binary(&exe, b"new build", "1.2.3", &dir).unwrap();

        assert_eq!(std::fs::read(&exe).unwrap(), b"new build");
        assert_eq!(std::fs::read(with_suffix(&exe, ".old")).unwrap(), b"old build");
    }

    fn tempdir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lariska-managed-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}
