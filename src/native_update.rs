//! The privileged, separately supervised half of a native package update.
//!
//! The endpoint can only enqueue signed bytes. This process copies them into
//! private storage, verifies again, and keeps running while the OS restarts the
//! endpoint. Its journal survives both a failed endpoint and its own restart.
use crate::config::Config;
use crate::update::{self, PackageKind, ReleaseManifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const POWERSHELL: &str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const WINDOWS_POWERSHELL_MODULES: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules";

const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
const MAX_REQUESTS: usize = 200;

#[derive(Clone, Serialize, Deserialize)]
struct CachedRelease {
    manifest: ReleaseManifest,
    directory: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    release: CachedRelease,
    nonce: String,
    started_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    active: Option<CachedRelease>,
    pending: Option<Pending>,
    #[serde(default)]
    consumed: Vec<ConsumedRequest>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ConsumedRequest {
    nonce: String,
    version: String,
    sequence: u64,
}

trait NativeOperations {
    fn verify_signature(
        &self,
        config: &Config,
        manifest: &ReleaseManifest,
        artifact: &Path,
    ) -> Result<(), String>;
    fn install(&self, manifest: &ReleaseManifest, artifact: &Path) -> Result<(), String>;
    fn restart(&self) -> Result<(), String>;
}
struct SystemNativeOperations;
impl NativeOperations for SystemNativeOperations {
    fn verify_signature(
        &self,
        config: &Config,
        manifest: &ReleaseManifest,
        artifact: &Path,
    ) -> Result<(), String> {
        verify_native_signature(config, manifest, artifact)
    }
    fn install(&self, manifest: &ReleaseManifest, artifact: &Path) -> Result<(), String> {
        install_package(manifest, artifact)
    }
    fn restart(&self) -> Result<(), String> {
        restart_agent()
    }
}

pub fn seed(config_path: &Path, manifest: &Path, artifact: &Path) -> Result<(), String> {
    trusted_config(config_path)?;
    let config = Config::from_file_and_env(config_path).map_err(|e| e.to_string())?;
    let root = private_root(&config)?;
    let _lock = crate::service::acquire(&root).map_err(|e| e.to_string())?;
    let mut journal = read_journal(&root)?;
    if journal.pending.is_some() {
        return Err("cannot replace rollback cache during a pending update".into());
    }
    if let Some(active) = journal.active.clone() {
        if valid_nonce(&active.directory) {
            remember_consumed_request(
                &config,
                &root,
                &mut journal,
                &active.directory,
                &active.manifest,
            )?;
        }
    }
    let directory = format!("seed-{}", rand::random::<u64>());
    let dest = root.join(&directory);
    copy_request(manifest, artifact, &dest, config.updates.max_download_bytes)?;
    let mut cleanup = CacheCleanup {
        directory: dest.clone(),
        retained: false,
    };
    let verified = update::verify_files(
        &config,
        &dest.join("manifest.json"),
        &dest.join("artifact"),
        &root,
    )?;
    if verified.version != installed_agent_version()? {
        let _ = fs::remove_dir_all(&dest);
        return Err("rollback seed must match the installed agent version".into());
    }
    verify_native_signature(&config, &verified, &dest.join("artifact"))?;
    // The stable helper may be older than the installed endpoint. Provisioning
    // a verified current rollback seed establishes that version's durable floor.
    let mut ledger = update::read_ledger(&root)?;
    if semver::Version::parse(&verified.version).map_err(|e| e.to_string())?
        > semver::Version::parse(&ledger.floor_version).map_err(|e| e.to_string())?
    {
        ledger.floor_version = verified.version.clone();
    }
    ledger.floor_sequence = ledger.floor_sequence.max(verified.sequence);
    update::atomic_json(&root.join("update-state.json"), &ledger)?;
    journal.active = Some(CachedRelease {
        manifest: verified,
        directory,
    });
    write_journal(&root, &journal)?;
    cleanup.retained = true;
    prune_cache(&root, &journal)?;
    Ok(())
}

pub fn supervise(config_path: &Path, once: bool) -> Result<(), String> {
    trusted_config(config_path)?;
    // Privileged execution does not accept ambient LARISKA_* overrides. The
    // same root-controlled file is used by the endpoint and the supervisor.
    reject_config_environment()?;
    let config = Config::from_file_and_env(config_path).map_err(|e| e.to_string())?;
    let root = private_root(&config)?;
    #[cfg(windows)]
    crate::telemetry::init_to_file(&config.log_level, &root.join("updater.log"));
    #[cfg(not(windows))]
    crate::telemetry::init(&config.log_level);
    let _lock = crate::service::acquire(&root).map_err(|e| e.to_string())?;
    let mut examined: BTreeSet<PathBuf> = BTreeSet::new();
    loop {
        let mut journal = read_journal(&root)?;
        recover_or_ack(&config, &root, &mut journal)?;
        prune_cache(&root, &journal)?;
        if journal.pending.is_none() {
            for entry in incoming_requests(&config)? {
                if examined.contains(&entry) {
                    continue;
                }
                examined.retain(|request| request.exists());
                if examined.len() >= MAX_REQUESTS {
                    if let Some(oldest) = examined.iter().next().cloned() {
                        examined.remove(&oldest);
                    }
                }
                examined.insert(entry.clone());
                if let Err(error) = accept_request(&config, &root, &entry, &mut journal) {
                    tracing::warn!(%error, "native update refused");
                    if let Some(nonce) = entry.file_name().and_then(|n| n.to_str()) {
                        let _ = update::ack_request(&config, nonce, "refused");
                    }
                    // Move a failed request out of the ready queue. No package
                    // install can occur without the private verification above.
                    // Do not write through endpoint-owned directories as root.
                }
                if journal.pending.is_some() {
                    break;
                }
            }
        }
        if once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn accept_request(
    config: &Config,
    root: &Path,
    request: &Path,
    journal: &mut Journal,
) -> Result<(), String> {
    accept_request_with(config, root, request, journal, &SystemNativeOperations)
}
fn accept_request_with(
    config: &Config,
    root: &Path,
    request: &Path,
    journal: &mut Journal,
    operations: &dyn NativeOperations,
) -> Result<(), String> {
    let nonce = request
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid request directory")?;
    if !valid_nonce(nonce) {
        return Err("invalid request nonce".into());
    }
    if journal
        .consumed
        .iter()
        .any(|request| request.nonce == nonce)
    {
        return Err("native request nonce was already consumed".into());
    }
    let previous = journal
        .active
        .as_ref()
        .ok_or("seed the current signed package before enabling native updates")?;
    let previous_dir = root.join(&previous.directory);
    update::verify_files_for_recovery(
        config,
        &previous_dir.join("manifest.json"),
        &previous_dir.join("artifact"),
        root,
    )?;
    let dest = root.join(nonce);
    copy_request(
        &request.join("manifest.json"),
        &request.join("artifact"),
        &dest,
        config.updates.max_download_bytes,
    )?;
    let mut cleanup = CacheCleanup {
        directory: dest.clone(),
        retained: false,
    };
    let manifest = update::verify_files(
        config,
        &dest.join("manifest.json"),
        &dest.join("artifact"),
        root,
    )?;
    if manifest.version == previous.manifest.version {
        return Err("the requested version is already installed".into());
    }
    operations.verify_signature(config, &manifest, &dest.join("artifact"))?;
    // Reserve the transaction identity durably before the ledger or installer.
    // A stale endpoint-owned ready directory must never re-install a completed
    // or interrupted request when this supervisor loses its in-memory set.
    remember_consumed_request(config, root, journal, nonce, &manifest)?;
    update::commit_pending(config, &manifest, nonce, root)?;
    journal.pending = Some(Pending {
        release: CachedRelease {
            manifest: manifest.clone(),
            directory: nonce.into(),
        },
        nonce: nonce.into(),
        started_at: now(),
    });
    // Journal BEFORE installation: a supervisor crash during package-manager
    // execution must still leave an independently recoverable transaction.
    write_journal(root, journal)?;
    cleanup.retained = true;
    update::ack_request(config, nonce, "accepted")?;
    let installed = (|| {
        operations.install(&manifest, &dest.join("artifact"))?;
        let armed = update::arm_health(config, root, nonce)?;
        if let Some(pending) = journal.pending.as_mut() {
            pending.started_at = armed.started_at;
        }
        write_journal(root, journal)?;
        operations.restart()
    })();
    if let Err(error) = installed {
        rollback_with(
            config,
            root,
            journal,
            &format!("native_install_failed: {error}"),
            operations,
        )?;
        return Err(error);
    }
    Ok(())
}

fn recover_or_ack(config: &Config, root: &Path, journal: &mut Journal) -> Result<(), String> {
    recover_or_ack_with(config, root, journal, &SystemNativeOperations)
}
fn recover_or_ack_with(
    config: &Config,
    root: &Path,
    journal: &mut Journal,
    operations: &dyn NativeOperations,
) -> Result<(), String> {
    let ledger = update::read_ledger(root)?;
    let Some(pending) = journal.pending.clone() else {
        // commit_pending precedes the installation journal. If it alone was
        // persisted, no package-manager execution has begun.
        if let Some(interrupted) = ledger.pending {
            remember_consumed_nonce(
                config,
                root,
                journal,
                &interrupted.nonce,
                &interrupted.version,
                interrupted.sequence,
            )?;
            update::finish_update(
                config,
                root,
                &interrupted.nonce,
                false,
                "interrupted_before_install",
            )?;
        }
        return Ok(());
    };
    if ledger.pending.is_none() {
        if let Some(last) = ledger.history.last() {
            if last.version == pending.release.manifest.version
                && last.sequence == pending.release.manifest.sequence
            {
                if last.nonce != pending.nonce {
                    return Err("protected completed transaction nonce is missing or disagrees with the native journal; administrator repair is required".into());
                }
                remember_consumed_request(
                    config,
                    root,
                    journal,
                    &pending.nonce,
                    &pending.release.manifest,
                )?;
                if last.outcome == "healthy" {
                    journal.active = Some(pending.release);
                }
                journal.pending = None;
                write_journal(root, journal)?;
                prune_cache(root, journal)?;
                return Ok(());
            }
        }
        return Err("native update journal disagrees with protected ledger".into());
    }
    let authoritative = ledger
        .pending
        .as_ref()
        .ok_or("missing protected pending update")?;
    if authoritative.nonce != pending.nonce
        || authoritative.version != pending.release.manifest.version
        || authoritative.sequence != pending.release.manifest.sequence
    {
        return Err("protected transaction identities disagree".into());
    }
    remember_consumed_request(
        config,
        root,
        journal,
        &pending.nonce,
        &pending.release.manifest,
    )?;
    if update::health_status_for_pending(config, authoritative).unwrap_or(false) {
        update::finish_update(config, root, &pending.nonce, true, "healthy_heartbeat")?;
        journal.active = Some(pending.release);
        journal.pending = None;
        write_journal(root, journal)?;
        prune_cache(root, journal)?;
    } else if now() >= authoritative.deadline {
        rollback_with(
            config,
            root,
            journal,
            "healthy_heartbeat_timeout",
            operations,
        )?;
    }
    Ok(())
}

fn rollback_with(
    config: &Config,
    root: &Path,
    journal: &mut Journal,
    reason: &str,
    operations: &dyn NativeOperations,
) -> Result<(), String> {
    let pending = journal
        .pending
        .clone()
        .ok_or("no pending update to roll back")?;
    let previous = journal
        .active
        .as_ref()
        .ok_or("missing previous native package")?;
    let dir = root.join(&previous.directory);
    let manifest = update::verify_files_for_recovery(
        config,
        &dir.join("manifest.json"),
        &dir.join("artifact"),
        root,
    )?;
    operations.verify_signature(config, &manifest, &dir.join("artifact"))?;
    operations.install(&manifest, &dir.join("artifact"))?;
    operations.restart()?;
    update::finish_update(config, root, &pending.nonce, false, reason)?;
    journal.pending = None;
    write_journal(root, journal)?;
    prune_cache(root, journal)?;
    Ok(())
}

fn install_package(manifest: &ReleaseManifest, artifact: &Path) -> Result<(), String> {
    match manifest.package_kind {
        PackageKind::Deb => {
            let metadata = command_output(
                "/usr/bin/dpkg-deb",
                &[
                    "--field".as_ref(),
                    artifact.as_os_str(),
                    "Package".as_ref(),
                    "Version".as_ref(),
                ],
            )?;
            if !metadata.lines().any(|l| l == "Package: lariska")
                || !metadata
                    .lines()
                    .any(|l| l == format!("Version: {}", manifest.version))
            {
                return Err("deb package name/version does not match signed manifest".into());
            }
            run_command(
                "/usr/bin/dpkg",
                &["--install".as_ref(), artifact.as_os_str()],
            )
        }
        PackageKind::Rpm => {
            let metadata = command_output(
                "/usr/bin/rpm",
                &[
                    "-qp".as_ref(),
                    "--queryformat".as_ref(),
                    "%{NAME}\n%{VERSION}\n".as_ref(),
                    artifact.as_os_str(),
                ],
            )?;
            if metadata != format!("lariska\n{}\n", manifest.version) {
                return Err("rpm identity does not match signed manifest".into());
            }
            run_command(
                "/usr/bin/rpm",
                &[
                    "-U".as_ref(),
                    "--oldpackage".as_ref(),
                    "--replacepkgs".as_ref(),
                    artifact.as_os_str(),
                ],
            )
        }
        PackageKind::Pkg => {
            // Installer requires a .pkg suffix even for the verified flat
            // package bytes. Both forward updates and rollback use this path.
            let alias = PkgInstallerAlias::new(artifact)?;
            run_command(
                "/usr/sbin/installer",
                &[
                    "-pkg".as_ref(),
                    alias.path.as_os_str(),
                    "-target".as_ref(),
                    "/".as_ref(),
                ],
            )
        }
        PackageKind::Msi => run_command(
            "C:\\Windows\\System32\\msiexec.exe",
            &[
                "/i".as_ref(),
                artifact.as_os_str(),
                "/qn".as_ref(),
                "/norestart".as_ref(),
                "REINSTALLMODE=amus".as_ref(),
            ],
        ),
    }
}

struct PkgInstallerAlias {
    path: PathBuf,
}
impl PkgInstallerAlias {
    fn new(artifact: &Path) -> Result<Self, String> {
        // Only called for the verified artifact in root-private cache while
        // holding the supervisor lock. No endpoint can replace these entries.
        if !fs::symlink_metadata(artifact)
            .map_err(|e| e.to_string())?
            .is_file()
        {
            return Err("Installer artifact must be a regular private cached file".into());
        }
        let parent = artifact.parent().ok_or("Installer artifact has no cache")?;
        let path = parent.join("installer-artifact.pkg");
        if path == artifact {
            return Err("Installer alias must differ from the cached artifact".into());
        }
        // A crashed installer may leave our fixed alias. Unlink that directory
        // entry, including a stale symlink, without opening or following it.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("stale Installer alias: {e}")),
        }
        fs::hard_link(artifact, &path).map_err(|e| format!("Installer package alias: {e}"))?;
        let alias = Self { path };
        sync_directory(parent)?;
        Ok(alias)
    }
}
impl Drop for PkgInstallerAlias {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = sync_directory(parent);
        }
    }
}

fn verify_native_signature(
    config: &Config,
    manifest: &ReleaseManifest,
    artifact: &Path,
) -> Result<(), String> {
    match manifest.package_kind {
        PackageKind::Deb | PackageKind::Rpm => Ok(()), // Ed25519 signature is mandatory for every package.
        PackageKind::Pkg => {
            let output = command_output(
                "/usr/sbin/pkgutil",
                &["--check-signature".as_ref(), artifact.as_os_str()],
            )?;
            if config.updates.allow_self_signed_native {
                let pin = config
                    .updates
                    .macos_signer_sha256
                    .as_deref()
                    .ok_or("self-signed macOS package requires a local SHA-256 signer pin")?;
                if !macos_leaf_signature(&output)?
                    .sha256
                    .eq_ignore_ascii_case(pin)
                {
                    return Err("macOS package signer fingerprint does not match local pin".into());
                }
                Ok(())
            } else {
                let team = config
                    .updates
                    .macos_team_id
                    .as_deref()
                    .ok_or("macOS package requires local Team ID")?;
                let leaf = macos_leaf_signature(&output)?;
                let expected = format!("{team})");
                if leaf.subject.rsplit_once(" (").map(|(_, tail)| tail) != Some(expected.as_str()) {
                    return Err("macOS package Team ID does not match the leaf signer".into());
                }
                run_command(
                    "/usr/sbin/spctl",
                    &[
                        "--assess".as_ref(),
                        "--type".as_ref(),
                        "install".as_ref(),
                        artifact.as_os_str(),
                    ],
                )
            }
        }
        PackageKind::Msi => {
            let pin = config
                .updates
                .windows_signer_thumbprint
                .as_deref()
                .ok_or("MSI package requires a local signer thumbprint")?;
            let script = r"$s=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $env:LARISKA_UPDATE_ARTIFACT; if($s.Status -ne 'Valid'){exit 1}; $s.SignerCertificate.Thumbprint";
            let (status, output) = execute_bounded_env(
                POWERSHELL,
                &[
                    "-NoProfile".as_ref(),
                    "-NonInteractive".as_ref(),
                    "-Command".as_ref(),
                    script.as_ref(),
                ],
                &[("LARISKA_UPDATE_ARTIFACT", artifact.as_os_str())],
            )?;
            if !status.success()
                || !String::from_utf8_lossy(&output)
                    .trim()
                    .eq_ignore_ascii_case(pin)
            {
                return Err("MSI signature is invalid or the signer is not pinned".into());
            }
            Ok(())
        }
    }
}

struct MacosLeafSignature {
    subject: String,
    sha256: String,
}
fn macos_leaf_signature(output: &str) -> Result<MacosLeafSignature, String> {
    let mut in_leaf = false;
    let mut subject = None;
    let mut digest = String::new();
    let mut reading_digest = false;
    for line in output.lines() {
        let text = line.trim();
        if let Some((number, name)) = text.split_once('.') {
            if number.bytes().all(|c| c.is_ascii_digit()) && !number.is_empty() {
                if in_leaf {
                    break;
                }
                if number == "1" {
                    in_leaf = true;
                    subject = Some(name.trim().to_string());
                }
                continue;
            }
        }
        if !in_leaf {
            continue;
        }
        if let Some((label, value)) = text.split_once(':') {
            if label.trim().eq_ignore_ascii_case("SHA256 Fingerprint")
                || label.trim().eq_ignore_ascii_case("SHA-256 Fingerprint")
            {
                reading_digest = true;
                digest.push_str(
                    &value
                        .chars()
                        .filter(|c| c.is_ascii_hexdigit())
                        .collect::<String>(),
                );
                continue;
            }
        }
        if reading_digest {
            if text
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c.is_whitespace())
            {
                digest.push_str(
                    &text
                        .chars()
                        .filter(|c| c.is_ascii_hexdigit())
                        .collect::<String>(),
                );
            } else {
                reading_digest = false;
            }
        }
    }
    let subject = subject.ok_or("macOS package signature has no leaf certificate")?;
    if digest.len() != 64 {
        return Err("macOS leaf certificate has no unambiguous SHA-256 fingerprint".into());
    }
    Ok(MacosLeafSignature {
        subject,
        sha256: digest.to_ascii_lowercase(),
    })
}
fn installed_agent_version() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let receipt = command_output(
            "/usr/sbin/pkgutil",
            &["--pkg-info".as_ref(), "com.shapoclyack.lariska".as_ref()],
        )?;
        let version = receipt
            .lines()
            .find_map(|line| line.strip_prefix("version: "))
            .ok_or("installed macOS endpoint receipt has no version")?;
        semver::Version::parse(version).map_err(|e| format!("installed endpoint version: {e}"))?;
        Ok(version.into())
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        #[cfg(target_os = "linux")]
        let binary = Path::new("/usr/bin/lariska");
        #[cfg(target_os = "windows")]
        let binary = Path::new(r"C:\Program Files\Lariska\lariska.exe");
        trusted_config(binary)?;
        let output = command_output(
            binary
                .to_str()
                .ok_or("installed endpoint path is not Unicode")?,
            &["--version".as_ref()],
        )?;
        parse_installed_cli_version(&output)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("unsupported installed endpoint platform".into())
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn parse_installed_cli_version(output: &str) -> Result<String, String> {
    let output = output.trim();
    // The current CLI prints a bare version; older packages may include its name.
    let version = output.strip_prefix("lariska ").unwrap_or(output);
    if version.len() > 128 {
        return Err("installed endpoint version exceeds its length limit".into());
    }
    semver::Version::parse(version).map_err(|e| format!("installed endpoint version: {e}"))?;
    Ok(version.into())
}

fn restart_agent() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        run_command(
            "/usr/bin/systemctl",
            &["restart".as_ref(), "lariska.service".as_ref()],
        )
    }
    #[cfg(target_os = "macos")]
    {
        run_command(
            "/bin/launchctl",
            &[
                "kickstart".as_ref(),
                "-k".as_ref(),
                "system/com.shapoclyack.lariska".as_ref(),
            ],
        )
    }
    #[cfg(target_os = "windows")]
    {
        use windows_service::service::{ServiceAccess, ServiceState};
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| e.to_string())?;
        let service = manager
            .open_service(
                "Lariska",
                ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
            )
            .map_err(|e| e.to_string())?;
        let status = service.query_status().map_err(|e| e.to_string())?;
        if status.current_state != ServiceState::Stopped {
            if status.current_state != ServiceState::StopPending {
                service.stop().map_err(|e| e.to_string())?;
            }
            wait_windows_service(&service, ServiceState::Stopped)?;
        }
        service.start(&[] as &[&str]).map_err(|e| e.to_string())?;
        wait_windows_service(&service, ServiceState::Running)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("native updates are unsupported on this operating system".into())
    }
}

#[cfg(windows)]
fn wait_windows_service(
    service: &windows_service::service::Service,
    expected: windows_service::service::ServiceState,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let status = service.query_status().map_err(|e| e.to_string())?;
        if status.current_state == expected {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("Lariska service failed to reach {expected:?}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn run_command(program: &str, args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let (status, _) = execute_bounded(program, args)?;
    if status.success() || program.ends_with("msiexec.exe") && status.code() == Some(3010) {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}
fn command_output(program: &str, args: &[&std::ffi::OsStr]) -> Result<String, String> {
    let (status, bytes) = execute_bounded(program, args)?;
    if !status.success() {
        return Err(format!("{program} signature/metadata check failed"));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
fn execute_bounded(
    program: &str,
    args: &[&std::ffi::OsStr],
) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    execute_bounded_env(program, args, &[])
}
fn execute_bounded_env(
    program: &str,
    args: &[&std::ffi::OsStr],
    environment: &[(&str, &std::ffi::OsStr)],
) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    let path = std::env::temp_dir().join(format!(
        "lariska-native-output-{:016x}",
        rand::random::<u64>()
    ));
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let stderr_path = path.with_extension("stderr");
    let mut options = OpenOptions::new();
    options.create_new(true).write(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(|e| e.to_string())?;
    let _cleanup = Cleanup(path.clone());
    let stderr_file = options.open(&stderr_path).map_err(|e| e.to_string())?;
    let _stderr_cleanup = Cleanup(stderr_path.clone());
    let mut command = Command::new(program);
    for (name, value) in environment {
        command.env(name, value);
    }
    if program.eq_ignore_ascii_case(POWERSHELL) {
        // A pwsh 7 parent can otherwise make WindowsPowerShell 5.1 autoload
        // incompatible Core modules. Privileged scripts use only OS-controlled
        // builtins; user directories and module-analysis caches establish no trust.
        command
            .env("PSModulePath", WINDOWS_POWERSHELL_MODULES)
            .env("WinPSModulePath", WINDOWS_POWERSHELL_MODULES)
            .env_remove("PSModuleAnalysisCachePath");
        if args.len() != 4
            || args[0] != "-NoProfile"
            || args[1] != "-NonInteractive"
            || args[2] != "-Command"
        {
            return Err("native PowerShell requires a fixed, noninteractive script".into());
        }
        // WindowsPowerShell startup can prepend CurrentUser/AllUsers locations,
        // even when the inherited path contains only PSHOME. Reset before any
        // cmdlet discovery or module autoload in the actual privileged script.
        let mut script = std::ffi::OsString::from(format!(
            "$env:PSModulePath='{WINDOWS_POWERSHELL_MODULES}';$env:WinPSModulePath=$env:PSModulePath;"
        ));
        script.push(args[3]);
        command.args(&args[..3]).arg(script);
    } else {
        command.args(args);
    }
    command
        .stdin(Stdio::null())
        .stdout(file.try_clone().map_err(|e| e.to_string())?)
        // Keep diagnostics bounded, separate from successful metadata stdout.
        .stderr(stderr_file.try_clone().map_err(|e| e.to_string())?);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|e| format!("{program}: {e}"))?;
    let started = std::time::Instant::now();
    let status = loop {
        if file
            .metadata()
            .map_err(|e| e.to_string())?
            .len()
            .saturating_add(stderr_file.metadata().map_err(|e| e.to_string())?.len())
            > MAX_JOURNAL_BYTES
            || started.elapsed() > Duration::from_secs(300)
        {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{program} exceeded its time/output limit"));
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut bytes = Vec::new();
    // Read the created objects through held descriptors, never resolve mutable
    // temporary paths again after executing a privileged command.
    let mut stdout_reader = file.try_clone().map_err(|e| e.to_string())?;
    stdout_reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| e.to_string())?;
    stdout_reader
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if !status.success() {
        let mut stderr_reader = stderr_file.try_clone().map_err(|e| e.to_string())?;
        stderr_reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        stderr_reader
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
    }
    if bytes.len() as u64 > MAX_JOURNAL_BYTES
        || file
            .metadata()
            .map_err(|e| e.to_string())?
            .len()
            .saturating_add(stderr_file.metadata().map_err(|e| e.to_string())?.len())
            > MAX_JOURNAL_BYTES
    {
        return Err("native command output exceeded limit".into());
    }
    Ok((status, bytes))
}

fn copy_request(
    manifest: &Path,
    artifact: &Path,
    dest: &Path,
    max_bytes: u64,
) -> Result<(), String> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    builder
        .create(dest)
        .map_err(|e| format!("private staging: {e}"))?;
    let result = (|| {
        copy_bounded(manifest, &dest.join("manifest.json"), MAX_JOURNAL_BYTES)?;
        copy_bounded(artifact, &dest.join("artifact"), max_bytes)?;
        sync_directory(dest)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(dest);
    }
    result
}

fn copy_bounded(source: &Path, target: &Path, limit: u64) -> Result<(), String> {
    // Reject symlinks and nonregular objects before opening (Unix open uses
    // O_NOFOLLOW as well, closing the swap race in the agent-writable queue).
    if !fs::symlink_metadata(source)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_file()
    {
        return Err("update input must be a regular file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let input = options.open(source).map_err(|e| e.to_string())?;
    if !input.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("update input changed file type".into());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(target)
        .map_err(|e| e.to_string())?;
    let written =
        std::io::copy(&mut input.take(limit + 1), &mut output).map_err(|e| e.to_string())?;
    if written > limit {
        return Err("update input exceeds size limit".into());
    }
    output.sync_all().map_err(|e| e.to_string())
}

fn private_root(config: &Config) -> Result<PathBuf, String> {
    let root = update::native_state_dir(config);
    if !root.is_absolute() {
        return Err("native updater state must be absolute".into());
    }
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        return Err("native updater requires root".into());
    }
    #[cfg(unix)]
    {
        let parent = root.parent().ok_or("native updater state has no parent")?;
        trusted_directory_ancestors(parent)?;
        match fs::create_dir(&root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    #[cfg(windows)]
    {
        // Bootstrap belongs to the signed installer. It sets a protected ACL;
        // creating this directory with an inherited user-writable ACL is unsafe.
        if !root.is_dir() {
            return Err("signed installer must provision the private updater directory".into());
        }
        windows_trusted_path(&root, true)?;
    }
    #[cfg(not(any(unix, windows)))]
    return Err("unsupported native updater platform".into());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if unsafe { libc::geteuid() } != 0 {
            return Err("native updater requires root".into());
        }
        let meta = fs::symlink_metadata(&root).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(
                "native updater state must be root-owned and not group/world writable".into(),
            );
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(root)
}

#[cfg(unix)]
fn trusted_directory_ancestors(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if path.components().any(|part| {
        matches!(
            part,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err("native updater directory path must be normalized".into());
    }
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent)
            .map_err(|e| format!("native updater parent {}: {e}", parent.display()))?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("native updater parents must be existing root-owned directories inaccessible for endpoint writes".into());
        }
    }
    Ok(())
}
struct CacheCleanup {
    directory: PathBuf,
    retained: bool,
}
impl Drop for CacheCleanup {
    fn drop(&mut self) {
        if !self.retained {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}
#[cfg(any(windows, test))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsAce {
    sid: String,
    rights: u32,
    allow: bool,
    inherit_only: bool,
}
#[cfg(any(windows, test))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsPathSecurity {
    path: String,
    owner: String,
    reparse: bool,
    aces: Vec<WindowsAce>,
}
#[cfg(any(windows, test))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsTrustReport {
    trusted_sids: Vec<String>,
    objects: Vec<WindowsPathSecurity>,
}
#[cfg(any(windows, test))]
fn validate_windows_trust(report: &WindowsTrustReport, strict_leaf: bool) -> Result<(), String> {
    if report.objects.is_empty() || report.objects.len() > 128 || report.trusted_sids.len() > 256 {
        return Err("invalid bounded Windows ownership report".into());
    }
    // Leaf: every content/metadata/replacement permission. Ancestors: deleting
    // an existing protected child, replacing the directory or changing ACL/owner.
    // ProgramData permits add-child and metadata writes. They cannot modify the
    // protected child's ACL, and that child keeps the ancestor nonempty: Windows
    // rejects FSCTL_SET_REPARSE_POINT on a nonempty directory ([MS-FSA] 2.1.5.10.37).
    const LEAF_WRITE: u32 =
        0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    const PARENT_REPLACE: u32 = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    for (index, object) in report.objects.iter().enumerate() {
        let location = format!("{:?}", object.path.chars().take(512).collect::<String>());
        if object.reparse || !report.trusted_sids.contains(&object.owner) {
            return Err(format!(
                "Windows updater paths must have privileged owners and no reparse points: path={location}, owner={:?}, reparse={}",
                object.owner.chars().take(96).collect::<String>(), object.reparse
            ));
        }
        if object.aces.len() > 2048 {
            return Err(format!(
                "Windows updater ACL exceeds bound: path={location}"
            ));
        }
        let forbidden = if index == 0 && strict_leaf {
            LEAF_WRITE
        } else {
            PARENT_REPLACE
        };
        if let Some(ace) = object.aces.iter().find(|ace| {
            ace.allow
                && !ace.inherit_only
                && !report.trusted_sids.contains(&ace.sid)
                && ace.rights & forbidden != 0
        }) {
            return Err(format!(
                "Windows updater path is writable or replaceable by an unprivileged account: path={location}, sid={:?}, rights={:#010x}, forbidden={:#010x}, strict_leaf={}",
                ace.sid.chars().take(96).collect::<String>(), ace.rights, forbidden,
                index == 0 && strict_leaf
            ));
        }
    }
    Ok(())
}
#[cfg(windows)]
fn windows_trusted_path(path: &Path, strict_leaf: bool) -> Result<(), String> {
    use std::path::{Component, Prefix};
    if !matches!(path.components().next(),Some(Component::Prefix(prefix)) if matches!(prefix.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_)))
    {
        return Err("privileged Windows updater requires a local absolute disk path".into());
    }
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("privileged Windows updater paths must be normalized".into());
    }
    // The literal never incorporates a path or account name as PowerShell code.
    // SID-based checks work with localized Windows group names.
    let script = r#"$ErrorActionPreference='Stop';
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();
$principal=[Security.Principal.WindowsPrincipal]::new($identity);
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 1};
$trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',$identity.User.Value);
$trusted+=@(Microsoft.PowerShell.LocalAccounts\Get-LocalGroupMember -SID 'S-1-5-32-544'|ForEach-Object {$_.SID.Value});
$objects=@();$item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $env:LARISKA_UPDATE_TRUST_PATH -Force;
while($null -ne $item){
$acl=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $item.FullName;
$aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {@{sid=$_.IdentityReference.Value;rights=[uint32]([int64]$_.FileSystemRights -band [int64]([uint32]::MaxValue));allow=($_.AccessControlType -eq 'Allow');inherit_only=(($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)-ne 0)}});
$objects+=@{path=$item.FullName;owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;reparse=(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0);aces=$aces};
if($item.PSIsContainer){$parent=$item.Parent}else{$parent=$item.Directory};
if($null -eq $parent){break};$item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $parent.FullName -Force;
};@{trusted_sids=$trusted;objects=$objects}|Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8 -Compress"#;
    let (status, bytes) = execute_bounded_env(
        POWERSHELL,
        &[
            "-NoProfile".as_ref(),
            "-NonInteractive".as_ref(),
            "-Command".as_ref(),
            script.as_ref(),
        ],
        &[("LARISKA_UPDATE_TRUST_PATH", path.as_os_str())],
    )?;
    if !status.success() {
        let detail = String::from_utf8_lossy(&bytes)
            .chars()
            .take(2048)
            .collect::<String>();
        return Err(format!(
            "Windows updater ownership/ACL check failed ({status}): {detail}"
        ));
    }
    let report: WindowsTrustReport =
        serde_json::from_slice(&bytes).map_err(|e| format!("Windows ACL report: {e}"))?;
    validate_windows_trust(&report, strict_leaf)
}

fn trusted_config(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("native updater config path must be absolute".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for item in path.ancestors() {
            let meta = fs::symlink_metadata(item).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err("updater config and parent directories must be root-owned and not writable by the endpoint".into());
            }
        }
    }
    #[cfg(windows)]
    windows_trusted_path(path, true)?;
    reject_config_environment()
}

fn reject_config_environment() -> Result<(), String> {
    if std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with("LARISKA_")) {
        return Err("native updater refuses ambient LARISKA_* configuration overrides".into());
    }
    Ok(())
}

fn incoming_requests(config: &Config) -> Result<Vec<PathBuf>, String> {
    let incoming = config.state_dir.join("update/incoming");
    let entries = match fs::read_dir(incoming) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut ready = Vec::new();
    for entry in entries.take(MAX_REQUESTS) {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir()
            && entry.path().join("ready.json").is_file()
        {
            ready.push(entry.path());
        }
    }
    ready.sort();
    Ok(ready)
}

fn read_journal(root: &Path) -> Result<Journal, String> {
    let path = root.join("native-journal.json");
    if !path.exists() {
        return Ok(Journal::default());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err("native journal exceeds size limit".into());
    }
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|e| format!("native journal corrupted: {e}"))?;
    if journal.consumed.len() > MAX_REQUESTS {
        return Err("native consumed request history exceeds its hard bound".into());
    }
    let mut nonces = BTreeSet::new();
    for request in &journal.consumed {
        if !valid_nonce(&request.nonce)
            || !nonces.insert(&request.nonce)
            || request.version.len() > 128
        {
            return Err("invalid native consumed request identity".into());
        }
        semver::Version::parse(&request.version)
            .map_err(|e| format!("consumed request version: {e}"))?;
    }
    for cached in journal
        .active
        .iter()
        .chain(journal.pending.iter().map(|p| &p.release))
    {
        if cached.directory.is_empty()
            || !cached
                .directory
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("invalid cached package directory".into());
        }
    }
    Ok(journal)
}

fn write_journal(root: &Path, journal: &Journal) -> Result<(), String> {
    if serde_json::to_vec(journal)
        .map_err(|e| e.to_string())?
        .len() as u64
        > MAX_JOURNAL_BYTES
    {
        return Err("native journal exceeds size limit".into());
    }
    update::atomic_json(&root.join("native-journal.json"), journal)
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn remember_consumed_request(
    config: &Config,
    root: &Path,
    journal: &mut Journal,
    nonce: &str,
    manifest: &ReleaseManifest,
) -> Result<(), String> {
    remember_consumed_nonce(
        config,
        root,
        journal,
        nonce,
        &manifest.version,
        manifest.sequence,
    )
}

fn remember_consumed_nonce(
    config: &Config,
    root: &Path,
    journal: &mut Journal,
    nonce: &str,
    version: &str,
    sequence: u64,
) -> Result<(), String> {
    if !valid_nonce(nonce) || version.len() > 128 {
        return Err("invalid native consumed request identity".into());
    }
    semver::Version::parse(version).map_err(|e| format!("consumed request version: {e}"))?;
    if let Some(previous) = journal
        .consumed
        .iter()
        .find(|request| request.nonce == nonce)
    {
        return if previous.version == version && previous.sequence == sequence {
            Ok(())
        } else {
            Err("consumed native request nonce changed its release identity".into())
        };
    }
    // Prune only transactions that the authoritative anti-rollback floor must
    // reject. Emergency policy can admit those old releases, so retain every
    // receipt while an override is configured. Never evict replayable nonces.
    if config.updates.emergency_version.is_none() {
        let ledger = update::read_ledger(root)?;
        let floor = semver::Version::parse(&ledger.floor_version).map_err(|e| e.to_string())?;
        let mut retained = Vec::new();
        for request in &journal.consumed {
            let candidate = semver::Version::parse(&request.version).map_err(|e| e.to_string())?;
            if candidate >= floor && request.sequence >= ledger.floor_sequence {
                retained.push(request.clone());
            }
        }
        journal.consumed = retained;
    }
    if journal.consumed.len() >= MAX_REQUESTS {
        return Err("native consumed request history is full; administrator repair is required before accepting another update".into());
    }
    journal.consumed.push(ConsumedRequest {
        nonce: nonce.into(),
        version: version.into(),
        sequence,
    });
    write_journal(root, journal)
}

fn prune_cache(root: &Path, journal: &Journal) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if journal.active.as_ref().is_some_and(|r| r.directory == name)
            || journal
                .pending
                .as_ref()
                .is_some_and(|p| p.release.directory == name)
        {
            continue;
        }
        if name.starts_with("seed-")
            || name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit())
        {
            fs::remove_dir_all(entry.path()).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    update::sync_dir(path)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_pkg_alias_preserves_cached_bytes_and_cleans_stale_files() {
        let root =
            std::env::temp_dir().join(format!("lariska-pkg-alias-{}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("manifest"), b"{}").unwrap();
        fs::write(root.join("source"), b"verified signed package bytes").unwrap();
        let cache = root.join("private");
        copy_request(&root.join("manifest"), &root.join("source"), &cache, 128).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let artifact = cache.join("artifact");
        let alias_path = cache.join("installer-artifact.pkg");
        fs::write(&alias_path, b"stale package from interrupted install").unwrap();
        {
            let alias = PkgInstallerAlias::new(&artifact).unwrap();
            assert_eq!(alias.path, alias_path);
            assert_eq!(fs::read(&alias.path).unwrap(), fs::read(&artifact).unwrap());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(
                    fs::metadata(&alias.path).unwrap().ino(),
                    fs::metadata(&artifact).unwrap().ino()
                );
            }
        }
        assert!(!alias_path.exists());
        assert_eq!(
            fs::read(&artifact).unwrap(),
            b"verified signed package bytes"
        );
        fs::create_dir(&alias_path).unwrap();
        assert!(PkgInstallerAlias::new(&artifact).is_err());
        assert!(alias_path.is_dir());
        assert_eq!(
            fs::read(&artifact).unwrap(),
            b"verified signed package bytes"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn installer_pkg_alias_unlinks_stale_symlink_and_cleans_after_command_failure() {
        let root = std::env::temp_dir().join(format!("lariska-pkg-link-{}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let artifact = root.join("artifact");
        let outside = root.join("unrelated");
        let alias_path = root.join("installer-artifact.pkg");
        fs::write(&artifact, b"verified package").unwrap();
        fs::write(&outside, b"untouched outside target").unwrap();
        std::os::unix::fs::symlink(&outside, &alias_path).unwrap();
        let result = (|| {
            let alias = PkgInstallerAlias::new(&artifact)?;
            assert!(!fs::symlink_metadata(&alias.path)
                .unwrap()
                .file_type()
                .is_symlink());
            run_command("/usr/bin/false", &[alias.path.as_os_str()])
        })();
        assert!(result.is_err());
        assert!(!alias_path.exists());
        assert_eq!(fs::read(&outside).unwrap(), b"untouched outside target");
        assert_eq!(fs::read(&artifact).unwrap(), b"verified package");
        fs::remove_file(&artifact).unwrap();
        std::os::unix::fs::symlink(&outside, &artifact).unwrap();
        assert!(PkgInstallerAlias::new(&artifact).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"untouched outside target");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_installer_reads_alias_of_extensionless_signed_package_fixture() {
        let Some(fixture) = std::env::var_os("LARISKA_NATIVE_TEST_PKG") else {
            return;
        };
        let root = std::env::temp_dir().join(format!("lariska-pkg-info-{}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let _cleanup = CacheCleanup {
            directory: root.clone(),
            retained: false,
        };
        let artifact = root.join("artifact");
        fs::copy(PathBuf::from(fixture), &artifact).unwrap();
        let (status, _) = execute_bounded(
            "/usr/sbin/installer",
            &["-pkginfo".as_ref(), "-pkg".as_ref(), artifact.as_os_str()],
        )
        .unwrap();
        assert!(
            !status.success(),
            "counterfactual extensionless package must reproduce the native failure"
        );
        let alias = PkgInstallerAlias::new(&artifact).unwrap();
        let (status, bytes) = execute_bounded(
            "/usr/sbin/installer",
            &["-pkginfo".as_ref(), "-pkg".as_ref(), alias.path.as_os_str()],
        )
        .unwrap();
        assert!(status.success(), "{}", String::from_utf8_lossy(&bytes));
        assert!(String::from_utf8_lossy(&bytes).contains("installer-artifact"));
    }

    #[test]
    fn installed_cli_version_accepts_current_output_and_rejects_non_versions() {
        let current = env!("CARGO_PKG_VERSION");
        assert_eq!(parse_installed_cli_version(current).unwrap(), current);
        assert_eq!(
            parse_installed_cli_version(&format!("{current}\r\n")).unwrap(),
            current
        );
        assert_eq!(
            parse_installed_cli_version(&format!("lariska {current}\n")).unwrap(),
            current
        );
        for invalid in ["", "0.4", "other-agent 0.4.0", "0.4.0\nwarning"] {
            assert!(parse_installed_cli_version(invalid).is_err(), "{invalid}");
        }
        assert!(parse_installed_cli_version(&format!("0.4.0+{}", "a".repeat(128))).is_err());
    }
    #[test]
    fn queue_copy_rejects_oversized_and_cleans_private_staging() {
        let root = std::env::temp_dir().join(format!("lariska-native-{}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("manifest"), b"{}").unwrap();
        fs::write(root.join("package"), b"12345").unwrap();
        let dest = root.join("private");
        assert!(copy_request(&root.join("manifest"), &root.join("package"), &dest, 4).is_err());
        assert!(!dest.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn queue_copy_rejects_symlink_inputs() {
        let root = std::env::temp_dir().join(format!("lariska-native-{}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source"), b"hello").unwrap();
        std::os::unix::fs::symlink(root.join("source"), root.join("link")).unwrap();
        assert!(copy_bounded(&root.join("link"), &root.join("target"), 100).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    fn fixture() -> (PathBuf, Config, Journal) {
        use ed25519_dalek::SigningKey;
        let root =
            std::env::temp_dir().join(format!("lariska-native-state-{}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let state = root.join("endpoint");
        fs::create_dir(&state).unwrap();
        let kind = if cfg!(target_os = "macos") {
            PackageKind::Pkg
        } else if cfg!(target_os = "windows") {
            PackageKind::Msi
        } else {
            PackageKind::Deb
        };
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let config = Config {
            server_url: "https://example.test".into(),
            provisioning_key_file: state.join("key"),
            state_dir: state,
            inventory_interval: Duration::from_secs(3600),
            heartbeat_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(5),
            tls_ca_file: None,
            log_level: "info".into(),
            allow_plain_http: false,
            allow_insecure_updates: false,
            inventory_full_refresh_interval: Duration::from_secs(86400),
            max_spool_entries: 200,
            updates: update::UpdateConfig {
                trusted_keys: vec![update::TrustedKey {
                    id: "test-key".into(),
                    public_key: update::encode_hex(signing.verifying_key().as_bytes()),
                    revoked: false,
                }],
                package_kind: Some(kind),
                ..Default::default()
            },
        };
        let old = signed(&config, env!("CARGO_PKG_VERSION"), 1, b"old executable");
        let cached = root.join("seed-test");
        fs::create_dir(&cached).unwrap();
        fs::write(cached.join("artifact"), b"old executable").unwrap();
        update::atomic_json(&cached.join("manifest.json"), &old).unwrap();
        let journal = Journal {
            active: Some(CachedRelease {
                manifest: old.manifest,
                directory: "seed-test".into(),
            }),
            pending: None,
            consumed: Vec::new(),
        };
        write_journal(&root, &journal).unwrap();
        fs::write(root.join("installed-agent"), b"old executable").unwrap();
        (root, config, journal)
    }
    fn signed(
        config: &Config,
        version: &str,
        sequence: u64,
        bytes: &[u8],
    ) -> update::SignedManifest {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};
        let manifest = ReleaseManifest {
            schema: 1,
            key_id: "test-key".into(),
            version: version.into(),
            platform: crate::managed::target_triple(),
            package_kind: config.updates.package_kind.unwrap(),
            size_bytes: bytes.len() as u64,
            sha256: update::encode_hex(&Sha256::digest(bytes)),
            expires_at: now() + 3600,
            sequence,
        };
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signature = update::encode_hex(
            &key.sign(&update::canonical_manifest(&manifest).unwrap())
                .to_bytes(),
        );
        update::SignedManifest {
            manifest,
            signature,
        }
    }
    fn request(_root: &Path, config: &Config) -> PathBuf {
        let request = config
            .state_dir
            .join("update/incoming/0123456789abcdef0123456789abcdef");
        fs::create_dir_all(&request).unwrap();
        let signed = signed(config, "1.2.3", 2, b"new executable");
        update::atomic_json(&request.join("manifest.json"), &signed).unwrap();
        fs::write(request.join("artifact"), b"new executable").unwrap();
        request
    }
    struct TestPackages {
        installed: PathBuf,
        fail_first_restart: bool,
        installs: std::cell::Cell<u32>,
        restarts: std::cell::Cell<u32>,
    }
    impl NativeOperations for TestPackages {
        fn verify_signature(
            &self,
            _config: &Config,
            _manifest: &ReleaseManifest,
            _artifact: &Path,
        ) -> Result<(), String> {
            Ok(())
        }
        fn install(&self, _manifest: &ReleaseManifest, artifact: &Path) -> Result<(), String> {
            self.installs.set(self.installs.get() + 1);
            fs::copy(artifact, &self.installed)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        fn restart(&self) -> Result<(), String> {
            self.restarts.set(self.restarts.get() + 1);
            if self.fail_first_restart && self.restarts.get() == 1 {
                Err("new executable cannot start".into())
            } else {
                Ok(())
            }
        }
    }
    fn operations(root: &Path, fail_first_restart: bool) -> TestPackages {
        TestPackages {
            installed: root.join("installed-agent"),
            fail_first_restart,
            installs: std::cell::Cell::new(0),
            restarts: std::cell::Cell::new(0),
        }
    }
    #[test]
    fn failed_new_process_restores_previous_and_records_reason_without_lowering_floor() {
        let (root, config, mut journal) = fixture();
        let request = request(&root, &config);
        let ops = operations(&root, true);
        let error = accept_request_with(&config, &root, &request, &mut journal, &ops).unwrap_err();
        assert!(error.contains("cannot start"));
        assert_eq!(fs::read(&ops.installed).unwrap(), b"old executable");
        assert_eq!(ops.installs.get(), 2);
        assert_eq!(ops.restarts.get(), 2);
        assert!(journal.pending.is_none());
        let ledger = update::read_ledger(&root).unwrap();
        assert!(ledger.pending.is_none());
        assert_eq!(ledger.floor_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(ledger.history.last().unwrap().outcome, "rolled_back");
        assert!(ledger
            .history
            .last()
            .unwrap()
            .reason
            .contains("cannot start"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn independent_watchdog_rolls_back_without_any_new_agent_heartbeat() {
        let (root, config, mut journal) = fixture();
        let request = request(&root, &config);
        let ops = operations(&root, false);
        accept_request_with(&config, &root, &request, &mut journal, &ops).unwrap();
        assert_eq!(fs::read(&ops.installed).unwrap(), b"new executable");
        let mut ledger = update::read_ledger(&root).unwrap();
        ledger.pending.as_mut().unwrap().deadline = now().saturating_sub(1);
        update::atomic_json(&root.join("update-state.json"), &ledger).unwrap();
        // Re-open persisted journal as a freshly restarted independent helper.
        let mut recovered = read_journal(&root).unwrap();
        recover_or_ack_with(&config, &root, &mut recovered, &ops).unwrap();
        assert_eq!(fs::read(&ops.installed).unwrap(), b"old executable");
        assert!(recovered.pending.is_none());
        assert_eq!(
            update::read_ledger(&root)
                .unwrap()
                .history
                .last()
                .unwrap()
                .reason,
            "healthy_heartbeat_timeout"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rolled_back_request_cannot_replay_after_supervisor_restart() {
        let (root, config, mut journal) = fixture();
        let request = request(&root, &config);
        let ops = operations(&root, false);
        accept_request_with(&config, &root, &request, &mut journal, &ops).unwrap();
        let mut ledger = update::read_ledger(&root).unwrap();
        ledger.pending.as_mut().unwrap().deadline = now().saturating_sub(1);
        update::atomic_json(&root.join("update-state.json"), &ledger).unwrap();
        let mut restarted = read_journal(&root).unwrap();
        recover_or_ack_with(&config, &root, &mut restarted, &ops).unwrap();
        // The failed endpoint cannot reap its accepted ready request. A second
        // helper restart must not install those same signed bytes a second time.
        assert!(request.is_dir());
        let mut restarted = read_journal(&root).unwrap();
        let error =
            accept_request_with(&config, &root, &request, &mut restarted, &ops).unwrap_err();
        assert!(error.contains("already consumed"), "{error}");
        assert_eq!(ops.installs.get(), 2);
        assert_eq!(fs::read(&ops.installed).unwrap(), b"old executable");
        assert!(update::read_ledger(&root).unwrap().pending.is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn invalid_uppercase_nonce_cannot_reserve_a_transaction() {
        let (root, config, mut journal) = fixture();
        let request = request(&root, &config);
        let request = request.with_file_name(
            request
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_ascii_uppercase(),
        );
        let ops = operations(&root, false);
        let error = accept_request_with(&config, &root, &request, &mut journal, &ops).unwrap_err();
        assert!(error.contains("invalid request nonce"));
        assert!(read_journal(&root).unwrap().consumed.is_empty());
        assert_eq!(ops.installs.get(), 0);
        assert!(update::read_ledger(&root).unwrap().pending.is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn authoritative_pending_sequence_must_match_the_native_journal() {
        let (root, config, mut journal) = fixture();
        let request = request(&root, &config);
        let ops = operations(&root, false);
        accept_request_with(&config, &root, &request, &mut journal, &ops).unwrap();
        let mut ledger = update::read_ledger(&root).unwrap();
        ledger.pending.as_mut().unwrap().sequence += 1;
        update::atomic_json(&root.join("update-state.json"), &ledger).unwrap();
        let mut restarted = read_journal(&root).unwrap();
        let error = recover_or_ack_with(&config, &root, &mut restarted, &ops).unwrap_err();
        assert!(error.contains("transaction identities disagree"));
        assert!(restarted.pending.is_some());
        assert_eq!(ops.installs.get(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn durable_consumed_history_prunes_only_strictly_blocked_release_identities() {
        let (root, config, mut journal) = fixture();
        journal.consumed = vec![
            ConsumedRequest {
                nonce: "00".repeat(16),
                version: "0.3.0".into(),
                sequence: 5,
            },
            ConsumedRequest {
                nonce: "11".repeat(16),
                version: "1.2.3".into(),
                sequence: 4,
            },
            ConsumedRequest {
                nonce: "22".repeat(16),
                version: env!("CARGO_PKG_VERSION").into(),
                sequence: 5,
            },
            ConsumedRequest {
                nonce: "33".repeat(16),
                version: "1.2.3".into(),
                sequence: 6,
            },
        ];
        let mut ledger = update::read_ledger(&root).unwrap();
        ledger.floor_sequence = 5;
        update::atomic_json(&root.join("update-state.json"), &ledger).unwrap();
        remember_consumed_nonce(&config, &root, &mut journal, &"44".repeat(16), "2.0.0", 7)
            .unwrap();
        assert_eq!(journal.consumed.len(), 3);
        assert_eq!(journal.consumed[0].nonce, "22".repeat(16));
        assert_eq!(journal.consumed[1].nonce, "33".repeat(16));
        assert_eq!(read_journal(&root).unwrap().consumed.len(), 3);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn replayable_nonce_capacity_and_emergency_policy_fail_closed_without_eviction() {
        let (root, mut config, mut journal) = fixture();
        journal.consumed = (0..MAX_REQUESTS)
            .map(|index| ConsumedRequest {
                nonce: format!("{index:032x}"),
                version: "1.2.3".into(),
                sequence: 2,
            })
            .collect();
        write_journal(&root, &journal).unwrap();
        let candidate = "ff".repeat(16);
        let error = remember_consumed_nonce(&config, &root, &mut journal, &candidate, "2.0.0", 3)
            .unwrap_err();
        assert!(error.contains("history is full"));
        assert_eq!(read_journal(&root).unwrap().consumed.len(), MAX_REQUESTS);
        let mut ledger = update::read_ledger(&root).unwrap();
        ledger.floor_sequence = 3;
        update::atomic_json(&root.join("update-state.json"), &ledger).unwrap();
        config.updates.emergency_version = Some("1.2.3".into());
        assert!(
            remember_consumed_nonce(&config, &root, &mut journal, &candidate, "2.0.0", 3).is_err()
        );
        assert_eq!(journal.consumed.len(), MAX_REQUESTS);
        config.updates.emergency_version = None;
        remember_consumed_nonce(&config, &root, &mut journal, &candidate, "2.0.0", 3).unwrap();
        assert_eq!(journal.consumed.len(), 1);
        assert_eq!(journal.consumed[0].nonce, candidate);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn legacy_journal_reads_but_completed_history_requires_exact_nonce() {
        let (root, config, mut journal) = fixture();
        let mut legacy = serde_json::to_value(&journal).unwrap();
        legacy.as_object_mut().unwrap().remove("consumed");
        update::atomic_json(&root.join("native-journal.json"), &legacy).unwrap();
        assert!(read_journal(&root).unwrap().consumed.is_empty());
        let request = request(&root, &config);
        let ops = operations(&root, false);
        accept_request_with(&config, &root, &request, &mut journal, &ops).unwrap();
        let nonce = journal.pending.as_ref().unwrap().nonce.clone();
        update::finish_update(&config, &root, &nonce, true, "healthy_heartbeat").unwrap();
        let mut legacy = serde_json::to_value(update::read_ledger(&root).unwrap()).unwrap();
        legacy["history"][0]
            .as_object_mut()
            .unwrap()
            .remove("nonce");
        update::atomic_json(&root.join("update-state.json"), &legacy).unwrap();
        let mut restarted = read_journal(&root).unwrap();
        assert!(update::read_ledger(&root).unwrap().history[0]
            .nonce
            .is_empty());
        let error = recover_or_ack_with(&config, &root, &mut restarted, &ops).unwrap_err();
        assert!(error.contains("transaction nonce"));
        let mut ledger = update::read_ledger(&root).unwrap();
        ledger.history[0].nonce = "ff".repeat(16);
        update::atomic_json(&root.join("update-state.json"), &ledger).unwrap();
        assert!(recover_or_ack_with(&config, &root, &mut restarted, &ops).is_err());
        assert_eq!(ops.installs.get(), 1);
        assert!(restarted.pending.is_some());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn crash_between_ledger_and_journal_does_not_run_an_installer() {
        let (root, config, mut journal) = fixture();
        let manifest = signed(&config, "1.2.3", 2, b"new executable").manifest;
        let nonce = "0123456789abcdef0123456789abcdef";
        update::commit_pending(&config, &manifest, nonce, &root).unwrap();
        let ops = operations(&root, false);
        recover_or_ack_with(&config, &root, &mut journal, &ops).unwrap();
        assert_eq!(ops.installs.get(), 0);
        assert_eq!(ops.restarts.get(), 0);
        assert!(update::read_ledger(&root).unwrap().pending.is_none());
        assert_eq!(
            update::read_ledger(&root)
                .unwrap()
                .history
                .last()
                .unwrap()
                .reason,
            "interrupted_before_install"
        );
        let request = request(&root, &config);
        let mut restarted = read_journal(&root).unwrap();
        let error =
            accept_request_with(&config, &root, &request, &mut restarted, &ops).unwrap_err();
        assert!(error.contains("already consumed"));
        assert_eq!(ops.installs.get(), 0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn crash_after_durable_healthy_floor_promotes_cached_package_idempotently() {
        let (root, config, mut journal) = fixture();
        let request = request(&root, &config);
        let ops = operations(&root, false);
        accept_request_with(&config, &root, &request, &mut journal, &ops).unwrap();
        let nonce = journal.pending.as_ref().unwrap().nonce.clone();
        update::finish_update(&config, &root, &nonce, true, "healthy_heartbeat").unwrap();
        let mut recovered = read_journal(&root).unwrap();
        recover_or_ack_with(&config, &root, &mut recovered, &ops).unwrap();
        assert!(recovered.pending.is_none());
        assert_eq!(recovered.active.as_ref().unwrap().manifest.version, "1.2.3");
        assert_eq!(update::read_ledger(&root).unwrap().floor_version, "1.2.3");
        assert_eq!(ops.installs.get(), 1);
        assert_eq!(ops.restarts.get(), 1);
        assert_eq!(update::read_ledger(&root).unwrap().history[0].nonce, nonce);
        let mut restarted = read_journal(&root).unwrap();
        let error =
            accept_request_with(&config, &root, &request, &mut restarted, &ops).unwrap_err();
        assert!(error.contains("already consumed"));
        assert_eq!(ops.installs.get(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn macos_pin_and_team_are_taken_only_from_the_leaf_certificate() {
        let leaf = "11".repeat(32);
        let root = "22".repeat(32);
        let output=format!("Package signature:\n Certificate Chain:\n  1. Developer ID Installer: Name (LEAFTEAM01)\n     SHA256 Fingerprint:\n       {}\n  2. Root Authority (ROOTTEAM02)\n     SHA256 Fingerprint: {}\n",leaf,root);
        let parsed = macos_leaf_signature(&output).unwrap();
        assert_eq!(parsed.sha256, leaf);
        assert_ne!(parsed.sha256, root);
        assert_eq!(parsed.subject, "Developer ID Installer: Name (LEAFTEAM01)");
        let no_leaf_hash = format!("1. Leaf\n2. Intermediate\nSHA256 Fingerprint: {root}\n");
        assert!(macos_leaf_signature(&no_leaf_hash).is_err());
        let duplicate =
            format!("1. Leaf\nSHA256 Fingerprint: {leaf}\nSHA256 Fingerprint: {leaf}\n");
        assert!(macos_leaf_signature(&duplicate).is_err());
    }
    #[test]
    fn hostile_windows_acl_reparse_and_owner_reports_are_rejected() {
        let source = r#"{"trusted_sids":["S-1-5-18","S-1-5-32-544"],"objects":[{"path":"C:\\ProgramData\\LariskaUpdater","owner":"S-1-5-18","reparse":false,"aces":[{"sid":"S-1-1-0","rights":1179785,"allow":true,"inherit_only":false}]},{"path":"C:\\ProgramData","owner":"S-1-5-32-544","reparse":false,"aces":[{"sid":"S-1-5-11","rights":4,"allow":true,"inherit_only":false}]}]}"#;
        let mut report: WindowsTrustReport = serde_json::from_str(source).unwrap();
        validate_windows_trust(&report, true).unwrap();
        // The native MSI runner's real ProgramData Users ACE: add-file,
        // add-subdirectory, write-EA and write-attributes on an ancestor.
        report.objects[1].aces[0].sid = "S-1-5-32-545".into();
        report.objects[1].aces[0].rights = 0x116;
        validate_windows_trust(&report, true).unwrap();
        for destructive in [0x40, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000] {
            report.objects[1].aces[0].rights = 0x116 | destructive;
            assert!(validate_windows_trust(&report, true).is_err());
        }
        report.objects[1].aces[0].rights = 0x116;
        for leaf_metadata in [0x10, 0x100, 0x116] {
            report.objects[0].aces[0].rights = leaf_metadata;
            assert!(validate_windows_trust(&report, true).is_err());
        }
        report.objects[0].aces[0].rights = 1179785;
        // Windows stores generic read/execute as a negative signed enum. The
        // PowerShell bridge preserves those bits in unsigned JSON; they never
        // grant write access, whereas GENERIC_WRITE must remain forbidden.
        report.objects[0].aces[0].rights = 0xA0000000;
        validate_windows_trust(&report, true).unwrap();
        report.objects[0].aces[0].rights = 0xC0000000;
        assert!(validate_windows_trust(&report, true).is_err());
        report.objects[0].aces[0].rights = 2;
        let detail = validate_windows_trust(&report, true).unwrap_err();
        assert!(detail.contains("LariskaUpdater"));
        assert!(detail.contains("S-1-1-0"));
        assert!(detail.contains("rights=0x00000002"));
        assert!(detail.contains("strict_leaf=true"));
        report.objects[0].aces[0].rights = 1179785;
        report.objects[1].aces[0].rights = 0x40;
        let detail = validate_windows_trust(&report, true).unwrap_err();
        assert!(detail.contains("S-1-5-32-545"));
        assert!(detail.contains("rights=0x00000040"));
        assert!(detail.contains("strict_leaf=false"));
        report.objects[1].aces[0].rights = 4;
        report.objects[1].reparse = true;
        assert!(validate_windows_trust(&report, true).is_err());
        report.objects[1].reparse = false;
        report.objects[0].owner = "S-1-5-21-unprivileged".into();
        assert!(validate_windows_trust(&report, true).is_err());
        report.objects[0].path = format!("{}\nforged log", "x".repeat(10_000));
        report.objects[0].owner = "y".repeat(10_000);
        let detail = validate_windows_trust(&report, true).unwrap_err();
        assert!(detail.len() < 1024);
        assert!(!detail.contains('\n'));
    }
    #[cfg(windows)]
    #[test]
    fn windows_runtime_rejects_everyone_write_access_to_private_state() {
        if std::env::var_os("CI").is_none() {
            eprintln!("Windows ACL integration requires the elevated CI runner");
            return;
        }
        let path = std::env::temp_dir().join(format!("lariska-acl-{}", rand::random::<u64>()));
        fs::create_dir(&path).unwrap();
        let icacls = "C:\\Windows\\System32\\icacls.exe";
        run_command(
            icacls,
            &[
                path.as_os_str(),
                "/inheritance:r".as_ref(),
                "/grant:r".as_ref(),
                "*S-1-5-18:(OI)(CI)F".as_ref(),
                "*S-1-5-32-544:(OI)(CI)F".as_ref(),
            ],
        )
        .unwrap();
        run_command(
            icacls,
            &[
                path.as_os_str(),
                "/setowner".as_ref(),
                "*S-1-5-32-544".as_ref(),
            ],
        )
        .unwrap();
        windows_trusted_path(&path, true)
            .expect("protected private directory must pass the actual Windows ACL check");
        run_command(
            icacls,
            &[
                path.as_os_str(),
                "/grant".as_ref(),
                "*S-1-1-0:(OI)(CI)W".as_ref(),
            ],
        )
        .unwrap();
        assert!(windows_trusted_path(&path, true).is_err());
        fs::remove_dir_all(path).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn windows_runtime_metadata_writable_ancestor_preserves_protected_child() {
        if std::env::var_os("CI").is_none() {
            eprintln!("Windows ACL integration requires the elevated CI runner");
            return;
        }
        let parent =
            std::env::temp_dir().join(format!("lariska-parent-acl-{}", rand::random::<u64>()));
        let child = parent.join("protected");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&child).unwrap();
        let icacls = "C:\\Windows\\System32\\icacls.exe";
        for path in [&parent, &child] {
            run_command(
                icacls,
                &[
                    path.as_os_str(),
                    "/inheritance:r".as_ref(),
                    "/grant:r".as_ref(),
                    "*S-1-5-18:(OI)(CI)F".as_ref(),
                    "*S-1-5-32-544:(OI)(CI)F".as_ref(),
                ],
            )
            .unwrap();
        }
        run_command(
            icacls,
            &[
                parent.as_os_str(),
                "/grant:r".as_ref(),
                "*S-1-5-32-545:(WD,AD,WEA,WA)".as_ref(),
            ],
        )
        .unwrap();
        windows_trusted_path(&child, true)
            .expect("ancestor metadata rights must not reject an existing protected child");
        assert!(windows_trusted_path(&parent, true).is_err());
        run_command(
            icacls,
            &[
                parent.as_os_str(),
                "/grant:r".as_ref(),
                "*S-1-5-32-545:(DC)".as_ref(),
            ],
        )
        .unwrap();
        assert!(windows_trusted_path(&child, true).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn bounded_command_keeps_success_metadata_clean_and_preserves_failure_diagnostics() {
        let (status, bytes) = execute_bounded(
            "/bin/sh",
            &[
                "-c".as_ref(),
                "printf metadata; printf warning >&2".as_ref(),
            ],
        )
        .unwrap();
        assert!(status.success());
        assert_eq!(bytes, b"metadata");
        let (status, bytes) = execute_bounded(
            "/bin/sh",
            &["-c".as_ref(), "printf provider_failed >&2; exit 1".as_ref()],
        )
        .unwrap();
        assert!(!status.success());
        assert_eq!(bytes, b"provider_failed");
        let script = format!("/usr/bin/head -c {} /dev/zero >&2", MAX_JOURNAL_BYTES + 1);
        assert!(
            execute_bounded("/bin/sh", &["-c".as_ref(), script.as_ref()])
                .unwrap_err()
                .contains("limit")
        );
    }
    #[cfg(windows)]
    #[test]
    fn windows_powershell_builtin_modules_ignore_poisoned_parent_search_paths() {
        let script = r"$ErrorActionPreference='Stop';
foreach($entry in @(
@{name='Microsoft.PowerShell.Security\Get-Acl';module='Microsoft.PowerShell.Security'},
@{name='Microsoft.PowerShell.LocalAccounts\Get-LocalGroupMember';module='Microsoft.PowerShell.LocalAccounts'},
@{name='Microsoft.PowerShell.Security\Get-AuthenticodeSignature';module='Microsoft.PowerShell.Security'},
@{name='Microsoft.PowerShell.Management\Get-Item';module='Microsoft.PowerShell.Management'},
@{name='Microsoft.PowerShell.Utility\ConvertTo-Json';module='Microsoft.PowerShell.Utility'}
)){
$command=Get-Command -Name $entry.name -CommandType Cmdlet;
if($command.CommandType -ne 'Cmdlet' -or $command.ModuleName -ne $entry.module){throw 'unexpected native command provider'};
};$env:PSModulePath;$env:WinPSModulePath";
        let poison = std::ffi::OsStr::new(r"Z:\untrusted-modules");
        let (status, bytes) = execute_bounded_env(
            POWERSHELL,
            &[
                "-NoProfile".as_ref(),
                "-NonInteractive".as_ref(),
                "-Command".as_ref(),
                script.as_ref(),
            ],
            &[("PSModulePath", poison), ("WinPSModulePath", poison)],
        )
        .unwrap();
        assert!(status.success(), "{}", String::from_utf8_lossy(&bytes));
        let output = String::from_utf8(bytes).unwrap();
        let paths: Vec<_> = output.lines().collect();
        assert_eq!(
            paths,
            vec![WINDOWS_POWERSHELL_MODULES, WINDOWS_POWERSHELL_MODULES]
        );
    }
}
