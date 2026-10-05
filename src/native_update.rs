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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const POWERSHELL: &str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

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
    if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid request nonce".into());
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
    {
        return Err("protected transaction identities disagree".into());
    }
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
        PackageKind::Pkg => run_command(
            "/usr/sbin/installer",
            &[
                "-pkg".as_ref(),
                artifact.as_os_str(),
                "-target".as_ref(),
                "/".as_ref(),
            ],
        ),
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
            let script = "$s=Get-AuthenticodeSignature -LiteralPath $env:LARISKA_UPDATE_ARTIFACT; if($s.Status -ne 'Valid'){exit 1}; $s.SignerCertificate.Thumbprint";
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
        let version = output
            .trim()
            .strip_prefix("lariska ")
            .ok_or("installed endpoint returned invalid version output")?;
        semver::Version::parse(version).map_err(|e| format!("installed endpoint version: {e}"))?;
        Ok(version.into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("unsupported installed endpoint platform".into())
    }
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
    let _cleanup = Cleanup(path.clone());
    let mut options = OpenOptions::new();
    options.create_new(true).write(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(|e| e.to_string())?;
    let mut command = Command::new(program);
    for (name, value) in environment {
        command.env(name, value);
    }
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(file.try_clone().map_err(|e| e.to_string())?)
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|e| format!("{program}: {e}"))?;
    let started = std::time::Instant::now();
    let status = loop {
        if file.metadata().map_err(|e| e.to_string())?.len() > MAX_JOURNAL_BYTES
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
    File::open(&path)
        .map_err(|e| e.to_string())?
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
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
    fs::create_dir(dest).map_err(|e| format!("private staging: {e}"))?;
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
        windows_trusted_path(
            root.parent().ok_or("native updater state has no parent")?,
            false,
        )?;
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
    // Leaf: every content/metadata/replacement permission. Ancestors: replacing
    // the existing protected child, changing ACL/owner or turning the directory
    // into a reparse point. Creating unrelated ProgramData children is allowed.
    const LEAF_WRITE: u32 =
        0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    const PARENT_REPLACE: u32 =
        0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    for (index, object) in report.objects.iter().enumerate() {
        if object.reparse || !report.trusted_sids.contains(&object.owner) {
            return Err(
                "Windows updater paths must have privileged owners and no reparse points".into(),
            );
        }
        if object.aces.len() > 2048 {
            return Err("Windows updater ACL exceeds bound".into());
        }
        let forbidden = if index == 0 && strict_leaf {
            LEAF_WRITE
        } else {
            PARENT_REPLACE
        };
        if object.aces.iter().any(|ace| {
            ace.allow
                && !ace.inherit_only
                && !report.trusted_sids.contains(&ace.sid)
                && ace.rights & forbidden != 0
        }) {
            return Err(
                "Windows updater path is writable or replaceable by an unprivileged account".into(),
            );
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
$trusted+=@(Get-LocalGroupMember -SID 'S-1-5-32-544'|ForEach-Object {$_.SID.Value});
$objects=@();$item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $env:LARISKA_UPDATE_TRUST_PATH -Force;
while($null -ne $item){
$acl=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $item.FullName;
$aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {@{sid=$_.IdentityReference.Value;rights=[uint32]$_.FileSystemRights;allow=($_.AccessControlType -eq 'Allow');inherit_only=(($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)-ne 0)}});
$objects+=@{owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;reparse=(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0);aces=$aces};
if($item.PSIsContainer){$parent=$item.Parent}else{$parent=$item.Directory};
if($null -eq $parent){break};$item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $parent.FullName -Force;
};@{trusted_sids=$trusted;objects=$objects}|ConvertTo-Json -Depth 8 -Compress"#;
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
        return Err("Windows updater ownership/ACL check failed".into());
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
    update::atomic_json(&root.join("native-journal.json"), journal)
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
        let source = r#"{"trusted_sids":["S-1-5-18","S-1-5-32-544"],"objects":[{"owner":"S-1-5-18","reparse":false,"aces":[{"sid":"S-1-1-0","rights":1179785,"allow":true,"inherit_only":false}]},{"owner":"S-1-5-32-544","reparse":false,"aces":[{"sid":"S-1-5-11","rights":4,"allow":true,"inherit_only":false}]}]}"#;
        let mut report: WindowsTrustReport = serde_json::from_str(source).unwrap();
        validate_windows_trust(&report, true).unwrap();
        report.objects[0].aces[0].rights = 2;
        assert!(validate_windows_trust(&report, true).is_err());
        report.objects[0].aces[0].rights = 1179785;
        report.objects[1].aces[0].rights = 0x40;
        assert!(validate_windows_trust(&report, true).is_err());
        report.objects[1].aces[0].rights = 4;
        report.objects[1].reparse = true;
        assert!(validate_windows_trust(&report, true).is_err());
        report.objects[1].reparse = false;
        report.objects[0].owner = "S-1-5-21-unprivileged".into();
        assert!(validate_windows_trust(&report, true).is_err());
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
}
