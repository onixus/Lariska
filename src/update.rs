//! Signed native-package update protocol. Network responses never establish trust.
use crate::config::Config;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HARD_MAX_DOWNLOAD_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
const MAX_LEDGER_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PackageKind {
    Deb,
    Rpm,
    Msi,
    Pkg,
}
impl PackageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Msi => "msi",
            Self::Pkg => "pkg",
        }
    }
    pub fn matches_os(self) -> bool {
        match self {
            Self::Deb | Self::Rpm => cfg!(target_os = "linux"),
            Self::Msi => cfg!(target_os = "windows"),
            Self::Pkg => cfg!(target_os = "macos"),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub id: String,
    /// Ed25519 public key, 32 bytes represented by 64 hexadecimal characters.
    pub public_key: String,
    #[serde(default)]
    pub revoked: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    pub trusted_keys: Vec<TrustedKey>,
    pub package_kind: Option<PackageKind>,
    pub max_download_bytes: u64,
    pub health_timeout_secs: u64,
    pub history_limit: usize,
    /// Exact signed version an administrator authorizes for emergency recovery.
    /// This never changes the persisted floor and cannot be set by the server.
    pub emergency_version: Option<String>,
    pub windows_signer_thumbprint: Option<String>,
    pub macos_team_id: Option<String>,
    pub allow_self_signed_native: bool,
    pub macos_signer_sha256: Option<String>,
    pub native_state_dir: Option<PathBuf>,
}
impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            trusted_keys: Vec::new(),
            package_kind: None,
            max_download_bytes: 256 * 1024 * 1024,
            health_timeout_secs: 180,
            history_limit: 20,
            emergency_version: None,
            windows_signer_thumbprint: None,
            macos_team_id: None,
            native_state_dir: None,
            allow_self_signed_native: false,
            macos_signer_sha256: None,
        }
    }
}
impl UpdateConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_download_bytes == 0 || self.max_download_bytes > HARD_MAX_DOWNLOAD_BYTES {
            return Err(format!(
                "updates.max_download_bytes must be between 1 and {HARD_MAX_DOWNLOAD_BYTES}"
            ));
        }
        if !(30..=3600).contains(&self.health_timeout_secs) {
            return Err("updates.health_timeout_secs must be between 30 and 3600".into());
        }
        if !(1..=100).contains(&self.history_limit) {
            return Err("updates.history_limit must be between 1 and 100".into());
        }
        if self.trusted_keys.len() > 32 {
            return Err("updates.trusted_keys has more than 32 keys".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for key in &self.trusted_keys {
            if !safe_id(&key.id) || !ids.insert(key.id.as_str()) {
                return Err("updates key ids must be unique ASCII identifiers".into());
            }
            let bytes = decode_hex::<32>(&key.public_key)?;
            VerifyingKey::from_bytes(&bytes)
                .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;
        }
        if let Some(version) = &self.emergency_version {
            parse_version(version)?;
        }
        if let Some(path) = &self.native_state_dir {
            if !path.is_absolute() {
                return Err("updates.native_state_dir must be absolute".into());
            }
        }
        if let Some(pin) = &self.windows_signer_thumbprint {
            if pin.len() != 40 || !pin.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(
                    "updates.windows_signer_thumbprint must contain 40 hex characters".into(),
                );
            }
        }
        if let Some(team) = &self.macos_team_id {
            if team.len() != 10
                || !team
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                return Err("updates.macos_team_id must be a 10-character Apple Team ID".into());
            }
        }
        if let Some(pin) = &self.macos_signer_sha256 {
            decode_hex::<32>(pin)?;
        }
        if self.allow_self_signed_native
            && self.windows_signer_thumbprint.is_none()
            && self.macos_signer_sha256.is_none()
        {
            return Err(
                "self-signed native updates require a locally pinned signing certificate".into(),
            );
        }
        Ok(())
    }
}
pub fn native_state_dir(config: &Config) -> PathBuf {
    config.updates.native_state_dir.clone().unwrap_or_else(|| {
        if cfg!(target_os = "windows") {
            PathBuf::from(r"C:\ProgramData\LariskaUpdater")
        } else if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/LariskaUpdater")
        } else {
            PathBuf::from("/var/lib/lariska-updater")
        }
    })
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema: u32,
    pub key_id: String,
    pub version: String,
    pub platform: String,
    pub package_kind: PackageKind,
    pub size_bytes: u64,
    pub sha256: String,
    pub expires_at: u64,
    pub sequence: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub manifest: ReleaseManifest,
    pub signature: String,
}

/// Compact, lexicographically sorted JSON. All fields are mandatory; integers
/// have no alternate string encoding. Publishers sign these exact UTF-8 bytes.
pub fn canonical_manifest(manifest: &ReleaseManifest) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(manifest).map_err(|e| e.to_string())?;
    let object = value
        .as_object()
        .ok_or("release manifest must be an object")?;
    // Do not depend on serde_json's optional preserve_order feature, which
    // another dependency may enable through Cargo feature unification.
    let sorted: std::collections::BTreeMap<_, _> = object.iter().collect();
    serde_json::to_vec(&sorted).map_err(|e| e.to_string())
}
pub fn verify_manifest(
    config: &Config,
    signed: &SignedManifest,
    ledger_dir: &Path,
) -> Result<(), String> {
    verify_manifest_inner(config, signed, false)?;
    let manifest = &signed.manifest;
    let ledger = read_ledger(ledger_dir)?;
    let floor = parse_version(&ledger.floor_version)?;
    let candidate = parse_version(&manifest.version)?;
    let emergency = config.updates.emergency_version.as_deref() == Some(manifest.version.as_str());
    if !emergency && (candidate < floor || manifest.sequence < ledger.floor_sequence) {
        return Err(format!(
            "anti-rollback floor rejects {} sequence {} (floor {} sequence {})",
            manifest.version, manifest.sequence, ledger.floor_version, ledger.floor_sequence
        ));
    }
    if ledger.pending.is_some() {
        return Err("an update transaction is already pending".into());
    }
    Ok(())
}
fn verify_manifest_inner(
    config: &Config,
    signed: &SignedManifest,
    recovery: bool,
) -> Result<(), String> {
    config.updates.validate()?;
    let manifest = &signed.manifest;
    if manifest.schema != 1 {
        return Err("unsupported signed update manifest schema".into());
    }
    parse_version(&manifest.version)?;
    if manifest.platform != crate::managed::target_triple() {
        return Err(format!(
            "foreign-platform manifest: {} != {}",
            manifest.platform,
            crate::managed::target_triple()
        ));
    }
    if !manifest.package_kind.matches_os()
        || config.updates.package_kind != Some(manifest.package_kind)
    {
        return Err(
            "manifest package kind does not match locally provisioned native installer".into(),
        );
    }
    if manifest.sequence == 0 {
        return Err("release sequence must be positive".into());
    }
    if manifest.size_bytes == 0
        || manifest.size_bytes > config.updates.max_download_bytes
        || manifest.size_bytes > HARD_MAX_DOWNLOAD_BYTES
    {
        return Err("signed package size exceeds the local download limit".into());
    }
    if manifest.sha256.len() != 64
        || !manifest
            .sha256
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("manifest SHA-256 must contain 64 lowercase hex characters".into());
    }
    if !recovery && manifest.expires_at <= unix_now()? {
        return Err("signed update manifest has expired".into());
    }
    let key = config
        .updates
        .trusted_keys
        .iter()
        .find(|k| k.id == manifest.key_id && !k.revoked)
        .ok_or("manifest signing key is unknown or revoked in the local keyring")?;
    let verifying =
        VerifyingKey::from_bytes(&decode_hex::<32>(&key.public_key)?).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(&decode_hex::<64>(&signed.signature)?);
    verifying
        .verify_strict(&canonical_manifest(manifest)?, &signature)
        .map_err(|_| "invalid Ed25519 release manifest signature".to_string())
}
pub fn verify_files(
    config: &Config,
    manifest_path: &Path,
    artifact: &Path,
    ledger_dir: &Path,
) -> Result<ReleaseManifest, String> {
    let signed: SignedManifest = read_json(manifest_path, MAX_MANIFEST_BYTES)?;
    verify_manifest(config, &signed, ledger_dir)?;
    verify_artifact(config, &signed, artifact)?;
    Ok(signed.manifest)
}
/// Only for a retained previous package in a root-owned recovery cache. The
/// supervisor authenticates that cache independently before invoking this API.
/// Recovery never changes the floor; revocation and signature checks still apply.
pub fn verify_files_for_recovery(
    config: &Config,
    manifest_path: &Path,
    artifact: &Path,
    _ledger_dir: &Path,
) -> Result<ReleaseManifest, String> {
    let signed: SignedManifest = read_json(manifest_path, MAX_MANIFEST_BYTES)?;
    verify_manifest_inner(config, &signed, true)?;
    verify_artifact(config, &signed, artifact)?;
    Ok(signed.manifest)
}
pub fn verify_artifact(
    config: &Config,
    signed: &SignedManifest,
    artifact: &Path,
) -> Result<(), String> {
    let manifest = &signed.manifest;
    if manifest.size_bytes > config.updates.max_download_bytes
        || manifest.size_bytes > HARD_MAX_DOWNLOAD_BYTES
    {
        return Err("package exceeds local size limit".into());
    }
    let metadata = fs::symlink_metadata(artifact).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() != manifest.size_bytes {
        return Err("package is not a regular file of the signed size".into());
    }
    let mut file = open_read_nofollow(artifact)?;
    let mut buffer = [0u8; 64 * 1024];
    let mut hash = Sha256::new();
    let mut count = 0u64;
    loop {
        let len = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if len == 0 {
            break;
        }
        count = count
            .checked_add(len as u64)
            .ok_or("package length overflow")?;
        if count > manifest.size_bytes {
            return Err("package grew beyond signed size while verifying".into());
        }
        hash.update(&buffer[..len]);
    }
    if count != manifest.size_bytes || encode_hex(&hash.finalize()) != manifest.sha256 {
        return Err("package size or SHA-256 does not match signed manifest".into());
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyRequest {
    pub nonce: String,
    pub version: String,
    pub package_kind: PackageKind,
    pub created_at: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestResult {
    nonce: String,
    outcome: String,
    at: u64,
}
/// Privileged helper publishes completion without resolving the agent's mutable
/// directory names. The agent itself owns removal of its consumed staging.
pub fn ack_request(config: &Config, nonce: &str, outcome: &str) -> Result<(), String> {
    validate_nonce(nonce)?;
    if !matches!(outcome, "accepted" | "refused") {
        return Err("invalid native request result".into());
    }
    SharedUpdateDir::open(config, true)?.write(
        "request-result.json",
        &RequestResult {
            nonce: nonce.into(),
            outcome: outcome.into(),
            at: unix_now()?,
        },
        true,
    )
}
fn reap_consumed_request(config: &Config) -> Result<(), String> {
    let shared = match SharedUpdateDir::open(config, false) {
        Ok(dir) => dir,
        Err(_) => return Ok(()),
    };
    let result: RequestResult = match shared.read("request-result.json") {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    validate_nonce(&result.nonce)?;
    if !matches!(result.outcome.as_str(), "accepted" | "refused") {
        return Err("invalid request consumption result".into());
    }
    let path = config.state_dir.join("update/incoming").join(result.nonce);
    match fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    };
    shared.remove("request-result.json")
}
/// The directory remains removable until publishing ready.json. Drop guarantees
/// that cancellation, transport errors, write errors and policy failures clean it.
struct Staging {
    path: PathBuf,
    published: bool,
}
impl Drop for Staging {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub async fn queue_update(
    config: &Config,
    signed: &SignedManifest,
    url: &str,
    token: &str,
    http: &reqwest::Client,
) -> Result<String, String> {
    verify_manifest(config, signed, &config.state_dir.join("update"))?;
    let base = reqwest::Url::parse(&config.server_url).map_err(|e| e.to_string())?;
    if !url.starts_with('/')
        || url.starts_with("//")
        || url.contains('#')
        || url.contains('?')
        || url.contains('\\')
    {
        return Err(
            "update download must be an absolute API path without query or fragment".into(),
        );
    }
    let parsed = base.join(url).map_err(|e| e.to_string())?;
    if parsed.origin() != base.origin() {
        return Err("update URL changed server origin".into());
    }
    reap_consumed_request(config)?;
    let nonce = random_nonce();
    let incoming = config.state_dir.join("update").join("incoming");
    fs::create_dir_all(&incoming).map_err(|e| e.to_string())?;
    // One outstanding request per agent. The worker removes a consumed request;
    // do not accumulate packages indefinitely if the native helper is absent.
    if fs::read_dir(&incoming)
        .map_err(|e| e.to_string())?
        .next()
        .is_some()
    {
        return Err("a native update request is already queued".into());
    }
    let path = incoming.join(&nonce);
    fs::create_dir(&path).map_err(|e| e.to_string())?;
    let mut staging = Staging {
        path: path.clone(),
        published: false,
    };
    set_private_dir(&path)?;
    let artifact = path.join("artifact");
    let mut file = create_private_file(&artifact)?;
    let mut response = http
        .get(parsed.clone())
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| format!("package download failed: {e}"))?;
    if response.url().origin() != base.origin() {
        return Err("package download redirected outside the configured server origin".into());
    }
    if !response.status().is_success() {
        return Err(format!(
            "package download failed: HTTP {}",
            response.status()
        ));
    }
    let expected = signed.manifest.size_bytes;
    if let Some(length) = response.content_length() {
        if length != expected {
            return Err("HTTP Content-Length does not match signed package size".into());
        }
    }
    let mut count = 0u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("interrupted package download: {e}"))?
    {
        count = count
            .checked_add(chunk.len() as u64)
            .ok_or("package size overflow")?;
        if count > expected
            || count > config.updates.max_download_bytes
            || count > HARD_MAX_DOWNLOAD_BYTES
        {
            return Err("streamed package exceeds the signed or local size limit".into());
        }
        file.write_all(&chunk)
            .map_err(|e| format!("cannot stage package: {e}"))?;
        hash.update(&chunk);
    }
    if count != expected {
        return Err("interrupted package download: length differs from signed size".into());
    }
    if encode_hex(&hash.finalize()) != signed.manifest.sha256 {
        return Err("streamed package SHA-256 differs from signed manifest".into());
    }
    file.sync_all()
        .map_err(|e| format!("cannot fsync package: {e}"))?;
    drop(file);
    atomic_json(&path.join("manifest.json"), signed)?;
    sync_dir(&path)?;
    atomic_json(
        &path.join("ready.json"),
        &ReadyRequest {
            nonce: nonce.clone(),
            version: signed.manifest.version.clone(),
            package_kind: signed.manifest.package_kind,
            created_at: unix_now()?,
        },
    )?;
    sync_dir(&incoming)?;
    staging.published = true;
    Ok(nonce)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingUpdate {
    pub nonce: String,
    pub version: String,
    pub sequence: u64,
    pub started_at: u64,
    pub deadline: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub version: String,
    pub sequence: u64,
    pub at: u64,
    pub outcome: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateLedger {
    pub floor_version: String,
    pub floor_sequence: u64,
    pub pending: Option<PendingUpdate>,
    pub history: Vec<HistoryEntry>,
}
impl Default for UpdateLedger {
    fn default() -> Self {
        Self {
            floor_version: env!("CARGO_PKG_VERSION").into(),
            floor_sequence: 0,
            pending: None,
            history: Vec::new(),
        }
    }
}
pub fn read_ledger(ledger_dir: &Path) -> Result<UpdateLedger, String> {
    let path = ledger_dir.join("update-state.json");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err("update ledger must be a regular file".into());
            }
            let ledger: UpdateLedger = read_json(&path, MAX_LEDGER_BYTES)?;
            parse_version(&ledger.floor_version)?;
            if ledger.history.len() > 100 {
                return Err("update history exceeds its hard bound".into());
            }
            Ok(ledger)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdateLedger::default()),
        Err(e) => Err(e.to_string()),
    }
}
pub fn commit_pending(
    config: &Config,
    manifest: &ReleaseManifest,
    nonce: &str,
    ledger_dir: &Path,
) -> Result<(), String> {
    validate_nonce(nonce)?;
    let mut ledger = read_ledger(ledger_dir)?;
    if ledger.pending.is_some() {
        return Err("update already pending".into());
    }
    let now = unix_now()?;
    let pending = PendingUpdate {
        nonce: nonce.into(),
        version: manifest.version.clone(),
        sequence: manifest.sequence,
        started_at: now,
        deadline: now
            .checked_add(config.updates.health_timeout_secs)
            .ok_or("deadline overflow")?,
    };
    ledger.pending = Some(pending.clone());
    fs::create_dir_all(ledger_dir).map_err(|e| e.to_string())?;
    atomic_json(&ledger_dir.join("update-state.json"), &ledger)?;
    publish_pending_health(config, &pending)
}
/// Starts the health window only after native installation finishes, immediately
/// before restarting the endpoint. Package-manager runtime does not consume the
/// new process's heartbeat deadline. The protected transaction remains durable.
pub fn arm_health(
    config: &Config,
    ledger_dir: &Path,
    nonce: &str,
) -> Result<PendingUpdate, String> {
    validate_nonce(nonce)?;
    let mut ledger = read_ledger(ledger_dir)?;
    let pending = ledger.pending.as_mut().ok_or("no update is pending")?;
    if pending.nonce != nonce {
        return Err("update transaction nonce mismatch".into());
    }
    pending.started_at = unix_now()?;
    pending.deadline = pending
        .started_at
        .checked_add(config.updates.health_timeout_secs)
        .ok_or("health deadline overflow")?;
    let pending = pending.clone();
    atomic_json(&ledger_dir.join("update-state.json"), &ledger)?;
    publish_pending_health(config, &pending)?;
    Ok(pending)
}
fn publish_pending_health(config: &Config, pending: &PendingUpdate) -> Result<(), String> {
    let shared = SharedUpdateDir::open(config, true)?;
    shared.remove("health.json")?;
    shared.write("pending-health.json", pending, true)
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthAck {
    nonce: String,
    version: String,
    at: u64,
}
/// Called only after a successful heartbeat. Startup alone is not health.
pub fn ack_health(config: &Config) -> Result<(), String> {
    let shared = match SharedUpdateDir::open(config, false) {
        Ok(dir) => dir,
        Err(_) => return Ok(()),
    };
    let pending: PendingUpdate = match shared.read("pending-health.json") {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    validate_nonce(&pending.nonce)?;
    let now = unix_now()?;
    if pending.version != env!("CARGO_PKG_VERSION")
        || now < pending.started_at
        || now > pending.deadline
    {
        return Ok(());
    }
    shared.write(
        "health.json",
        &HealthAck {
            nonce: pending.nonce,
            version: pending.version,
            at: now,
        },
        false,
    )
}
/// Compatibility query for the local diagnostics CLI. Privileged supervisors
/// use health_status_for_pending with their root-owned transaction record.
pub fn health_status(config: &Config, nonce: &str, version: &str) -> Result<bool, String> {
    validate_nonce(nonce)?;
    let shared = match SharedUpdateDir::open(config, false) {
        Ok(dir) => dir,
        Err(_) => return Ok(false),
    };
    let pending: PendingUpdate = match shared.read("pending-health.json") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if pending.nonce != nonce || pending.version != version {
        return Ok(false);
    }
    health_status_for_pending(config, &pending)
}
/// Missing, malformed or replaced shared files are unhealthy. A hostile agent
/// cannot extend the watchdog's deadline by replacing pending-health.json.
pub fn health_status_for_pending(config: &Config, pending: &PendingUpdate) -> Result<bool, String> {
    validate_nonce(&pending.nonce)?;
    let shared = match SharedUpdateDir::open(config, false) {
        Ok(dir) => dir,
        Err(_) => return Ok(false),
    };
    let ack: HealthAck = match shared.read("health.json") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    Ok(ack.nonce == pending.nonce
        && ack.version == pending.version
        && ack.at >= pending.started_at
        && ack.at <= pending.deadline
        && ack.at <= unix_now()?)
}
pub fn finish_update(
    config: &Config,
    ledger_dir: &Path,
    nonce: &str,
    healthy: bool,
    reason: &str,
) -> Result<(), String> {
    validate_nonce(nonce)?;
    let mut ledger = read_ledger(ledger_dir)?;
    let pending = ledger.pending.as_ref().ok_or("no update is pending")?;
    if pending.nonce != nonce {
        return Err("update transaction nonce mismatch".into());
    }
    let record = HistoryEntry {
        version: pending.version.clone(),
        sequence: pending.sequence,
        at: unix_now()?,
        outcome: if healthy { "healthy" } else { "rolled_back" }.into(),
        reason: reason.chars().take(1024).collect(),
    };
    if healthy {
        if parse_version(&pending.version)? > parse_version(&ledger.floor_version)? {
            ledger.floor_version = pending.version.clone();
        }
        ledger.floor_sequence = ledger.floor_sequence.max(pending.sequence);
    }
    ledger.pending = None;
    ledger.history.push(record);
    let excess = ledger
        .history
        .len()
        .saturating_sub(config.updates.history_limit);
    if excess > 0 {
        ledger.history.drain(..excess);
    }
    atomic_json(&ledger_dir.join("update-state.json"), &ledger)?;
    // Cleanup uses held directory descriptors, including in the privileged helper.
    if let Ok(shared) = SharedUpdateDir::open(config, false) {
        let _ = shared.remove("pending-health.json");
        let _ = shared.remove("health.json");
    }

    Ok(())
}
/// Descriptor-relative shared mailbox I/O. The service owns this directory;
/// resolving a mutable parent by path from a privileged process is unsafe.
#[cfg(unix)]
struct SharedUpdateDir {
    directory: File,
}
#[cfg(unix)]
impl SharedUpdateDir {
    fn open(config: &Config, create: bool) -> Result<Self, String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let state = std::ffi::CString::new(config.state_dir.as_os_str().as_bytes())
            .map_err(|e| e.to_string())?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::open(state.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let state = unsafe { File::from_raw_fd(fd) };
        let update = c"update";
        let made =
            create && unsafe { libc::mkdirat(state.as_raw_fd(), update.as_ptr(), 0o750) } == 0;
        let fd = unsafe { libc::openat(state.as_raw_fd(), update.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        if made {
            use std::os::unix::fs::MetadataExt;
            let owner = state.metadata().map_err(|e| e.to_string())?;
            if unsafe { libc::geteuid() } == 0
                && unsafe { libc::fchown(directory.as_raw_fd(), owner.uid(), owner.gid()) } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            directory.sync_all().map_err(|e| e.to_string())?;
            state.sync_all().map_err(|e| e.to_string())?;
        }
        Ok(Self { directory })
    }
    fn remove(&self, name: &str) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        let name = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.to_string());
            }
        }
        self.directory.sync_all().map_err(|e| e.to_string())
    }
    fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T, String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
            return Err("shared update record is not a regular bounded file".into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err("shared update record grew beyond limit".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
    fn write<T: Serialize>(&self, name: &str, value: &T, public: bool) -> Result<(), String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        let temporary = std::ffi::CString::new(format!(".{}.tmp", random_nonce()))
            .map_err(|e| e.to_string())?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            if public && unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            file.sync_all().map_err(|e| e.to_string())?;
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            self.directory.sync_all().map_err(|e| e.to_string())
        })();
        if result.is_err() {
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0) };
        }
        result
    }
}
#[cfg(not(unix))]
struct SharedUpdateDir {
    path: PathBuf,
}
#[cfg(not(unix))]
impl SharedUpdateDir {
    fn open(config: &Config, create: bool) -> Result<Self, String> {
        let path = config.state_dir.join("update");
        if create {
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        }
        if !fs::symlink_metadata(&path)
            .map_err(|e| e.to_string())?
            .is_dir()
        {
            return Err("shared update directory must not be a symlink".into());
        }
        Ok(Self { path })
    }
    fn remove(&self, name: &str) -> Result<(), String> {
        match fs::remove_file(self.path.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T, String> {
        read_json(&self.path.join(name), MAX_MANIFEST_BYTES)
    }
    fn write<T: Serialize>(&self, name: &str, value: &T, _public: bool) -> Result<(), String> {
        atomic_json(&self.path.join(name), value)
    }
}
pub fn validate_nonce(nonce: &str) -> Result<(), String> {
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        Err("transaction nonce must contain 32 lowercase hex characters".into())
    } else {
        Ok(())
    }
}
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
fn parse_version(version: &str) -> Result<semver::Version, String> {
    if version.len() > 128 {
        return Err("version is too long".into());
    }
    semver::Version::parse(version)
        .map_err(|_| "update version must be valid semantic version".into())
}
pub fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|e| e.to_string())
}
fn random_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    encode_hex(&bytes)
}
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("expected {} hexadecimal characters", N * 2));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path, limit: u64) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!(
            "{} is not a regular bounded JSON file",
            path.display()
        ));
    }
    let mut file = open_read_nofollow(path)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("JSON file grew beyond limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
pub fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path.parent().ok_or("file has no parent directory")?;
    let temp = parent.join(format!(".{}.tmp", random_nonce()));
    let result = (|| {
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        let mut file = create_private_file(&temp)?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        replace_file(&temp, path)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
fn replace_file(from: &Path, to: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to).map_err(|e| e.to_string())
    }
}
pub fn sync_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("cannot fsync directory {}: {e}", path.display()))
    }
    #[cfg(windows)]
    {
        // Win32 does not support FlushFileBuffers on directory handles.
        // Every durable publication uses MoveFileExW(MOVEFILE_WRITE_THROUGH)
        // after FlushFileBuffers on the complete file. This check makes the
        // platform distinction explicit without issuing an invalid flush.
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err("durable publication parent must be a directory".into());
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err("directory durability unsupported on this OS".into())
    }
}
fn create_private_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x80000000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|e| e.to_string())
}
fn open_read_nofollow(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|e| e.to_string())
}
fn set_private_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lariska-update-test-{}", random_nonce()));
        fs::create_dir(&dir).unwrap();
        dir
    }
    fn fixture_config(state: &Path) -> Config {
        let kind = if cfg!(target_os = "macos") {
            PackageKind::Pkg
        } else if cfg!(target_os = "windows") {
            PackageKind::Msi
        } else {
            PackageKind::Deb
        };
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        Config {
            server_url: "https://example.test".into(),
            provisioning_key_file: state.join("key"),
            state_dir: state.into(),
            inventory_interval: std::time::Duration::from_secs(3600),
            heartbeat_interval: std::time::Duration::from_secs(60),
            request_timeout: std::time::Duration::from_secs(5),
            tls_ca_file: None,
            log_level: "info".into(),
            allow_plain_http: false,
            allow_insecure_updates: false,
            inventory_full_refresh_interval: std::time::Duration::from_secs(86400),
            max_spool_entries: 200,
            updates: UpdateConfig {
                trusted_keys: vec![TrustedKey {
                    id: "test-key".into(),
                    public_key: encode_hex(signing.verifying_key().as_bytes()),
                    revoked: false,
                }],
                package_kind: Some(kind),
                ..Default::default()
            },
        }
    }
    fn signed(config: &Config, bytes: &[u8]) -> SignedManifest {
        let manifest = ReleaseManifest {
            schema: 1,
            key_id: "test-key".into(),
            version: "1.2.3".into(),
            platform: crate::managed::target_triple(),
            package_kind: config.updates.package_kind.unwrap(),
            size_bytes: bytes.len() as u64,
            sha256: encode_hex(&Sha256::digest(bytes)),
            expires_at: unix_now().unwrap() + 3600,
            sequence: 10,
        };
        sign(manifest)
    }
    fn sign(manifest: ReleaseManifest) -> SignedManifest {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signature = encode_hex(&key.sign(&canonical_manifest(&manifest).unwrap()).to_bytes());
        SignedManifest {
            manifest,
            signature,
        }
    }
    #[test]
    fn canonical_bytes_sort_keys_and_bind_every_field() {
        let dir = dir();
        let config = fixture_config(&dir);
        let signed = signed(&config, b"new package");
        let bytes = canonical_manifest(&signed.manifest).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("{\"expires_at\":"));
        assert!(!text.contains('\n'));
        let mut fields = Vec::new();
        let mut m = signed.clone();
        m.manifest.version = "1.2.4".into();
        fields.push(m);
        let mut m = signed.clone();
        m.manifest.platform = "foreign-platform".into();
        fields.push(m);
        let mut m = signed.clone();
        m.manifest.size_bytes += 1;
        fields.push(m);
        let mut m = signed.clone();
        m.manifest.sha256 = "0".repeat(64);
        fields.push(m);
        let mut m = signed.clone();
        m.manifest.expires_at += 1;
        fields.push(m);
        let mut m = signed.clone();
        m.manifest.sequence += 1;
        fields.push(m);
        let mut m = signed.clone();
        m.manifest.key_id = "unknown".into();
        fields.push(m);
        for modified in fields {
            assert!(verify_manifest(&config, &modified, &dir).is_err());
        }
        verify_manifest(&config, &signed, &dir).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn trust_is_local_and_revocation_expiry_and_size_fail_closed() {
        let dir = dir();
        let mut config = fixture_config(&dir);
        let signed = signed(&config, b"package");
        config.updates.trusted_keys[0].revoked = true;
        assert!(verify_manifest(&config, &signed, &dir)
            .unwrap_err()
            .contains("revoked"));
        config.updates.trusted_keys.clear();
        assert!(verify_manifest(&config, &signed, &dir).is_err());
        config = fixture_config(&dir);
        let mut m = signed.manifest.clone();
        m.expires_at = unix_now().unwrap();
        assert!(verify_manifest(&config, &sign(m), &dir)
            .unwrap_err()
            .contains("expired"));
        config.updates.max_download_bytes = 1;
        assert!(verify_manifest(&config, &signed, &dir)
            .unwrap_err()
            .contains("size"));
        config.updates.max_download_bytes = HARD_MAX_DOWNLOAD_BYTES + 1;
        assert!(config.updates.validate().is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn artifact_must_match_signed_size_digest_and_regular_file() {
        let dir = dir();
        let config = fixture_config(&dir);
        let signed = signed(&config, b"package");
        let artifact = dir.join("artifact");
        fs::write(&artifact, b"package").unwrap();
        verify_artifact(&config, &signed, &artifact).unwrap();
        fs::write(&artifact, b"packagE").unwrap();
        assert!(verify_artifact(&config, &signed, &artifact).is_err());
        fs::write(&artifact, b"package extra").unwrap();
        assert!(verify_artifact(&config, &signed, &artifact).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&artifact, dir.join("alias")).unwrap();
            assert!(verify_artifact(&config, &signed, &dir.join("alias")).is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn durable_floor_survives_rollback_and_emergency_override_is_exact_and_signed() {
        let dir = dir();
        let mut config = fixture_config(&dir);
        let signed = signed(&config, b"package");
        let nonce = random_nonce();
        commit_pending(&config, &signed.manifest, &nonce, &dir).unwrap();
        finish_update(&config, &dir, &nonce, true, "healthy heartbeat").unwrap();
        let mut older = signed.manifest.clone();
        older.version = "1.2.2".into();
        older.sequence = 9;
        let older = sign(older);
        assert!(verify_manifest(&config, &older, &dir)
            .unwrap_err()
            .contains("floor"));
        config.updates.emergency_version = Some("1.2.1".into());
        assert!(verify_manifest(&config, &older, &dir).is_err());
        config.updates.emergency_version = Some("1.2.2".into());
        verify_manifest(&config, &older, &dir).unwrap();
        let nonce = random_nonce();
        commit_pending(&config, &older.manifest, &nonce, &dir).unwrap();
        finish_update(&config, &dir, &nonce, true, "local emergency").unwrap();
        let floor = read_ledger(&dir).unwrap();
        assert_eq!(floor.floor_version, "1.2.3");
        assert_eq!(floor.floor_sequence, 10);
        let nonce = random_nonce();
        commit_pending(&config, &signed.manifest, &nonce, &dir).unwrap();
        finish_update(&config, &dir, &nonce, false, "new binary failed to start").unwrap();
        assert_eq!(read_ledger(&dir).unwrap().floor_version, "1.2.3");
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn pending_blocks_new_transactions_and_history_is_bounded() {
        let dir = dir();
        let mut config = fixture_config(&dir);
        config.updates.history_limit = 2;
        let signed = signed(&config, b"package");
        for _ in 0..5 {
            let nonce = random_nonce();
            commit_pending(&config, &signed.manifest, &nonce, &dir).unwrap();
            assert!(verify_manifest(&config, &signed, &dir).is_err());
            assert!(finish_update(&config, &dir, &random_nonce(), false, "wrong nonce").is_err());
            finish_update(&config, &dir, &nonce, false, "failed startup").unwrap();
        }
        assert_eq!(read_ledger(&dir).unwrap().history.len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn health_requires_matching_version_nonce_and_heartbeat_ack() {
        let dir = dir();
        let config = fixture_config(&dir);
        let mut manifest = signed(&config, b"package").manifest;
        manifest.version = env!("CARGO_PKG_VERSION").into();
        let nonce = random_nonce();
        commit_pending(&config, &manifest, &nonce, &dir).unwrap();
        assert!(!health_status(&config, &nonce, &manifest.version).unwrap());
        ack_health(&config).unwrap();
        assert!(health_status(&config, &nonce, &manifest.version).unwrap());
        assert!(!health_status(&config, &random_nonce(), &manifest.version).unwrap());
        finish_update(&config, &dir, &nonce, false, "test complete").unwrap();
        manifest.version = "999.0.0".into();
        let nonce = random_nonce();
        commit_pending(&config, &manifest, &nonce, &dir).unwrap();
        ack_health(&config).unwrap();
        assert!(!health_status(&config, &nonce, &manifest.version).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
    async fn raw_server(body: &'static [u8]) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let _received = socket.read(&mut request).await.unwrap();
            socket.write_all(body).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        (format!("http://{addr}"), task)
    }
    #[tokio::test]
    async fn chunked_oversize_interrupted_and_hash_failure_leave_no_request() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\npackageX\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\npack\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n7\r\npackagE\r\n0\r\n\r\n"[..],
        ] {let dir=dir();let mut config=fixture_config(&dir);let signed=signed(&config,b"package");let(server,task)=raw_server(response).await;config.server_url=server;assert!(queue_update(&config,&signed,"/package","token",&reqwest::Client::new()).await.is_err());task.await.unwrap();assert_eq!(fs::read_dir(dir.join("update/incoming")).unwrap().count(),0);fs::remove_dir_all(dir).unwrap();}
    }
    #[tokio::test]
    async fn signed_package_is_staged_without_changing_executable_and_queue_is_bounded() {
        let dir = dir();
        let mut config = fixture_config(&dir);
        let signed = signed(&config, b"package");
        let (server, task) =
            raw_server(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npackage")
                .await;
        config.server_url = server;
        let nonce = queue_update(
            &config,
            &signed,
            "/package",
            "token",
            &reqwest::Client::new(),
        )
        .await
        .unwrap();
        task.await.unwrap();
        let staged = dir.join("update/incoming").join(nonce);
        verify_files(
            &config,
            &staged.join("manifest.json"),
            &staged.join("artifact"),
            &dir,
        )
        .unwrap();
        assert!(staged.join("ready.json").is_file());
        assert!(queue_update(
            &config,
            &signed,
            "/package",
            "token",
            &reqwest::Client::new()
        )
        .await
        .unwrap_err()
        .contains("already queued"));
        fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn remote_origin_and_path_injection_are_refused_before_fetch() {
        let dir = dir();
        let config = fixture_config(&dir);
        let signed = signed(&config, b"package");
        for url in [
            "https://evil.test/package",
            "//evil.test/package",
            "/package?token=1",
            "/package#hash",
            "/\\evil.test/package",
        ] {
            assert!(
                queue_update(&config, &signed, url, "token", &reqwest::Client::new())
                    .await
                    .is_err()
            );
        }
        assert!(!dir.join("update/incoming").exists());
        fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn shared_mailbox_symlinks_cannot_redirect_privileged_writes() {
        let dir = dir();
        let config = fixture_config(&dir);
        let outside = dir.join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("update")).unwrap();
        let manifest = signed(&config, b"package").manifest;
        assert!(commit_pending(&config, &manifest, &random_nonce(), &dir).is_err());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn mutable_shared_deadline_cannot_extend_authoritative_health_deadline() {
        let dir = dir();
        let config = fixture_config(&dir);
        let mut manifest = signed(&config, b"package").manifest;
        manifest.version = env!("CARGO_PKG_VERSION").into();
        let nonce = random_nonce();
        commit_pending(&config, &manifest, &nonce, &dir).unwrap();
        let mut protected = read_ledger(&dir).unwrap().pending.unwrap();
        protected.deadline = protected.started_at.saturating_sub(1);
        ack_health(&config).unwrap();
        assert!(!health_status_for_pending(&config, &protected).unwrap());
        fs::write(dir.join("update/health.json"), b"corrupt").unwrap();
        assert!(!health_status_for_pending(&config, &protected).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn cancelled_download_cleans_unpublished_staging() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = dir();
        let mut config = fixture_config(&dir);
        let signed = signed(&config, b"package");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.server_url = format!("http://{}", listener.local_addr().unwrap());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let _received = socket.read(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npack")
                .await
                .unwrap();
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let client_config = config.clone();
        let task = tokio::spawn(async move {
            queue_update(
                &client_config,
                &signed,
                "/package",
                "token",
                &reqwest::Client::new(),
            )
            .await
        });
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        server.abort();
        let _ = server.await;
        assert_eq!(
            fs::read_dir(dir.join("update/incoming")).unwrap().count(),
            0
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn helper_acknowledgement_reaps_only_the_named_agent_request() {
        let dir = dir();
        let config = fixture_config(&dir);
        let nonce = random_nonce();
        let request = dir.join("update/incoming").join(&nonce);
        fs::create_dir_all(&request).unwrap();
        fs::write(request.join("artifact"), b"package").unwrap();
        ack_request(&config, &nonce, "accepted").unwrap();
        reap_consumed_request(&config).unwrap();
        assert!(!request.exists());
        assert!(ack_request(&config, "../../outside", "refused").is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn cross_language_fixture_has_exact_canonical_bytes_and_a_real_signature() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/signed_manifest_v1.json"))
                .unwrap();
        let signed: SignedManifest =
            serde_json::from_value(fixture["signed_manifest"].clone()).unwrap();
        assert_eq!(
            canonical_manifest(&signed.manifest).unwrap(),
            fixture["canonical_utf8"].as_str().unwrap().as_bytes()
        );
        let public = decode_hex::<32>(fixture["public_key"].as_str().unwrap()).unwrap();
        let verifying = VerifyingKey::from_bytes(&public).unwrap();
        verifying
            .verify_strict(
                &canonical_manifest(&signed.manifest).unwrap(),
                &Signature::from_bytes(&decode_hex::<64>(&signed.signature).unwrap()),
            )
            .unwrap();
    }
}
