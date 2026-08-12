use crate::model::{EndpointIdentifier, IdentifierType};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const IDENTITY_FILE: &str = "agent_id";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentity {
    pub agent_id: String,
}

pub fn load_or_create(state_dir: &Path) -> Result<AgentIdentity, IdentityError> {
    fs::create_dir_all(state_dir).map_err(|error| {
        IdentityError::Io(format!(
            "failed to create state directory {}: {error}",
            state_dir.display()
        ))
    })?;

    let path = state_dir.join(IDENTITY_FILE);
    if path.exists() {
        return load(&path);
    }

    let identity = AgentIdentity {
        agent_id: generate_agent_id()?,
    };
    persist_atomically(&path, &identity.agent_id)?;
    Ok(identity)
}

fn load(path: &Path) -> Result<AgentIdentity, IdentityError> {
    let agent_id = fs::read_to_string(path)
        .map_err(|error| IdentityError::Io(format!("failed to read identity: {error}")))?
        .trim()
        .to_string();

    if !is_valid_agent_id(&agent_id) {
        return Err(IdentityError::Corrupt(
            "identity file does not contain a valid agent id".to_string(),
        ));
    }

    Ok(AgentIdentity { agent_id })
}

fn persist_atomically(path: &Path, agent_id: &str) -> Result<(), IdentityError> {
    let temp_path = temp_identity_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|error| {
            IdentityError::Io(format!("failed to create identity temp file: {error}"))
        })?;

    file.write_all(agent_id.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| IdentityError::Io(format!("failed to write identity: {error}")))?;

    fs::rename(&temp_path, path)
        .map_err(|error| IdentityError::Io(format!("failed to persist identity: {error}")))?;
    Ok(())
}

fn temp_identity_path(path: &Path) -> PathBuf {
    path.with_extension(format!("tmp-{}", std::process::id()))
}

fn generate_agent_id() -> Result<String, IdentityError> {
    random_hex_id("agent")
}

/// Generates a fresh, opaque snapshot ID (Plan.md §7: "generated once and
/// retained across retries"). The server treats it as an opaque string with
/// no format requirement — only uniqueness matters.
pub fn generate_snapshot_id() -> Result<String, IdentityError> {
    random_hex_id("snap")
}

fn random_hex_id(prefix: &str) -> Result<String, IdentityError> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes)?;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("{prefix}_{hex}"))
}

/// Fill ID material from the operating system CSPRNG on every platform.
/// `OsRng` delegates to the platform's cryptographically secure random source
/// (including BCryptGenRandom/RtlGenRandom-backed facilities on Windows), so
/// IDs are not derived from predictable process metadata such as PID/time.
fn fill_random(bytes: &mut [u8]) -> Result<(), IdentityError> {
    let mut rng = OsRng;
    rng.try_fill_bytes(bytes)
        .map_err(|error| IdentityError::Io(format!("failed to obtain OS randomness: {error}")))
}

/// Platform evidence supplementing the random `agent_id` — never a
/// replacement for it (Plan.md §8 rule 3: never derive identity from MAC
/// address or hostname alone; here the primary key is `agent_id`, and these
/// are additional matching evidence the server can use for reconciliation).
///
/// None of Linux's `/etc/machine-id`, Windows' `MachineGuid`, or macOS'
/// `IOPlatformUUID` is literally a MAC address, hardware serial, or TPM
/// endorsement key — the four identifier types the server accepts. Of those,
/// `bios_uuid_hash` is the closest semantic fit for "the platform's
/// software/hardware-assigned unique ID", so all three are reported under
/// that type. This is a documented policy choice, not a hard contract
/// guarantee from the server.
pub fn platform_identifiers() -> Vec<EndpointIdentifier> {
    let mut identifiers = Vec::new();

    if let Some(raw) = platform_uuid_raw() {
        identifiers.push(EndpointIdentifier {
            identifier_type: IdentifierType::BiosUuidHash,
            value_hash: hash_identifier(&raw),
        });
    }

    identifiers
}

/// SHA-256 over the lowercased, trimmed identifier — no salt. A salt would
/// make the same physical machine hash differently per agent install, which
/// would break the server's `(tenant_id, identifier_type, value_hash)`
/// dedup/reconciliation matching across reinstalls.
fn hash_identifier(raw: &str) -> String {
    let normalized = raw.trim().to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(target_os = "linux")]
fn platform_uuid_raw() -> Option<String> {
    fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "windows")]
fn platform_uuid_raw() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography").ok()?;
    let guid: String = key.get_value("MachineGuid").ok()?;
    let trimmed = guid.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(target_os = "macos")]
fn platform_uuid_raw() -> Option<String> {
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .and_then(|line| line.split('"').nth(3))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn platform_uuid_raw() -> Option<String> {
    None
}

fn is_valid_agent_id(agent_id: &str) -> bool {
    let Some(value) = agent_id.strip_prefix("agent_") else {
        return false;
    };

    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
    Io(String),
    Corrupt(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) | Self::Corrupt(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_identifier_is_deterministic_and_case_insensitive() {
        let lower = hash_identifier("abc123-def456");
        let upper = hash_identifier("ABC123-DEF456");
        let padded = hash_identifier("  abc123-def456  ");

        assert_eq!(lower, upper);
        assert_eq!(lower, padded);
        assert_eq!(lower.len(), 64); // hex-encoded SHA-256
    }

    #[test]
    fn hash_identifier_differs_for_different_input() {
        assert_ne!(hash_identifier("machine-a"), hash_identifier("machine-b"));
    }

    #[test]
    fn generated_ids_have_expected_format_and_are_distinct() {
        let first = generate_agent_id().expect("agent id should be generated");
        let second = generate_agent_id().expect("agent id should be generated");
        let snapshot = generate_snapshot_id().expect("snapshot id should be generated");

        assert!(is_valid_agent_id(&first));
        assert!(is_valid_agent_id(&second));
        assert_ne!(first, second);
        assert!(snapshot.starts_with("snap_"));
        assert_eq!(snapshot.len(), "snap_".len() + 32);
        assert!(snapshot["snap_".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn load_or_create_reuses_existing_identity() {
        let state_dir =
            std::env::temp_dir().join(format!("lariska-id-test-{}", std::process::id()));
        let first = load_or_create(&state_dir).expect("identity should be created");
        let second = load_or_create(&state_dir).expect("identity should be loaded");

        assert_eq!(first, second);

        fs::remove_dir_all(state_dir).expect("state dir should be removed");
    }

    #[test]
    fn load_or_create_rejects_corrupt_identity() {
        let state_dir =
            std::env::temp_dir().join(format!("lariska-corrupt-id-test-{}", std::process::id()));
        fs::create_dir_all(&state_dir).expect("state dir should be created");
        fs::write(state_dir.join(IDENTITY_FILE), "not-valid").expect("identity should be written");

        let error = load_or_create(&state_dir).expect_err("corrupt identity should fail");

        assert_eq!(
            error,
            IdentityError::Corrupt("identity file does not contain a valid agent id".to_string())
        );

        fs::remove_dir_all(state_dir).expect("state dir should be removed");
    }
}
