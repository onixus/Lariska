use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
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
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes)?;
    Ok(format!(
        "agent_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

#[cfg(unix)]
fn fill_random(bytes: &mut [u8]) -> Result<(), IdentityError> {
    let mut file = fs::File::open("/dev/urandom")
        .map_err(|error| IdentityError::Io(format!("failed to open /dev/urandom: {error}")))?;
    file.read_exact(bytes)
        .map_err(|error| IdentityError::Io(format!("failed to read random bytes: {error}")))
}

#[cfg(not(unix))]
fn fill_random(bytes: &mut [u8]) -> Result<(), IdentityError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| IdentityError::Io(format!("system clock error: {error}")))?
        .as_nanos();
    let pid = u128::from(std::process::id());
    bytes.copy_from_slice(&(now ^ pid).to_le_bytes());
    Ok(())
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
