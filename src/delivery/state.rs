use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const STATE_FILE: &str = "delivery-state-v1.json";
const FORMAT_VERSION: u16 = 1;
const MAX_STATE_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedState {
    pub digest: String,
    pub accepted_at_unix_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StateDocument {
    format_version: u16,
    digest: String,
    accepted_at_unix_secs: u64,
}

pub struct DeliveryStateStore {
    path: PathBuf,
}

impl DeliveryStateStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(STATE_FILE),
        }
    }

    pub fn load(&self) -> Result<Option<AcceptedState>, String> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "failed to open delivery state {}: {error}",
                    self.path.display()
                ))
            }
        };

        let mut bytes = Vec::with_capacity(512);
        file.take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read delivery state: {error}"))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(format!(
                "delivery state exceeds the {MAX_STATE_BYTES} byte limit"
            ));
        }

        let document: StateDocument = serde_json::from_slice(&bytes)
            .map_err(|error| format!("failed to parse delivery state: {error}"))?;
        if document.format_version != FORMAT_VERSION {
            return Err(format!(
                "unsupported delivery state format version {}",
                document.format_version
            ));
        }
        if document.digest.len() != 64
            || !document.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("delivery state contains an invalid SHA-256 digest".to_string());
        }
        if document.accepted_at_unix_secs == 0 {
            return Err("delivery state contains an invalid acceptance timestamp".to_string());
        }

        Ok(Some(AcceptedState {
            digest: document.digest.to_ascii_lowercase(),
            accepted_at_unix_secs: document.accepted_at_unix_secs,
        }))
    }

    pub fn load_or_discard_invalid(&self) -> Option<AcceptedState> {
        match self.load() {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(%error, "discarding invalid delivery state");
                if let Err(remove_error) = fs::remove_file(&self.path) {
                    if remove_error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            error = %remove_error,
                            path = %self.path.display(),
                            "could not remove invalid delivery state"
                        );
                    }
                }
                None
            }
        }
    }

    pub fn store(&self, state: &AcceptedState) -> Result<(), String> {
        let document = StateDocument {
            format_version: FORMAT_VERSION,
            digest: state.digest.clone(),
            accepted_at_unix_secs: state.accepted_at_unix_secs,
        };
        let bytes = serde_json::to_vec(&document)
            .map_err(|error| format!("failed to serialize delivery state: {error}"))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(format!(
                "delivery state is {} bytes, exceeding the {MAX_STATE_BYTES} byte limit",
                bytes.len()
            ));
        }

        let temp_path = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .map_err(|error| format!("failed to create delivery state: {error}"))?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("failed to write delivery state: {error}"))
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        replace_file(&temp_path, &self.path).map_err(|error| {
            format!(
                "failed to publish delivery state {}: {error}",
                self.path.display()
            )
        })?;
        sync_parent_dir(&self.path).map_err(|error| {
            format!(
                "failed to sync delivery state directory {}: {error}",
                self.path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .display()
            )
        })?;
        Ok(())
    }
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::remove_file(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(source, destination)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lariska-delivery-state-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn accepted() -> AcceptedState {
        AcceptedState {
            digest: "a".repeat(64),
            accepted_at_unix_secs: 1_800_000_000,
        }
    }

    #[test]
    fn accepted_state_round_trips() {
        let state_dir = temp_state_dir("roundtrip");
        let store = DeliveryStateStore::new(&state_dir);
        store.store(&accepted()).unwrap();

        assert_eq!(store.load().unwrap(), Some(accepted()));
        fs::remove_dir_all(state_dir).ok();
    }

    #[test]
    fn invalid_state_is_rejected_and_removed() {
        let state_dir = temp_state_dir("invalid");
        let store = DeliveryStateStore::new(&state_dir);
        fs::write(&store.path, b"not json").unwrap();

        assert!(store.load_or_discard_invalid().is_none());
        assert!(!store.path.exists());
        fs::remove_dir_all(state_dir).ok();
    }

    #[test]
    fn oversized_state_is_rejected() {
        let state_dir = temp_state_dir("oversized");
        let store = DeliveryStateStore::new(&state_dir);
        fs::write(&store.path, vec![b'x'; MAX_STATE_BYTES + 1]).unwrap();

        assert!(store.load().is_err());
        fs::remove_dir_all(state_dir).ok();
    }
}
