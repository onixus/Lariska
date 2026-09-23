use crate::model::InventorySnapshot;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const SPOOL_SUBDIR: &str = "spool";
const QUARANTINE_SUBDIR: &str = "spool/quarantine";
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SPOOL_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
pub enum SpoolError {
    Io(String),
    Capacity(String),
}

impl fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) | Self::Capacity(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SpoolError {}

#[derive(Debug)]
struct PendingFile {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
}

/// Durable local queue of not-yet-acknowledged inventory snapshots. A
/// snapshot is written here *before* any network submission is attempted,
/// so killing the process mid-upload never loses it. Pending entries are
/// enumerated as paths and decoded one at a time, keeping memory bounded by a
/// single snapshot rather than by the whole outage backlog.
pub struct Spool {
    dir: PathBuf,
    quarantine_dir: PathBuf,
}

impl Spool {
    pub fn open(state_dir: &Path) -> Result<Self, SpoolError> {
        let dir = state_dir.join(SPOOL_SUBDIR);
        let quarantine_dir = state_dir.join(QUARANTINE_SUBDIR);
        fs::create_dir_all(&dir)
            .map_err(|error| SpoolError::Io(format!("failed to create spool dir: {error}")))?;
        fs::create_dir_all(&quarantine_dir)
            .map_err(|error| SpoolError::Io(format!("failed to create quarantine dir: {error}")))?;
        Ok(Self {
            dir,
            quarantine_dir,
        })
    }

    fn entry_path(&self, snapshot_id: &str) -> PathBuf {
        self.dir.join(format!("{snapshot_id}.json.zst"))
    }

    pub fn write(&self, snapshot: &InventorySnapshot) -> Result<(), SpoolError> {
        let path = self.entry_path(&snapshot.snapshot_id);
        let temp_path = path.with_extension(format!("tmp-{}", std::process::id()));
        let payload = snapshot.to_canonical_json();

        if payload.len() > MAX_SNAPSHOT_BYTES {
            return Err(SpoolError::Capacity(format!(
                "snapshot {} is {} bytes, exceeding the {} byte spool entry limit",
                snapshot.snapshot_id,
                payload.len(),
                MAX_SNAPSHOT_BYTES
            )));
        }

        let write_result = (|| -> Result<(), SpoolError> {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .map_err(|error| {
                    SpoolError::Io(format!("failed to create spool temp file: {error}"))
                })?;
            let mut encoder = zstd::stream::write::Encoder::new(file, 3)
                .map_err(|error| SpoolError::Io(format!("failed to start compression: {error}")))?;
            encoder
                .write_all(payload.as_bytes())
                .map_err(|error| SpoolError::Io(format!("failed to compress snapshot: {error}")))?;
            let file = encoder.finish().map_err(|error| {
                SpoolError::Io(format!("failed to finish compression: {error}"))
            })?;
            file.sync_all()
                .map_err(|error| SpoolError::Io(format!("failed to sync spool entry: {error}")))?;
            Ok(())
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        fs::rename(&temp_path, &path)
            .map_err(|error| SpoolError::Io(format!("failed to persist spool entry: {error}")))?;
        sync_parent_dir(&path)?;
        Ok(())
    }

    pub fn remove(&self, snapshot_id: &str) -> Result<(), SpoolError> {
        let zst_path = self.dir.join(format!("{snapshot_id}.json.zst"));
        let json_path = self.dir.join(format!("{snapshot_id}.json"));

        let mut last_err = None;
        for path in [&zst_path, &json_path] {
            if let Err(error) = fs::remove_file(path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    last_err = Some(error);
                }
            } else {
                let _ = sync_parent_dir(path);
            }
        }
        if let Some(error) = last_err {
            Err(SpoolError::Io(format!(
                "failed to remove spool entry: {error}"
            )))
        } else {
            Ok(())
        }
    }

    /// Moves a spool entry aside so it stops being retried every cycle,
    /// without deleting it outright.
    pub fn quarantine_by_id(&self, snapshot_id: &str) -> Result<(), SpoolError> {
        let zst_path = self.dir.join(format!("{snapshot_id}.json.zst"));
        let json_path = self.dir.join(format!("{snapshot_id}.json"));
        for path in [zst_path, json_path] {
            if path.exists() {
                self.quarantine(&path)?;
            }
        }
        Ok(())
    }

    fn quarantine(&self, path: &Path) -> Result<(), SpoolError> {
        let Some(file_name) = path.file_name() else {
            return Ok(());
        };
        let destination = self.quarantine_dir.join(file_name);
        fs::rename(path, &destination).map_err(|error| {
            SpoolError::Io(format!("failed to quarantine spool entry: {error}"))
        })?;
        sync_parent_dir(path)?;
        sync_parent_dir(&destination)?;
        Ok(())
    }

    fn pending_files(&self) -> Result<Vec<PendingFile>, SpoolError> {
        let mut candidates = Vec::new();

        for dir_entry in fs::read_dir(&self.dir)
            .map_err(|error| SpoolError::Io(format!("failed to read spool dir: {error}")))?
        {
            let dir_entry = dir_entry
                .map_err(|error| SpoolError::Io(format!("failed to read spool entry: {error}")))?;
            let path = dir_entry.path();
            let is_spool_file = path.to_string_lossy().ends_with(".json.zst")
                || path.extension().and_then(|ext| ext.to_str()) == Some("json");
            if !is_spool_file {
                continue;
            }
            let metadata = dir_entry.metadata().map_err(|error| {
                SpoolError::Io(format!("failed to stat {}: {error}", path.display()))
            })?;
            candidates.push(PendingFile {
                path,
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                size: metadata.len(),
            });
        }

        candidates.sort_by_key(|entry| entry.modified);
        Ok(candidates)
    }

    /// Pending entry paths, oldest first. No JSON is parsed and no zstd stream
    /// is expanded here, so a long outage costs only path metadata in memory.
    pub fn pending_paths(&self) -> Result<Vec<PathBuf>, SpoolError> {
        self.pending_files()
            .map(|entries| entries.into_iter().map(|entry| entry.path).collect())
    }

    /// Decode and validate one pending entry. Corrupt, oversized and invalid
    /// entries are quarantined and skipped so they cannot block newer data.
    pub fn read_pending(&self, path: &Path) -> Result<Option<InventorySnapshot>, SpoolError> {
        match read_entry(path) {
            Ok(snapshot) => Ok(Some(snapshot)),
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "quarantining invalid spool entry"
                );
                self.quarantine(path)?;
                Ok(None)
            }
        }
    }

    /// Test/diagnostic helper. Production delivery uses `pending_paths` and
    /// `read_pending`, so it never retains all decoded snapshots at once.
    #[cfg(test)]
    pub fn list_pending(&self) -> Result<Vec<(PathBuf, InventorySnapshot)>, SpoolError> {
        let mut pending = Vec::new();
        for path in self.pending_paths()? {
            if let Some(snapshot) = self.read_pending(&path)? {
                pending.push((path, snapshot));
            }
        }
        Ok(pending)
    }

    /// Evicts oldest pending entries until both the configured entry limit
    /// and the hard spool byte limit are satisfied. This operates only on file
    /// metadata: enforcing capacity must not decode an entire offline backlog.
    pub fn enforce_limit(&self, max_entries: usize) -> Result<Vec<String>, SpoolError> {
        let entries = self.pending_files()?;
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let max_entries = max_entries.max(1);
        let mut total_bytes = entries
            .iter()
            .fold(0_u64, |total, entry| total.saturating_add(entry.size));
        let mut remaining_entries = entries.len();
        let mut evicted = Vec::new();

        for entry in entries {
            if remaining_entries <= max_entries && total_bytes <= MAX_SPOOL_BYTES {
                break;
            }
            if remaining_entries <= 1 {
                break;
            }

            fs::remove_file(&entry.path)
                .map_err(|error| SpoolError::Io(format!("failed to evict spool entry: {error}")))?;
            sync_parent_dir(&entry.path)?;
            remaining_entries -= 1;
            total_bytes = total_bytes.saturating_sub(entry.size);
            evicted.push(snapshot_id_from_path(&entry.path));
        }

        Ok(evicted)
    }
}

fn snapshot_id_from_path(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");
    name.strip_suffix(".json.zst")
        .or_else(|| name.strip_suffix(".json"))
        .unwrap_or(name)
        .to_string()
}

fn is_zstd_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == [0x28, 0xB5, 0x2F, 0xFD]
}

fn read_entry(path: &Path) -> Result<InventorySnapshot, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let compressed_size = file.metadata().map_err(|error| error.to_string())?.len();
    if compressed_size > MAX_SNAPSHOT_BYTES as u64 {
        return Err(format!(
            "spool entry exceeds the {MAX_SNAPSHOT_BYTES} byte compressed-input limit"
        ));
    }

    let mut magic = [0_u8; 4];
    let magic_len = file.read(&mut magic).map_err(|error| error.to_string())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let compressed = path.to_string_lossy().ends_with(".zst") || is_zstd_magic(&magic[..magic_len]);

    let mut json_bytes = Vec::with_capacity(64 * 1024);
    if compressed {
        let decoder = zstd::stream::read::Decoder::new(file)
            .map_err(|error| format!("failed to open compressed spool entry: {error}"))?;
        decoder
            .take((MAX_SNAPSHOT_BYTES + 1) as u64)
            .read_to_end(&mut json_bytes)
            .map_err(|error| format!("failed to decompress spool entry: {error}"))?;
    } else {
        file.take((MAX_SNAPSHOT_BYTES + 1) as u64)
            .read_to_end(&mut json_bytes)
            .map_err(|error| error.to_string())?;
    }

    if json_bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "decompressed spool entry exceeds the {MAX_SNAPSHOT_BYTES} byte limit"
        ));
    }

    let snapshot: InventorySnapshot =
        serde_json::from_slice(&json_bytes).map_err(|error| error.to_string())?;
    snapshot.validate().map_err(|error| error.to_string())?;
    Ok(snapshot)
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<(), SpoolError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            SpoolError::Io(format!(
                "failed to sync spool directory {}: {error}",
                parent.display()
            ))
        })
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<(), SpoolError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SoftwareSource;
    use std::collections::BTreeMap;

    fn temp_state_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lariska-spool-test-{label}-{}", std::process::id()))
    }

    fn sample_snapshot(snapshot_id: &str) -> InventorySnapshot {
        InventorySnapshot::new(
            snapshot_id.to_string(),
            "agent_0123456789abcdef0123456789abcdef".to_string(),
            "2026-07-24T08:00:00Z".to_string(),
            "workstation".to_string(),
            Some("linux".to_string()),
            Some("Ubuntu".to_string()),
            Some("24.04".to_string()),
            Some("x86_64".to_string()),
            "0.1.0".to_string(),
            BTreeMap::new(),
            Vec::new(),
            vec![crate::model::SoftwareEntry {
                name: "bash".to_string(),
                version: None,
                publisher: None,
                architecture: None,
                source: SoftwareSource::Dpkg,
                install_location: None,
            }],
            Vec::new(),
        )
    }

    #[test]
    fn write_then_list_pending_round_trips() {
        let state_dir = temp_state_dir("roundtrip");
        let spool = Spool::open(&state_dir).expect("spool should open");

        spool
            .write(&sample_snapshot("snap-1"))
            .expect("write should succeed");
        let pending = spool.list_pending().expect("list should succeed");

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1.snapshot_id, "snap-1");

        fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn remove_clears_a_written_entry() {
        let state_dir = temp_state_dir("remove");
        let spool = Spool::open(&state_dir).expect("spool should open");

        spool
            .write(&sample_snapshot("snap-1"))
            .expect("write should succeed");
        spool.remove("snap-1").expect("remove should succeed");
        let pending = spool.list_pending().expect("list should succeed");

        assert!(pending.is_empty());

        fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn corrupt_entry_is_quarantined_not_returned() {
        let state_dir = temp_state_dir("corrupt");
        let spool = Spool::open(&state_dir).expect("spool should open");
        fs::write(state_dir.join(SPOOL_SUBDIR).join("bad.json"), b"not json")
            .expect("corrupt file should be written");

        let pending = spool.list_pending().expect("list should succeed");

        assert!(pending.is_empty());
        assert!(state_dir.join(QUARANTINE_SUBDIR).join("bad.json").exists());

        fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn compressed_expansion_is_bounded_and_quarantined() {
        let state_dir = temp_state_dir("compression_bomb");
        let spool = Spool::open(&state_dir).expect("spool should open");
        let path = state_dir.join(SPOOL_SUBDIR).join("bomb.json.zst");
        let oversized = vec![b'x'; MAX_SNAPSHOT_BYTES + 1];
        let compressed = zstd::encode_all(&oversized[..], 3).expect("test payload should compress");
        fs::write(&path, compressed).expect("compressed payload should be written");

        assert!(spool
            .list_pending()
            .expect("list should succeed")
            .is_empty());
        assert!(state_dir
            .join(QUARANTINE_SUBDIR)
            .join("bomb.json.zst")
            .exists());

        fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn enforce_limit_evicts_oldest_first_never_the_newest() {
        let state_dir = temp_state_dir("evict");
        let spool = Spool::open(&state_dir).expect("spool should open");

        for index in 0..5 {
            spool
                .write(&sample_snapshot(&format!("snap-{index}")))
                .expect("write should succeed");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let evicted = spool
            .enforce_limit(2)
            .expect("enforce_limit should succeed");
        let pending = spool.list_pending().expect("list should succeed");

        assert_eq!(evicted.len(), 3);
        assert_eq!(pending.len(), 2);
        assert!(pending
            .iter()
            .any(|(_, snapshot)| snapshot.snapshot_id == "snap-4"));

        fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn capacity_enforcement_does_not_decode_entries() {
        let state_dir = temp_state_dir("metadata_only_eviction");
        let spool = Spool::open(&state_dir).expect("spool should open");
        let spool_dir = state_dir.join(SPOOL_SUBDIR);
        for index in 0..3 {
            fs::write(spool_dir.join(format!("corrupt-{index}.json")), b"not-json")
                .expect("corrupt entry should be written");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let evicted = spool.enforce_limit(1).expect("limit should be enforced");

        assert_eq!(evicted, vec!["corrupt-0", "corrupt-1"]);
        assert_eq!(spool.pending_paths().expect("paths should list").len(), 1);
        assert!(state_dir.join(QUARANTINE_SUBDIR).read_dir().is_ok());

        fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn write_rejects_oversized_snapshot() {
        let state_dir = temp_state_dir("oversized");
        let spool = Spool::open(&state_dir).expect("spool should open");
        let mut snapshot = sample_snapshot("snap-big");
        snapshot.hostname = "x".repeat(MAX_SNAPSHOT_BYTES);

        let error = spool
            .write(&snapshot)
            .expect_err("oversized snapshot should be rejected");

        assert!(matches!(error, SpoolError::Capacity(_)));
        assert!(spool
            .list_pending()
            .expect("list should succeed")
            .is_empty());

        fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn reads_legacy_uncompressed_json_spool_entry() {
        let state_dir = temp_state_dir("legacy_uncompressed");
        let spool = Spool::open(&state_dir).expect("spool should open");

        let legacy_file = state_dir.join(SPOOL_SUBDIR).join("legacy-1.json");
        let snapshot = sample_snapshot("legacy-1");
        fs::write(&legacy_file, snapshot.to_canonical_json().as_bytes())
            .expect("legacy file should be written");

        let pending = spool.list_pending().expect("list should succeed");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1.snapshot_id, "legacy-1");

        spool
            .remove("legacy-1")
            .expect("remove legacy should succeed");
        assert!(spool.list_pending().unwrap().is_empty());

        fs::remove_dir_all(&state_dir).ok();
    }
}
