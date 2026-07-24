use crate::model::InventorySnapshot;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const SPOOL_SUBDIR: &str = "spool";
const QUARANTINE_SUBDIR: &str = "spool/quarantine";

#[derive(Debug)]
pub enum SpoolError {
    Io(String),
}

impl fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SpoolError {}

/// Durable local queue of not-yet-acknowledged inventory snapshots. A
/// snapshot is written here *before* any network submission is attempted
/// (Plan.md §11 steps 5-7), so killing the process mid-upload never loses
/// it — the next `list_pending` call after restart picks it back up.
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
        self.dir.join(format!("{snapshot_id}.json"))
    }

    pub fn write(&self, snapshot: &InventorySnapshot) -> Result<(), SpoolError> {
        let path = self.entry_path(&snapshot.snapshot_id);
        let temp_path = path.with_extension(format!("tmp-{}", std::process::id()));
        let payload = snapshot.to_canonical_json();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|error| {
                SpoolError::Io(format!("failed to create spool temp file: {error}"))
            })?;
        file.write_all(payload.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| SpoolError::Io(format!("failed to write spool entry: {error}")))?;

        fs::rename(&temp_path, &path)
            .map_err(|error| SpoolError::Io(format!("failed to persist spool entry: {error}")))?;
        Ok(())
    }

    pub fn remove(&self, snapshot_id: &str) -> Result<(), SpoolError> {
        match fs::remove_file(self.entry_path(snapshot_id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(SpoolError::Io(format!(
                "failed to remove spool entry: {error}"
            ))),
        }
    }

    /// Moves a spool entry aside so it stops being retried every cycle,
    /// without deleting it outright (Plan.md §11: "quarantine malformed
    /// queue entries instead of looping forever").
    pub fn quarantine_by_id(&self, snapshot_id: &str) -> Result<(), SpoolError> {
        let path = self.entry_path(snapshot_id);
        if path.exists() {
            self.quarantine(&path)
        } else {
            Ok(())
        }
    }

    fn quarantine(&self, path: &Path) -> Result<(), SpoolError> {
        let Some(file_name) = path.file_name() else {
            return Ok(());
        };
        let destination = self.quarantine_dir.join(file_name);
        fs::rename(path, destination)
            .map_err(|error| SpoolError::Io(format!("failed to quarantine spool entry: {error}")))
    }

    /// Pending snapshots, oldest first by file modification time. Entries
    /// that fail to parse or fail snapshot validation are quarantined here
    /// rather than returned, so a corrupt file can never cause an infinite
    /// retry loop.
    pub fn list_pending(&self) -> Result<Vec<(PathBuf, InventorySnapshot)>, SpoolError> {
        let mut candidates: Vec<(PathBuf, SystemTime)> = Vec::new();

        for dir_entry in fs::read_dir(&self.dir)
            .map_err(|error| SpoolError::Io(format!("failed to read spool dir: {error}")))?
        {
            let dir_entry = dir_entry
                .map_err(|error| SpoolError::Io(format!("failed to read spool entry: {error}")))?;
            let path = dir_entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let modified = dir_entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            candidates.push((path, modified));
        }

        candidates.sort_by_key(|(_, modified)| *modified);

        let mut pending = Vec::with_capacity(candidates.len());
        for (path, _) in candidates {
            match read_entry(&path) {
                Ok(snapshot) => pending.push((path, snapshot)),
                Err(_) => self.quarantine(&path)?,
            }
        }

        Ok(pending)
    }

    /// Evicts the oldest pending entries beyond `max_entries`, never the
    /// newest unsent snapshot (Plan.md §11: "cap disk usage without
    /// deleting the newest unsent snapshot"). Returns the evicted snapshot
    /// IDs so the caller can log what was dropped.
    pub fn enforce_limit(&self, max_entries: usize) -> Result<Vec<String>, SpoolError> {
        let pending = self.list_pending()?;
        if pending.len() <= max_entries {
            return Ok(Vec::new());
        }

        let overflow = pending.len() - max_entries;
        let mut evicted = Vec::with_capacity(overflow);
        for (path, snapshot) in pending.into_iter().take(overflow) {
            fs::remove_file(&path)
                .map_err(|error| SpoolError::Io(format!("failed to evict spool entry: {error}")))?;
            evicted.push(snapshot.snapshot_id);
        }

        Ok(evicted)
    }
}

fn read_entry(path: &Path) -> Result<InventorySnapshot, String> {
    let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let snapshot: InventorySnapshot =
        serde_json::from_str(&content).map_err(|error| error.to_string())?;
    snapshot.validate().map_err(|error| error.to_string())?;
    Ok(snapshot)
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
}
