use crate::model::InventorySnapshot;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
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

pub struct Spool {
    dir: PathBuf,
    quarantine_dir: PathBuf,
}

impl Spool {
    // unchanged implementation; formatting-only commit intentionally omitted in transcript
}

fn sync_parent_dir(_path: &Path) -> Result<(), SpoolError> {
    Ok(())
}
