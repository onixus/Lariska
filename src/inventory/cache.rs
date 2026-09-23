use super::{runtimes, CollectorResult};
use crate::model::SoftwareEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CACHE_SUBDIR: &str = "inventory-cache-v1";
const CACHE_FORMAT_VERSION: u16 = 1;
const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FINGERPRINT_ITEMS: usize = 100_000;

#[derive(Clone, Copy, Debug)]
enum CacheKind {
    Platform,
    Python,
    Nodejs,
    Java,
}

impl CacheKind {
    fn file_name(self) -> &'static str {
        match self {
            Self::Platform => "platform.json",
            Self::Python => "python.json",
            Self::Nodejs => "nodejs.json",
            Self::Java => "java.json",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Python => "python",
            Self::Nodejs => "nodejs",
            Self::Java => "java",
        }
    }
}

#[derive(Clone)]
struct InventoryCache {
    dir: PathBuf,
    max_age: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedCollector {
    format_version: u16,
    agent_version: String,
    fingerprint: String,
    stored_at_unix_secs: u64,
    result: CollectorResult,
}

impl InventoryCache {
    fn open(state_dir: &Path, max_age: Duration) -> Result<Self, String> {
        let dir = state_dir.join(CACHE_SUBDIR);
        fs::create_dir_all(&dir)
            .map_err(|error| format!("failed to create inventory cache directory: {error}"))?;
        Ok(Self { dir, max_age })
    }

    fn path(&self, kind: CacheKind) -> PathBuf {
        self.dir.join(kind.file_name())
    }

    fn load(&self, kind: CacheKind, fingerprint: &str) -> Result<Option<CollectorResult>, String> {
        let path = self.path(kind);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "failed to open {} inventory cache: {error}",
                    kind.label()
                ))
            }
        };

        let mut bytes = Vec::with_capacity(64 * 1024);
        file.take((MAX_CACHE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read {} inventory cache: {error}", kind.label()))?;
        if bytes.len() > MAX_CACHE_BYTES {
            return Err(format!(
                "{} inventory cache exceeds {MAX_CACHE_BYTES} bytes",
                kind.label()
            ));
        }

        let cached: CachedCollector = serde_json::from_slice(&bytes).map_err(|error| {
            format!("failed to parse {} inventory cache: {error}", kind.label())
        })?;
        if cached.format_version != CACHE_FORMAT_VERSION
            || cached.agent_version != env!("CARGO_PKG_VERSION")
            || cached.fingerprint != fingerprint
            || !cached.result.complete
            || cache_expired(cached.stored_at_unix_secs, self.max_age)
        {
            return Ok(None);
        }

        Ok(Some(cached.result))
    }

    fn load_or_miss(&self, kind: CacheKind, fingerprint: &str) -> Option<CollectorResult> {
        match self.load(kind, fingerprint) {
            Ok(hit) => hit,
            Err(error) => {
                tracing::warn!(collector = kind.label(), %error, "ignoring invalid inventory cache");
                let _ = fs::remove_file(self.path(kind));
                None
            }
        }
    }

    fn store(
        &self,
        kind: CacheKind,
        fingerprint: &str,
        result: &CollectorResult,
    ) -> Result<(), String> {
        if !result.complete {
            return Ok(());
        }

        let cached = CachedCollector {
            format_version: CACHE_FORMAT_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            fingerprint: fingerprint.to_string(),
            stored_at_unix_secs: unix_time_secs(),
            result: result.clone(),
        };
        let bytes = serde_json::to_vec(&cached).map_err(|error| {
            format!(
                "failed to serialize {} inventory cache: {error}",
                kind.label()
            )
        })?;
        if bytes.len() > MAX_CACHE_BYTES {
            return Err(format!(
                "{} inventory cache is {} bytes, exceeding the {MAX_CACHE_BYTES} byte limit",
                kind.label(),
                bytes.len()
            ));
        }

        let path = self.path(kind);
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)
                .map_err(|error| {
                    format!("failed to create {} inventory cache: {error}", kind.label())
                })?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| {
                    format!("failed to write {} inventory cache: {error}", kind.label())
                })
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }

        replace_file(&temp, &path).map_err(|error| {
            format!(
                "failed to publish {} inventory cache {}: {error}",
                kind.label(),
                path.display()
            )
        })?;
        sync_parent_dir(&path).map_err(|error| {
            format!(
                "failed to sync {} inventory cache directory: {error}",
                kind.label()
            )
        })?;
        Ok(())
    }
}

pub async fn collect_all_cached(
    state_dir: &Path,
    timeout: Duration,
    max_age: Duration,
) -> CollectorResult {
    let started = Instant::now();
    let cache = match InventoryCache::open(state_dir, max_age) {
        Ok(cache) => Some(cache),
        Err(error) => {
            tracing::warn!(%error, "inventory cache unavailable; running full collection");
            None
        }
    };

    let mut result = collect_platform_cached(cache.clone(), timeout).await;
    let runtime_cache = cache.clone();
    match tokio::task::spawn_blocking(move || collect_runtimes_cached(runtime_cache.as_ref())).await
    {
        Ok(runtime_result) => result.merge(runtime_result),
        Err(error) => {
            result.complete = false;
            result
                .warnings
                .push(format!("runtime collectors panicked: {error}"));
        }
    }

    tracing::debug!(
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        entries = result.entries.len(),
        warnings = result.warnings.len(),
        complete = result.complete,
        cached = cache.is_some(),
        "cached inventory collection completed"
    );
    result
}

async fn collect_platform_cached(
    cache: Option<InventoryCache>,
    timeout: Duration,
) -> CollectorResult {
    let lookup_cache = cache.clone();
    let lookup = tokio::task::spawn_blocking(move || {
        let cache = lookup_cache.as_ref()?;
        let fingerprint = match platform_fingerprint() {
            Ok(Some(fingerprint)) => fingerprint,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "platform fingerprint failed; running full collector");
                return None;
            }
        };
        let hit = cache.load_or_miss(CacheKind::Platform, &fingerprint);
        Some((fingerprint, hit))
    })
    .await
    .ok()
    .flatten();

    if let Some((_, Some(result))) = &lookup {
        tracing::debug!(collector = "platform", "inventory cache hit");
        return result.clone();
    }

    let result = collect_platform(timeout).await;
    if let (Some(cache), Some((fingerprint, _))) = (cache, lookup) {
        let stored = result.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(error) = cache.store(CacheKind::Platform, &fingerprint, &stored) {
                tracing::warn!(%error, "could not update platform inventory cache");
            }
        })
        .await;
    }
    result
}

async fn collect_platform(timeout: Duration) -> CollectorResult {
    #[cfg(target_os = "linux")]
    {
        super::linux::collect(timeout).await
    }
    #[cfg(target_os = "windows")]
    {
        super::windows::collect(timeout).await
    }
    #[cfg(target_os = "macos")]
    {
        super::macos::collect(timeout).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = timeout;
        CollectorResult {
            entries: Vec::new(),
            warnings: vec![
                "software collection is not supported on this operating system".to_string(),
            ],
            complete: false,
        }
    }
}

fn collect_runtimes_cached(cache: Option<&InventoryCache>) -> CollectorResult {
    let mut result = CollectorResult::default();
    result.merge(collect_runtime_cached(
        cache,
        CacheKind::Python,
        python_fingerprint,
        runtimes::python::collect_python_packages,
    ));
    result.merge(collect_runtime_cached(
        cache,
        CacheKind::Nodejs,
        nodejs_fingerprint,
        runtimes::nodejs::collect_nodejs_packages,
    ));
    result.merge(collect_runtime_cached(
        cache,
        CacheKind::Java,
        java_fingerprint,
        runtimes::java::collect_java_runtimes,
    ));
    result
}

fn collect_runtime_cached<Fingerprint, Collect>(
    cache: Option<&InventoryCache>,
    kind: CacheKind,
    fingerprint_fn: Fingerprint,
    collect_fn: Collect,
) -> CollectorResult
where
    Fingerprint: FnOnce() -> Result<String, String>,
    Collect: FnOnce() -> Vec<SoftwareEntry>,
{
    let fingerprint = match fingerprint_fn() {
        Ok(fingerprint) => Some(fingerprint),
        Err(error) => {
            tracing::warn!(collector = kind.label(), %error, "runtime fingerprint failed");
            None
        }
    };

    if let (Some(cache), Some(fingerprint)) = (cache, fingerprint.as_deref()) {
        if let Some(result) = cache.load_or_miss(kind, fingerprint) {
            tracing::debug!(collector = kind.label(), "inventory cache hit");
            return result;
        }
    }

    let result = CollectorResult {
        entries: collect_fn(),
        warnings: Vec::new(),
        complete: true,
    };
    if let (Some(cache), Some(fingerprint)) = (cache, fingerprint.as_deref()) {
        if let Err(error) = cache.store(kind, fingerprint, &result) {
            tracing::warn!(collector = kind.label(), %error, "could not update runtime inventory cache");
        }
    }
    result
}

fn platform_fingerprint() -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        let mut builder = FingerprintBuilder::new();
        builder.add_tree(Path::new("/var/lib/dpkg/status"), 0)?;
        builder.add_tree(Path::new("/usr/lib/sysimage/rpm"), 2)?;
        builder.add_tree(Path::new("/var/lib/rpm"), 2)?;
        builder.add_tree(Path::new("/var/lib/pacman/local"), 2)?;
        Ok(Some(builder.finish()))
    }
    #[cfg(target_os = "macos")]
    {
        let mut builder = FingerprintBuilder::new();
        builder.add_applications_dir(Path::new("/Applications"))?;
        if let Ok(home) = std::env::var("HOME") {
            builder.add_applications_dir(&Path::new(&home).join("Applications"))?;
        }
        for cellar in [
            "/opt/homebrew/Cellar",
            "/opt/homebrew/Caskroom",
            "/usr/local/Cellar",
            "/usr/local/Caskroom",
        ] {
            builder.add_tree(Path::new(cellar), 2)?;
        }
        Ok(Some(builder.finish()))
    }
    #[cfg(target_os = "windows")]
    {
        // Registry reads are already cheap, while approximating registry state
        // from filesystem timestamps would be incorrect. Runtime collectors are
        // still cached independently on Windows.
        Ok(None)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Ok(None)
    }
}

fn python_fingerprint() -> Result<String, String> {
    let mut builder = FingerprintBuilder::new();
    for dir in runtimes::python::candidate_python_dirs() {
        builder.add_path(&dir)?;
        for path in sorted_children(&dir)? {
            if path.is_dir()
                && path.extension().and_then(|value| value.to_str()) == Some("dist-info")
            {
                builder.add_path(&path)?;
                builder.add_path(&path.join("METADATA"))?;
            }
        }
    }
    Ok(builder.finish())
}

fn nodejs_fingerprint() -> Result<String, String> {
    let mut builder = FingerprintBuilder::new();
    for dir in runtimes::nodejs::candidate_node_modules_dirs() {
        builder.add_path(&dir)?;
        for path in sorted_children(&dir)? {
            if !path.is_dir() {
                continue;
            }
            let scoped = path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with('@'));
            if scoped {
                builder.add_path(&path)?;
                for package in sorted_children(&path)? {
                    if package.is_dir() {
                        builder.add_path(&package)?;
                        builder.add_path(&package.join("package.json"))?;
                    }
                }
            } else {
                builder.add_path(&path)?;
                builder.add_path(&path.join("package.json"))?;
            }
        }
    }
    Ok(builder.finish())
}

fn java_fingerprint() -> Result<String, String> {
    let mut builder = FingerprintBuilder::new();
    for dir in runtimes::java::candidate_jvm_dirs() {
        builder.add_path(&dir)?;
        for runtime in sorted_children(&dir)? {
            if !runtime.is_dir() {
                continue;
            }
            builder.add_path(&runtime)?;
            let bundle_release = runtime.join("Contents/Home/release");
            if bundle_release.is_file() {
                builder.add_path(&bundle_release)?;
            } else {
                builder.add_path(&runtime.join("release"))?;
            }
        }
    }
    Ok(builder.finish())
}

struct FingerprintBuilder {
    hasher: Sha256,
    items: usize,
}

impl FingerprintBuilder {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            items: 0,
        }
    }

    fn add_path(&mut self, path: &Path) -> Result<bool, String> {
        self.items += 1;
        if self.items > MAX_FINGERPRINT_ITEMS {
            return Err(format!(
                "fingerprint exceeded {MAX_FINGERPRINT_ITEMS} filesystem entries"
            ));
        }

        let rendered = path.to_string_lossy();
        self.hasher.update((rendered.len() as u64).to_le_bytes());
        self.hasher.update(rendered.as_bytes());
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.hasher.update([0]);
                return Ok(false);
            }
            Err(error) => {
                return Err(format!("failed to stat {}: {error}", path.display()));
            }
        };

        let file_type = metadata.file_type();
        self.hasher.update([if file_type.is_dir() {
            1
        } else if file_type.is_file() {
            2
        } else if file_type.is_symlink() {
            3
        } else {
            4
        }]);
        self.hasher.update(metadata.len().to_le_bytes());
        match metadata.modified() {
            Ok(modified) => hash_system_time(&mut self.hasher, modified),
            Err(_) => self.hasher.update([0; 12]),
        }
        Ok(file_type.is_dir())
    }

    fn add_tree(&mut self, path: &Path, depth: usize) -> Result<(), String> {
        let is_dir = self.add_path(path)?;
        if !is_dir || depth == 0 {
            return Ok(());
        }
        for child in sorted_children(path)? {
            self.add_tree(&child, depth - 1)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn add_applications_dir(&mut self, path: &Path) -> Result<(), String> {
        let is_dir = self.add_path(path)?;
        if !is_dir {
            return Ok(());
        }
        for application in sorted_children(path)? {
            if application.extension().and_then(|value| value.to_str()) != Some("app") {
                continue;
            }
            self.add_path(&application)?;
            self.add_path(&application.join("Contents/Info.plist"))?;
        }
        Ok(())
    }

    fn finish(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }
}

fn sorted_children(path: &Path) -> Result<Vec<PathBuf>, String> {
    if !path.is_dir() {
        return Ok(Vec::new());
    }
    let mut children = Vec::new();
    for entry in
        fs::read_dir(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?
    {
        children.push(
            entry
                .map_err(|error| format!("failed to enumerate {}: {error}", path.display()))?
                .path(),
        );
    }
    children.sort();
    Ok(children)
}

fn hash_system_time(hasher: &mut Sha256, value: SystemTime) {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            hasher.update(duration.as_secs().to_le_bytes());
            hasher.update(duration.subsec_nanos().to_le_bytes());
        }
        Err(_) => hasher.update([0; 12]),
    }
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_expired(stored_at: u64, max_age: Duration) -> bool {
    let now = unix_time_secs();
    stored_at > now || now.saturating_sub(stored_at) >= max_age.as_secs()
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
    use crate::model::{SoftwareEntry, SoftwareSource};

    fn temp_state_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lariska-inventory-cache-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn sample_result() -> CollectorResult {
        CollectorResult {
            entries: vec![SoftwareEntry {
                name: "bash".to_string(),
                version: Some("5.2".to_string()),
                publisher: None,
                architecture: Some("x86_64".to_string()),
                source: SoftwareSource::Dpkg,
                install_location: None,
            }],
            warnings: Vec::new(),
            complete: true,
        }
    }

    #[test]
    fn cache_round_trips_only_for_the_same_fingerprint() {
        let state_dir = temp_state_dir("roundtrip");
        let cache = InventoryCache::open(&state_dir, Duration::from_secs(3600)).unwrap();
        cache
            .store(CacheKind::Platform, "fingerprint-a", &sample_result())
            .unwrap();

        let hit = cache
            .load(CacheKind::Platform, "fingerprint-a")
            .unwrap()
            .expect("matching fingerprint should hit");
        assert_eq!(hit.entries.len(), 1);
        assert!(cache
            .load(CacheKind::Platform, "fingerprint-b")
            .unwrap()
            .is_none());

        fs::remove_dir_all(state_dir).ok();
    }

    #[test]
    fn incomplete_results_are_never_cached() {
        let state_dir = temp_state_dir("partial");
        let cache = InventoryCache::open(&state_dir, Duration::from_secs(3600)).unwrap();
        let mut result = sample_result();
        result.complete = false;
        cache
            .store(CacheKind::Platform, "fingerprint", &result)
            .unwrap();

        assert!(!cache.path(CacheKind::Platform).exists());
        fs::remove_dir_all(state_dir).ok();
    }

    #[test]
    fn expired_cache_is_ignored() {
        let state_dir = temp_state_dir("expired");
        let cache = InventoryCache::open(&state_dir, Duration::from_secs(60)).unwrap();
        let cached = CachedCollector {
            format_version: CACHE_FORMAT_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            fingerprint: "fingerprint".to_string(),
            stored_at_unix_secs: 0,
            result: sample_result(),
        };
        fs::write(
            cache.path(CacheKind::Platform),
            serde_json::to_vec(&cached).unwrap(),
        )
        .unwrap();

        assert!(cache
            .load(CacheKind::Platform, "fingerprint")
            .unwrap()
            .is_none());
        fs::remove_dir_all(state_dir).ok();
    }

    #[test]
    fn fingerprint_changes_when_evidence_changes() {
        let state_dir = temp_state_dir("fingerprint");
        fs::create_dir_all(&state_dir).unwrap();
        let evidence = state_dir.join("metadata");
        fs::write(&evidence, b"one").unwrap();
        let mut first = FingerprintBuilder::new();
        first.add_path(&evidence).unwrap();
        let first = first.finish();

        fs::write(&evidence, b"a longer value").unwrap();
        let mut second = FingerprintBuilder::new();
        second.add_path(&evidence).unwrap();
        let second = second.finish();

        assert_ne!(first, second);
        fs::remove_dir_all(state_dir).ok();
    }
}
