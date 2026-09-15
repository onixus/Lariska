use std::collections::BTreeMap;
use std::fmt;

pub const INVENTORY_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InventorySnapshot {
    pub schema_version: u16,
    pub snapshot_id: String,
    pub agent_id: String,
    pub collected_at: String,
    pub hostname: String,
    pub os_family: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_arch: Option<String>,
    pub agent_version: String,
    pub labels: BTreeMap<String, String>,
    pub identifiers: Vec<EndpointIdentifier>,
    pub software: Vec<SoftwareEntry>,
    pub collector_warnings: Vec<String>,
}

/// Orders two version strings the way a human reads them: digit runs compare as
/// numbers, everything else as text.
///
/// Plain string ordering is wrong wherever two components differ in digit
/// count — `"1.10.0"` sorts below `"1.9.0"`, `"22631"` below `"9600"` — and the
/// inventory is full of both. Neither this nor any other single rule is a
/// correct version comparison for every packaging ecosystem at once (that is
/// what the server's per-flavour `version_compare` is for); it only has to
/// pick the better of two builds of *one* product on *one* host, and it is
/// applied nowhere else.
///
/// `None` sorts below any version: an entry the registry gave no version for
/// tells us less than one that has a version, so it loses.
pub fn compare_versions(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    match (left, right) {
        (None, None) => return Ordering::Equal,
        (None, Some(_)) => return Ordering::Less,
        (Some(_), None) => return Ordering::Greater,
        (Some(_), Some(_)) => {}
    }

    let mut left_parts = version_chunks(left.unwrap_or_default());
    let mut right_parts = version_chunks(right.unwrap_or_default());

    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                let ordering = match (&a, &b) {
                    (Chunk::Number(x), Chunk::Number(y)) => x.cmp(y),
                    (Chunk::Text(x), Chunk::Text(y)) => x.cmp(y),
                    // A numeric component outranks a textual one at the same
                    // position: "4.10.08029" against "4.10.08029.BYOD" is
                    // settled by length below, but "1.0" against "1.beta" is
                    // this case, and the release beats the pre-release.
                    (Chunk::Number(_), Chunk::Text(_)) => Ordering::Greater,
                    (Chunk::Text(_), Chunk::Number(_)) => Ordering::Less,
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Chunk {
    Number(u128),
    Text(String),
}

/// Splits a version into runs of digits and runs of everything else, dropping
/// the separators between them. A digit run too long for `u128` is kept as
/// text rather than truncated to a number that would compare wrongly.
fn version_chunks(value: &str) -> impl Iterator<Item = Chunk> + '_ {
    let mut rest = value.trim();
    std::iter::from_fn(move || {
        while let Some(first) = rest.chars().next() {
            if first.is_ascii_digit() || first.is_alphanumeric() {
                break;
            }
            rest = &rest[first.len_utf8()..];
        }
        let first = rest.chars().next()?;
        let numeric = first.is_ascii_digit();
        let end = rest
            .char_indices()
            .find(|(_, c)| c.is_ascii_digit() != numeric || !c.is_alphanumeric())
            .map(|(index, _)| index)
            .unwrap_or(rest.len());
        let (head, tail) = rest.split_at(end);
        rest = tail;
        Some(if numeric {
            match head.trim_start_matches('0') {
                "" => Chunk::Number(0),
                trimmed => match trimmed.parse::<u128>() {
                    Ok(number) => Chunk::Number(number),
                    Err(_) => Chunk::Text(head.to_string()),
                },
            }
        } else {
            Chunk::Text(head.to_ascii_lowercase())
        })
    })
}

impl InventorySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: String,
        agent_id: String,
        collected_at: String,
        hostname: String,
        os_family: Option<String>,
        os_name: Option<String>,
        os_version: Option<String>,
        os_arch: Option<String>,
        agent_version: String,
        labels: BTreeMap<String, String>,
        identifiers: Vec<EndpointIdentifier>,
        software: Vec<SoftwareEntry>,
        collector_warnings: Vec<String>,
    ) -> Self {
        let mut snapshot = Self {
            schema_version: INVENTORY_SCHEMA_VERSION,
            snapshot_id,
            agent_id,
            collected_at,
            hostname,
            os_family,
            os_name,
            os_version,
            os_arch,
            agent_version,
            labels,
            identifiers,
            software,
            collector_warnings,
        };
        snapshot.normalize();
        snapshot
    }

    /// Sorts and deduplicates identifiers/software deterministically. Software
    /// entries are deduplicated on the server's comparison key (name +
    /// publisher + architecture + source, excluding version) because the
    /// server holds `UNIQUE(snapshot_id, comparison_key)` and rejects a
    /// payload carrying two entries with the same key — it does not
    /// deduplicate for us. A host with two versions of one product installed
    /// side by side (three Visual C++ redistributables of the same year is
    /// ordinary on Windows) therefore cannot be represented in full, and the
    /// greater version is what survives.
    ///
    /// "Greater" is decided by [`compare_versions`], not by string order.
    /// Lexicographically `"1.9.0"` beats `"1.10.0"`, which would have kept the
    /// *older* build and reported the machine as running software it had
    /// already replaced — or, in the other direction, hidden the old copy that
    /// is the one an advisory is about. Every dropped version is named in
    /// `collector_warnings`, so what could not be sent is at least visible.
    pub fn normalize(&mut self) {
        self.identifiers
            .retain(|identifier| !identifier.value_hash.trim().is_empty());
        self.identifiers.sort_by(|left, right| {
            left.identifier_type
                .cmp(&right.identifier_type)
                .then_with(|| left.value_hash.cmp(&right.value_hash))
        });
        self.identifiers.dedup();

        self.software.iter_mut().for_each(SoftwareEntry::normalize);
        self.software.retain(|entry| !entry.name.is_empty());
        self.software.sort_by(|left, right| {
            left.comparison_key().cmp(&right.comparison_key()).then_with(|| {
                // Descending: the survivor of each group is the one
                // `deduplicate_software` keeps, which is the first it sees.
                compare_versions(right.version.as_deref(), left.version.as_deref())
            })
        });
        self.deduplicate_software();
    }

    fn deduplicate_software(&mut self) {
        let mut deduped: Vec<SoftwareEntry> = Vec::with_capacity(self.software.len());
        let mut warnings = Vec::new();

        for entry in self.software.drain(..) {
            match deduped.last() {
                Some(last) if last.comparison_key() == entry.comparison_key() => {
                    // Named plainly rather than with Rust's `{:?}`, which
                    // rendered these as `Some("8.0.61001")` in an operator's
                    // console.
                    warnings.push(format!(
                        "{} is installed more than once ({}); the server's inventory \
                         key does not carry a version, so only {} was sent and {} was dropped",
                        entry.name,
                        entry.comparison_key(),
                        last.version.as_deref().unwrap_or("no version"),
                        entry.version.as_deref().unwrap_or("no version"),
                    ));
                }
                _ => deduped.push(entry),
            }
        }

        self.software = deduped;
        self.collector_warnings.append(&mut warnings);
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != INVENTORY_SCHEMA_VERSION {
            return Err(ModelError::Invalid(format!(
                "unsupported inventory schema version {}",
                self.schema_version
            )));
        }
        validate_required("snapshot_id", &self.snapshot_id)?;
        validate_required("agent_id", &self.agent_id)?;
        validate_required("collected_at", &self.collected_at)?;
        validate_required("hostname", &self.hostname)?;
        validate_required("agent_version", &self.agent_version)?;

        if self
            .software
            .iter()
            .any(|entry| entry.name.trim().is_empty())
        {
            return Err(ModelError::Invalid(
                "software entries must not have empty names".to_string(),
            ));
        }

        for identifier in &self.identifiers {
            if identifier.value_hash.trim().len() < 8 {
                return Err(ModelError::Invalid(
                    "identifier value_hash must be at least 8 characters".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Deterministic JSON used only for Lariska's own unchanged-snapshot
    /// content digest (Phase L4). It does not need to byte-match the
    /// server's independently recomputed digest — the server parses the
    /// JSON body and hashes its own canonical form.
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).expect("InventorySnapshot serialization must not fail")
    }

    /// Calculates the delta (added, removed, modified software) between `self` (current snapshot)
    /// and a `previous` snapshot for delta-synchronization.
    pub fn diff(&self, previous: &InventorySnapshot) -> InventoryDelta {
        let prev_map: BTreeMap<String, &SoftwareEntry> = previous
            .software
            .iter()
            .map(|entry| (entry.comparison_key(), entry))
            .collect();

        let curr_map: BTreeMap<String, &SoftwareEntry> = self
            .software
            .iter()
            .map(|entry| (entry.comparison_key(), entry))
            .collect();

        let mut changes = Vec::new();

        // Check for added or modified entries in current snapshot
        for (key, curr_entry) in &curr_map {
            match prev_map.get(key) {
                Some(prev_entry) => {
                    if curr_entry.version != prev_entry.version {
                        changes.push(SoftwareDeltaItem {
                            action: DeltaAction::Modified,
                            entry: (*curr_entry).clone(),
                            previous_version: prev_entry.version.clone(),
                        });
                    }
                }
                None => {
                    changes.push(SoftwareDeltaItem {
                        action: DeltaAction::Added,
                        entry: (*curr_entry).clone(),
                        previous_version: None,
                    });
                }
            }
        }

        // Check for removed entries that were in previous snapshot
        for (key, prev_entry) in &prev_map {
            if !curr_map.contains_key(key) {
                changes.push(SoftwareDeltaItem {
                    action: DeltaAction::Removed,
                    entry: (*prev_entry).clone(),
                    previous_version: prev_entry.version.clone(),
                });
            }
        }

        // Sort deterministically by entry comparison key
        changes.sort_by(|left, right| {
            left.entry
                .comparison_key()
                .cmp(&right.entry.comparison_key())
        });

        InventoryDelta {
            schema_version: self.schema_version,
            snapshot_id: self.snapshot_id.clone(),
            base_snapshot_id: previous.snapshot_id.clone(),
            agent_id: self.agent_id.clone(),
            collected_at: self.collected_at.clone(),
            software_changes: changes,
            collector_warnings: self.collector_warnings.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaAction {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SoftwareDeltaItem {
    pub action: DeltaAction,
    pub entry: SoftwareEntry,
    pub previous_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InventoryDelta {
    pub schema_version: u16,
    pub snapshot_id: String,
    pub base_snapshot_id: String,
    pub agent_id: String,
    pub collected_at: String,
    pub software_changes: Vec<SoftwareDeltaItem>,
    pub collector_warnings: Vec<String>,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum IdentifierType {
    MacHash,
    SerialHash,
    BiosUuidHash,
    TpmEkHash,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct EndpointIdentifier {
    pub identifier_type: IdentifierType,
    pub value_hash: String,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareSource {
    Apt,
    Dpkg,
    Rpm,
    Winreg,
    Msi,
    Brew,
    Pip,
    Npm,
    Java,
    /// A Windows servicing update -- a `KB` id from Component Based Servicing,
    /// not a product in the uninstall list (#358). Kept separate because it is
    /// what a Microsoft advisory is actually matched against: an OS build plus
    /// the updates applied on top of it.
    Kb,
    #[default]
    Other,
}

impl SoftwareSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dpkg => "dpkg",
            Self::Rpm => "rpm",
            Self::Winreg => "winreg",
            Self::Msi => "msi",
            Self::Brew => "brew",
            Self::Pip => "pip",
            Self::Npm => "npm",
            Self::Java => "java",
            Self::Kb => "kb",
            Self::Other => "other",
        }
    }

    /// Maps a collector-reported source name onto the software source enum.
    pub fn from_raw(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "apt" => Self::Apt,
            "dpkg" => Self::Dpkg,
            "rpm" => Self::Rpm,
            "winreg" => Self::Winreg,
            "msi" => Self::Msi,
            "brew" => Self::Brew,
            "pip" | "python" => Self::Pip,
            "npm" | "node" | "nodejs" => Self::Npm,
            "java" | "jar" | "jdk" | "jre" => Self::Java,
            "kb" | "msu" | "hotfix" => Self::Kb,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub architecture: Option<String>,
    pub source: SoftwareSource,
    pub install_location: Option<String>,
}

impl SoftwareEntry {
    pub fn normalize(&mut self) {
        self.name = normalize_required_string(&self.name);
        self.version = normalize_optional_string(self.version.as_deref());
        self.publisher = normalize_optional_string(self.publisher.as_deref());
        self.architecture = normalize_optional_string(self.architecture.as_deref())
            .map(|architecture| normalize_architecture(&architecture));
        self.install_location = normalize_optional_string(self.install_location.as_deref());
    }

    /// The server's software-diff/dedup comparison key: name + publisher +
    /// architecture + source, case-insensitively, excluding version.
    pub fn comparison_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.name.to_lowercase(),
            self.publisher.as_deref().unwrap_or("").to_lowercase(),
            self.architecture.as_deref().unwrap_or("").to_lowercase(),
            self.source.as_str()
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ModelError {
    Invalid(String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ModelError {}

fn validate_required(name: &str, value: &str) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(ModelError::Invalid(format!("{name} is required")));
    }
    Ok(())
}

fn normalize_required_string(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(normalize_required_string)
        .filter(|value| !value.is_empty())
}

fn normalize_architecture(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "amd64" | "x64" => "x86_64".to_string(),
        "arm64" => "aarch64".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod version_order_tests {
    use super::compare_versions;
    use std::cmp::Ordering;

    #[test]
    fn a_longer_number_wins_over_a_bigger_first_digit() {
        // The case plain string ordering gets backwards, and the reason this
        // function exists: lexicographically "1.9.0" beats "1.10.0".
        assert_eq!(compare_versions(Some("1.10.0"), Some("1.9.0")), Ordering::Greater);
        assert_eq!(compare_versions(Some("1.9.0"), Some("1.10.0")), Ordering::Less);
    }

    #[test]
    fn windows_build_numbers_order_numerically() {
        assert_eq!(
            compare_versions(Some("10.0.22631.4169"), Some("10.0.9600.1")),
            Ordering::Greater
        );
    }

    #[test]
    fn leading_zeroes_do_not_change_the_number() {
        assert_eq!(compare_versions(Some("4.10.08029"), Some("4.10.8029")), Ordering::Equal);
    }

    #[test]
    fn a_suffixed_build_outranks_the_bare_one() {
        // Seen in the field: Cisco AnyConnect ships 4.10.08029 and
        // 4.10.08029.BYOD side by side.
        assert_eq!(
            compare_versions(Some("4.10.08029.BYOD"), Some("4.10.08029")),
            Ordering::Greater
        );
    }

    #[test]
    fn a_release_outranks_its_pre_release() {
        assert_eq!(compare_versions(Some("1.0"), Some("1.beta")), Ordering::Greater);
    }

    #[test]
    fn an_entry_without_a_version_loses() {
        assert_eq!(compare_versions(None, Some("0.0.1")), Ordering::Less);
        assert_eq!(compare_versions(Some("0.0.1"), None), Ordering::Greater);
        assert_eq!(compare_versions(None, None), Ordering::Equal);
    }

    #[test]
    fn a_digit_run_too_long_for_u128_does_not_panic_or_truncate() {
        let huge = "9".repeat(60);
        assert_eq!(compare_versions(Some(&huge), Some(&huge)), Ordering::Equal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_normalizes_sorts_and_deduplicates_entries() {
        // "Zed" and "zed" share the server's case-insensitive comparison key
        // (name+publisher+architecture+source, excluding version) and must
        // collapse to one entry, same as the server would enforce.
        let snapshot = fixture_snapshot(vec![
            software("  Zed  ", Some(" AMD64 "), None, "dpkg"),
            software("zed", Some("amd64"), None, "dpkg"),
            software("", None, None, "dpkg"),
            software(" Bash ", Some("x64"), None, "DPKG"),
        ]);

        assert_eq!(snapshot.software.len(), 2);
        assert_eq!(snapshot.software[0].name, "Bash");
        assert_eq!(snapshot.software[0].architecture.as_deref(), Some("x86_64"));
        assert_eq!(snapshot.software[0].source, SoftwareSource::Dpkg);
    }

    #[test]
    fn snapshot_collapses_comparison_key_collisions_with_a_warning() {
        let snapshot = fixture_snapshot(vec![
            software("curl", Some("amd64"), Some("1.0"), "dpkg"),
            software("curl", Some("amd64"), Some("2.0"), "dpkg"),
        ]);

        assert_eq!(snapshot.software.len(), 1);
        assert_eq!(snapshot.software[0].version.as_deref(), Some("2.0"));
        let warning = snapshot
            .collector_warnings
            .iter()
            .find(|warning| warning.contains("installed more than once"))
            .expect("the drop must be visible");
        // Both versions are named: what was sent and what could not be. An
        // operator reading this has to be able to tell which copy the
        // inventory is missing.
        assert!(warning.contains("2.0"), "{warning}");
        assert!(warning.contains("1.0"), "{warning}");
        assert!(!warning.contains("Some("), "Rust Debug output leaked: {warning}");
    }

    #[test]
    fn the_collapse_keeps_the_newer_build_not_the_lexicographically_larger() {
        // Before natural ordering this kept 1.9.0 and dropped 1.10.0, so the
        // inventory named a build the host had already replaced.
        let snapshot = fixture_snapshot(vec![
            software("agent", Some("amd64"), Some("1.9.0"), "dpkg"),
            software("agent", Some("amd64"), Some("1.10.0"), "dpkg"),
        ]);

        assert_eq!(snapshot.software.len(), 1);
        assert_eq!(snapshot.software[0].version.as_deref(), Some("1.10.0"));
    }

    #[test]
    fn snapshot_validates_required_fields() {
        let mut snapshot = fixture_snapshot(vec![software("bash", None, None, "dpkg")]);
        snapshot.agent_id.clear();

        let error = snapshot
            .validate()
            .expect_err("missing agent_id should fail");

        assert_eq!(
            error,
            ModelError::Invalid("agent_id is required".to_string())
        );
    }

    #[test]
    fn canonical_json_matches_fixture() {
        let snapshot = fixture_snapshot(vec![software("bash", Some("x64"), None, "dpkg")]);
        let expected = include_str!("../tests/fixtures/inventory_v1.json").trim();

        assert_eq!(snapshot.to_canonical_json(), expected);
    }

    /// Cross-repo contract check (Plan.md §3 "shared JSON fixture in both
    /// repositories to prevent contract drift"): deserializes Shapoclyack's
    /// own golden fixture through Lariska's wire model. Skipped unless
    /// `SHAPOCLYACK_FIXTURE_PATH` is set (CI sets it after checking out
    /// Shapoclyack as a sibling checkout — see
    /// .github/workflows/ci.yml "contract-fixture" job); a plain local
    /// `cargo test` without that env var is a no-op here, not a failure.
    #[test]
    fn shapoclyack_fixture_is_schema_compatible() {
        let Ok(path) = std::env::var("SHAPOCLYACK_FIXTURE_PATH") else {
            eprintln!(
                "skipping shapoclyack_fixture_is_schema_compatible: SHAPOCLYACK_FIXTURE_PATH not set"
            );
            return;
        };

        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read fixture at {path}: {error}"));
        let snapshot: InventorySnapshot = serde_json::from_str(&content)
            .unwrap_or_else(|error| panic!("fixture at {path} did not deserialize: {error}"));
        snapshot
            .validate()
            .expect("Shapoclyack's fixture must pass Lariska's own validation");
    }

    #[test]
    fn snapshot_diff_computes_added_removed_and_modified() {
        let prev = fixture_snapshot(vec![
            software("bash", Some("x64"), Some("5.1"), "dpkg"),
            software("curl", Some("x64"), Some("7.88"), "dpkg"),
            software("nginx", Some("x64"), Some("1.22"), "dpkg"),
        ]);

        let curr = fixture_snapshot(vec![
            software("bash", Some("x64"), Some("5.2"), "dpkg"), // modified
            software("curl", Some("x64"), Some("7.88"), "dpkg"), // unchanged
            software("git", Some("x64"), Some("2.40"), "dpkg"), // added
                                                                // nginx removed
        ]);

        let delta = curr.diff(&prev);
        assert_eq!(delta.base_snapshot_id, prev.snapshot_id);
        assert_eq!(delta.snapshot_id, curr.snapshot_id);
        assert_eq!(delta.software_changes.len(), 3);

        let bash_change = delta
            .software_changes
            .iter()
            .find(|c| c.entry.name == "bash")
            .expect("bash change present");
        assert_eq!(bash_change.action, DeltaAction::Modified);
        assert_eq!(bash_change.previous_version.as_deref(), Some("5.1"));
        assert_eq!(bash_change.entry.version.as_deref(), Some("5.2"));

        let git_change = delta
            .software_changes
            .iter()
            .find(|c| c.entry.name == "git")
            .expect("git change present");
        assert_eq!(git_change.action, DeltaAction::Added);
        assert_eq!(git_change.previous_version, None);

        let nginx_change = delta
            .software_changes
            .iter()
            .find(|c| c.entry.name == "nginx")
            .expect("nginx change present");
        assert_eq!(nginx_change.action, DeltaAction::Removed);
        assert_eq!(nginx_change.previous_version.as_deref(), Some("1.22"));
    }

    #[test]
    fn unknown_source_maps_to_other() {
        assert_eq!(SoftwareSource::from_raw("pacman"), SoftwareSource::Other);
        assert_eq!(SoftwareSource::from_raw("DPKG"), SoftwareSource::Dpkg);
    }

    fn fixture_snapshot(software: Vec<SoftwareEntry>) -> InventorySnapshot {
        let mut labels = BTreeMap::new();
        labels.insert("site".to_string(), "helsinki".to_string());

        InventorySnapshot::new(
            "018f0000000000000000000000000000".to_string(),
            "agent_0123456789abcdef0123456789abcdef".to_string(),
            "2026-07-24T08:00:00Z".to_string(),
            "workstation-17".to_string(),
            Some("linux".to_string()),
            Some("Ubuntu".to_string()),
            Some("24.04".to_string()),
            Some("x86_64".to_string()),
            "0.1.0".to_string(),
            labels,
            vec![EndpointIdentifier {
                identifier_type: IdentifierType::MacHash,
                value_hash: "0123456789abcdef0123456789abcdef".to_string(),
            }],
            software,
            Vec::new(),
        )
    }

    fn software(
        name: &str,
        architecture: Option<&str>,
        version: Option<&str>,
        source: &str,
    ) -> SoftwareEntry {
        SoftwareEntry {
            name: name.to_string(),
            version: version.map(ToOwned::to_owned),
            publisher: Some(" Example Publisher ".to_string()),
            architecture: architecture.map(ToOwned::to_owned),
            source: SoftwareSource::from_raw(source),
            install_location: None,
        }
    }
}
