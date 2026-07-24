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
    /// server rejects a payload containing two entries with the same key —
    /// it does not deduplicate for us. When a collision has differing
    /// versions we keep the greater version string (best-effort heuristic;
    /// there is no reliable cross-source version ordering) and record a
    /// `collector_warnings` entry so the drop is visible.
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
            left.comparison_key()
                .cmp(&right.comparison_key())
                .then_with(|| right.version.cmp(&left.version))
        });
        self.deduplicate_software();
    }

    fn deduplicate_software(&mut self) {
        let mut deduped: Vec<SoftwareEntry> = Vec::with_capacity(self.software.len());
        let mut warnings = Vec::new();

        for entry in self.software.drain(..) {
            match deduped.last() {
                Some(last) if last.comparison_key() == entry.comparison_key() => {
                    warnings.push(format!(
                        "duplicate software entry collapsed for key \"{}\": kept version {:?}, dropped version {:?}",
                        entry.comparison_key(),
                        last.version,
                        entry.version
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
            Self::Other => "other",
        }
    }

    /// Maps a collector-reported source name onto the server's closed enum.
    /// Anything the server doesn't recognize (e.g. `pacman`, `snap`,
    /// `flatpak`) becomes `other` — the server would reject an unknown
    /// literal outright. Used by the Phase L3 collectors.
    #[allow(dead_code)]
    pub fn from_raw(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "apt" => Self::Apt,
            "dpkg" => Self::Dpkg,
            "rpm" => Self::Rpm,
            "winreg" => Self::Winreg,
            "msi" => Self::Msi,
            "brew" => Self::Brew,
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
        assert!(snapshot
            .collector_warnings
            .iter()
            .any(|warning| warning.contains("duplicate software entry collapsed")));
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
