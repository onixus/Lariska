use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub const INVENTORY_SCHEMA_VERSION: u16 = 2;
pub const LEGACY_INVENTORY_SCHEMA_VERSION: u16 = 1;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<CollectionSource>,
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
            schema_version: LEGACY_INVENTORY_SCHEMA_VERSION,
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
            sources: Vec::new(),
        };
        snapshot.normalize();
        snapshot
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_v2(
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
        sources: Vec<CollectionSource>,
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
            sources,
        };
        snapshot.normalize();
        snapshot
    }

    /// Builds the legacy wire shape only after a complete collection.
    pub fn into_v1(mut self) -> Self {
        self.schema_version = LEGACY_INVENTORY_SCHEMA_VERSION;
        self.sources.clear();
        for entry in &mut self.software {
            if matches!(
                entry.source,
                SoftwareSource::Pacman | SoftwareSource::MacBundle
            ) {
                entry.source = SoftwareSource::Other;
            }
            entry.product_identity = None;
            entry.installation_identity = None;
            entry.package_id = None;
            entry.scope = None;
            entry.install_instance_id = None;
        }
        self.normalize();
        self
    }

    /// Keeps one row per installation in v2. Legacy v1 retains the newest
    /// product row because old servers enforce a product comparison key.
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
        if self.schema_version == INVENTORY_SCHEMA_VERSION {
            for entry in &mut self.software {
                if entry.installation_identity.is_none() {
                    entry.ensure_installation_identity();
                    entry.install_instance_id = Some(hash_identity(&[
                        "lariska-endpoint-instance-v2",
                        &self.agent_id,
                        entry.install_instance_id.as_deref().unwrap_or(""),
                    ]));
                }
                entry.ensure_installation_identity();
            }
            self.sources.sort_by_key(|source| source.source);
        }
        self.software.retain(|entry| !entry.name.is_empty());
        self.software.sort_by(|left, right| {
            left.identity_key(self.schema_version)
                .cmp(&right.identity_key(self.schema_version))
                .then_with(|| {
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
                Some(last)
                    if last.identity_key(self.schema_version)
                        == entry.identity_key(self.schema_version) =>
                {
                    // Named plainly rather than with Rust's `{:?}`, which
                    // rendered these as `Some("8.0.61001")` in an operator's
                    // console.
                    if self.schema_version == INVENTORY_SCHEMA_VERSION {
                        if last.version != entry.version {
                            warnings.push(format!(
                                "conflicting versions for installation {}",
                                entry.installation_identity.as_deref().unwrap_or("unknown")
                            ));
                        }
                        continue;
                    }
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
        if ![LEGACY_INVENTORY_SCHEMA_VERSION, INVENTORY_SCHEMA_VERSION]
            .contains(&self.schema_version)
        {
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

        if self.schema_version == INVENTORY_SCHEMA_VERSION {
            let mut sources = std::collections::BTreeSet::new();
            for source in &self.sources {
                if !sources.insert(source.source) {
                    return Err(ModelError::Invalid(
                        "duplicate collection source".to_string(),
                    ));
                }
                validate_required("collector_version", &source.collector_version)?;
                validate_required("source collected_at", &source.collected_at)?;
                if source.diagnostic_code.as_ref().is_some_and(|code| {
                    code.len() > 64
                        || !code
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                }) {
                    return Err(ModelError::Invalid("invalid diagnostic code".to_string()));
                }
                if source.status == CollectionStatus::Complete && source.last_complete_at.is_none()
                {
                    return Err(ModelError::Invalid(
                        "complete sources require last_complete_at".to_string(),
                    ));
                }
            }
            for entry in &self.software {
                if !sources.contains(&entry.source) {
                    return Err(ModelError::Invalid(
                        "software source has no completeness state".to_string(),
                    ));
                }
                for id in [&entry.installation_identity, &entry.install_instance_id] {
                    if !id.as_ref().is_some_and(|value| {
                        value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
                    }) {
                        return Err(ModelError::Invalid(
                            "invalid installation identity".to_string(),
                        ));
                    }
                }
                if entry.product_identity.as_deref() != Some(entry.comparison_key().as_str())
                    || entry.scope.is_none()
                    || entry.install_location.is_some()
                {
                    return Err(ModelError::Invalid(
                        "invalid v2 product identity or raw install location".to_string(),
                    ));
                }
            }
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
            .map(|entry| (entry.identity_key(self.schema_version), entry))
            .collect();

        let curr_map: BTreeMap<String, &SoftwareEntry> = self
            .software
            .iter()
            .map(|entry| (entry.identity_key(self.schema_version), entry))
            .collect();

        let mut changes = Vec::new();

        // Check for added or modified entries in current snapshot
        for (key, curr_entry) in &curr_map {
            if self.schema_version == INVENTORY_SCHEMA_VERSION
                && !self.sources.iter().any(|source| {
                    source.source == curr_entry.source
                        && source.status == CollectionStatus::Complete
                })
            {
                continue;
            }
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
            if !curr_map.contains_key(key)
                && (self.schema_version == LEGACY_INVENTORY_SCHEMA_VERSION
                    || self.sources.iter().any(|source| {
                        source.source == prev_entry.source
                            && source.status == CollectionStatus::Complete
                    }))
            {
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
    Pacman,
    MacBundle,
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
            Self::Pacman => "pacman",
            Self::MacBundle => "mac_bundle",
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
            "pacman" => Self::Pacman,
            "mac_bundle" => Self::MacBundle,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub architecture: Option<String>,
    pub source: SoftwareSource,
    pub install_location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<InstallationScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_instance_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationScope {
    System,
    User,
    Runtime,
    Container,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    Complete,
    Partial,
    Failed,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollectionSource {
    pub source: SoftwareSource,
    pub status: CollectionStatus,
    pub collected_at: String,
    pub last_complete_at: Option<String>,
    pub collector_version: String,
    pub diagnostic_code: Option<String>,
}

impl CollectionSource {
    pub fn new(
        source: SoftwareSource,
        status: CollectionStatus,
        diagnostic_code: Option<&str>,
    ) -> Self {
        let collected_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .expect("valid UTC timestamp");
        Self {
            source,
            status,
            last_complete_at: (status == CollectionStatus::Complete).then(|| collected_at.clone()),
            collected_at,
            collector_version: env!("CARGO_PKG_VERSION").to_string(),
            diagnostic_code: diagnostic_code.map(ToOwned::to_owned),
        }
    }
}

impl SoftwareEntry {
    pub fn with_instance(
        mut self,
        package_id: Option<String>,
        scope: InstallationScope,
        private_instance: &str,
    ) -> Self {
        self.package_id = package_id;
        self.scope = Some(scope);
        self.install_instance_id = Some(hash_identity(&[
            "lariska-install-instance-v2",
            private_instance,
        ]));
        self
    }

    pub fn with_path_instance(
        self,
        package_id: Option<String>,
        scope: InstallationScope,
        path: &std::path::Path,
    ) -> Self {
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        self.with_instance(package_id, scope, &canonical.to_string_lossy())
    }

    pub fn ensure_installation_identity(&mut self) {
        self.normalize();
        self.package_id = normalize_optional_string(self.package_id.as_deref());
        let scope = *self.scope.get_or_insert({
            if matches!(
                self.source,
                SoftwareSource::Pip | SoftwareSource::Npm | SoftwareSource::Java
            ) {
                InstallationScope::Runtime
            } else {
                InstallationScope::System
            }
        });
        let product = self.comparison_key();
        if self.install_instance_id.is_none() {
            // With no native key/path, version is necessary to retain parallel
            // installations instead of hiding a vulnerable older build.
            let instance = self
                .install_location
                .as_deref()
                .or(self.package_id.as_deref())
                .unwrap_or(self.version.as_deref().unwrap_or("unknown"));
            self.install_instance_id =
                Some(hash_identity(&["lariska-install-instance-v2", instance]));
        }
        let scope_name = match scope {
            InstallationScope::System => "system",
            InstallationScope::User => "user",
            InstallationScope::Runtime => "runtime",
            InstallationScope::Container => "container",
        };
        self.installation_identity = Some(hash_identity(&[
            "lariska-installation-v2",
            &product,
            self.package_id.as_deref().unwrap_or(""),
            scope_name,
            self.install_instance_id.as_deref().unwrap_or(""),
        ]));
        self.product_identity = Some(product);
        self.install_location = None;
    }

    pub fn identity_key(&self, schema_version: u16) -> String {
        if schema_version == INVENTORY_SCHEMA_VERSION {
            self.installation_identity
                .clone()
                .unwrap_or_else(|| self.comparison_key())
        } else {
            self.comparison_key()
        }
    }

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

fn hash_identity(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{:x}", hasher.finalize())
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
        assert_eq!(
            compare_versions(Some("1.10.0"), Some("1.9.0")),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions(Some("1.9.0"), Some("1.10.0")),
            Ordering::Less
        );
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
        assert_eq!(
            compare_versions(Some("4.10.08029"), Some("4.10.8029")),
            Ordering::Equal
        );
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
        assert_eq!(
            compare_versions(Some("1.0"), Some("1.beta")),
            Ordering::Greater
        );
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
        assert!(
            !warning.contains("Some("),
            "Rust Debug output leaked: {warning}"
        );
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
        assert_eq!(SoftwareSource::from_raw("pacman"), SoftwareSource::Pacman);
        assert_eq!(SoftwareSource::from_raw("DPKG"), SoftwareSource::Dpkg);
    }

    fn source_fixture(source: SoftwareSource, status: CollectionStatus) -> CollectionSource {
        CollectionSource {
            source,
            status,
            collected_at: "2026-10-06T10:00:00Z".into(),
            last_complete_at: (status == CollectionStatus::Complete)
                .then(|| "2026-10-06T10:00:00Z".into()),
            collector_version: "0.4.0".into(),
            diagnostic_code: (status == CollectionStatus::Failed)
                .then(|| "metadata_unreadable".into()),
        }
    }

    fn fixture_v2(
        software: Vec<SoftwareEntry>,
        sources: Vec<CollectionSource>,
    ) -> InventorySnapshot {
        let base = fixture_snapshot(Vec::new());
        InventorySnapshot::new_v2(
            base.snapshot_id,
            base.agent_id,
            "2026-10-06T10:00:00Z".into(),
            base.hostname,
            base.os_family,
            base.os_name,
            base.os_version,
            base.os_arch,
            "0.4.0".into(),
            base.labels,
            base.identifiers,
            software,
            Vec::new(),
            sources,
        )
    }

    fn java_install(version: &str, instance: &str) -> SoftwareEntry {
        SoftwareEntry {
            name: "OpenJDK".into(),
            version: Some(version.into()),
            publisher: Some("Eclipse Adoptium".into()),
            architecture: Some("x86_64".into()),
            source: SoftwareSource::Java,
            install_location: Some(instance.into()),
            ..SoftwareEntry::default()
        }
        .with_instance(
            Some("java-runtime".into()),
            InstallationScope::Runtime,
            instance,
        )
    }

    #[test]
    fn v2_preserves_old_vulnerable_installation_and_is_idempotent() {
        let entries = vec![
            java_install("17.0.1", "/private/users/alice/java17"),
            java_install("21.0.3", "/private/users/alice/java21"),
        ];
        let mut snapshot = fixture_v2(
            entries,
            vec![source_fixture(
                SoftwareSource::Java,
                CollectionStatus::Complete,
            )],
        );
        assert_eq!(snapshot.software.len(), 2);
        assert!(snapshot
            .software
            .iter()
            .any(|entry| entry.version.as_deref() == Some("17.0.1")));
        assert_eq!(
            snapshot.software[0].product_identity,
            snapshot.software[1].product_identity
        );
        assert_ne!(
            snapshot.software[0].installation_identity,
            snapshot.software[1].installation_identity
        );
        snapshot.validate().unwrap();
        let json = snapshot.to_canonical_json();
        assert!(!json.contains("alice"));
        assert!(!json.contains("/private/users"));
        snapshot.normalize();
        assert_eq!(snapshot.to_canonical_json(), json);
        snapshot.software.push(snapshot.software[0].clone());
        snapshot.normalize();
        assert_eq!(snapshot.to_canonical_json(), json);
    }

    #[test]
    fn v2_version_change_modifies_same_installation_and_scope_keeps_copies_distinct() {
        let previous = fixture_v2(
            vec![java_install("17.0.1", "/java")],
            vec![source_fixture(
                SoftwareSource::Java,
                CollectionStatus::Complete,
            )],
        );
        let current = fixture_v2(
            vec![java_install("17.0.2", "/java")],
            previous.sources.clone(),
        );
        assert_eq!(
            current.software[0].installation_identity,
            previous.software[0].installation_identity
        );
        let delta = current.diff(&previous);
        assert_eq!(delta.software_changes.len(), 1);
        assert_eq!(delta.software_changes[0].action, DeltaAction::Modified);
        let mut user = java_install("17.0.2", "/java");
        user.scope = Some(InstallationScope::User);
        let two = fixture_v2(vec![current.software[0].clone(), user], current.sources);
        assert_eq!(two.software.len(), 2);
    }

    #[test]
    fn v2_partial_source_never_manufactures_changes_while_healthy_source_updates() {
        let previous = fixture_v2(
            vec![
                software("bash", None, Some("5.1"), "dpkg"),
                software("requests", None, Some("2.30"), "pip"),
            ],
            vec![
                source_fixture(SoftwareSource::Dpkg, CollectionStatus::Complete),
                source_fixture(SoftwareSource::Pip, CollectionStatus::Complete),
            ],
        );
        let current = fixture_v2(
            vec![
                software("bash", None, Some("5.2"), "dpkg"),
                software("untrusted-observation", None, Some("1"), "pip"),
            ],
            vec![
                source_fixture(SoftwareSource::Dpkg, CollectionStatus::Complete),
                source_fixture(SoftwareSource::Pip, CollectionStatus::Partial),
            ],
        );
        let changes = current.diff(&previous).software_changes;
        assert!(changes
            .iter()
            .all(|change| change.entry.source == SoftwareSource::Dpkg));
        assert!(!changes.is_empty());
        let recovered = fixture_v2(
            vec![software("bash", None, Some("5.2"), "dpkg")],
            vec![
                source_fixture(SoftwareSource::Dpkg, CollectionStatus::Complete),
                source_fixture(SoftwareSource::Pip, CollectionStatus::Complete),
            ],
        );
        assert!(recovered
            .diff(&previous)
            .software_changes
            .iter()
            .any(|change| change.entry.source == SoftwareSource::Pip
                && change.action == DeltaAction::Removed));
    }

    #[test]
    fn v2_falls_back_to_legacy_shape_for_complete_older_server_collection() {
        let snapshot = fixture_v2(
            vec![
                java_install("17.0.1", "/java17"),
                java_install("21.0.3", "/java21"),
            ],
            vec![source_fixture(
                SoftwareSource::Java,
                CollectionStatus::Complete,
            )],
        )
        .into_v1();
        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.software.len(), 1);
        assert_eq!(snapshot.software[0].version.as_deref(), Some("21.0.3"));
        assert!(snapshot.sources.is_empty());
        let json = snapshot.to_canonical_json();
        assert!(!json.contains("installation_identity"));
        snapshot.validate().unwrap();
    }

    #[test]
    fn v2_contract_fixture_roundtrips_and_validates() {
        let text = include_str!("../tests/fixtures/inventory_v2.json").trim();
        let mut snapshot: InventorySnapshot = serde_json::from_str(text).unwrap();
        snapshot.validate().unwrap();
        snapshot.normalize();
        assert_eq!(snapshot.to_canonical_json(), text);
        assert_eq!(snapshot.software.len(), 2);
        assert_eq!(
            snapshot
                .sources
                .iter()
                .find(|source| source.source == SoftwareSource::Pip)
                .unwrap()
                .status,
            CollectionStatus::Failed
        );
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
            ..SoftwareEntry::default()
        }
    }
}
