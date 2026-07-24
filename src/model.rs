use std::fmt;

pub const INVENTORY_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthExchangeRequest {
    pub provisioning_key: String,
    pub agent_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthExchangeResponse {
    pub access_token: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRegistrationRequest {
    pub agent_id: String,
    pub hostname: String,
    pub agent_version: String,
    pub labels: Vec<Label>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    pub status: HeartbeatStatus,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeartbeatStatus {
    Idle,
    Busy,
    Error,
}

impl AuthExchangeRequest {
    pub fn to_canonical_json(&self) -> String {
        format!(
            r#"{{"provisioning_key":"{}","agent_id":"{}"}}"#,
            escape_json(&self.provisioning_key),
            escape_json(&self.agent_id)
        )
    }
}

impl AgentRegistrationRequest {
    pub fn to_canonical_json(&self) -> String {
        let labels = self
            .labels
            .iter()
            .map(|label| {
                format!(
                    r#"{{"key":"{}","value":"{}"}}"#,
                    escape_json(&label.key),
                    escape_json(&label.value)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"agent_id":"{}","hostname":"{}","agent_version":"{}","labels":[{}]}}"#,
            escape_json(&self.agent_id),
            escape_json(&self.hostname),
            escape_json(&self.agent_version),
            labels
        )
    }
}

impl HeartbeatRequest {
    pub fn to_canonical_json(&self) -> String {
        format!(
            r#"{{"agent_id":"{}","status":"{}","detail":{}}}"#,
            escape_json(&self.agent_id),
            self.status.as_str(),
            optional_json_string(self.detail.as_deref())
        )
    }
}

impl HeartbeatStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Busy => "busy",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventorySnapshot {
    pub schema_version: u16,
    pub snapshot_id: String,
    pub agent_id: String,
    pub collected_at: String,
    pub agent: AgentInfo,
    pub os: OsInfo,
    pub identifiers: Vec<EndpointIdentifier>,
    pub software: Vec<SoftwareEntry>,
}

impl InventorySnapshot {
    pub fn new(
        snapshot_id: String,
        agent_id: String,
        collected_at: String,
        agent: AgentInfo,
        os: OsInfo,
        identifiers: Vec<EndpointIdentifier>,
        software: Vec<SoftwareEntry>,
    ) -> Self {
        let mut snapshot = Self {
            schema_version: INVENTORY_SCHEMA_VERSION,
            snapshot_id,
            agent_id,
            collected_at,
            agent,
            os,
            identifiers,
            software,
        };
        snapshot.normalize();
        snapshot
    }

    pub fn normalize(&mut self) {
        self.agent.labels.sort();
        self.agent.labels.dedup();
        self.identifiers
            .retain(|identifier| !identifier.value.trim().is_empty());
        self.identifiers.sort_by(|left, right| {
            left.identifier_type
                .cmp(&right.identifier_type)
                .then_with(|| left.value.cmp(&right.value))
        });
        self.identifiers.dedup();

        self.software.iter_mut().for_each(SoftwareEntry::normalize);
        self.software.retain(|entry| !entry.name.is_empty());
        self.software.sort();
        self.software.dedup();
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
        validate_required("agent.version", &self.agent.version)?;
        validate_required("agent.hostname", &self.agent.hostname)?;
        validate_required("os.family", &self.os.family)?;
        validate_required("os.name", &self.os.name)?;
        validate_required("os.architecture", &self.os.architecture)?;

        if self
            .software
            .iter()
            .any(|entry| entry.name.trim().is_empty())
        {
            return Err(ModelError::Invalid(
                "software entries must not have empty names".to_string(),
            ));
        }

        Ok(())
    }

    pub fn to_canonical_json(&self) -> String {
        let labels = self
            .agent
            .labels
            .iter()
            .map(|label| {
                format!(
                    r#"{{"key":"{}","value":"{}"}}"#,
                    escape_json(&label.key),
                    escape_json(&label.value)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let identifiers = self
            .identifiers
            .iter()
            .map(|identifier| {
                format!(
                    r#"{{"type":"{}","value":"{}"}}"#,
                    escape_json(&identifier.identifier_type),
                    escape_json(&identifier.value)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let software = self
            .software
            .iter()
            .map(SoftwareEntry::to_canonical_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"schema_version":{},"snapshot_id":"{}","agent_id":"{}","collected_at":"{}","agent":{{"version":"{}","hostname":"{}","labels":[{}]}},"os":{{"family":"{}","name":"{}","version":{},"architecture":"{}"}},"identifiers":[{}],"software":[{}]}}"#,
            self.schema_version,
            escape_json(&self.snapshot_id),
            escape_json(&self.agent_id),
            escape_json(&self.collected_at),
            escape_json(&self.agent.version),
            escape_json(&self.agent.hostname),
            labels,
            escape_json(&self.os.family),
            escape_json(&self.os.name),
            optional_json_string(self.os.version.as_deref()),
            escape_json(&self.os.architecture),
            identifiers,
            software
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentInfo {
    pub version: String,
    pub hostname: String,
    pub labels: Vec<Label>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Label {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsInfo {
    pub family: String,
    pub name: String,
    pub version: Option<String>,
    pub architecture: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndpointIdentifier {
    pub identifier_type: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub architecture: Option<String>,
    pub source: String,
    pub install_location: Option<String>,
}

impl SoftwareEntry {
    pub fn normalize(&mut self) {
        self.name = normalize_required_string(&self.name);
        self.version = normalize_optional_string(self.version.as_deref());
        self.publisher = normalize_optional_string(self.publisher.as_deref());
        self.architecture = normalize_optional_string(self.architecture.as_deref())
            .map(|architecture| normalize_architecture(&architecture));
        self.source = normalize_required_string(&self.source).to_lowercase();
        self.install_location = normalize_optional_string(self.install_location.as_deref());
    }

    fn to_canonical_json(&self) -> String {
        format!(
            r#"{{"name":"{}","version":{},"publisher":{},"architecture":{},"source":"{}","install_location":{}}}"#,
            escape_json(&self.name),
            optional_json_string(self.version.as_deref()),
            optional_json_string(self.publisher.as_deref()),
            optional_json_string(self.architecture.as_deref()),
            escape_json(&self.source),
            optional_json_string(self.install_location.as_deref())
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

fn optional_json_string(value: Option<&str>) -> String {
    value
        .map(|value| format!(r#""{}""#, escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn escape_json(value: &str) -> String {
    value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            control if control.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => escaped.push(other),
        }
        escaped
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_models_serialize_to_contract_json() {
        let exchange = AuthExchangeRequest {
            provisioning_key: "bootstrap-secret".to_string(),
            agent_id: "agent_0123456789abcdef0123456789abcdef".to_string(),
        };
        assert_eq!(
            exchange.to_canonical_json(),
            include_str!("../tests/fixtures/auth_exchange_request_v1.json").trim()
        );

        let registration = AgentRegistrationRequest {
            agent_id: "agent_0123456789abcdef0123456789abcdef".to_string(),
            hostname: "workstation-17".to_string(),
            agent_version: "0.1.0".to_string(),
            labels: vec![Label {
                key: "site".to_string(),
                value: "helsinki".to_string(),
            }],
        };
        assert_eq!(
            registration.to_canonical_json(),
            include_str!("../tests/fixtures/agent_register_request_v1.json").trim()
        );

        let heartbeat = HeartbeatRequest {
            agent_id: "agent_0123456789abcdef0123456789abcdef".to_string(),
            status: HeartbeatStatus::Idle,
            detail: None,
        };
        assert_eq!(
            heartbeat.to_canonical_json(),
            include_str!("../tests/fixtures/heartbeat_request_v1.json").trim()
        );
    }

    #[test]
    fn canonical_json_escapes_all_json_control_characters() {
        let request = HeartbeatRequest {
            agent_id: "agent_0123456789abcdef0123456789abcdef".to_string(),
            status: HeartbeatStatus::Error,
            detail: Some("quote \" slash \\ newline\n backspace \u{08} unit \u{1f}".to_string()),
        };

        assert_eq!(
            request.to_canonical_json(),
            r#"{"agent_id":"agent_0123456789abcdef0123456789abcdef","status":"error","detail":"quote \" slash \\ newline\n backspace \b unit \u001f"}"#
        );
    }

    #[test]
    fn snapshot_normalizes_sorts_and_deduplicates_entries() {
        let snapshot = fixture_snapshot(vec![
            software("  Zed  ", Some(" AMD64 "), "dpkg"),
            software("zed", Some("amd64"), "dpkg"),
            software("", None, "dpkg"),
            software(" Bash ", Some("x64"), "DPKG"),
        ]);

        assert_eq!(snapshot.software.len(), 3);
        assert_eq!(snapshot.software[0].name, "Bash");
        assert_eq!(snapshot.software[0].architecture.as_deref(), Some("x86_64"));
        assert_eq!(snapshot.software[0].source, "dpkg");
    }

    #[test]
    fn snapshot_validates_required_fields() {
        let mut snapshot = fixture_snapshot(vec![software("bash", None, "dpkg")]);
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
        let snapshot = fixture_snapshot(vec![software("bash", Some("x64"), "dpkg")]);
        let expected = include_str!("../tests/fixtures/inventory_v1.json").trim();

        assert_eq!(snapshot.to_canonical_json(), expected);
    }

    fn fixture_snapshot(software: Vec<SoftwareEntry>) -> InventorySnapshot {
        InventorySnapshot::new(
            "018f0000000000000000000000000000".to_string(),
            "agent_0123456789abcdef0123456789abcdef".to_string(),
            "2026-07-24T08:00:00Z".to_string(),
            AgentInfo {
                version: "0.1.0".to_string(),
                hostname: "workstation-17".to_string(),
                labels: vec![Label {
                    key: "site".to_string(),
                    value: "helsinki".to_string(),
                }],
            },
            OsInfo {
                family: "linux".to_string(),
                name: "Ubuntu".to_string(),
                version: Some("24.04".to_string()),
                architecture: "x86_64".to_string(),
            },
            vec![EndpointIdentifier {
                identifier_type: "machine_id".to_string(),
                value: "machine-1".to_string(),
            }],
            software,
        )
    }

    fn software(name: &str, architecture: Option<&str>, source: &str) -> SoftwareEntry {
        SoftwareEntry {
            name: name.to_string(),
            version: None,
            publisher: Some(" Example Publisher ".to_string()),
            architecture: architecture.map(ToOwned::to_owned),
            source: source.to_string(),
            install_location: None,
        }
    }
}
