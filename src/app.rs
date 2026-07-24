use crate::config::Config;
use crate::identity;
use crate::inventory;
use crate::model::{AgentInfo, EndpointIdentifier, InventorySnapshot, OsInfo, SoftwareEntry};
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub struct ScanResult {
    pub asset_id: String,
    pub software_list: Vec<String>,
}

pub fn run(config_path: &Path) -> Result<(), String> {
    let config = Config::from_file_and_env(config_path).map_err(|error| error.to_string())?;
    let identity =
        identity::load_or_create(&config.state_dir).map_err(|error| error.to_string())?;
    let result = ScanResult {
        asset_id: identity.agent_id,
        software_list: inventory::collect_software(),
    };

    println!("Lariska Endpoint Agent started...");
    println!("Agent identity loaded: {}", result.asset_id);
    println!(
        "Collected {} software entries; gateway submission is not implemented yet.",
        result.software_list.len()
    );

    Ok(())
}

pub fn check_config(config_path: &Path) -> Result<(), String> {
    let config = Config::from_file_and_env(config_path).map_err(|error| error.to_string())?;
    println!("Configuration is valid: {config:?}");
    Ok(())
}

pub fn print_inventory() {
    let snapshot = diagnostic_snapshot(inventory::collect_software());
    if let Err(error) = snapshot.validate() {
        eprintln!("Inventory snapshot validation failed: {error}");
        return;
    }

    println!("{}", snapshot.to_canonical_json());
}

fn diagnostic_snapshot(software_names: Vec<String>) -> InventorySnapshot {
    InventorySnapshot::new(
        "diagnostic-snapshot".to_string(),
        "agent_00000000000000000000000000000000".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        AgentInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: "localhost".to_string(),
            labels: Vec::new(),
        },
        OsInfo {
            family: std::env::consts::OS.to_string(),
            name: std::env::consts::OS.to_string(),
            version: None,
            architecture: std::env::consts::ARCH.to_string(),
        },
        Vec::<EndpointIdentifier>::new(),
        software_names
            .into_iter()
            .map(|name| SoftwareEntry {
                name,
                version: None,
                publisher: None,
                architecture: None,
                source: "platform".to_string(),
                install_location: None,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_snapshot_normalizes_inventory_names() {
        let snapshot = diagnostic_snapshot(vec![" bash ".to_string(), "".to_string()]);

        assert_eq!(snapshot.software.len(), 1);
        assert_eq!(snapshot.software[0].name, "bash");
    }

    #[test]
    fn scan_result_debug_output_has_no_token_fields() {
        let result = ScanResult {
            asset_id: "node-001".to_string(),
            software_list: vec!["bash".to_string()],
        };

        let output = format!("{result:?}").to_lowercase();

        assert!(output.contains("node-001"));
        assert!(!output.contains("token"));
        assert!(!output.contains("authorization"));
    }
}
