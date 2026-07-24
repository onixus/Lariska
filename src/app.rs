use crate::config::Config;
use crate::identity;
use crate::inventory;
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
    let software = inventory::collect_software();
    println!("[");
    for (index, item) in software.iter().enumerate() {
        let comma = if index + 1 == software.len() { "" } else { "," };
        println!("  \"{}\"{}", escape_json(item), comma);
    }
    println!("]");
}

fn escape_json(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_json_escapes_control_characters() {
        assert_eq!(escape_json("a\\b\"c\n"), "a\\\\b\\\"c\\n");
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
