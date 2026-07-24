use super::{non_empty, run_command, CollectorResult, CommandRunError};
use crate::model::{SoftwareEntry, SoftwareSource};
use std::path::{Path, PathBuf};
use std::time::Duration;

const APPLICATION_DIRS: [&str; 2] = ["/Applications", "~/Applications"];

pub async fn collect(timeout: Duration) -> CollectorResult {
    let mut result = collect_bundles().await;
    if let Some(brew) = collect_homebrew(timeout).await {
        result.merge(brew);
    }
    result
}

async fn collect_bundles() -> CollectorResult {
    let home = std::env::var("HOME").ok();
    let dirs: Vec<PathBuf> = APPLICATION_DIRS
        .iter()
        .filter_map(|dir| match dir.strip_prefix("~/") {
            Some(suffix) => home.as_ref().map(|home| PathBuf::from(home).join(suffix)),
            None => Some(PathBuf::from(dir)),
        })
        .collect();

    tokio::task::spawn_blocking(move || collect_bundles_sync(&dirs))
        .await
        .unwrap_or_else(|error| CollectorResult {
            entries: Vec::new(),
            warnings: vec![format!("macOS bundle collector panicked: {error}")],
        })
}

fn collect_bundles_sync(dirs: &[PathBuf]) -> CollectorResult {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();

    for dir in dirs {
        let read_dir = match std::fs::read_dir(dir) {
            Ok(read_dir) => read_dir,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                warnings.push(format!("failed to read {}: {error}", dir.display()));
                continue;
            }
        };

        for dir_entry in read_dir.filter_map(Result::ok) {
            let path = dir_entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("app") {
                continue;
            }

            match read_bundle_info(&path) {
                Ok(Some(software)) => entries.push(software),
                Ok(None) => {}
                Err(error) => {
                    warnings.push(format!("failed to read bundle {}: {error}", path.display()))
                }
            }
        }
    }

    CollectorResult { entries, warnings }
}

/// Reads `Info.plist` metadata rather than treating the `.app` filename as
/// authoritative (Plan.md §10.3).
fn read_bundle_info(app_path: &Path) -> Result<Option<SoftwareEntry>, String> {
    let plist_path = app_path.join("Contents/Info.plist");
    if !plist_path.exists() {
        return Ok(None);
    }

    let value = plist::Value::from_file(&plist_path).map_err(|error| error.to_string())?;
    let dictionary = value
        .as_dictionary()
        .ok_or_else(|| "Info.plist root is not a dictionary".to_string())?;

    let name = dictionary
        .get("CFBundleName")
        .and_then(|value| value.as_string())
        .and_then(non_empty)
        .or_else(|| {
            app_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(non_empty)
        });
    let Some(name) = name else {
        return Ok(None);
    };

    let version = dictionary
        .get("CFBundleShortVersionString")
        .or_else(|| dictionary.get("CFBundleVersion"))
        .and_then(|value| value.as_string())
        .and_then(non_empty);

    Ok(Some(SoftwareEntry {
        name,
        version,
        publisher: None,
        architecture: None,
        source: SoftwareSource::Other,
        install_location: non_empty(&app_path.display().to_string()),
    }))
}

async fn collect_homebrew(timeout: Duration) -> Option<CollectorResult> {
    let formula_output =
        match run_command("brew", &["list", "--formula", "--versions"], timeout).await {
            Ok(output) => output,
            Err(CommandRunError::NotFound) => return None,
            Err(CommandRunError::Other(message)) => {
                return Some(CollectorResult {
                    entries: Vec::new(),
                    warnings: vec![format!("brew formula collector failed: {message}")],
                })
            }
        };

    let mut entries = parse_brew_versions(&formula_output);
    let mut warnings = Vec::new();

    match run_command("brew", &["list", "--cask", "--versions"], timeout).await {
        Ok(cask_output) => entries.extend(parse_brew_versions(&cask_output)),
        Err(CommandRunError::NotFound) => {}
        Err(CommandRunError::Other(message)) => {
            warnings.push(format!("brew cask collector failed: {message}"))
        }
    }

    Some(CollectorResult { entries, warnings })
}

fn parse_brew_versions(output: &str) -> Vec<SoftwareEntry> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            if name.trim().is_empty() {
                return None;
            }
            let version = fields.next();
            Some(SoftwareEntry {
                name: name.to_string(),
                version: version.and_then(non_empty),
                publisher: None,
                architecture: None,
                source: SoftwareSource::Brew,
                install_location: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_brew_list_versions_output() {
        let output = "wget 1.24.5\ncurl 8.5.0\n";
        let entries = parse_brew_versions(output);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "wget");
        assert_eq!(entries[0].version.as_deref(), Some("1.24.5"));
        assert_eq!(entries[0].source, SoftwareSource::Brew);
    }

    #[test]
    fn skips_blank_lines_in_brew_output() {
        let output = "\nwget 1.24.5\n\n";
        let entries = parse_brew_versions(output);

        assert_eq!(entries.len(), 1);
    }
}
