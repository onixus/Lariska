use crate::inventory::{read_text_file_limited, CollectorResult};
use crate::model::{InstallationScope, SoftwareEntry, SoftwareSource};
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct PackageJson {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    author: Option<Value>,
}

/// Collects globally installed Node.js packages.
pub fn collect_nodejs_packages() -> CollectorResult {
    collect_nodejs_dirs(&candidate_node_modules_dirs())
}

pub(crate) fn collect_nodejs_dirs(dirs: &[PathBuf]) -> CollectorResult {
    let mut result = CollectorResult::default();
    let mut found = false;
    for dir in dirs {
        if dir.exists() {
            found = true;
        }
        for path in super::child_dirs(dir, &mut result) {
            let packages = if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name.starts_with('@'))
            {
                super::child_dirs(&path, &mut result)
            } else {
                vec![path]
            };
            for package in packages {
                match read_text_file_limited(&package.join("package.json"))
                    .and_then(|content| parse_package_json(&content, &package))
                {
                    Some(entry) => result.entries.push(entry),
                    None => result.mark_failed("metadata_unreadable"),
                }
            }
        }
    }
    if !found && result.complete {
        CollectorResult::not_applicable(SoftwareSource::Npm)
    } else {
        result.with_source(SoftwareSource::Npm)
    }
}

pub fn parse_package_json(content: &str, install_dir: &Path) -> Option<SoftwareEntry> {
    let parsed: PackageJson = serde_json::from_str(content).ok()?;
    let name = parsed.name?.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let version = parsed
        .version
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let publisher = parsed.author.and_then(package_author_name);

    Some(
        SoftwareEntry {
            name: name.clone(),
            version,
            publisher,
            architecture: None,
            source: SoftwareSource::Npm,
            install_location: Some(install_dir.display().to_string()),
            ..SoftwareEntry::default()
        }
        .with_path_instance(Some(name), InstallationScope::Runtime, install_dir),
    )
}

/// npm accepts several shapes for `author`. Unknown-but-valid shapes must not
/// make the entire package disappear from inventory; they only mean the
/// optional publisher field is unavailable.
fn package_author_name(author: Value) -> Option<String> {
    let raw = match author {
        Value::String(value) => Some(value),
        Value::Object(values) => values
            .get("name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        _ => None,
    }?;
    let value = raw.trim().to_string();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn candidate_node_modules_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        dirs.push(PathBuf::from("/usr/lib/node_modules"));
        dirs.push(PathBuf::from("/usr/local/lib/node_modules"));
    }

    #[cfg(target_os = "macos")]
    {
        dirs.push(PathBuf::from("/opt/homebrew/lib/node_modules"));
        dirs.push(PathBuf::from("/usr/local/lib/node_modules"));
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(app_data) = std::env::var("APPDATA") {
            dirs.push(Path::new(&app_data).join("npm\\node_modules"));
        }
        if let Ok(prog_files) = std::env::var("ProgramFiles") {
            dirs.push(Path::new(&prog_files).join("nodejs\\node_modules"));
        }
    }

    dirs.sort();
    dirs.dedup();
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_metadata_is_degraded_instead_of_authoritative_removal() {
        let root = std::env::temp_dir().join(format!(
            "lariska-nodejs-completeness-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let good = root.join("good/package.json");
        std::fs::create_dir_all(good.parent().unwrap()).unwrap();
        std::fs::write(good, "{\"name\":\"good\",\"version\":\"1.2\"}").unwrap();
        let good_result = collect_nodejs_dirs(std::slice::from_ref(&root));
        assert!(good_result.complete);
        assert_eq!(good_result.entries.len(), 1);
        let bad = root.join("broken/package.json");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, "{bad json").unwrap();
        let result = collect_nodejs_dirs(std::slice::from_ref(&root));
        assert!(!result.complete);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.sources[0].source, SoftwareSource::Npm);
        assert_eq!(
            result.sources[0].status,
            crate::model::CollectionStatus::Partial
        );
        assert_eq!(
            result.sources[0].diagnostic_code.as_deref(),
            Some("metadata_unreadable")
        );
        assert!(result.sources[0].last_complete_at.is_none());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn parses_valid_package_json() {
        let json = r#"{
            "name": "typescript",
            "version": "5.4.5",
            "author": "Microsoft Corp.",
            "description": "TypeScript is a language for application scale JavaScript development"
        }"#;

        let entry = parse_package_json(json, Path::new("/usr/local/lib/node_modules/typescript"))
            .expect("should parse");
        assert_eq!(entry.name, "typescript");
        assert_eq!(entry.version.as_deref(), Some("5.4.5"));
        assert_eq!(entry.publisher.as_deref(), Some("Microsoft Corp."));
        assert_eq!(entry.source, SoftwareSource::Npm);
    }

    #[test]
    fn keeps_package_when_author_has_an_unknown_shape() {
        let json = r#"{
            "name": "example-package",
            "version": "1.2.3",
            "author": {"email": "maintainer@example.test"}
        }"#;

        let entry = parse_package_json(json, Path::new("/tmp/example-package"))
            .expect("package should not be dropped because an optional field is unusual");
        assert_eq!(entry.name, "example-package");
        assert_eq!(entry.publisher, None);
    }
}
