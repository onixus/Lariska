use crate::inventory::read_text_file_limited;
use crate::model::{SoftwareEntry, SoftwareSource};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct PackageJson {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    author: Option<Value>,
}

/// Collects globally installed Node.js packages.
pub fn collect_nodejs_packages() -> Vec<SoftwareEntry> {
    let mut entries = Vec::new();

    for dir in candidate_node_modules_dirs() {
        if !dir.is_dir() {
            continue;
        }

        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };

        for item in read_dir.flatten() {
            let path = item.path();
            if !path.is_dir() {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();

            // Handle scoped packages like @angular/cli.
            if file_name.starts_with('@') {
                if let Ok(scoped_dir) = fs::read_dir(&path) {
                    for scoped_item in scoped_dir.flatten() {
                        let sub_path = scoped_item.path();
                        if sub_path.is_dir() {
                            if let Some(entry) = check_package_json(&sub_path) {
                                entries.push(entry);
                            }
                        }
                    }
                }
            } else if let Some(entry) = check_package_json(&path) {
                entries.push(entry);
            }
        }
    }

    entries
}

fn check_package_json(module_dir: &Path) -> Option<SoftwareEntry> {
    let pkg_file = module_dir.join("package.json");
    let content = read_text_file_limited(&pkg_file)?;
    parse_package_json(&content, module_dir)
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

    Some(SoftwareEntry {
        name,
        version,
        publisher,
        architecture: None,
        source: SoftwareSource::Npm,
        install_location: Some(install_dir.display().to_string()),
    })
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
