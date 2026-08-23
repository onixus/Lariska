use crate::model::{SoftwareEntry, SoftwareSource};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct PackageJson {
    name: Option<String>,
    version: Option<String>,
    author: Option<PackageAuthor>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PackageAuthor {
    String(String),
    Object { name: String },
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

            // Handle scoped packages like @angular/cli
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
    let content = fs::read_to_string(pkg_file).ok()?;
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
    let publisher = parsed.author.and_then(|a| match a {
        PackageAuthor::String(s) => {
            let s = s.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        PackageAuthor::Object { name } => {
            let s = name.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
    });

    Some(SoftwareEntry {
        name,
        version,
        publisher,
        architecture: None,
        source: SoftwareSource::Npm,
        install_location: Some(install_dir.display().to_string()),
    })
}

fn candidate_node_modules_dirs() -> Vec<PathBuf> {
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
}
