use crate::inventory::read_text_file_limited;
use crate::model::{SoftwareEntry, SoftwareSource};
use std::fs;
use std::path::{Path, PathBuf};

/// Collects installed Java runtimes (JDK/JRE) by reading their `release` metadata.
pub fn collect_java_runtimes() -> Vec<SoftwareEntry> {
    let mut entries = Vec::new();

    for parent in candidate_jvm_dirs() {
        if !parent.is_dir() {
            continue;
        }

        let Ok(read_dir) = fs::read_dir(&parent) else {
            continue;
        };

        for item in read_dir.flatten() {
            let path = item.path();
            if !path.is_dir() {
                continue;
            }

            // macOS JDK bundles have Contents/Home/release.
            let release_file = if path.join("Contents/Home/release").is_file() {
                path.join("Contents/Home/release")
            } else if path.join("release").is_file() {
                path.join("release")
            } else {
                continue;
            };

            if let Some(content) = read_text_file_limited(&release_file) {
                if let Some(entry) = parse_java_release(&content, &path) {
                    entries.push(entry);
                }
            }
        }
    }

    entries
}

pub fn parse_java_release(content: &str, install_dir: &Path) -> Option<SoftwareEntry> {
    let mut version = None;
    let mut implementor = None;
    let mut arch = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("JAVA_VERSION=") {
            version = non_empty_release_value(val);
        } else if let Some(val) = trimmed.strip_prefix("IMPLEMENTOR=") {
            implementor = non_empty_release_value(val);
        } else if let Some(val) = trimmed.strip_prefix("OS_ARCH=") {
            arch = non_empty_release_value(val);
        }
    }

    let version_str = version?;
    let name = if let Some(ref imp) = implementor {
        format!("{imp} OpenJDK")
    } else {
        "Java SE Runtime Environment".to_string()
    };

    Some(SoftwareEntry {
        name,
        version: Some(version_str),
        publisher: implementor,
        architecture: arch,
        source: SoftwareSource::Java,
        install_location: Some(install_dir.display().to_string()),
    })
}

fn non_empty_release_value(value: &str) -> Option<String> {
    let value = value.trim_matches('"').trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub(crate) fn candidate_jvm_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        dirs.push(PathBuf::from("/usr/lib/jvm"));
    }

    #[cfg(target_os = "macos")]
    {
        dirs.push(PathBuf::from("/Library/Java/JavaVirtualMachines"));
        dirs.push(PathBuf::from("/System/Library/Java/JavaVirtualMachines"));
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(prog_files) = std::env::var("ProgramFiles") {
            let base = Path::new(&prog_files);
            dirs.push(base.join("Java"));
            dirs.push(base.join("Eclipse Adoptium"));
            dirs.push(base.join("Amazon Corretto"));
            dirs.push(base.join("Microsoft"));
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
    fn parses_valid_java_release_file() {
        let release = r#"
JAVA_VERSION="21.0.2"
IMPLEMENTOR="Eclipse Adoptium"
OS_NAME="Linux"
OS_ARCH="x86_64"
"#;
        let entry = parse_java_release(release, Path::new("/usr/lib/jvm/temurin-21-jdk"))
            .expect("should parse");
        assert_eq!(entry.name, "Eclipse Adoptium OpenJDK");
        assert_eq!(entry.version.as_deref(), Some("21.0.2"));
        assert_eq!(entry.publisher.as_deref(), Some("Eclipse Adoptium"));
        assert_eq!(entry.architecture.as_deref(), Some("x86_64"));
        assert_eq!(entry.source, SoftwareSource::Java);
    }

    #[test]
    fn rejects_a_release_without_a_version() {
        assert!(parse_java_release("IMPLEMENTOR=\"Example\"", Path::new("/tmp/jdk")).is_none());
    }
}
