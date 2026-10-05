use crate::inventory::{read_text_file_limited, CollectorResult};
use crate::model::{InstallationScope, SoftwareEntry, SoftwareSource};
use std::path::{Path, PathBuf};

/// Collects installed Java runtimes (JDK/JRE) by reading their `release` metadata.
pub fn collect_java_runtimes() -> CollectorResult {
    collect_java_dirs(&candidate_jvm_dirs())
}

pub(crate) fn collect_java_dirs(dirs: &[PathBuf]) -> CollectorResult {
    let mut result = CollectorResult::default();
    let mut found = false;
    for parent in dirs {
        if parent.exists() {
            found = true;
        }
        for path in super::child_dirs(parent, &mut result) {
            let bundle_release = path.join("Contents/Home/release");
            let release_file = if bundle_release.exists() {
                bundle_release
            } else {
                path.join("release")
            };
            // A parent may also contain unrelated product directories. Missing
            // release metadata is a coverage error only for an apparent JDK.
            if !release_file.exists()
                && !path.join("bin/java").exists()
                && !path.join("bin/java.exe").exists()
            {
                continue;
            }
            match read_text_file_limited(&release_file)
                .and_then(|content| parse_java_release(&content, &path))
            {
                Some(entry) => result.entries.push(entry),
                None => result.mark_failed("metadata_unreadable"),
            }
        }
    }
    if !found && result.complete {
        CollectorResult::not_applicable(SoftwareSource::Java)
    } else {
        result.with_source(SoftwareSource::Java)
    }
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

    Some(
        SoftwareEntry {
            name,
            version: Some(version_str),
            publisher: implementor,
            architecture: arch,
            source: SoftwareSource::Java,
            install_location: Some(install_dir.display().to_string()),
            ..SoftwareEntry::default()
        }
        .with_path_instance(
            Some("java-runtime".to_string()),
            InstallationScope::Runtime,
            install_dir,
        ),
    )
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
    fn malformed_metadata_is_degraded_instead_of_authoritative_removal() {
        let root =
            std::env::temp_dir().join(format!("lariska-java-completeness-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let good = root.join("java17/release");
        std::fs::create_dir_all(good.parent().unwrap()).unwrap();
        std::fs::write(good, "JAVA_VERSION=\"17.0.1\"\nIMPLEMENTOR=\"Example\"").unwrap();
        let good = root.join("java21/release");
        std::fs::create_dir_all(good.parent().unwrap()).unwrap();
        std::fs::write(good, "JAVA_VERSION=\"21.0.2\"\nIMPLEMENTOR=\"Example\"").unwrap();
        let good_result = collect_java_dirs(std::slice::from_ref(&root));
        assert!(good_result.complete);
        assert_eq!(good_result.entries.len(), 2);
        let bad = root.join("broken/release");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, "no JAVA_VERSION").unwrap();
        let result = collect_java_dirs(std::slice::from_ref(&root));
        assert!(!result.complete);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.sources[0].source, SoftwareSource::Java);
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
