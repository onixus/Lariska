use crate::inventory::{read_text_file_limited, CollectorResult};
use crate::model::{InstallationScope, SoftwareEntry, SoftwareSource};
use std::fs;
use std::path::{Path, PathBuf};

/// Collects installed Python packages from standard site-packages directories.
pub fn collect_python_packages() -> CollectorResult {
    let mut discovery = CollectorResult::default();
    let dirs = candidate_python_dirs_with_status(&mut discovery);
    let mut result = collect_python_dirs(&dirs);
    result.warnings.extend(discovery.warnings);
    if !discovery.complete {
        result.complete = false;
        result.sources.clear();
        result = result.with_source(SoftwareSource::Pip);
    }
    result
}

pub(crate) fn collect_python_dirs(dirs: &[PathBuf]) -> CollectorResult {
    let mut result = CollectorResult::default();
    for dir in dirs {
        for path in super::child_dirs(dir, &mut result) {
            if path.extension().and_then(|ext| ext.to_str()) != Some("dist-info") {
                continue;
            }
            let metadata_path = path.join("METADATA");
            match read_text_file_limited(&metadata_path)
                .and_then(|content| parse_python_metadata(&content, &path))
            {
                Some(entry) => result.entries.push(entry),
                None => result.mark_failed("metadata_unreadable"),
            }
        }
    }
    if dirs.is_empty() && result.complete {
        CollectorResult::not_applicable(SoftwareSource::Pip)
    } else {
        result.with_source(SoftwareSource::Pip)
    }
}

pub fn parse_python_metadata(content: &str, install_dir: &Path) -> Option<SoftwareEntry> {
    let mut name = None;
    let mut version = None;
    let mut author = None;

    for line in content.lines() {
        if line.trim().is_empty() {
            // End of header section in RFC 822 / Core Metadata.
            break;
        }
        let Some((key, raw_value)) = line.split_once(':') else {
            continue;
        };
        let value = raw_value.trim();

        if key.eq_ignore_ascii_case("name") {
            if !value.is_empty() {
                name = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("version") {
            if !value.is_empty() {
                version = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("author")
            && !value.is_empty()
            && !value.eq_ignore_ascii_case("unknown")
        {
            author = Some(value.to_string());
        }
    }

    let name = name?;
    if name.is_empty() {
        return None;
    }

    Some(
        SoftwareEntry {
            name: name.clone(),
            version,
            publisher: author,
            architecture: None,
            source: SoftwareSource::Pip,
            install_location: Some(install_dir.display().to_string()),
            ..SoftwareEntry::default()
        }
        .with_path_instance(Some(name.clone()), InstallationScope::Runtime, install_dir),
    )
}

pub(crate) fn candidate_python_dirs() -> Vec<PathBuf> {
    candidate_python_dirs_with_status(&mut CollectorResult::default())
}

fn candidate_python_dirs_with_status(result: &mut CollectorResult) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        add_glob_dirs("/usr/lib", "python*", "site-packages", &mut dirs, result);
        add_glob_dirs("/usr/lib", "python*", "dist-packages", &mut dirs, result);
        add_glob_dirs(
            "/usr/local/lib",
            "python*",
            "site-packages",
            &mut dirs,
            result,
        );
        add_glob_dirs(
            "/usr/local/lib",
            "python*",
            "dist-packages",
            &mut dirs,
            result,
        );
    }

    #[cfg(target_os = "macos")]
    {
        add_glob_dirs("/Library/Python", "*", "site-packages", &mut dirs, result);
        add_glob_dirs(
            "/opt/homebrew/lib",
            "python*",
            "site-packages",
            &mut dirs,
            result,
        );
        add_glob_dirs(
            "/usr/local/lib",
            "python*",
            "site-packages",
            &mut dirs,
            result,
        );
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let base = Path::new(&local_app_data).join("Programs\\Python");
            add_glob_dirs_path(&base, "Python*", "Lib\\site-packages", &mut dirs, result);
        }
        if let Ok(prog_files) = std::env::var("ProgramFiles") {
            add_glob_dirs_path(
                Path::new(&prog_files),
                "Python*",
                "Lib\\site-packages",
                &mut dirs,
                result,
            );
        }
    }

    dirs.sort();
    dirs.dedup();
    dirs
}

#[allow(dead_code)]
fn add_glob_dirs(
    parent: &str,
    pattern_prefix: &str,
    sub: &str,
    out: &mut Vec<PathBuf>,
    result: &mut CollectorResult,
) {
    add_glob_dirs_path(Path::new(parent), pattern_prefix, sub, out, result);
}

fn add_glob_dirs_path(
    parent: &Path,
    pattern_prefix: &str,
    sub: &str,
    out: &mut Vec<PathBuf>,
    result: &mut CollectorResult,
) {
    let prefix = pattern_prefix.trim_end_matches('*');
    for path in super::child_dirs(parent, result) {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.starts_with(prefix))
        {
            let target = path.join(sub);
            match fs::metadata(&target) {
                Ok(metadata) if metadata.is_dir() => out.push(target),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => result.mark_failed("directory_unreadable"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_metadata_is_degraded_instead_of_authoritative_removal() {
        let root = std::env::temp_dir().join(format!(
            "lariska-python-completeness-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let good = root.join("requests-2.31.dist-info/METADATA");
        std::fs::create_dir_all(good.parent().unwrap()).unwrap();
        std::fs::write(good, "Name: requests\nVersion: 2.31\n").unwrap();
        let good_result = collect_python_dirs(std::slice::from_ref(&root));
        assert!(good_result.complete);
        assert_eq!(good_result.entries.len(), 1);
        let bad = root.join("broken-1.dist-info/METADATA");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, "not metadata").unwrap();
        let result = collect_python_dirs(std::slice::from_ref(&root));
        assert!(!result.complete);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.sources[0].source, SoftwareSource::Pip);
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
    fn parses_valid_python_metadata() {
        let metadata = "\
Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
Home-page: https://requests.readthedocs.io
Author: Kenneth Reitz
Author-email: me@kennethreitz.org
License: Apache-2.0
";
        let entry = parse_python_metadata(metadata, Path::new("/usr/lib/python3/dist-packages"))
            .expect("should parse");
        assert_eq!(entry.name, "requests");
        assert_eq!(entry.version.as_deref(), Some("2.31.0"));
        assert_eq!(entry.publisher.as_deref(), Some("Kenneth Reitz"));
        assert_eq!(entry.source, SoftwareSource::Pip);
        assert_eq!(
            entry.install_location.as_deref(),
            Some("/usr/lib/python3/dist-packages")
        );
    }

    #[test]
    fn parses_metadata_without_a_space_after_the_separator() {
        let metadata = "Name:requests\nVersion:2.32.0\nAuthor:UNKNOWN\n\nbody";
        let entry = parse_python_metadata(metadata, Path::new("/tmp/site-packages"))
            .expect("should parse compact headers");

        assert_eq!(entry.name, "requests");
        assert_eq!(entry.version.as_deref(), Some("2.32.0"));
        assert_eq!(entry.publisher, None);
    }
}
