use crate::inventory::read_text_file_limited;
use crate::model::{SoftwareEntry, SoftwareSource};
use std::fs;
use std::path::{Path, PathBuf};

/// Collects installed Python packages from standard site-packages directories.
pub fn collect_python_packages() -> Vec<SoftwareEntry> {
    let search_dirs = candidate_python_dirs();
    let mut entries = Vec::new();

    for dir in search_dirs {
        if !dir.is_dir() {
            continue;
        }

        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };

        for item in read_dir.flatten() {
            let path = item.path();
            if path.is_dir() && path.extension().and_then(|ext| ext.to_str()) == Some("dist-info") {
                let metadata_path = path.join("METADATA");
                if let Some(content) = read_text_file_limited(&metadata_path) {
                    if let Some(entry) = parse_python_metadata(&content, &dir) {
                        entries.push(entry);
                    }
                }
            }
        }
    }

    entries
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

    Some(SoftwareEntry {
        name,
        version,
        publisher: author,
        architecture: None,
        source: SoftwareSource::Pip,
        install_location: Some(install_dir.display().to_string()),
    })
}

pub(crate) fn candidate_python_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        add_glob_dirs("/usr/lib", "python*", "site-packages", &mut dirs);
        add_glob_dirs("/usr/lib", "python*", "dist-packages", &mut dirs);
        add_glob_dirs("/usr/local/lib", "python*", "site-packages", &mut dirs);
        add_glob_dirs("/usr/local/lib", "python*", "dist-packages", &mut dirs);
    }

    #[cfg(target_os = "macos")]
    {
        add_glob_dirs("/Library/Python", "*", "site-packages", &mut dirs);
        add_glob_dirs("/opt/homebrew/lib", "python*", "site-packages", &mut dirs);
        add_glob_dirs("/usr/local/lib", "python*", "site-packages", &mut dirs);
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let base = Path::new(&local_app_data).join("Programs\\Python");
            add_glob_dirs_path(&base, "Python*", "Lib\\site-packages", &mut dirs);
        }
        if let Ok(prog_files) = std::env::var("ProgramFiles") {
            add_glob_dirs_path(
                Path::new(&prog_files),
                "Python*",
                "Lib\\site-packages",
                &mut dirs,
            );
        }
    }

    dirs.sort();
    dirs.dedup();
    dirs
}

#[allow(dead_code)]
fn add_glob_dirs(parent: &str, pattern_prefix: &str, sub: &str, out: &mut Vec<PathBuf>) {
    add_glob_dirs_path(Path::new(parent), pattern_prefix, sub, out);
}

fn add_glob_dirs_path(parent: &Path, pattern_prefix: &str, sub: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let prefix = pattern_prefix.trim_end_matches('*');

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(prefix) {
                    let target = path.join(sub);
                    if target.is_dir() {
                        out.push(target);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
