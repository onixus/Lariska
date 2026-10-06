pub mod java;
pub mod nodejs;
pub mod python;
use crate::inventory::CollectorResult;

pub fn collect_all_runtimes() -> CollectorResult {
    let mut result = CollectorResult::default();
    result.merge(python::collect_python_packages());
    result.merge(nodejs::collect_nodejs_packages());
    result.merge(java::collect_java_runtimes());
    result
}

pub(crate) fn child_dirs(
    path: &std::path::Path,
    result: &mut CollectorResult,
) -> Vec<std::path::PathBuf> {
    let items = match std::fs::read_dir(path) {
        Ok(items) => items,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            result.mark_failed("directory_unreadable");
            return Vec::new();
        }
    };
    let mut dirs = Vec::new();
    for item in items {
        if dirs.len() >= 100_000 {
            result.mark_failed("collection_limit_exceeded");
            break;
        }
        let item = match item {
            Ok(item) => item,
            Err(_) => {
                result.mark_failed("directory_unreadable");
                continue;
            }
        };
        let path = item.path();
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => dirs.push(path),
            Ok(_) => {}
            // A dangling symlink is not an unreadable directory.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => result.mark_failed("directory_unreadable"),
        }
    }
    dirs.sort();
    dirs
}
