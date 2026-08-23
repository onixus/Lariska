pub mod java;
pub mod nodejs;
pub mod python;

use crate::model::SoftwareEntry;

/// Collects software from all language runtime package ecosystems.
pub fn collect_all_runtimes() -> Vec<SoftwareEntry> {
    let mut entries = Vec::new();

    entries.extend(python::collect_python_packages());
    entries.extend(nodejs::collect_nodejs_packages());
    entries.extend(java::collect_java_runtimes());

    entries
}
