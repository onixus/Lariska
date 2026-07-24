use super::{non_empty, CollectorResult};
use crate::model::{SoftwareEntry, SoftwareSource};
use std::time::Duration;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

/// Native and 32-on-64 uninstall registry views. `Win32_Product` (WMI) is
/// deliberately avoided (Plan.md §10.2: slow, can trigger MSI repair).
/// Machine scope only in this release — see the open decision on user-scope
/// inventory for a system-context service in Plan.md §19.
const UNINSTALL_KEYS: [(&str, &str); 2] = [
    (
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "x86_64",
    ),
    (
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "x86",
    ),
];

pub async fn collect(_timeout: Duration) -> CollectorResult {
    // Registry reads are synchronous and fast, but run off the async runtime
    // thread anyway so a slow/contended registry never blocks the heartbeat
    // loop.
    tokio::task::spawn_blocking(collect_sync)
        .await
        .unwrap_or_else(|error| CollectorResult {
            entries: Vec::new(),
            warnings: vec![format!("windows registry collector panicked: {error}")],
        })
}

fn collect_sync() -> CollectorResult {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    for (subkey_path, architecture) in UNINSTALL_KEYS {
        match hklm.open_subkey_with_flags(subkey_path, KEY_READ) {
            Ok(uninstall_key) => {
                collect_from_key(&uninstall_key, architecture, &mut entries, &mut warnings)
            }
            // The Wow6432Node view does not exist on 32-bit-only Windows —
            // that is expected, not a collector failure.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warnings.push(format!("failed to open {subkey_path}: {error}")),
        }
    }

    if entries.is_empty() && warnings.is_empty() {
        warnings.push("no entries found under either uninstall registry view".to_string());
    }

    CollectorResult { entries, warnings }
}

fn collect_from_key(
    uninstall_key: &RegKey,
    architecture: &str,
    entries: &mut Vec<SoftwareEntry>,
    warnings: &mut Vec<String>,
) {
    for name in uninstall_key.enum_keys() {
        let name = match name {
            Ok(name) => name,
            Err(error) => {
                warnings.push(format!("failed to enumerate uninstall subkey: {error}"));
                continue;
            }
        };

        let Ok(subkey) = uninstall_key.open_subkey(&name) else {
            continue;
        };

        // Patches/system components without a DisplayName are not
        // user-facing software; skip them rather than emit a blank entry.
        let display_name: Option<String> = subkey.get_value("DisplayName").ok();
        let Some(display_name) = display_name.as_deref().and_then(non_empty) else {
            continue;
        };

        let version: Option<String> = subkey.get_value("DisplayVersion").ok();
        let publisher: Option<String> = subkey.get_value("Publisher").ok();
        let install_location: Option<String> = subkey.get_value("InstallLocation").ok();

        entries.push(SoftwareEntry {
            name: display_name,
            version: version.as_deref().and_then(non_empty),
            publisher: publisher.as_deref().and_then(non_empty),
            architecture: Some(architecture.to_string()),
            source: SoftwareSource::Winreg,
            install_location: install_location.as_deref().and_then(non_empty),
        });
    }
}
