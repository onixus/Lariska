use super::{non_empty, CollectorResult};
use crate::model::{SoftwareEntry, SoftwareSource};
use std::collections::BTreeSet;
use std::time::Duration;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};
use winreg::RegKey;

/// Native and 32-on-64 uninstall registry views. `Win32_Product` (WMI) is
/// deliberately avoided (Plan.md §10.2: slow, can trigger MSI repair).
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

/// The same two views inside a user hive, which is rooted one level deeper.
const USER_UNINSTALL_KEYS: [(&str, &str); 2] = [
    (
        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "x86_64",
    ),
    (
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "x86",
    ),
];

/// Where Windows records the servicing updates applied to the running build.
/// Keys are named `Package_for_KB5034123~31bf3856ad364e35~amd64~~10.0.1.7`.
const CBS_PACKAGES: &str =
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";

/// `CurrentState` of a CBS package that is installed. The key exists for
/// packages that were staged, superseded or removed as well, and counting
/// those as applied updates would report a host as patched against something
/// it is not.
const CBS_STATE_INSTALLED: u32 = 112;

pub async fn collect(_timeout: Duration) -> CollectorResult {
    // Registry reads are synchronous and fast, but run off the async runtime
    // thread anyway so a slow/contended registry never blocks the heartbeat
    // loop.
    tokio::task::spawn_blocking(collect_sync)
        .await
        .unwrap_or_else(|error| CollectorResult {
            entries: Vec::new(),
            warnings: vec![format!("windows registry collector panicked: {error}")],
            complete: false,
        })
}

fn collect_sync() -> CollectorResult {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let mut complete = true;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    for (subkey_path, architecture) in UNINSTALL_KEYS {
        match hklm.open_subkey_with_flags(subkey_path, KEY_READ) {
            Ok(uninstall_key) => {
                complete &=
                    collect_from_key(&uninstall_key, architecture, &mut entries, &mut warnings)
            }
            // The Wow6432Node view does not exist on 32-bit-only Windows —
            // that is expected, not a collector failure.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                complete = false;
                warnings.push(format!("failed to open {subkey_path}: {error}"));
            }
        }
    }

    complete &= collect_user_scope(&mut entries, &mut warnings);
    complete &= collect_updates(&hklm, &mut entries, &mut warnings);

    if entries.is_empty() && warnings.is_empty() {
        complete = false;
        warnings.push("no entries found under either uninstall registry view".to_string());
    }

    CollectorResult {
        entries,
        warnings,
        complete,
    }
}

/// Per-user installs, read out of the loaded profiles under `HKEY_USERS`.
///
/// Not `HKEY_CURRENT_USER`: the agent runs as a service under SYSTEM, whose own
/// hive is where that points, and it holds nothing an operator wants. What this
/// reaches instead is every profile the system currently has loaded.
///
/// **A profile that is not loaded is not visible**, which is the honest limit of
/// doing this without mounting hives: software a signed-out user installed for
/// themselves is missing until they log in. Reported as a warning rather than
/// passed over in silence, so the gap is in the snapshot and not only in this
/// comment. Mounting every profile's `NTUSER.DAT` is the alternative, and is not
/// something a background inventory agent should be doing to a machine.
fn collect_user_scope(entries: &mut Vec<SoftwareEntry>, warnings: &mut Vec<String>) -> bool {
    let users = RegKey::predef(HKEY_USERS);
    let mut profiles = 0usize;
    let mut complete = true;

    for name in users.enum_keys() {
        let name = match name {
            Ok(name) => name,
            Err(error) => {
                complete = false;
                warnings.push(format!("failed to enumerate a user profile hive: {error}"));
                continue;
            }
        };
        if !is_user_profile_sid(&name) {
            continue;
        }
        let hive = match users.open_subkey_with_flags(&name, KEY_READ) {
            Ok(hive) => hive,
            Err(error) => {
                complete = false;
                warnings.push(format!("failed to open user profile hive {name}: {error}"));
                continue;
            }
        };
        profiles += 1;

        for (subkey_path, architecture) in USER_UNINSTALL_KEYS {
            match hive.open_subkey_with_flags(subkey_path, KEY_READ) {
                Ok(uninstall_key) => {
                    complete &= collect_from_key(&uninstall_key, architecture, entries, warnings)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    complete = false;
                    warnings.push(format!(
                        "failed to open {subkey_path} for user profile {name}: {error}"
                    ));
                }
            }
        }
    }

    if profiles == 0 {
        // This is a coverage limitation, not a failed read. Treating it as a
        // fatal collection failure would prevent unattended Windows servers
        // from ever reporting their system-wide software inventory.
        warnings.push(
            "no user profiles are loaded, so per-user installs were not collected".to_string(),
        );
    }

    complete
}

/// Whether a `HKEY_USERS` subkey is a real user's profile.
///
/// Skips `.DEFAULT`, the `_Classes` companion hives (the same software seen
/// twice), and the built-in service accounts — SYSTEM (`S-1-5-18`), LOCAL
/// SERVICE (`-19`) and NETWORK SERVICE (`-20`), the first of which is the
/// agent's own.
fn is_user_profile_sid(name: &str) -> bool {
    name.starts_with("S-1-5-21") && !name.ends_with("_Classes")
}

/// Whether an uninstall entry was installed by Windows Installer.
///
/// Two signals, because neither is present everywhere: the `WindowsInstaller`
/// value, and a key name that is a product GUID, which is what MSI names its
/// entries. Read rather than asked of WMI for the reason at the top of this
/// file — enumerating `Win32_Product` can trigger an MSI repair of every
/// installed product, which is not something an inventory agent may do.
fn is_msi_entry(subkey: &RegKey, key_name: &str) -> bool {
    if subkey.get_value::<u32, _>("WindowsInstaller").ok() == Some(1) {
        return true;
    }
    looks_like_product_guid(key_name)
}

fn looks_like_product_guid(name: &str) -> bool {
    let trimmed = name.trim();
    trimmed.len() == 38
        && trimmed.starts_with('{')
        && trimmed.ends_with('}')
        && trimmed[1..37]
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn collect_from_key(
    uninstall_key: &RegKey,
    architecture: &str,
    entries: &mut Vec<SoftwareEntry>,
    warnings: &mut Vec<String>,
) -> bool {
    let mut complete = true;

    for name in uninstall_key.enum_keys() {
        let name = match name {
            Ok(name) => name,
            Err(error) => {
                complete = false;
                warnings.push(format!("failed to enumerate uninstall subkey: {error}"));
                continue;
            }
        };

        let subkey = match uninstall_key.open_subkey(&name) {
            Ok(subkey) => subkey,
            Err(error) => {
                complete = false;
                warnings.push(format!("failed to open uninstall entry {name}: {error}"));
                continue;
            }
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
            source: if is_msi_entry(&subkey, &name) {
                SoftwareSource::Msi
            } else {
                SoftwareSource::Winreg
            },
            install_location: install_location.as_deref().and_then(non_empty),
        });
    }

    complete
}

/// The separately-identified `KB` updates applied to the running Windows build.
///
/// **This is not the whole update history, and cannot be.** A cumulative update
/// is recorded in Component Based Servicing as `Package_for_RollupFix~...~~
/// 26200.9445.1.x`, which names a build and no KB at all — so the updates that
/// matter most are, by construction, absent from this list. That is not a gap
/// in the inventory: the cumulative state *is* the build revision the host
/// reports in `os_version`, and that revision is what a match is decided on.
/// What this adds is the rest — the separately-named updates (.NET, out-of-band
/// fixes, driver packages) that ship their own KB and raise no revision, which
/// is exactly the case a revision comparison alone gets wrong.
///
/// A host with a handful of rows here is therefore normal and not a broken
/// collector.
///
/// Read from the registry rather than through the Windows Update agent's COM
/// API: no service dependency, and it still reflects a host whose update
/// history was cleared.
///
/// Only packages in state `112` are reported. A package key exists for staged,
/// superseded and removed packages too, and counting those would claim a patch
/// level the host does not have.
fn collect_updates(
    hklm: &RegKey,
    entries: &mut Vec<SoftwareEntry>,
    warnings: &mut Vec<String>,
) -> bool {
    let packages = match hklm.open_subkey_with_flags(CBS_PACKAGES, KEY_READ) {
        Ok(key) => key,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warnings.push("Component Based Servicing has no package list".to_string());
            return true;
        }
        Err(error) => {
            warnings.push(format!("failed to read installed updates: {error}"));
            return false;
        }
    };

    // One KB is many packages — one per component, per architecture — and the
    // inventory wants the update, not its parts.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut complete = true;

    for name in packages.enum_keys() {
        let name = match name {
            Ok(name) => name,
            Err(error) => {
                complete = false;
                warnings.push(format!("failed to enumerate an installed update: {error}"));
                continue;
            }
        };
        let Some(kb) = kb_id_from_package_name(&name) else {
            continue;
        };
        if seen.contains(&kb) {
            continue;
        }
        let package = match packages.open_subkey_with_flags(&name, KEY_READ) {
            Ok(package) => package,
            Err(error) => {
                complete = false;
                warnings.push(format!("failed to open installed update {name}: {error}"));
                continue;
            }
        };
        if package.get_value::<u32, _>("CurrentState").ok() != Some(CBS_STATE_INSTALLED) {
            continue;
        }
        seen.insert(kb.clone());
        entries.push(SoftwareEntry {
            name: kb,
            // A KB has no version of its own: the identifier *is* the version.
            // Repeating it would make every update look like a product whose
            // version never changes.
            version: None,
            publisher: Some("Microsoft Corporation".to_string()),
            architecture: None,
            source: SoftwareSource::Kb,
            install_location: None,
        });
    }

    if seen.is_empty() {
        warnings.push("no installed updates found under Component Based Servicing".to_string());
    }

    complete
}

/// Extracts `KB5034123` from `Package_for_KB5034123~31bf3856ad364e35~amd64~~10.0.1.7`.
///
/// `None` for the package names that carry no KB: rollups named after a
/// feature, language packs, and anything where "KB" is part of another token.
fn kb_id_from_package_name(name: &str) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    let start = upper.find("KB")?;
    let digits: String = upper[start + 2..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    // Real KB ids are six or seven digits; the length test is what keeps "KB"
    // appearing inside some other token from producing a fictitious update.
    if !(6..=8).contains(&digits.len()) {
        return None;
    }
    Some(format!("KB{digits}"))
}

#[cfg(test)]
mod tests {
    use super::{is_user_profile_sid, kb_id_from_package_name, looks_like_product_guid};

    #[test]
    fn reads_the_kb_out_of_a_package_name() {
        assert_eq!(
            kb_id_from_package_name("Package_for_KB5034123~31bf3856ad364e35~amd64~~10.0.1.7")
                .as_deref(),
            Some("KB5034123")
        );
    }

    #[test]
    fn ignores_packages_that_name_no_update() {
        assert_eq!(
            kb_id_from_package_name("Package_for_RollupFix~~amd64~~19041.1"),
            None
        );
        assert_eq!(
            kb_id_from_package_name("Microsoft-Windows-Foo~~amd64~~10.0.1"),
            None
        );
        // "KB" followed by too few digits is some other token, not an update.
        assert_eq!(kb_id_from_package_name("Package_for_KB12~amd64"), None);
    }

    #[test]
    fn recognises_an_msi_product_guid() {
        assert!(looks_like_product_guid(
            "{90160000-008C-0000-1000-0000000FF1CE}"
        ));
        assert!(!looks_like_product_guid("7-Zip"));
        assert!(!looks_like_product_guid("{not-a-guid}"));
    }

    #[test]
    fn skips_the_hives_that_are_not_a_users_software() {
        assert!(is_user_profile_sid(
            "S-1-5-21-1111111111-2222222222-3333333333-1001"
        ));
        // The agent's own hive, and the two other service accounts.
        assert!(!is_user_profile_sid("S-1-5-18"));
        assert!(!is_user_profile_sid("S-1-5-19"));
        assert!(!is_user_profile_sid("S-1-5-20"));
        assert!(!is_user_profile_sid(".DEFAULT"));
        // The same software seen twice.
        assert!(!is_user_profile_sid(
            "S-1-5-21-1111111111-2222222222-3333333333-1001_Classes"
        ));
    }
}
