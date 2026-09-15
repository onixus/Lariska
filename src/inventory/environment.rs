use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentInfo {
    pub env_type: &'static str,
    pub container_engine: Option<&'static str>,
    pub hypervisor: Option<&'static str>,
    pub cloud_provider: Option<&'static str>,
}

impl EnvironmentInfo {
    pub fn to_labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert("env.type".to_string(), self.env_type.to_string());

        if let Some(engine) = self.container_engine {
            labels.insert("env.container_engine".to_string(), engine.to_string());
        }
        if let Some(hypervisor) = self.hypervisor {
            labels.insert("env.hypervisor".to_string(), hypervisor.to_string());
        }
        if let Some(cloud) = self.cloud_provider {
            labels.insert("env.cloud_provider".to_string(), cloud.to_string());
        }

        labels
    }
}

/// Detects whether the agent is running on physical hardware, inside a virtual machine,
/// or inside a container.
pub fn detect_environment() -> EnvironmentInfo {
    // 1. Check for container environment first (highest specificity)
    if let Some(container_engine) = detect_container() {
        return EnvironmentInfo {
            env_type: "container",
            container_engine: Some(container_engine),
            hypervisor: None,
            cloud_provider: None,
        };
    }

    // 2. Check for hypervisor / virtualization
    let (hypervisor, cloud) = detect_hypervisor();
    if hypervisor.is_some() || cloud.is_some() {
        return EnvironmentInfo {
            env_type: "virtual",
            container_engine: None,
            hypervisor,
            cloud_provider: cloud,
        };
    }

    // 3. Physical hardware fallback
    EnvironmentInfo {
        env_type: "physical",
        container_engine: None,
        hypervisor: None,
        cloud_provider: None,
    }
}

fn detect_container() -> Option<&'static str> {
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        return Some("kubernetes");
    }
    if Path::new("/run/.containerenv").exists() {
        return Some("podman");
    }
    if Path::new("/.dockerenv").exists() {
        return Some("docker");
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            if cgroup.contains("docker") {
                return Some("docker");
            }
            if cgroup.contains("kubepods") {
                return Some("kubernetes");
            }
            if cgroup.contains("containerd") {
                return Some("containerd");
            }
        }
    }

    None
}

fn detect_hypervisor() -> (Option<&'static str>, Option<&'static str>) {
    #[cfg(target_os = "linux")]
    {
        let vendor = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor").unwrap_or_default();
        let product = std::fs::read_to_string("/sys/class/dmi/id/product_name").unwrap_or_default();
        classify_dmi(&vendor, &product)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS sysctl check for Virtual Machine guest
        let output = std::process::Command::new("sysctl")
            .args(["-n", "kern.hv_vmm_present"])
            .output();

        if let Ok(output) = output {
            if String::from_utf8_lossy(&output.stdout).trim() == "1" {
                return (Some("hypervisor_framework"), None);
            }
        }
        (None, None)
    }

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("HARDWARE\\DESCRIPTION\\System\\BIOS") {
            let vendor: String = key.get_value("SystemManufacturer").unwrap_or_default();
            let product: String = key.get_value("SystemProductName").unwrap_or_default();
            return classify_dmi(&vendor, &product);
        }
        (None, None)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        (None, None)
    }
}

#[allow(dead_code)]
fn classify_dmi(vendor: &str, product: &str) -> (Option<&'static str>, Option<&'static str>) {
    let v_lower = vendor.to_lowercase();
    let p_lower = product.to_lowercase();

    if v_lower.contains("qemu") || p_lower.contains("qemu") || p_lower.contains("kvm") {
        (Some("kvm_qemu"), None)
    } else if v_lower.contains("vmware") || p_lower.contains("vmware") {
        (Some("vmware"), None)
    } else if v_lower.contains("innotek") || p_lower.contains("virtualbox") {
        (Some("virtualbox"), None)
    } else if v_lower.contains("microsoft") && p_lower.contains("virtual") {
        (Some("hyperv"), None)
    } else if v_lower.contains("amazon ec2") || p_lower.contains("amazon ec2") {
        (Some("nitro_kvm"), Some("aws"))
    } else if v_lower.contains("google") || p_lower.contains("google") {
        (Some("kvm"), Some("gcp"))
    } else {
        (None, None)
    }
}

/// Product name and version of the running OS, as the inventory schema wants
/// them: `name` is what an operator calls the machine's OS ("Windows 11 Pro"),
/// `version` is what a matcher parses ("10.0.22631.4169"). Either may be
/// `None` on a platform whose collector has not been written yet; the caller
/// falls back to `std::env::consts::OS` for the name and sends no version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Reads the OS product name and version from the platform.
///
/// Windows is the only platform implemented here (#358). Linux and macOS still
/// report `std::env::consts::OS` with no version, which is why their inventory
/// matches as `unknown_distro` server-side — tracked separately.
pub fn detect_os_release() -> OsRelease {
    #[cfg(target_os = "windows")]
    {
        windows_os_release()
    }

    #[cfg(not(target_os = "windows"))]
    {
        OsRelease::default()
    }
}

#[cfg(target_os = "windows")]
fn windows_os_release() -> OsRelease {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm
        .open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", KEY_READ)
    {
        Ok(key) => key,
        Err(_) => return OsRelease::default(),
    };

    let product: Option<String> = key.get_value("ProductName").ok();
    let build: Option<String> = key.get_value("CurrentBuildNumber").ok();
    let major: Option<u32> = key.get_value("CurrentMajorVersionNumber").ok();
    let minor: Option<u32> = key.get_value("CurrentMinorVersionNumber").ok();
    let ubr: Option<u32> = key.get_value("UBR").ok();
    let installation_type: Option<String> = key.get_value("InstallationType").ok();

    let build_number = build.as_deref().and_then(|value| value.trim().parse::<u32>().ok());

    OsRelease {
        name: product.map(|product| {
            windows_product_name(&product, build_number, installation_type.as_deref())
        }),
        version: windows_version_string(major, minor, build.as_deref(), ubr),
    }
}

/// Windows 11 keeps reporting `ProductName` as "Windows 10 …" — the edition was
/// never rewritten in the registry, and Microsoft's own guidance is to read the
/// build number instead. Client builds from 22000 up are Windows 11; Server
/// installations keep whatever name they were given.
#[cfg(target_os = "windows")]
fn windows_product_name(
    product: &str,
    build: Option<u32>,
    installation_type: Option<&str>,
) -> String {
    let is_client = installation_type
        .map(|value| value.eq_ignore_ascii_case("Client"))
        .unwrap_or(true);

    if is_client && build.map(|build| build >= 22000).unwrap_or(false) {
        if let Some(rest) = product.strip_prefix("Windows 10") {
            return format!("Windows 11{rest}");
        }
    }

    product.to_string()
}

/// `major.minor.build.ubr`, the form MSRC and the Update Guide use. Anything the
/// registry does not answer is dropped from the right, so a machine missing
/// `UBR` still reports `10.0.22631` rather than a version with an empty field.
#[cfg(target_os = "windows")]
fn windows_version_string(
    major: Option<u32>,
    minor: Option<u32>,
    build: Option<&str>,
    ubr: Option<u32>,
) -> Option<String> {
    let build = build.map(str::trim).filter(|value| !value.is_empty())?;
    let major = major?;
    let minor = minor.unwrap_or(0);

    Some(match ubr {
        Some(ubr) => format!("{major}.{minor}.{build}.{ubr}"),
        None => format!("{major}.{minor}.{build}"),
    })
}

#[cfg(all(test, target_os = "windows"))]
mod windows_release_tests {
    use super::{windows_product_name, windows_version_string};

    #[test]
    fn renames_windows_10_product_on_a_windows_11_client_build() {
        assert_eq!(
            windows_product_name("Windows 10 Pro", Some(22631), Some("Client")),
            "Windows 11 Pro"
        );
    }

    #[test]
    fn leaves_the_product_name_alone_below_the_windows_11_build() {
        assert_eq!(
            windows_product_name("Windows 10 Pro", Some(19045), Some("Client")),
            "Windows 10 Pro"
        );
    }

    #[test]
    fn leaves_server_names_alone_even_on_a_high_build() {
        assert_eq!(
            windows_product_name("Windows Server 2025 Standard", Some(26100), Some("Server")),
            "Windows Server 2025 Standard"
        );
    }

    #[test]
    fn builds_the_four_part_version() {
        assert_eq!(
            windows_version_string(Some(10), Some(0), Some("22631"), Some(4169)).as_deref(),
            Some("10.0.22631.4169")
        );
    }

    #[test]
    fn drops_the_revision_when_the_registry_has_no_ubr() {
        assert_eq!(
            windows_version_string(Some(10), Some(0), Some("22631"), None).as_deref(),
            Some("10.0.22631")
        );
    }

    #[test]
    fn reports_no_version_without_a_build_number() {
        assert_eq!(windows_version_string(Some(10), Some(0), None, Some(4169)), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_kvm_qemu_correctly() {
        let (hv, cloud) = classify_dmi("QEMU", "Standard PC (Q35 + ICH9, 2009)");
        assert_eq!(hv, Some("kvm_qemu"));
        assert_eq!(cloud, None);
    }

    #[test]
    fn classifies_vmware_correctly() {
        let (hv, cloud) = classify_dmi("VMware, Inc.", "VMware Virtual Platform");
        assert_eq!(hv, Some("vmware"));
        assert_eq!(cloud, None);
    }

    #[test]
    fn classifies_aws_ec2_correctly() {
        let (hv, cloud) = classify_dmi("Amazon EC2", "t4g.nano");
        assert_eq!(hv, Some("nitro_kvm"));
        assert_eq!(cloud, Some("aws"));
    }

    #[test]
    fn classifies_physical_when_no_match() {
        let (hv, cloud) = classify_dmi("Dell Inc.", "PowerEdge R640");
        assert_eq!(hv, None);
        assert_eq!(cloud, None);
    }
}
