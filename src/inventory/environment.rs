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
