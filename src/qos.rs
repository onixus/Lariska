/// Sets the current process to background/idle priority and restricts execution
/// to Efficiency (E-cores) / low-power cores on hybrid CPU architectures
/// (Intel Alder/Raptor Lake, Apple Silicon M-series, ARM big.LITTLE).
pub fn set_background_priority() {
    #[cfg(target_os = "macos")]
    {
        enforce_macos_efficiency_cores();
    }

    #[cfg(target_os = "linux")]
    {
        enforce_linux_efficiency_cores();
    }

    #[cfg(target_os = "windows")]
    {
        enforce_windows_eco_qos();
    }
}

#[cfg(target_os = "macos")]
fn enforce_macos_efficiency_cores() {
    unsafe {
        // PRIO_DARWIN_BG (0x1000) puts the process into Darwin background mode.
        // On Apple Silicon (M1/M2/M3/M4) and hybrid architectures, macOS routes
        // Darwin background tasks strictly to Efficiency cores (E-cores) and
        // lowers disk/network I/O tier to background throttle.
        const PRIO_DARWIN_BG: libc::c_int = 0x1000;
        libc::setpriority(libc::PRIO_PROCESS, 0, PRIO_DARWIN_BG);

        // Also set thread QoS to background (0x09).
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_BACKGROUND, 0);
    }
}

#[cfg(target_os = "linux")]
fn enforce_linux_efficiency_cores() {
    unsafe {
        // Standard nice 19 (lowest CPU priority for CFS scheduler).
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }

    // Try to detect and pin to E-cores on hybrid Linux systems (Intel Atom / ARM LITTLE).
    if let Some(e_cores) = detect_linux_efficiency_cores() {
        if !e_cores.is_empty() {
            pin_to_cpu_indices(&e_cores);
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_efficiency_cores() -> Option<Vec<usize>> {
    use std::fs;
    use std::path::Path;

    // 1. Intel Hybrid CPUs (Linux 5.18+): /sys/devices/system/cpu/types/cpu_atom/cpus.
    let atom_path = Path::new("/sys/devices/system/cpu/types/cpu_atom/cpus");
    if let Ok(content) = fs::read_to_string(atom_path) {
        let cores = parse_cpulist(content.trim());
        if !cores.is_empty() {
            return Some(cores);
        }
    }

    // 2. ARM big.LITTLE: check /sys/devices/system/cpu/cpu*/cpu_capacity.
    let mut core_capacities: Vec<(usize, u64)> = Vec::new();
    let cpu_dir = Path::new("/sys/devices/system/cpu");
    if let Ok(entries) = fs::read_dir(cpu_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_prefix("cpu") {
                if let Ok(cpu_id) = id_str.parse::<usize>() {
                    let cap_file = entry.path().join("cpu_capacity");
                    if let Ok(cap_str) = fs::read_to_string(cap_file) {
                        if let Ok(cap) = cap_str.trim().parse::<u64>() {
                            core_capacities.push((cpu_id, cap));
                        }
                    }
                }
            }
        }
    }

    if !core_capacities.is_empty() {
        let max_capacity = core_capacities
            .iter()
            .map(|(_, cap)| *cap)
            .max()
            .unwrap_or(0);
        let min_capacity = core_capacities
            .iter()
            .map(|(_, cap)| *cap)
            .min()
            .unwrap_or(0);

        // If heterogeneous core capacities are present (e.g. 300 LITTLE vs 1024 big).
        if max_capacity > min_capacity {
            let e_cores: Vec<usize> = core_capacities
                .into_iter()
                .filter(|(_, cap)| *cap < max_capacity)
                .map(|(cpu_id, _)| cpu_id)
                .collect();
            if !e_cores.is_empty() {
                return Some(e_cores);
            }
        }
    }

    // 3. AMD Zen 4c / Zen 5c & x86 CPPC (acpi_cppc/highest_perf or cpuinfo_max_freq).
    let mut core_cppc: Vec<(usize, u64)> = Vec::new();
    if let Ok(entries) = fs::read_dir(cpu_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_prefix("cpu") {
                if let Ok(cpu_id) = id_str.parse::<usize>() {
                    let cppc_file = entry.path().join("acpi_cppc/highest_perf");
                    if let Ok(val_str) = fs::read_to_string(cppc_file) {
                        if let Ok(perf) = val_str.trim().parse::<u64>() {
                            core_cppc.push((cpu_id, perf));
                            continue;
                        }
                    }

                    // Fallback to max frequency check.
                    let freq_file = entry.path().join("cpufreq/cpuinfo_max_freq");
                    if let Ok(val_str) = fs::read_to_string(freq_file) {
                        if let Ok(freq) = val_str.trim().parse::<u64>() {
                            core_cppc.push((cpu_id, freq));
                        }
                    }
                }
            }
        }
    }

    if !core_cppc.is_empty() {
        let max_perf = core_cppc.iter().map(|(_, p)| *p).max().unwrap_or(0);
        let min_perf = core_cppc.iter().map(|(_, p)| *p).min().unwrap_or(0);

        // If heterogeneous cores exist (e.g. Zen 5 vs Zen 5c).
        if max_perf > min_perf && min_perf > 0 {
            let e_cores: Vec<usize> = core_cppc
                .into_iter()
                .filter(|(_, p)| *p < max_perf)
                .map(|(cpu_id, _)| cpu_id)
                .collect();
            if !e_cores.is_empty() {
                return Some(e_cores);
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn parse_cpulist(list: &str) -> Vec<usize> {
    let mut cores = Vec::new();
    for part in list.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<usize>(), end.parse::<usize>()) {
                for id in s..=e {
                    cores.push(id);
                }
            }
        } else if let Ok(id) = part.parse::<usize>() {
            cores.push(id);
        }
    }
    cores
}

#[cfg(target_os = "linux")]
fn pin_to_cpu_indices(core_indices: &[usize]) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &cpu in core_indices {
            if cpu < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(cpu, &mut set);
            }
        }
        libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set as *const libc::cpu_set_t,
        );
    }
}

#[cfg(target_os = "windows")]
fn enforce_windows_eco_qos() {
    #[repr(C)]
    struct ProcessPowerThrottlingState {
        version: u32,
        control_mask: u32,
        state_mask: u32,
    }

    const PROCESS_POWER_THROTTLING_CURRENT_VERSION: u32 = 1;
    const PROCESS_POWER_THROTTLING_EXECUTION_SPEED: u32 = 1;
    const PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION: u32 = 4;
    const PROCESS_INFORMATION_CLASS_POWER_THROTTLING: i32 = 4;
    const IDLE_PRIORITY_CLASS: u32 = 0x00000040;

    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn SetPriorityClass(process: isize, priority_class: u32) -> i32;
        fn SetProcessInformation(
            process: isize,
            process_information_class: i32,
            process_information: *const std::ffi::c_void,
            process_information_size: u32,
        ) -> i32;
    }

    unsafe {
        let process = GetCurrentProcess();
        // 1. Lower process priority class.
        SetPriorityClass(process, IDLE_PRIORITY_CLASS);

        // 2. Enable Windows 11 / 10 EcoQoS (Power Throttling).
        // This instructs Intel Thread Director / Windows Scheduler to execute on E-cores.
        let throttle = ProcessPowerThrottlingState {
            version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            control_mask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED
                | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
            state_mask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED
                | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
        };
        SetProcessInformation(
            process,
            PROCESS_INFORMATION_CLASS_POWER_THROTTLING,
            &throttle as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<ProcessPowerThrottlingState>() as u32,
        );
    }
}

/// Detects whether the host device is currently running on battery power.
pub fn is_on_battery() -> bool {
    #[cfg(target_os = "linux")]
    {
        check_linux_battery()
    }

    #[cfg(target_os = "macos")]
    {
        check_macos_battery()
    }

    #[cfg(target_os = "windows")]
    {
        check_windows_battery()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn check_linux_battery() -> bool {
    use std::path::Path;
    let power_supply = Path::new("/sys/class/power_supply");
    if let Ok(entries) = std::fs::read_dir(power_supply) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("BAT") {
                let status_path = entry.path().join("status");
                if let Ok(status) = std::fs::read_to_string(status_path) {
                    if status.trim().eq_ignore_ascii_case("Discharging") {
                        return true;
                    }
                }
            } else if name.starts_with("AC") || name.starts_with("ADP") {
                let online_path = entry.path().join("online");
                if let Ok(online) = std::fs::read_to_string(online_path) {
                    if online.trim() == "0" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn check_macos_battery() -> bool {
    use crate::inventory::find_trusted_binary;
    let pmset =
        find_trusted_binary("pmset").unwrap_or_else(|| std::path::PathBuf::from("/usr/bin/pmset"));
    let output = std::process::Command::new(pmset)
        .args(["-g", "batt"])
        .output();

    if let Ok(output) = output {
        let text = String::from_utf8_lossy(&output.stdout);
        return text.contains("Battery Power");
    }
    false
}

#[cfg(target_os = "windows")]
fn check_windows_battery() -> bool {
    #[repr(C)]
    struct SystemPowerStatus {
        ac_line_status: u8,
        battery_flag: u8,
        battery_life_percent: u8,
        system_status_flag: u8,
        battery_life_time: u32,
        battery_full_life_time: u32,
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetSystemPowerStatus(status: *mut SystemPowerStatus) -> i32;
    }

    let mut status = SystemPowerStatus {
        ac_line_status: u8::MAX,
        battery_flag: u8::MAX,
        battery_life_percent: u8::MAX,
        system_status_flag: 0,
        battery_life_time: u32::MAX,
        battery_full_life_time: u32::MAX,
    };

    let succeeded = unsafe { GetSystemPowerStatus(&mut status) } != 0;
    succeeded && ac_line_status_is_battery(status.ac_line_status)
}

#[cfg(any(test, target_os = "windows"))]
fn ac_line_status_is_battery(status: u8) -> bool {
    // SYSTEM_POWER_STATUS: 0 = offline/DC, 1 = online/AC, 255 = unknown.
    status == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_background_priority_does_not_panic() {
        set_background_priority();
    }

    #[test]
    fn is_on_battery_returns_boolean() {
        let _on_battery = is_on_battery();
    }

    #[test]
    fn windows_ac_status_mapping_is_conservative() {
        assert!(ac_line_status_is_battery(0));
        assert!(!ac_line_status_is_battery(1));
        assert!(!ac_line_status_is_battery(u8::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_cpulist() {
        let cores = parse_cpulist("0-3,8-11,15");
        assert_eq!(cores, vec![0, 1, 2, 3, 8, 9, 10, 11, 15]);
    }
}
