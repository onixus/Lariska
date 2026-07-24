use std::process::Command;

pub fn collect_software() -> Vec<String> {
    platform_software().unwrap_or_else(|error| {
        eprintln!("Software inventory collection failed: {error}");
        Vec::new()
    })
}

#[cfg(target_os = "windows")]
fn platform_software() -> Result<Vec<String>, String> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object -ExpandProperty DisplayName",
        ])
        .output()
        .map_err(|error| format!("failed to execute PowerShell: {error}"))?;

    if !output.status.success() {
        return Err(format!("PowerShell exited with status {}", output.status));
    }

    Ok(parse_lines(&output.stdout))
}

#[cfg(target_os = "linux")]
fn platform_software() -> Result<Vec<String>, String> {
    let output = Command::new("dpkg-query")
        .args(["-f", "${binary:Package}\n", "-W"])
        .output()
        .map_err(|error| format!("failed to execute dpkg-query: {error}"))?;

    if !output.status.success() {
        return Err(format!("dpkg-query exited with status {}", output.status));
    }

    Ok(parse_lines(&output.stdout))
}

#[cfg(target_os = "macos")]
fn platform_software() -> Result<Vec<String>, String> {
    let output = Command::new("ls")
        .args(["/Applications"])
        .output()
        .map_err(|error| format!("failed to list /Applications: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "ls /Applications exited with status {}",
            output.status
        ));
    }

    Ok(parse_lines(&output.stdout))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn platform_software() -> Result<Vec<String>, String> {
    Err("software collection is not supported on this operating system".to_string())
}

fn parse_lines(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines_trims_and_skips_empty_lines() {
        let packages = parse_lines(b" bash \n\n coreutils\n\tserde-json\t\n");

        assert_eq!(packages, vec!["bash", "coreutils", "serde-json"]);
    }
}
