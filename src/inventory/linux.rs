use super::{non_empty, run_command, CollectorResult, CommandRunError};
use crate::model::{SoftwareEntry, SoftwareSource};
use std::path::Path;
use std::time::Duration;

const DPKG_DATABASES: &[&str] = &["/var/lib/dpkg/status"];
const RPM_DATABASES: &[&str] = &["/usr/lib/sysimage/rpm", "/var/lib/rpm"];
const PACMAN_DATABASES: &[&str] = &["/var/lib/pacman/local"];

/// Runs the Linux package-manager collectors that own a package database on
/// this host. Merely having a client binary installed is not enough: build
/// images and administrator toolboxes frequently contain `rpm` on Debian or
/// `dpkg-query` on RPM systems, and querying all of them wastes I/O and can
/// produce duplicate/confusing inventory.
///
/// If no standard database location is found, fall back to probing available
/// binaries. This preserves compatibility with installations that relocate a
/// package database instead of silently returning an empty inventory.
pub async fn collect(timeout: Duration) -> CollectorResult {
    let mut result = CollectorResult::default();
    let mut any_manager_present = false;

    let dpkg_database = database_present(DPKG_DATABASES);
    let rpm_database = database_present(RPM_DATABASES);
    let pacman_database = database_present(PACMAN_DATABASES);
    let any_database = dpkg_database || rpm_database || pacman_database;

    if should_probe_manager(dpkg_database, any_database) {
        if let Some(dpkg) = collect_dpkg(timeout).await {
            any_manager_present = true;
            result.merge(dpkg);
        }
    }
    if should_probe_manager(rpm_database, any_database) {
        if let Some(rpm) = collect_rpm(timeout).await {
            any_manager_present = true;
            result.merge(rpm);
        }
    }
    if should_probe_manager(pacman_database, any_database) {
        if let Some(pacman) = collect_pacman(timeout).await {
            any_manager_present = true;
            result.merge(pacman);
        }
    }

    if !any_manager_present {
        result.complete = false;
        result.warnings.push(
            "no supported Linux package manager (dpkg-query/rpm/pacman) was found".to_string(),
        );
    }

    result
}

fn database_present(paths: &[&str]) -> bool {
    paths.iter().any(|path| Path::new(path).exists())
}

fn should_probe_manager(its_database_is_present: bool, any_database_is_present: bool) -> bool {
    its_database_is_present || !any_database_is_present
}

async fn collect_dpkg(timeout: Duration) -> Option<CollectorResult> {
    let output = match run_command(
        "dpkg-query",
        &[
            "-W",
            "-f",
            "${Package}\t${Version}\t${Architecture}\t${Maintainer}\n",
        ],
        timeout,
    )
    .await
    {
        Ok(output) => output,
        Err(CommandRunError::NotFound) => return None,
        Err(CommandRunError::Other(message)) => {
            return Some(collector_failure("dpkg-query", &message))
        }
    };

    Some(CollectorResult {
        entries: parse_tab_separated(&output, SoftwareSource::Dpkg),
        warnings: Vec::new(),
        complete: true,
    })
}

async fn collect_rpm(timeout: Duration) -> Option<CollectorResult> {
    let output = match run_command(
        "rpm",
        &[
            "-qa",
            "--qf",
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n",
        ],
        timeout,
    )
    .await
    {
        Ok(output) => output,
        Err(CommandRunError::NotFound) => return None,
        Err(CommandRunError::Other(message)) => return Some(collector_failure("rpm", &message)),
    };

    Some(CollectorResult {
        entries: parse_tab_separated(&output, SoftwareSource::Rpm),
        warnings: Vec::new(),
        complete: true,
    })
}

async fn collect_pacman(timeout: Duration) -> Option<CollectorResult> {
    // `pacman -Q` only prints "name version" — no architecture or publisher
    // field is available without a much slower `-Qi` call per package.
    let output = match run_command("pacman", &["-Q"], timeout).await {
        Ok(output) => output,
        Err(CommandRunError::NotFound) => return None,
        Err(CommandRunError::Other(message)) => return Some(collector_failure("pacman", &message)),
    };

    let entries = output
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(2, ' ');
            let name = fields.next()?;
            let version = fields.next();
            if name.trim().is_empty() {
                return None;
            }
            Some(SoftwareEntry {
                name: name.to_string(),
                version: version.and_then(non_empty),
                publisher: None,
                architecture: None,
                // pacman is not in the server's closed source enum; bucket
                // it as "other" rather than inventing a new literal.
                source: SoftwareSource::from_raw("pacman"),
                install_location: None,
            })
        })
        .collect();

    Some(CollectorResult {
        entries,
        warnings: Vec::new(),
        complete: true,
    })
}

fn parse_tab_separated(output: &str, source: SoftwareSource) -> Vec<SoftwareEntry> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, '\t');
            let name = fields.next()?;
            let version = fields.next();
            let architecture = fields.next();
            let publisher = fields.next();
            if name.trim().is_empty() {
                return None;
            }
            Some(SoftwareEntry {
                name: name.to_string(),
                version: version.and_then(non_empty),
                publisher: publisher.and_then(non_empty),
                architecture: architecture.and_then(non_empty),
                source,
                install_location: None,
            })
        })
        .collect()
}

fn collector_failure(collector: &str, message: &str) -> CollectorResult {
    CollectorResult {
        entries: Vec::new(),
        warnings: vec![format!("{collector} collector failed: {message}")],
        complete: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dpkg_style_tab_separated_output() {
        let output = "curl\t8.5.0-2ubuntu10\tamd64\tCanonical\nbash\t5.2.15-2\tamd64\t \n";
        let entries = parse_tab_separated(output, SoftwareSource::Dpkg);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "curl");
        assert_eq!(entries[0].version.as_deref(), Some("8.5.0-2ubuntu10"));
        assert_eq!(entries[0].publisher.as_deref(), Some("Canonical"));
        assert_eq!(entries[1].publisher, None);
    }

    #[test]
    fn skips_malformed_and_blank_lines() {
        let output = "\n   \ncurl\t1.0\tamd64\tCanonical\n";
        let entries = parse_tab_separated(output, SoftwareSource::Dpkg);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "curl");
    }

    #[test]
    fn a_collector_failure_is_not_authoritative() {
        let result = collector_failure("dpkg-query", "timed out");

        assert!(!result.complete);
        assert!(result.entries.is_empty());
    }

    #[test]
    fn probes_only_the_manager_with_database_evidence() {
        assert!(should_probe_manager(true, true));
        assert!(!should_probe_manager(false, true));
    }

    #[test]
    fn falls_back_to_binary_probing_when_databases_are_relocated() {
        assert!(should_probe_manager(false, false));
    }
}
