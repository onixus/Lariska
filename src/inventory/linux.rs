use super::{non_empty, run_command, CollectorResult, CommandRunError};
use crate::model::{SoftwareEntry, SoftwareSource};
use std::time::Duration;

/// Runs every Linux package-manager collector that is actually present on
/// this system (Plan.md §10.1 "detect available package managers"). A
/// missing binary is not an error; a binary that exists but fails is.
pub async fn collect(timeout: Duration) -> CollectorResult {
    let mut result = CollectorResult::default();
    let mut any_manager_present = false;

    if let Some(dpkg) = collect_dpkg(timeout).await {
        any_manager_present = true;
        result.merge(dpkg);
    }
    if let Some(rpm) = collect_rpm(timeout).await {
        any_manager_present = true;
        result.merge(rpm);
    }
    if let Some(pacman) = collect_pacman(timeout).await {
        any_manager_present = true;
        result.merge(pacman);
    }

    if !any_manager_present {
        result.warnings.push(
            "no supported Linux package manager (dpkg-query/rpm/pacman) was found".to_string(),
        );
    }

    result
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
}
