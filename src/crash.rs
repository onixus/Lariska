use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const CRASH_REPORT_FILE: &str = "crash_report.json";
const LAST_CRASH_REPORT_FILE: &str = "crash_report.last.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashReport {
    pub timestamp: String,
    pub agent_version: String,
    pub message: String,
    pub location: Option<String>,
}

/// Initializes the global panic hook to capture unhandled panics and persist
/// a safe, structured crash report in `state_dir/crash_report.json`.
pub fn init_panic_hook(state_dir: PathBuf) {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unspecified panic payload".to_string()
        };

        let location = panic_info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()));

        let report = CrashReport {
            timestamp,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            message: sanitize_panic_message(&message),
            location,
        };

        let report_path = state_dir.join(CRASH_REPORT_FILE);
        if let Ok(json) = serde_json::to_string_pretty(&report) {
            let temp_path = report_path.with_extension(format!("tmp-{}", std::process::id()));
            if let Ok(mut file) = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
            {
                let _ = file.write_all(json.as_bytes());
                let _ = file.sync_all();
                let _ = fs::rename(&temp_path, &report_path);
            }
        }

        default_hook(panic_info);
    }));
}

/// Checks if a crash report from a previous run exists, logs it, and moves it aside.
pub fn check_and_report_previous_crash(state_dir: &Path) -> Option<CrashReport> {
    let report_path = state_dir.join(CRASH_REPORT_FILE);
    if !report_path.exists() {
        return None;
    }

    let report = match fs::read_to_string(&report_path) {
        Ok(content) => match serde_json::from_str::<CrashReport>(&content) {
            Ok(report) => {
                tracing::error!(
                    timestamp = %report.timestamp,
                    version = %report.agent_version,
                    message = %report.message,
                    location = ?report.location,
                    "recovered crash report from previous agent panic"
                );
                Some(report)
            }
            Err(err) => {
                tracing::warn!(%err, "failed to parse previous crash report");
                None
            }
        },
        Err(err) => {
            tracing::warn!(%err, "failed to read previous crash report");
            None
        }
    };

    // Archive previous crash report to crash_report.last.json
    let last_path = state_dir.join(LAST_CRASH_REPORT_FILE);
    let _ = fs::rename(&report_path, &last_path);

    report
}

/// Bounds error message and prevents unbounded payload logging.
fn sanitize_panic_message(message: &str) -> String {
    let mut sanitized = message.trim().to_string();
    if sanitized.chars().count() > 500 {
        sanitized.truncate(500);
        sanitized.push_str("... (truncated)");
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lariska-crash-test-{label}-{}", std::process::id()))
    }

    #[test]
    fn crash_report_round_trips_and_archives() {
        let dir = temp_dir("roundtrip");
        fs::create_dir_all(&dir).unwrap();

        let report = CrashReport {
            timestamp: "2026-08-23T12:00:00Z".to_string(),
            agent_version: "0.1.0".to_string(),
            message: "unexpected test panic".to_string(),
            location: Some("src/test.rs:10:5".to_string()),
        };

        let file_path = dir.join(CRASH_REPORT_FILE);
        let json = serde_json::to_string_pretty(&report).unwrap();
        fs::write(&file_path, json).unwrap();

        let recovered = check_and_report_previous_crash(&dir).expect("should recover crash");
        assert_eq!(recovered, report);
        assert!(!file_path.exists(), "original report should be archived");
        assert!(dir.join(LAST_CRASH_REPORT_FILE).exists());

        fs::remove_dir_all(&dir).ok();
    }
}
