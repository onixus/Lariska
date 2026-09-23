use crate::api::{ApiClient, ApiError};
use crate::auth::AuthClient;
use crate::config::Config;
use crate::delivery::DeliveryClient;
use crate::heartbeat::{self, HeartbeatClient};
use crate::identity;
use crate::inventory::{self, CollectorResult};
use crate::managed;
use crate::model::{EndpointIdentifier, InventorySnapshot};
use crate::{service, telemetry};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// Bounded retry for the one-time startup registration call: a transient
/// network blip at boot should not require a process restart, but a
/// misconfigured/revoked provisioning key must fail fast.
const REGISTER_MAX_ATTEMPTS: u32 = 5;
const REGISTER_BASE_BACKOFF: Duration = Duration::from_secs(1);
const BATTERY_INTERVAL_MULTIPLIER: u64 = 4;
const MAX_EFFECTIVE_INVENTORY_INTERVAL: Duration = Duration::from_secs(86_400);
const MAX_STARTUP_JITTER: Duration = Duration::from_secs(300);
const INVENTORY_JITTER_DIVISOR: u64 = 10;

pub fn run(config_path: &Path, running_as_service: bool) -> Result<(), String> {
    run_internal(config_path, running_as_service, None)
}

/// Entry point used by the Windows SCM integration (`service::windows_scm`):
/// same as `run`, but shutdown is additionally driven by `external_shutdown`,
/// which the SCM's Stop/Shutdown control handler notifies — under the SCM
/// there is no console attached, so `Ctrl-C`/`SIGTERM` never fire.
#[cfg(windows)]
pub fn run_as_windows_service(
    config_path: &Path,
    external_shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> Result<(), String> {
    run_internal(config_path, true, Some(external_shutdown))
}

#[cfg(windows)]
pub fn default_service_config_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\Lariska\config\lariska.toml")
}

/// Where the service writes a failure it hit before the configuration — and
/// therefore the configured `state_dir` — was readable. Fixed rather than
/// derived for exactly that reason.
#[cfg(windows)]
pub fn default_service_state_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\Lariska\state")
}

fn run_internal(
    config_path: &Path,
    running_as_service: bool,
    external_shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Result<(), String> {
    let config = Config::from_file_and_env(config_path).map_err(|error| error.to_string())?;
    // Under the Windows SCM stdout goes nowhere, so a service that logs there
    // cannot be diagnosed at all; log into the state directory instead. Only
    // on Windows: the systemd unit and launchd job also pass `--service`, and
    // there stdout is exactly where the log belongs (journald / the plist's
    // StandardOutPath).
    #[cfg(windows)]
    if running_as_service {
        telemetry::init_to_file(&config.log_level, &config.state_dir.join("lariska.log"));
    } else {
        telemetry::init(&config.log_level);
    }
    #[cfg(not(windows))]
    telemetry::init(&config.log_level);

    // Initialize panic hook for crash recovery & reporting
    crate::crash::init_panic_hook(config.state_dir.clone());
    crate::crash::check_and_report_previous_crash(&config.state_dir);

    // Set background priority for the agent process
    crate::qos::set_background_priority();

    if running_as_service && !config.state_dir.is_absolute() {
        return Err("state_dir must be an absolute path when running with --service".to_string());
    }

    // Held for the process lifetime: a second `lariska run` against the same
    // state directory must fail fast rather than corrupt shared state
    // (Plan.md §12 "single-instance locking for one state directory").
    let _instance_lock = service::acquire(&config.state_dir).map_err(|error| error.to_string())?;

    let identity =
        identity::load_or_create(&config.state_dir).map_err(|error| error.to_string())?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start async runtime: {error}"))?;

    runtime.block_on(run_async(config, identity, external_shutdown))
}

async fn run_async(
    config: Config,
    identity: identity::AgentIdentity,
    external_shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Result<(), String> {
    let api = ApiClient::new(&config).map_err(|error| error.to_string())?;
    let auth = AuthClient::new(
        api.clone(),
        config.provisioning_key_file.clone(),
        identity.agent_id.clone(),
    );
    let heartbeat_client = HeartbeatClient::new(api.clone(), auth.clone());
    let delivery_client = DeliveryClient::new(
        api,
        auth,
        &config.state_dir,
        config.max_spool_entries,
        config.inventory_full_refresh_interval,
    )
    .map_err(|error| error.to_string())?;

    let hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let mut labels = inventory::environment::detect_environment().to_labels();
    let power_source = if crate::qos::is_on_battery() {
        "battery"
    } else {
        "ac"
    };
    labels.insert("host.power_source".to_string(), power_source.to_string());

    register_with_retry(
        &heartbeat_client,
        &identity.agent_id,
        &hostname,
        env!("CARGO_PKG_VERSION"),
        &labels,
    )
    .await?;

    tracing::info!(agent_id = %identity.agent_id, "Lariska Endpoint Agent started");

    // Resume anything left over from a prior crash/outage before collecting
    // a fresh snapshot.
    if let Err(error) = delivery_client.drain_spool().await {
        tracing::warn!(%error, "startup spool drain did not complete");
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // What the loops actually run on, as opposed to what the file said at
    // startup: the server can change it while they run (#358).
    let (runtime_tx, runtime_rx) =
        tokio::sync::watch::channel(managed::Runtime::from_config(&config));
    let heartbeat_loop = heartbeat_client.run_loop(
        &identity.agent_id,
        runtime_rx.clone(),
        &runtime_tx,
        &config,
        shutdown_rx.clone(),
    );
    let inventory_loop = inventory_loop(
        &delivery_client,
        &identity.agent_id,
        &hostname,
        runtime_rx,
        shutdown_rx,
    );

    let external_shutdown = async move {
        match external_shutdown {
            Some(notify) => notify.notified().await,
            None => std::future::pending::<()>().await,
        }
    };

    let mut updated_to: Option<String> = None;
    tokio::select! {
        outcome = heartbeat_loop => {
            if let heartbeat::LoopOutcome::Updated { version } = outcome {
                updated_to = Some(version);
            }
        }
        () = inventory_loop => {}
        () = service::wait_for_shutdown_signal() => {
            tracing::info!("shutdown signal received, stopping");
            let _ = shutdown_tx.send(true);
        }
        () = external_shutdown => {
            tracing::info!("external stop request received, stopping");
            let _ = shutdown_tx.send(true);
        }
    }

    // A staged upgrade only becomes the running agent when this process ends
    // and something starts the binary that is now on disk. Reported as an
    // error rather than a clean stop on purpose: systemd's `Restart=always`
    // would cover either, but the Windows SCM restarts a service only when it
    // *fails*, and a clean exit there would leave the machine with the new
    // build installed and nothing running it.
    if let Some(version) = updated_to {
        return Err(format!(
            "restarting to run the newly installed build {version}"
        ));
    }

    Ok(())
}

/// Runs independently of the heartbeat loop. A one-shot timer is scheduled
/// only after the previous collection finishes, so a slow endpoint never
/// accumulates catch-up ticks or runs two inventory scans concurrently.
///
/// The first scan is staggered by at most five minutes to avoid a fleet-wide
/// boot/update storm. Later scans use a deterministic per-agent jitter and are
/// stretched on battery power, while remaining capped at one day.
async fn inventory_loop(
    delivery_client: &DeliveryClient,
    agent_id: &str,
    hostname: &str,
    mut runtime: tokio::sync::watch::Receiver<managed::Runtime>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let initial_delay = startup_inventory_delay(runtime.borrow().inventory_interval, agent_id);
    let mut timer = Box::pin(tokio::time::sleep(initial_delay));
    tracing::debug!(
        delay_secs = initial_delay.as_secs(),
        "scheduled initial inventory collection"
    );

    loop {
        tokio::select! {
            _ = &mut timer => {
                if let Err(error) = collect_and_submit(delivery_client, agent_id, hostname).await {
                    tracing::warn!(%error, "inventory collection/submission failed");
                }

                let on_battery = crate::qos::is_on_battery();
                let delay = scheduled_inventory_delay(
                    runtime.borrow().inventory_interval,
                    agent_id,
                    on_battery,
                );
                tracing::debug!(
                    delay_secs = delay.as_secs(),
                    on_battery,
                    "scheduled next inventory collection"
                );
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + delay);
            }
            changed = runtime.changed() => {
                if changed.is_err() {
                    break;
                }
                let on_battery = crate::qos::is_on_battery();
                let delay = scheduled_inventory_delay(
                    runtime.borrow().inventory_interval,
                    agent_id,
                    on_battery,
                );
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + delay);
                tracing::info!(
                    delay_secs = delay.as_secs(),
                    on_battery,
                    "rescheduled inventory after managed interval change"
                );
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

fn startup_inventory_delay(base: Duration, agent_id: &str) -> Duration {
    let max_jitter_secs =
        (base.as_secs() / INVENTORY_JITTER_DIVISOR).min(MAX_STARTUP_JITTER.as_secs());
    Duration::from_secs(stable_jitter_secs(agent_id, max_jitter_secs))
}

fn scheduled_inventory_delay(base: Duration, agent_id: &str, on_battery: bool) -> Duration {
    let multiplier = if on_battery {
        BATTERY_INTERVAL_MULTIPLIER
    } else {
        1
    };
    let max_secs = MAX_EFFECTIVE_INVENTORY_INTERVAL.as_secs();
    let effective_secs = base.as_secs().saturating_mul(multiplier).min(max_secs);
    let jitter_room = max_secs.saturating_sub(effective_secs);
    let max_jitter_secs = (effective_secs / INVENTORY_JITTER_DIVISOR).min(jitter_room);
    let jitter_secs = stable_jitter_secs(agent_id, max_jitter_secs);
    Duration::from_secs(effective_secs.saturating_add(jitter_secs))
}

fn stable_jitter_secs(agent_id: &str, max_secs: u64) -> u64 {
    if max_secs == 0 {
        return 0;
    }
    let digest = Sha256::digest(agent_id.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix) % max_secs.saturating_add(1)
}

async fn collect_and_submit(
    delivery_client: &DeliveryClient,
    agent_id: &str,
    hostname: &str,
) -> Result<(), String> {
    let collected = inventory::collect_all().await;
    for warning in &collected.warnings {
        tracing::warn!(%warning, "inventory collector warning");
    }
    ensure_authoritative_collection(&collected)?;

    let identifiers = identity::platform_identifiers();
    let snapshot = build_snapshot(agent_id, hostname, identifiers, collected)?;

    delivery_client.submit_if_needed(snapshot).await
}

/// A partial snapshot must never replace the last accepted server-side state.
/// The ingestion API interprets absence as removal, so submitting the entries
/// that happened to be collected before a timeout would manufacture removals
/// and then manufacture reinstalls on the next healthy cycle.
fn ensure_authoritative_collection(collected: &CollectorResult) -> Result<(), String> {
    if collected.complete {
        return Ok(());
    }

    Err(format!(
        "inventory collection was incomplete ({} warning(s)); snapshot was not spooled or submitted",
        collected.warnings.len()
    ))
}

fn build_snapshot(
    agent_id: &str,
    hostname: &str,
    identifiers: Vec<EndpointIdentifier>,
    collected: CollectorResult,
) -> Result<InventorySnapshot, String> {
    let snapshot_id = identity::generate_snapshot_id()
        .map_err(|error| format!("failed to generate snapshot id: {error}"))?;
    let collected_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| format!("failed to format timestamp: {error}"))?;
    let mut labels = inventory::environment::detect_environment().to_labels();
    let power_source = if crate::qos::is_on_battery() {
        "battery"
    } else {
        "ac"
    };
    labels.insert("host.power_source".to_string(), power_source.to_string());

    let os_release = inventory::environment::detect_os_release();

    Ok(InventorySnapshot::new(
        snapshot_id,
        agent_id.to_string(),
        collected_at,
        hostname.to_string(),
        Some(std::env::consts::OS.to_string()),
        Some(
            os_release
                .name
                .unwrap_or_else(|| std::env::consts::OS.to_string()),
        ),
        os_release.version,
        Some(std::env::consts::ARCH.to_string()),
        env!("CARGO_PKG_VERSION").to_string(),
        labels,
        identifiers,
        collected.entries,
        collected.warnings,
    ))
}

async fn register_with_retry(
    heartbeat_client: &HeartbeatClient,
    agent_id: &str,
    hostname: &str,
    version: &str,
    labels: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match heartbeat_client
            .register(agent_id, hostname, version, labels)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) if attempt >= REGISTER_MAX_ATTEMPTS || !is_retryable(&error) => {
                return Err(format!("agent registration failed: {error}"));
            }
            Err(error) => {
                let backoff = REGISTER_BASE_BACKOFF * 2_u32.pow(attempt - 1);
                tracing::warn!(
                    attempt,
                    %error,
                    retry_in = ?backoff,
                    "agent registration attempt failed"
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

fn is_retryable(error: &ApiError) -> bool {
    matches!(error, ApiError::Transient(_) | ApiError::RateLimited { .. })
}

pub fn check_config(config_path: &Path) -> Result<(), String> {
    let config = Config::from_file_and_env(config_path).map_err(|error| error.to_string())?;
    println!("Configuration is valid: {config:?}");
    Ok(())
}

pub fn print_inventory() {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to initialize runtime: {error}");
            return;
        }
    };

    let (collected, identifiers) = runtime.block_on(async {
        (
            inventory::collect_all().await,
            identity::platform_identifiers(),
        )
    });

    let snapshot = diagnostic_snapshot(collected, identifiers);
    println!("{}", snapshot.to_canonical_json());
}

fn diagnostic_snapshot(
    collected: CollectorResult,
    identifiers: Vec<crate::model::EndpointIdentifier>,
) -> InventorySnapshot {
    let mut labels = inventory::environment::detect_environment().to_labels();
    let power_source = if crate::qos::is_on_battery() {
        "battery"
    } else {
        "ac"
    };
    labels.insert("host.power_source".to_string(), power_source.to_string());

    let os_release = inventory::environment::detect_os_release();

    InventorySnapshot::new(
        "diagnostic-snapshot".to_string(),
        "agent_00000000000000000000000000000000".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        "localhost".to_string(),
        Some(std::env::consts::OS.to_string()),
        Some(
            os_release
                .name
                .unwrap_or_else(|| std::env::consts::OS.to_string()),
        ),
        os_release.version,
        Some(std::env::consts::ARCH.to_string()),
        env!("CARGO_PKG_VERSION").to_string(),
        labels,
        identifiers,
        collected.entries,
        collected.warnings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SoftwareEntry, SoftwareSource};

    #[test]
    fn diagnostic_snapshot_normalizes_inventory_names() {
        let collected = CollectorResult {
            entries: vec![
                SoftwareEntry {
                    name: " bash ".to_string(),
                    version: None,
                    publisher: None,
                    architecture: None,
                    source: SoftwareSource::Other,
                    install_location: None,
                },
                SoftwareEntry {
                    name: "".to_string(),
                    version: None,
                    publisher: None,
                    architecture: None,
                    source: SoftwareSource::Other,
                    install_location: None,
                },
            ],
            warnings: Vec::new(),
            complete: true,
        };

        let snapshot = diagnostic_snapshot(collected, Vec::new());

        assert_eq!(snapshot.software.len(), 1);
        assert_eq!(snapshot.software[0].name, "bash");
    }

    #[test]
    fn incomplete_collection_is_not_publishable() {
        let collected = CollectorResult {
            entries: Vec::new(),
            warnings: vec!["dpkg-query collector failed: timed out".to_string()],
            complete: false,
        };

        let error = ensure_authoritative_collection(&collected)
            .expect_err("partial data must not be submitted as an authoritative snapshot");

        assert!(error.contains("not spooled or submitted"));
    }

    #[test]
    fn startup_jitter_is_bounded_and_stable() {
        let base = Duration::from_secs(3_600);
        let first = startup_inventory_delay(base, "agent_test");
        let second = startup_inventory_delay(base, "agent_test");

        assert_eq!(first, second);
        assert!(first <= MAX_STARTUP_JITTER);
        assert!(first <= base / INVENTORY_JITTER_DIVISOR as u32);
    }

    #[test]
    fn battery_schedule_is_slower_but_still_bounded() {
        let base = Duration::from_secs(3_600);
        let ac = scheduled_inventory_delay(base, "agent_test", false);
        let battery = scheduled_inventory_delay(base, "agent_test", true);

        assert!(battery > ac);
        assert!(battery <= MAX_EFFECTIVE_INVENTORY_INTERVAL);
    }

    #[test]
    fn schedule_never_exceeds_one_day() {
        let delay = scheduled_inventory_delay(MAX_EFFECTIVE_INVENTORY_INTERVAL, "agent_test", true);

        assert_eq!(delay, MAX_EFFECTIVE_INVENTORY_INTERVAL);
    }

    #[test]
    fn only_transient_and_rate_limited_errors_are_retried() {
        assert!(is_retryable(&ApiError::Transient("boom".to_string())));
        assert!(is_retryable(&ApiError::RateLimited { retry_after: None }));
        assert!(!is_retryable(&ApiError::Auth));
        assert!(!is_retryable(&ApiError::Forbidden("nope".to_string())));
        assert!(!is_retryable(&ApiError::Fatal("nope".to_string())));
    }
}
