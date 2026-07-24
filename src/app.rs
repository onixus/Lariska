use crate::api::{ApiClient, ApiError};
use crate::auth::AuthClient;
use crate::config::Config;
use crate::delivery::DeliveryClient;
use crate::heartbeat::HeartbeatClient;
use crate::identity;
use crate::inventory::{self, CollectorResult};
use crate::model::{EndpointIdentifier, InventorySnapshot};
use crate::{service, telemetry};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// Bounded retry for the one-time startup registration call: a transient
/// network blip at boot should not require a process restart, but a
/// misconfigured/revoked provisioning key must fail fast.
const REGISTER_MAX_ATTEMPTS: u32 = 5;
const REGISTER_BASE_BACKOFF: Duration = Duration::from_secs(1);

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

fn run_internal(
    config_path: &Path,
    running_as_service: bool,
    external_shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Result<(), String> {
    let config = Config::from_file_and_env(config_path).map_err(|error| error.to_string())?;
    telemetry::init(&config.log_level);

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
    let labels = BTreeMap::new();

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
    let heartbeat_loop = heartbeat_client.run_loop(
        &identity.agent_id,
        config.heartbeat_interval,
        shutdown_rx.clone(),
    );
    let inventory_loop = inventory_loop(
        &delivery_client,
        &identity.agent_id,
        &hostname,
        config.inventory_interval,
        shutdown_rx,
    );

    let external_shutdown = async move {
        match external_shutdown {
            Some(notify) => notify.notified().await,
            None => std::future::pending::<()>().await,
        }
    };

    tokio::select! {
        () = heartbeat_loop => {}
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

    Ok(())
}

/// Runs independently of the heartbeat loop on `inventory_interval`: a slow
/// collector must not delay heartbeats, and a failed heartbeat must not
/// touch the delivery spool (Plan.md §9.3, applied symmetrically here).
async fn inventory_loop(
    delivery_client: &DeliveryClient,
    agent_id: &str,
    hostname: &str,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(error) = collect_and_submit(delivery_client, agent_id, hostname).await {
                    tracing::warn!(%error, "inventory collection/submission failed");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
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

    let identifiers = identity::platform_identifiers();
    let snapshot = build_snapshot(agent_id, hostname, identifiers, collected)?;

    delivery_client.submit_if_needed(snapshot).await
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

    Ok(InventorySnapshot::new(
        snapshot_id,
        agent_id.to_string(),
        collected_at,
        hostname.to_string(),
        Some(std::env::consts::OS.to_string()),
        Some(std::env::consts::OS.to_string()),
        None,
        Some(std::env::consts::ARCH.to_string()),
        env!("CARGO_PKG_VERSION").to_string(),
        BTreeMap::new(),
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
            eprintln!("failed to start async runtime: {error}");
            return;
        }
    };

    let collected = runtime.block_on(inventory::collect_all());
    let identifiers = identity::platform_identifiers();
    let snapshot = diagnostic_snapshot(collected, identifiers);

    if let Err(error) = snapshot.validate() {
        eprintln!("Inventory snapshot validation failed: {error}");
        return;
    }

    println!("{}", snapshot.to_canonical_json());
}

fn diagnostic_snapshot(
    collected: CollectorResult,
    identifiers: Vec<crate::model::EndpointIdentifier>,
) -> InventorySnapshot {
    InventorySnapshot::new(
        "diagnostic-snapshot".to_string(),
        "agent_00000000000000000000000000000000".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        "localhost".to_string(),
        Some(std::env::consts::OS.to_string()),
        Some(std::env::consts::OS.to_string()),
        None,
        Some(std::env::consts::ARCH.to_string()),
        env!("CARGO_PKG_VERSION").to_string(),
        BTreeMap::new(),
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
        };

        let snapshot = diagnostic_snapshot(collected, Vec::new());

        assert_eq!(snapshot.software.len(), 1);
        assert_eq!(snapshot.software[0].name, "bash");
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
