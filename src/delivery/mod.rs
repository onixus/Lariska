use crate::api::{ApiClient, ApiError};
use crate::auth::AuthClient;
use crate::model::InventorySnapshot;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

pub mod retry;
pub mod spool;

use retry::{classify, RetryDecision};
use spool::{Spool, SpoolError};

const INVENTORY_PATH: &str = "/api/endpoint/inventory";
/// Bounds retries within a single delivery attempt; the spool itself is what
/// makes delivery durable across process restarts, so this does not need to
/// be unbounded.
const MAX_ATTEMPTS_PER_ENTRY: u32 = 6;

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct InventorySubmitResponse {
    snapshot_id: String,
    status: String,
    device_id: String,
    asset_id: Option<String>,
    #[serde(default)]
    reconciliation_status: String,
    software_count: u64,
    #[serde(default)]
    changes: BTreeMap<String, i64>,
}

struct LastAccepted {
    digest: String,
    accepted_at: SystemTime,
}

/// Orchestrates spool-then-submit delivery of inventory snapshots (Plan.md
/// §11). Collection and upload are decoupled: a snapshot always lands on
/// disk before any network attempt, and is removed only after the server
/// acknowledges it.
pub struct DeliveryClient {
    api: ApiClient,
    auth: AuthClient,
    spool: Spool,
    max_spool_entries: usize,
    full_refresh_interval: Duration,
    last_accepted: tokio::sync::Mutex<Option<LastAccepted>>,
}

impl DeliveryClient {
    pub fn new(
        api: ApiClient,
        auth: AuthClient,
        state_dir: &Path,
        max_spool_entries: usize,
        full_refresh_interval: Duration,
    ) -> Result<Self, SpoolError> {
        Ok(Self {
            api,
            auth,
            spool: Spool::open(state_dir)?,
            max_spool_entries,
            full_refresh_interval,
            last_accepted: tokio::sync::Mutex::new(None),
        })
    }

    /// Called once per collection cycle. Skips sending entirely when the
    /// snapshot is byte-identical (by Lariska's own digest) to the last
    /// accepted one and the full-refresh deadline has not yet passed
    /// (Plan.md §11 step 4). Otherwise spools it and drains the whole queue,
    /// oldest first — which also flushes anything left over from a prior
    /// crash or outage.
    pub async fn submit_if_needed(&self, snapshot: InventorySnapshot) -> Result<(), String> {
        let digest = content_digest(&snapshot);

        if !self.due_for_submission(&digest).await {
            return Ok(());
        }

        self.spool
            .write(&snapshot)
            .map_err(|error| format!("failed to spool snapshot: {error}"))?;

        if let Ok(evicted) = self.spool.enforce_limit(self.max_spool_entries) {
            for snapshot_id in evicted {
                tracing::warn!(
                    %snapshot_id,
                    max_spool_entries = self.max_spool_entries,
                    "spool over limit; evicted oldest unsent snapshot"
                );
            }
        }

        self.drain_spool().await
    }

    async fn due_for_submission(&self, digest: &str) -> bool {
        let last = self.last_accepted.lock().await;
        let Some(last) = last.as_ref() else {
            return true;
        };
        let due_for_refresh =
            last.accepted_at.elapsed().unwrap_or(Duration::MAX) >= self.full_refresh_interval;
        last.digest != digest || due_for_refresh
    }

    /// Submits every pending spool entry, oldest first. Safe to call at
    /// startup to resume delivery of anything left over from a prior crash.
    pub async fn drain_spool(&self) -> Result<(), String> {
        let pending = self
            .spool
            .list_pending()
            .map_err(|error| format!("failed to read spool: {error}"))?;

        for (_, snapshot) in pending {
            let digest = content_digest(&snapshot);
            match self.submit_one(&snapshot).await {
                Ok(()) => {
                    self.spool.remove(&snapshot.snapshot_id).ok();
                    let mut last = self.last_accepted.lock().await;
                    *last = Some(LastAccepted {
                        digest,
                        accepted_at: SystemTime::now(),
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "inventory submission failed, left in spool");
                    // Later pending entries are newer and would fail
                    // identically for a systemic problem (auth/network);
                    // stop draining rather than hammering the server.
                    // Payload-specific failures were already quarantined
                    // inside submit_one so they will not block this loop
                    // again next cycle.
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    async fn submit_one(&self, snapshot: &InventorySnapshot) -> Result<(), String> {
        let mut attempt = 0_u32;
        let mut refreshed_once = false;

        loop {
            attempt += 1;
            let token = self.auth.token().await.map_err(|error| error.to_string())?;

            let error = match self.post(snapshot, &token).await {
                Ok(()) => return Ok(()),
                Err(ApiError::Auth) if !refreshed_once => {
                    refreshed_once = true;
                    let token = self
                        .auth
                        .force_refresh()
                        .await
                        .map_err(|error| error.to_string())?;
                    match self.post(snapshot, &token).await {
                        Ok(()) => return Ok(()),
                        Err(error) => error,
                    }
                }
                Err(error) => error,
            };

            if matches!(
                error,
                ApiError::Conflict(_) | ApiError::Validation(_) | ApiError::PayloadTooLarge(_)
            ) {
                self.spool.quarantine_by_id(&snapshot.snapshot_id).ok();
                return Err(format!(
                    "snapshot {} rejected and quarantined: {error}",
                    snapshot.snapshot_id
                ));
            }

            match classify(&error, attempt) {
                RetryDecision::RetryAfter(delay) if attempt < MAX_ATTEMPTS_PER_ENTRY => {
                    tracing::warn!(
                        attempt,
                        %error,
                        retry_in = ?delay,
                        snapshot_id = %snapshot.snapshot_id,
                        "inventory submission attempt failed"
                    );
                    tokio::time::sleep(delay).await;
                }
                _ => return Err(error.to_string()),
            }
        }
    }

    async fn post(&self, snapshot: &InventorySnapshot, token: &str) -> Result<(), ApiError> {
        self.api
            .post_json::<_, InventorySubmitResponse>(
                INVENTORY_PATH,
                Some(token),
                snapshot,
                Some(&snapshot.snapshot_id),
            )
            .await
            .map(|_| ())
    }
}

/// SHA-256 over the fields that describe actual endpoint state, used only to
/// decide whether an unchanged snapshot needs resubmitting (Plan.md §11 step
/// 4). Deliberately excludes `snapshot_id` and `collected_at`, which differ
/// on every single collection by design — hashing the full canonical JSON
/// (as opposed to this semantic subset) would mean "unchanged" could never
/// be detected. Independent of the server's own digest, which it computes
/// from the full parsed request body.
fn content_digest(snapshot: &InventorySnapshot) -> String {
    let payload = serde_json::json!({
        "hostname": snapshot.hostname,
        "os_family": snapshot.os_family,
        "os_name": snapshot.os_name,
        "os_version": snapshot.os_version,
        "os_arch": snapshot.os_arch,
        "agent_version": snapshot.agent_version,
        "labels": snapshot.labels,
        "identifiers": snapshot.identifiers,
        "software": snapshot.software,
        "collector_warnings": snapshot.collector_warnings,
    });

    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&payload).unwrap_or_default());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod digest_tests {
    use super::*;
    use crate::model::SoftwareEntry;

    fn snapshot(snapshot_id: &str, collected_at: &str) -> InventorySnapshot {
        InventorySnapshot::new(
            snapshot_id.to_string(),
            "agent_test".to_string(),
            collected_at.to_string(),
            "test-host".to_string(),
            Some("linux".to_string()),
            Some("Ubuntu".to_string()),
            Some("24.04".to_string()),
            Some("x86_64".to_string()),
            "0.1.0".to_string(),
            BTreeMap::new(),
            Vec::new(),
            vec![SoftwareEntry {
                name: "bash".to_string(),
                version: None,
                publisher: None,
                architecture: None,
                source: crate::model::SoftwareSource::Dpkg,
                install_location: None,
            }],
            Vec::new(),
        )
    }

    #[test]
    fn digest_ignores_snapshot_id_and_collected_at() {
        let a = snapshot("snap-1", "2026-07-24T08:00:00Z");
        let b = snapshot("snap-2", "2026-07-24T09:30:00Z");

        assert_eq!(content_digest(&a), content_digest(&b));
    }

    #[test]
    fn digest_changes_when_software_changes() {
        let a = snapshot("snap-1", "2026-07-24T08:00:00Z");
        let mut b = snapshot("snap-2", "2026-07-24T08:00:00Z");
        b.software.push(SoftwareEntry {
            name: "curl".to_string(),
            version: None,
            publisher: None,
            architecture: None,
            source: crate::model::SoftwareSource::Dpkg,
            install_location: None,
        });

        assert_ne!(content_digest(&a), content_digest(&b));
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::config::Config;
    use crate::model::SoftwareEntry;
    use std::fs;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn write_temp_key(label: &str) -> std::path::PathBuf {
        let key_path = std::env::temp_dir().join(format!(
            "lariska-delivery-test-key-{label}-{}",
            std::process::id()
        ));
        fs::write(&key_path, "bootstrap-key").expect("key file should be written");
        key_path
    }

    fn temp_state_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "lariska-delivery-test-state-{label}-{}",
            std::process::id()
        ))
    }

    fn test_client(
        server_uri: String,
        key_path: std::path::PathBuf,
        state_dir: &Path,
    ) -> DeliveryClient {
        let config = Config {
            server_url: server_uri,
            provisioning_key_file: key_path.clone(),
            state_dir: state_dir.to_path_buf(),
            inventory_interval: Duration::from_secs(3600),
            heartbeat_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(5),
            tls_ca_file: None,
            log_level: "info".to_string(),
            allow_plain_http: true,
            inventory_full_refresh_interval: Duration::from_secs(86_400),
            max_spool_entries: 200,
        };
        let api = ApiClient::new(&config).expect("api client should build");
        let auth = AuthClient::new(api.clone(), key_path, "agent_test".to_string());
        DeliveryClient::new(
            api,
            auth,
            &config.state_dir,
            config.max_spool_entries,
            config.inventory_full_refresh_interval,
        )
        .expect("delivery client should build")
    }

    async fn mount_exchange(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/exchange"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-jwt",
                "token_type": "bearer",
                "tenant_id": "tenant-1",
                "agent_id": "agent_test",
                "key_id": null,
                "expires_in": 7200
            })))
            .mount(server)
            .await;
    }

    fn sample_snapshot(snapshot_id: &str) -> InventorySnapshot {
        InventorySnapshot::new(
            snapshot_id.to_string(),
            "agent_test".to_string(),
            "2026-07-24T08:00:00Z".to_string(),
            "test-host".to_string(),
            Some("linux".to_string()),
            Some("Ubuntu".to_string()),
            Some("24.04".to_string()),
            Some("x86_64".to_string()),
            "0.1.0".to_string(),
            BTreeMap::new(),
            Vec::new(),
            vec![SoftwareEntry {
                name: "bash".to_string(),
                version: None,
                publisher: None,
                architecture: None,
                source: crate::model::SoftwareSource::Dpkg,
                install_location: None,
            }],
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn successful_submission_removes_the_spool_entry() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/endpoint/inventory"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "snapshot_id": "snap-1",
                "status": "accepted",
                "device_id": "dev-1",
                "asset_id": "asset-1",
                "reconciliation_status": "linked",
                "software_count": 1,
                "changes": {"installed": 1, "removed": 0, "updated": 0}
            })))
            .mount(&server)
            .await;

        let key_path = write_temp_key("success");
        let state_dir = temp_state_dir("success");
        let client = test_client(server.uri(), key_path.clone(), &state_dir);

        client
            .submit_if_needed(sample_snapshot("snap-1"))
            .await
            .expect("submission should succeed");

        let pending = client.spool.list_pending().expect("list should succeed");
        assert!(pending.is_empty());

        fs::remove_file(key_path).ok();
        fs::remove_dir_all(state_dir).ok();
    }

    #[tokio::test]
    async fn unchanged_snapshot_is_not_resubmitted() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/endpoint/inventory"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "snapshot_id": "snap-1",
                "status": "accepted",
                "device_id": "dev-1",
                "asset_id": "asset-1",
                "reconciliation_status": "linked",
                "software_count": 1,
                "changes": {"installed": 1, "removed": 0, "updated": 0}
            })))
            .expect(1) // only the first submit_if_needed call should hit the network
            .mount(&server)
            .await;

        let key_path = write_temp_key("unchanged");
        let state_dir = temp_state_dir("unchanged");
        let client = test_client(server.uri(), key_path.clone(), &state_dir);

        client
            .submit_if_needed(sample_snapshot("snap-1"))
            .await
            .expect("first submission should succeed");
        client
            .submit_if_needed(sample_snapshot("snap-2")) // identical content, different id
            .await
            .expect("second call should short-circuit, not error");

        fs::remove_file(key_path).ok();
        fs::remove_dir_all(state_dir).ok();
    }

    #[tokio::test]
    async fn validation_failure_quarantines_the_entry_instead_of_looping() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/endpoint/inventory"))
            .respond_with(ResponseTemplate::new(422).set_body_string("schema validation failed"))
            .mount(&server)
            .await;

        let key_path = write_temp_key("invalid");
        let state_dir = temp_state_dir("invalid");
        let client = test_client(server.uri(), key_path.clone(), &state_dir);

        let result = client.submit_if_needed(sample_snapshot("snap-1")).await;
        assert!(result.is_err());

        let pending = client.spool.list_pending().expect("list should succeed");
        assert!(
            pending.is_empty(),
            "rejected entry must not stay in the retry queue"
        );
        assert!(state_dir.join("spool/quarantine/snap-1.json").exists());

        fs::remove_file(key_path).ok();
        fs::remove_dir_all(state_dir).ok();
    }

    #[tokio::test]
    async fn crash_recovery_resumes_pending_spool_entries() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/endpoint/inventory"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "snapshot_id": "snap-1",
                "status": "accepted",
                "device_id": "dev-1",
                "asset_id": "asset-1",
                "reconciliation_status": "linked",
                "software_count": 1,
                "changes": {"installed": 1, "removed": 0, "updated": 0}
            })))
            .mount(&server)
            .await;

        let key_path = write_temp_key("crash");
        let state_dir = temp_state_dir("crash");

        // Simulate a snapshot that was spooled by a previous process that
        // died before it could submit.
        {
            let client = test_client(server.uri(), key_path.clone(), &state_dir);
            client
                .spool
                .write(&sample_snapshot("snap-1"))
                .expect("write should succeed");
        }

        // A freshly started client (new process, in spirit) drains it.
        let client = test_client(server.uri(), key_path.clone(), &state_dir);
        client.drain_spool().await.expect("drain should succeed");

        let pending = client.spool.list_pending().expect("list should succeed");
        assert!(pending.is_empty());

        fs::remove_file(key_path).ok();
        fs::remove_dir_all(state_dir).ok();
    }
}
