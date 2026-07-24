use crate::api::{ApiClient, ApiError};
use crate::auth::AuthClient;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

const REGISTER_PATH: &str = "/api/agent/register";
const HEARTBEAT_PATH: &str = "/api/agent/heartbeat";

/// `Busy`/`Error` are reported once Phase L3/L4 wire collection and delivery
/// status into the heartbeat loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatStatus {
    Idle,
    #[allow(dead_code)]
    Busy,
    #[allow(dead_code)]
    Error,
}

#[derive(Serialize)]
struct AgentRegisterRequest<'a> {
    agent_id: &'a str,
    hostname: &'a str,
    version: &'a str,
    labels: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct AgentHeartbeatRequest<'a> {
    agent_id: &'a str,
    status: HeartbeatStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_job_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

/// Response shape shared by `register` and `heartbeat`. Fields are read
/// loosely (`#[serde(default)]`) so an unrecognized `status` value from a
/// newer server (e.g. `"stale"`) never fails deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AgentInfo {
    pub agent_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub status: String,
    pub current_job_id: Option<String>,
    pub detail: Option<String>,
    pub registered_at: Option<String>,
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub online: bool,
}

/// Registration and heartbeat calls against the Shapoclyack agent API. Both
/// calls follow the same policy: try with the cached token, and on `401`
/// refresh exactly once and retry the same request exactly once.
#[derive(Clone)]
pub struct HeartbeatClient {
    api: ApiClient,
    auth: AuthClient,
}

impl HeartbeatClient {
    pub fn new(api: ApiClient, auth: AuthClient) -> Self {
        Self { api, auth }
    }

    pub async fn register(
        &self,
        agent_id: &str,
        hostname: &str,
        version: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<AgentInfo, ApiError> {
        let body = AgentRegisterRequest {
            agent_id,
            hostname,
            version,
            labels,
        };

        let token = self.auth.token().await?;
        match self
            .api
            .post_json(REGISTER_PATH, Some(&token), &body, None)
            .await
        {
            Err(ApiError::Auth) => {
                let token = self.auth.force_refresh().await?;
                self.api
                    .post_json(REGISTER_PATH, Some(&token), &body, None)
                    .await
            }
            other => other,
        }
    }

    pub async fn heartbeat(
        &self,
        agent_id: &str,
        status: HeartbeatStatus,
        current_job_id: Option<&str>,
        detail: Option<&str>,
    ) -> Result<AgentInfo, ApiError> {
        let body = AgentHeartbeatRequest {
            agent_id,
            status,
            current_job_id,
            detail,
        };

        let token = self.auth.token().await?;
        match self
            .api
            .post_json(HEARTBEAT_PATH, Some(&token), &body, None)
            .await
        {
            Err(ApiError::Auth) => {
                let token = self.auth.force_refresh().await?;
                self.api
                    .post_json(HEARTBEAT_PATH, Some(&token), &body, None)
                    .await
            }
            other => other,
        }
    }

    /// Runs independently of inventory collection/delivery: a stalled
    /// collector must not stop heartbeats, and a failed heartbeat must not
    /// touch the delivery spool (Plan.md §9.3). Runs until `shutdown` signals
    /// `true`.
    pub async fn run_loop(
        &self,
        agent_id: &str,
        interval: Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // first tick fires immediately; skip it, register() already ran once

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(error) = self.heartbeat(agent_id, HeartbeatStatus::Idle, None, None).await {
                        tracing::warn!(%error, "heartbeat failed");
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
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::auth::AuthClient;
    use crate::config::Config;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn write_temp_key(label: &str) -> PathBuf {
        let key_path = std::env::temp_dir().join(format!(
            "lariska-heartbeat-test-key-{label}-{}",
            std::process::id()
        ));
        fs::write(&key_path, "bootstrap-key").expect("key file should be written");
        key_path
    }

    fn test_client(server_uri: String, key_path: PathBuf) -> HeartbeatClient {
        let config = Config {
            server_url: server_uri,
            provisioning_key_file: key_path.clone(),
            state_dir: std::env::temp_dir(),
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
        HeartbeatClient::new(api, auth)
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

    fn agent_info_body() -> serde_json::Value {
        serde_json::json!({
            "agent_id": "agent_test",
            "hostname": "test-host",
            "version": "0.1.0",
            "labels": {},
            "status": "idle",
            "online": true
        })
    }

    #[tokio::test]
    async fn register_and_heartbeat_succeed_against_mock_server() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path(REGISTER_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(agent_info_body()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(HEARTBEAT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(agent_info_body()))
            .mount(&server)
            .await;

        let key_path = write_temp_key("success");
        let client = test_client(server.uri(), key_path.clone());
        let labels = BTreeMap::new();

        let registered = client
            .register("agent_test", "test-host", "0.1.0", &labels)
            .await
            .expect("registration should succeed");
        assert_eq!(registered.agent_id, "agent_test");

        let heartbeat = client
            .heartbeat("agent_test", HeartbeatStatus::Idle, None, None)
            .await
            .expect("heartbeat should succeed");
        assert_eq!(heartbeat.status, "idle");

        fs::remove_file(key_path).ok();
    }

    #[tokio::test]
    async fn cross_tenant_heartbeat_surfaces_as_forbidden() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path(HEARTBEAT_PATH))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("cross-tenant agent access denied"),
            )
            .mount(&server)
            .await;

        let key_path = write_temp_key("forbidden");
        let client = test_client(server.uri(), key_path.clone());

        let error = client
            .heartbeat("agent_test", HeartbeatStatus::Idle, None, None)
            .await
            .expect_err("cross-tenant heartbeat should fail");
        assert!(matches!(error, ApiError::Forbidden(_)));

        fs::remove_file(key_path).ok();
    }
}
