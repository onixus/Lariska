use crate::api::{ApiClient, ApiError};
use crate::auth::AuthClient;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// Which of the two programs that register here this is (Shapoclyack
    /// #358). Without it the platform judged Lariska's version against the
    /// *scanning* agent's release line and reported every endpoint as
    /// permanently outdated, offering an upgrade to a different program.
    agent_kind: &'static str,
}

#[derive(Serialize)]
struct AgentHeartbeatRequest<'a> {
    agent_id: &'a str,
    status: HeartbeatStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_job_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    /// The target triple this build was compiled for. A remote upgrade is
    /// looked up by (version, platform): a version alone does not identify a
    /// binary, and handing an agent the wrong one is the failure mode worth
    /// designing out.
    platform: String,
    /// The management revision this process has already acted on, so the
    /// server's repeated decision is applied once rather than every minute.
    #[serde(skip_serializing_if = "Option::is_none")]
    applied_config_revision: Option<u64>,
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

/// Why the heartbeat loop ended.
#[derive(Debug)]
pub enum LoopOutcome {
    /// Asked to stop, by a signal or by the service control manager.
    Stopped,
    /// A new build is installed where this process's binary was. The process
    /// has to end for it to run, and it ends with a failure code so a
    /// supervisor configured to restart on failure does exactly that.
    Updated { version: String },
}

/// The heartbeat answer, read as two documents at once: the agent record the
/// API has always returned, and the management decision it now carries
/// alongside (Shapoclyack #358). Flattened rather than nested because the
/// server returns one flat object -- the response type there extends the agent
/// record rather than wrapping it, so that an agent written against the older
/// shape keeps reading the same document.
#[derive(Debug, Deserialize)]
struct HeartbeatResponse {
    #[serde(flatten)]
    info: AgentInfo,
    #[serde(flatten)]
    directive: crate::managed::ManagedDirective,
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
            agent_kind: "endpoint",
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
        self.heartbeat_with_revision(agent_id, status, current_job_id, detail, None)
            .await
            .map(|(info, _)| info)
    }

    /// The heartbeat as the run loop makes it: reports the management revision
    /// already applied, and returns what the server decided alongside the
    /// agent record.
    pub async fn heartbeat_with_revision(
        &self,
        agent_id: &str,
        status: HeartbeatStatus,
        current_job_id: Option<&str>,
        detail: Option<&str>,
        applied_config_revision: Option<u64>,
    ) -> Result<(AgentInfo, crate::managed::ManagedDirective), ApiError> {
        let body = AgentHeartbeatRequest {
            agent_id,
            status,
            current_job_id,
            detail,
            platform: crate::managed::target_triple(),
            applied_config_revision,
        };

        let token = self.auth.token().await?;
        let response: HeartbeatResponse = match self
            .api
            .post_json(HEARTBEAT_PATH, Some(&token), &body, None)
            .await
        {
            Err(ApiError::Auth) => {
                let token = self.auth.force_refresh().await?;
                self.api
                    .post_json(HEARTBEAT_PATH, Some(&token), &body, None)
                    .await?
            }
            other => other?,
        };
        Ok((response.info, response.directive))
    }

    /// Runs independently of inventory collection/delivery: a stalled
    /// collector must not stop heartbeats, and a failed heartbeat must not
    /// touch the delivery spool (Plan.md §9.3). Runs until `shutdown` signals
    /// `true`.
    pub async fn run_loop(
        &self,
        agent_id: &str,
        mut runtime: tokio::sync::watch::Receiver<crate::managed::Runtime>,
        runtime_tx: &tokio::sync::watch::Sender<crate::managed::Runtime>,
        config: &crate::config::Config,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> LoopOutcome {
        let mut ticker = tokio::time::interval(runtime.borrow().heartbeat_interval);
        ticker.tick().await; // first tick fires immediately; skip it, register() already ran once
        let mut applied: Option<u64> = None;
        let mut last_block_reason: Option<String> = None;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self
                        .heartbeat_with_revision(agent_id, HeartbeatStatus::Idle, None, None, applied)
                        .await
                    {
                        Ok((_, directive)) => {
                            applied = crate::managed::apply_settings(&directive, applied, runtime_tx);

                            // Logged on change only. The server repeats the
                            // reason on every beat, and an agent that cannot
                            // be upgraded would otherwise fill its log with
                            // one line per poll -- the same reasoning the
                            // scanning agent applies to its upgrade message.
                            if directive.managed_update_blocked != last_block_reason {
                                if let Some(reason) = directive.managed_update_blocked.as_deref() {
                                    tracing::warn!(%reason, "the server cannot offer the requested build");
                                }
                                last_block_reason = directive.managed_update_blocked.clone();
                            }

                            if let Some(update) = directive.managed_update.as_ref() {
                                if let Some(outcome) = self.try_update(update, config).await {
                                    return outcome;
                                }
                            }
                        }
                        Err(error) => tracing::warn!(%error, "heartbeat failed"),
                    }
                }
                changed = runtime.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    // Rebuilt rather than adjusted: `tokio::time::interval`
                    // has no way to change its period, and this is what makes
                    // a new interval take effect now instead of at the next
                    // restart -- which is the whole point of managing the
                    // agent remotely.
                    ticker = tokio::time::interval(runtime.borrow().heartbeat_interval);
                    ticker.tick().await;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        LoopOutcome::Stopped
    }

    /// Carries out an offered upgrade. `Some` means the process must end so the
    /// supervisor starts the build that is now installed; `None` means the
    /// agent is still running the one it started with.
    async fn try_update(
        &self,
        update: &crate::managed::ManagedUpdate,
        config: &crate::config::Config,
    ) -> Option<LoopOutcome> {
        let token = match self.auth.token().await {
            Ok(token) => token,
            Err(error) => {
                tracing::warn!(%error, "cannot authenticate to fetch the offered build");
                return None;
            }
        };
        match crate::managed::apply_update(update, config, &token, self.api.http()).await {
            crate::managed::UpdateOutcome::Staged { version } => {
                tracing::info!(%version, "new build installed; stopping so it can be started");
                Some(LoopOutcome::Updated { version })
            }
            crate::managed::UpdateOutcome::Refused(reason) => {
                // A refusal is a decision, not a fault: it is logged once per
                // offer and the agent carries on with the build it has.
                tracing::warn!(%reason, "declined the offered build");
                None
            }
            crate::managed::UpdateOutcome::Failed(error) => {
                tracing::error!(%error, "could not install the offered build");
                None
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
            allow_insecure_updates: false,
            inventory_full_refresh_interval: Duration::from_secs(86_400),
            max_spool_entries: 200,
        };
        let api = ApiClient::new(&config).expect("api client should build");
        let auth = AuthClient::new(api.clone(), key_path, "agent_test".to_string());
        HeartbeatClient::new(api, auth)
    }

    async fn mount_exchange(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path(crate::auth::AUTH_EXCHANGE_PATH))
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

#[cfg(test)]
mod managed_contract_tests {
    use super::*;
    use crate::auth::AuthClient;
    use crate::config::Config;
    use std::fs;
    use std::time::Duration;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(server: &MockServer) -> HeartbeatClient {
        let key_path = std::env::temp_dir().join(format!(
            "lariska-managed-test-key-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&key_path, "bootstrap-key").unwrap();
        let config = Config {
            server_url: server.uri(),
            provisioning_key_file: key_path.clone(),
            state_dir: std::env::temp_dir(),
            inventory_interval: Duration::from_secs(3600),
            heartbeat_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(5),
            tls_ca_file: None,
            log_level: "info".to_string(),
            allow_plain_http: true,
            allow_insecure_updates: false,
            inventory_full_refresh_interval: Duration::from_secs(86_400),
            max_spool_entries: 200,
        };
        let api = ApiClient::new(&config).unwrap();
        let auth = AuthClient::new(api.clone(), key_path, "agent_test".to_string());
        HeartbeatClient::new(api, auth)
    }

    async fn mount_exchange(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path(crate::auth::AUTH_EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-jwt",
                "expires_in": 7200
            })))
            .mount(server)
            .await;
    }

    fn info_with(extra: serde_json::Value) -> serde_json::Value {
        let mut body = serde_json::json!({
            "agent_id": "agent_test",
            "hostname": "test-host",
            "version": "0.2.0",
            "labels": {},
            "status": "idle",
            "online": true,
            "tenant_id": "tenant-1"
        });
        let (serde_json::Value::Object(target), serde_json::Value::Object(source)) =
            (&mut body, extra)
        else {
            unreachable!()
        };
        target.extend(source);
        body
    }

    /// The agent tells the server which program it is, which build it is, and
    /// what it has already applied. Each of the three decides something on the
    /// other side: the kind keeps it out of the scanning fleet, the platform is
    /// half of the key an upgrade is looked up by, and the revision is what
    /// stops a policy being re-applied every minute.
    #[tokio::test]
    async fn the_heartbeat_reports_platform_and_applied_revision() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path(HEARTBEAT_PATH))
            .and(body_partial_json(serde_json::json!({
                "agent_id": "agent_test",
                "platform": crate::managed::target_triple(),
                "applied_config_revision": 4
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(info_with(serde_json::json!({}))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .heartbeat_with_revision("agent_test", HeartbeatStatus::Idle, None, None, Some(4))
            .await
            .expect("heartbeat should succeed");
    }

    #[tokio::test]
    async fn registration_declares_this_is_an_endpoint_agent() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path(REGISTER_PATH))
            .and(body_partial_json(
                serde_json::json!({"agent_kind": "endpoint"}),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(info_with(serde_json::json!({}))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .register("agent_test", "test-host", "0.2.0", &BTreeMap::new())
            .await
            .expect("register should succeed");
    }

    /// The response is one flat object carrying both documents, and the agent
    /// has to read both out of it. A server that answers only the agent record
    /// — an installation with no policy, or an older API — must still parse.
    #[tokio::test]
    async fn the_directive_is_read_out_of_the_same_response_as_the_agent_record() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path(HEARTBEAT_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(info_with(serde_json::json!({
                    "managed_revision": 9,
                    "managed_settings": {"inventory_interval_secs": 900, "log_level": "debug"},
                    "managed_update": {
                        "version": "0.3.0",
                        "platform": "x86_64-pc-windows-msvc",
                        "sha256": "abc",
                        "size_bytes": 12,
                        "url": "/api/endpoint/agent/releases/0.3.0/x86_64-pc-windows-msvc/download"
                    }
                }))),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let (info, directive) = client
            .heartbeat_with_revision("agent_test", HeartbeatStatus::Idle, None, None, None)
            .await
            .expect("heartbeat should succeed");

        assert_eq!(info.agent_id, "agent_test");
        assert_eq!(directive.managed_revision, Some(9));
        assert_eq!(
            directive
                .managed_settings
                .as_ref()
                .and_then(|s| s.inventory_interval_secs),
            Some(900)
        );
        assert_eq!(
            directive
                .managed_update
                .as_ref()
                .map(|u| u.version.as_str()),
            Some("0.3.0")
        );
    }

    #[tokio::test]
    async fn a_response_with_no_directive_still_parses() {
        let server = MockServer::start().await;
        mount_exchange(&server).await;
        Mock::given(method("POST"))
            .and(path(HEARTBEAT_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(info_with(serde_json::json!({}))),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let (_, directive) = client
            .heartbeat_with_revision("agent_test", HeartbeatStatus::Idle, None, None, None)
            .await
            .expect("heartbeat should succeed");

        assert!(directive.managed_revision.is_none());
        assert!(directive.managed_update.is_none());
    }
}
