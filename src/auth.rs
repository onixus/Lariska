use crate::api::{ApiClient, ApiError};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const AUTH_EXCHANGE_PATH: &str = "/api/v1/auth/exchange";
/// Refresh somewhere in the first 10-25% of the token's remaining lifetime,
/// picked per-token so many agents restarting together don't all refresh in
/// lockstep.
const MIN_REFRESH_JITTER_FRACTION: f64 = 0.10;
const MAX_REFRESH_JITTER_FRACTION: f64 = 0.25;

#[derive(Serialize)]
struct AuthExchangeRequest<'a> {
    provisioning_key: &'a str,
    agent_id: &'a str,
}

#[derive(Deserialize)]
struct AuthExchangeResponse {
    access_token: String,
    expires_in: i64,
}

struct TokenState {
    access_token: String,
    refresh_at: Instant,
}

impl fmt::Debug for TokenState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenState")
            .field("access_token", &"<redacted>")
            .field("refresh_at", &self.refresh_at)
            .finish()
    }
}

/// Exchanges a provisioning key for a short-lived agent JWT and keeps it
/// refreshed. The JWT lives in memory only — it is never written to disk or
/// logged. Cheap to clone: internal state is `Arc`-shared.
#[derive(Clone)]
pub struct AuthClient {
    api: ApiClient,
    provisioning_key_file: PathBuf,
    agent_id: String,
    state: Arc<Mutex<Option<TokenState>>>,
}

impl AuthClient {
    pub fn new(api: ApiClient, provisioning_key_file: PathBuf, agent_id: String) -> Self {
        Self {
            api,
            provisioning_key_file,
            agent_id,
            state: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns a valid access token, exchanging for a new one only if none is
    /// cached or the cached one is due for refresh.
    pub async fn token(&self) -> Result<String, ApiError> {
        {
            let guard = self.state.lock().await;
            if let Some(state) = guard.as_ref() {
                if Instant::now() < state.refresh_at {
                    return Ok(state.access_token.clone());
                }
            }
        }
        self.force_refresh().await
    }

    /// Forces exactly one exchange, regardless of cached-token freshness.
    /// Callers use this after a `401` to refresh once and retry the original
    /// request once, per the Shapoclyack agent auth contract.
    pub async fn force_refresh(&self) -> Result<String, ApiError> {
        let fresh = self.exchange().await?;
        let token = fresh.access_token.clone();
        let mut guard = self.state.lock().await;
        *guard = Some(fresh);
        Ok(token)
    }

    async fn exchange(&self) -> Result<TokenState, ApiError> {
        let provisioning_key =
            fs::read_to_string(&self.provisioning_key_file).map_err(|error| {
                ApiError::Fatal(format!("failed to read provisioning key: {error}"))
            })?;
        let provisioning_key = provisioning_key.trim();
        if provisioning_key.is_empty() {
            return Err(ApiError::Fatal(
                "provisioning key file is empty".to_string(),
            ));
        }

        let request = AuthExchangeRequest {
            provisioning_key,
            agent_id: &self.agent_id,
        };

        let response: AuthExchangeResponse = self
            .api
            .post_json(AUTH_EXCHANGE_PATH, None, &request, None)
            .await?;

        let ttl_secs = response.expires_in.max(1) as u64;
        let ttl = Duration::from_secs(ttl_secs);
        let jitter_fraction =
            rand::thread_rng().gen_range(MIN_REFRESH_JITTER_FRACTION..MAX_REFRESH_JITTER_FRACTION);
        let refresh_in = ttl.mul_f64((1.0 - jitter_fraction).max(0.0));

        Ok(TokenState {
            access_token: response.access_token,
            refresh_at: Instant::now() + refresh_in,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_state_debug_never_leaks_the_access_token() {
        let state = TokenState {
            access_token: "super-secret-jwt".to_string(),
            refresh_at: Instant::now(),
        };

        let debug = format!("{state:?}");

        assert!(!debug.contains("super-secret-jwt"));
        assert!(debug.contains("<redacted>"));
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::config::Config;
    use std::fs;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn write_temp_key(label: &str) -> PathBuf {
        let key_path = std::env::temp_dir().join(format!(
            "lariska-auth-test-key-{label}-{}",
            std::process::id()
        ));
        fs::write(&key_path, "bootstrap-key").expect("key file should be written");
        key_path
    }

    fn test_config(server_url: String, key_path: PathBuf) -> Config {
        Config {
            server_url,
            provisioning_key_file: key_path,
            state_dir: std::env::temp_dir(),
            inventory_interval: Duration::from_secs(3600),
            heartbeat_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(5),
            tls_ca_file: None,
            log_level: "info".to_string(),
            allow_plain_http: true,
            inventory_full_refresh_interval: Duration::from_secs(86_400),
            max_spool_entries: 200,
        }
    }

    #[tokio::test]
    async fn successful_exchange_returns_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-jwt",
                "token_type": "bearer",
                "tenant_id": "tenant-1",
                "agent_id": "agent_test",
                "key_id": null,
                "expires_in": 7200
            })))
            .mount(&server)
            .await;

        let key_path = write_temp_key("success");
        let config = test_config(server.uri(), key_path.clone());
        let api = ApiClient::new(&config).expect("api client should build");
        let auth = AuthClient::new(api, config.provisioning_key_file, "agent_test".to_string());

        let token = auth.token().await.expect("exchange should succeed");
        assert_eq!(token, "test-jwt");

        fs::remove_file(key_path).ok();
    }

    #[tokio::test]
    async fn invalid_provisioning_key_surfaces_as_auth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let key_path = write_temp_key("invalid");
        let config = test_config(server.uri(), key_path.clone());
        let api = ApiClient::new(&config).expect("api client should build");
        let auth = AuthClient::new(api, config.provisioning_key_file, "agent_test".to_string());

        let error = auth.token().await.expect_err("invalid key should fail");
        assert!(matches!(error, ApiError::Auth));

        fs::remove_file(key_path).ok();
    }
}
