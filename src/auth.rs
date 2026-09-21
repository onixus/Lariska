use crate::api::{ApiClient, ApiError};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// APEX v1 requires versioned integration paths. Shapoclyack exposes the
// provisioning-key exchange under the versioned agent boundary below.
pub(crate) const AUTH_EXCHANGE_PATH: &str = "/api/v1/auth/agent/token";
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