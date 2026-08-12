use crate::config::Config;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;
use std::time::Duration;
use thiserror::Error;

const MAX_ERROR_DETAIL_CHARS: usize = 500;
const MAX_SUCCESS_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 64 * 1024;

/// Classified outcomes of a Shapoclyack API call. Callers branch on the
/// variant, not the HTTP status code, so retry/refresh policy lives in one
/// place (see `AuthClient` for the 401 refresh-and-retry-once rule and
/// Phase L4's `delivery::retry` for the full backoff policy).
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("authentication failed or expired")]
    Auth,
    #[error("access forbidden: {0}")]
    Forbidden(String),
    #[error("conflicting request: {0}")]
    Conflict(String),
    #[error("rate limited")]
    RateLimited { retry_after: Option<Duration> },
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    #[error("request validation failed: {0}")]
    Validation(String),
    #[error("transient error: {0}")]
    Transient(String),
    #[error("unrecoverable error: {0}")]
    Fatal(String),
}

/// Bounded HTTP client for the Shapoclyack API. Cheap to clone (the
/// underlying `reqwest::Client` is `Arc`-backed).
#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    base_url: String,
}

impl fmt::Debug for ApiClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiClient")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl ApiClient {
    pub fn new(config: &Config) -> Result<Self, ApiError> {
        let mut builder = Client::builder().timeout(config.request_timeout);

        if let Some(ca_path) = &config.tls_ca_file {
            let pem = std::fs::read(ca_path)
                .map_err(|error| ApiError::Fatal(format!("failed to read tls_ca_file: {error}")))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|error| ApiError::Fatal(format!("invalid tls_ca_file: {error}")))?;
            builder = builder.add_root_certificate(certificate);
        }

        let http = builder
            .build()
            .map_err(|error| ApiError::Fatal(format!("failed to build http client: {error}")))?;

        Ok(Self {
            http,
            base_url: config.server_url.trim_end_matches('/').to_string(),
        })
    }

    /// POSTs a JSON body and classifies the response. `idempotency_key`, when
    /// set, is sent as `Idempotency-Key` — the header is currently advisory
    /// only (the live Shapoclyack ingestion endpoint keys idempotency off the
    /// `snapshot_id` field in the body, not this header) but is sent anyway
    /// for spec compliance and forward compatibility.
    pub async fn post_json<B, R>(
        &self,
        path: &str,
        bearer_token: Option<&str>,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<R, ApiError>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let url = format!("{}{path}", self.base_url);
        let mut request = self.http.post(&url).json(body);
        if let Some(token) = bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }

        let response = request
            .send()
            .await
            .map_err(|error| classify_transport_error(&error))?;

        classify_response(response).await
    }
}

fn classify_transport_error(error: &reqwest::Error) -> ApiError {
    if error.is_timeout() || error.is_connect() || error.is_request() {
        ApiError::Transient(error.to_string())
    } else {
        ApiError::Fatal(error.to_string())
    }
}

#[derive(Debug)]
enum BodyReadError {
    TooLarge { limit: usize },
    Transport(ApiError),
}

async fn read_response_body_limited(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BodyReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(BodyReadError::TooLarge { limit });
    }

    let initial_capacity = response
        .content_length()
        .unwrap_or_default()
        .min(limit as u64) as usize;
    let mut body = Vec::with_capacity(initial_capacity);

    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|error| BodyReadError::Transport(classify_transport_error(&error)))?;
        let Some(chunk) = chunk else {
            break;
        };

        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(BodyReadError::TooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

async fn classify_response<R: DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<R, ApiError> {
    let status = response.status();
    if status.is_success() {
        let body = read_response_body_limited(&mut response, MAX_SUCCESS_RESPONSE_BYTES)
            .await
            .map_err(|error| match error {
                BodyReadError::TooLarge { limit } => {
                    ApiError::Fatal(format!("response body exceeds {limit} bytes"))
                }
                BodyReadError::Transport(error) => error,
            })?;

        return serde_json::from_slice::<R>(&body)
            .map_err(|error| ApiError::Fatal(format!("failed to decode response: {error}")));
    }

    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs);

    let detail = match read_response_body_limited(&mut response, MAX_ERROR_RESPONSE_BYTES).await {
        Ok(body) => sanitize_detail(&String::from_utf8_lossy(&body)),
        Err(BodyReadError::TooLarge { limit }) => {
            format!("response body exceeds {limit} bytes")
        }
        Err(BodyReadError::Transport(error)) => return Err(error),
    };

    Err(match status {
        StatusCode::UNAUTHORIZED => ApiError::Auth,
        StatusCode::FORBIDDEN => ApiError::Forbidden(detail),
        StatusCode::CONFLICT => ApiError::Conflict(detail),
        StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited { retry_after },
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::PayloadTooLarge(detail),
        StatusCode::UNPROCESSABLE_ENTITY => ApiError::Validation(detail),
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY => ApiError::Transient(detail),
        status if status.is_server_error() => ApiError::Transient(detail),
        status => ApiError::Fatal(format!("unexpected status {status}: {detail}")),
    })
}

/// Bounds error-body text before it is logged or wrapped in an error. The
/// server does not echo secrets in error bodies, but callers must still
/// never log this alongside a bearer token or provisioning key.
fn sanitize_detail(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.chars().count() <= MAX_ERROR_DETAIL_CHARS {
        trimmed.to_string()
    } else {
        let truncated: String = trimmed.chars().take(MAX_ERROR_DETAIL_CHARS).collect();
        format!("{truncated}... (truncated)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn oversized_success_response_is_rejected_before_json_decode() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("x".repeat(MAX_SUCCESS_RESPONSE_BYTES + 1)),
            )
            .mount(&server)
            .await;

        let client = ApiClient {
            http: Client::new(),
            base_url: server.uri(),
        };
        let result: Result<serde_json::Value, ApiError> = client
            .post_json("/test", None, &json!({}), None)
            .await;

        assert!(matches!(
            result,
            Err(ApiError::Fatal(message)) if message.contains("response body exceeds")
        ));
    }

    #[tokio::test]
    async fn oversized_error_response_preserves_http_classification() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_string("x".repeat(MAX_ERROR_RESPONSE_BYTES + 1)),
            )
            .mount(&server)
            .await;

        let client = ApiClient {
            http: Client::new(),
            base_url: server.uri(),
        };
        let result: Result<serde_json::Value, ApiError> = client
            .post_json("/test", None, &json!({}), None)
            .await;

        assert!(matches!(
            result,
            Err(ApiError::RateLimited { retry_after: None })
        ));
    }

    #[test]
    fn error_detail_is_sanitized_to_character_limit() {
        let body = "x".repeat(MAX_ERROR_DETAIL_CHARS + 10);
        let detail = sanitize_detail(&body);

        assert!(detail.ends_with("... (truncated)"));
        assert_eq!(detail.matches('x').count(), MAX_ERROR_DETAIL_CHARS);
    }
}
