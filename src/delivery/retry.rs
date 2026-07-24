use crate::api::ApiError;
use rand::Rng;
use std::time::Duration;

const BASE_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Caps the exponent so `2^attempt` cannot overflow; delay is separately
/// capped at `MAX_BACKOFF` well before this is reached.
const MAX_BACKOFF_EXPONENT: u32 = 16;

pub enum RetryDecision {
    RetryAfter(Duration),
    GiveUp,
}

/// Classifies an error already past the caller's own one-time 401
/// refresh-and-retry (see `heartbeat::HeartbeatClient` and
/// `delivery::DeliveryClient::submit_one`, which both do that inline).
/// Retries network errors, `429`, and `5xx` with full-jitter exponential
/// backoff (Plan.md §11); `403`/`409`/`422`/payload-too-large are
/// non-retryable and must be surfaced, not looped on forever.
pub fn classify(error: &ApiError, attempt: u32) -> RetryDecision {
    match error {
        ApiError::Transient(_) => RetryDecision::RetryAfter(backoff(attempt, None)),
        ApiError::RateLimited { retry_after } => {
            RetryDecision::RetryAfter(backoff(attempt, *retry_after))
        }
        ApiError::Auth
        | ApiError::Forbidden(_)
        | ApiError::Conflict(_)
        | ApiError::Validation(_)
        | ApiError::PayloadTooLarge(_)
        | ApiError::Fatal(_) => RetryDecision::GiveUp,
    }
}

/// AWS-style "full jitter": delay = random(0, min(max, base * 2^attempt)).
/// A server-supplied `Retry-After` always wins when present.
fn backoff(attempt: u32, retry_after: Option<Duration>) -> Duration {
    if let Some(retry_after) = retry_after {
        return retry_after;
    }

    let capped_attempt = attempt.min(MAX_BACKOFF_EXPONENT);
    let max_delay = BASE_BACKOFF
        .saturating_mul(1u32 << capped_attempt)
        .min(MAX_BACKOFF);
    let jitter_ms = rand::thread_rng().gen_range(0..=max_delay.as_millis().max(1) as u64);

    Duration::from_millis(jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_and_rate_limited_errors_are_retried() {
        assert!(matches!(
            classify(&ApiError::Transient("boom".to_string()), 1),
            RetryDecision::RetryAfter(_)
        ));
        assert!(matches!(
            classify(&ApiError::RateLimited { retry_after: None }, 1),
            RetryDecision::RetryAfter(_)
        ));
    }

    #[test]
    fn terminal_errors_give_up() {
        assert!(matches!(
            classify(&ApiError::Forbidden("no".to_string()), 1),
            RetryDecision::GiveUp
        ));
        assert!(matches!(
            classify(&ApiError::Conflict("dup".to_string()), 1),
            RetryDecision::GiveUp
        ));
        assert!(matches!(
            classify(&ApiError::Validation("bad".to_string()), 1),
            RetryDecision::GiveUp
        ));
        assert!(matches!(
            classify(&ApiError::Auth, 1),
            RetryDecision::GiveUp
        ));
    }

    #[test]
    fn retry_after_header_overrides_computed_backoff() {
        let decision = classify(
            &ApiError::RateLimited {
                retry_after: Some(Duration::from_secs(42)),
            },
            1,
        );
        match decision {
            RetryDecision::RetryAfter(delay) => assert_eq!(delay, Duration::from_secs(42)),
            RetryDecision::GiveUp => panic!("expected a retry decision"),
        }
    }

    #[test]
    fn backoff_never_exceeds_the_configured_maximum() {
        for attempt in 0..40 {
            let delay = backoff(attempt, None);
            assert!(delay <= MAX_BACKOFF, "attempt {attempt} produced {delay:?}");
        }
    }
}
