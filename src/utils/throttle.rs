//! HTTP throttling / 429-aware retry helper.
//!
//! Many target endpoints (Microsoft 365, Cloudflare-fronted hosts, AWS,
//! GitHub) respond with `429 Too Many Requests` or `503 Service Unavailable`
//! once you exceed their unauthenticated rate limit. The honest fix is to
//! back off — but the *correct* sleep duration is whatever the server tells
//! you in `Retry-After`, not a hard-coded constant.
//!
//! This helper wraps a closure that produces a `reqwest::Response` and:
//!
//! 1. Returns immediately on a non-throttle status.
//! 2. On 429/503, parses `Retry-After` (HTTP-date or seconds), falling back
//!    to `bruteforce::backoff_delay` jittered exponential backoff.
//! 3. Caps the wait at `max_wait` so a hostile server can't pin the scanner
//!    forever.
//! 4. Retries up to `max_retries`. After that, returns the final response
//!    (still throttled) so the caller can log it and move on.
//!
//! The helper is reqwest-specific because every consumer in the framework
//! uses reqwest. Modules that wrap arbitrary async work can call
//! [`bruteforce::backoff_delay`] directly.

use std::future::Future;
use std::time::Duration;

use reqwest::{Response, StatusCode};
use tokio::time::sleep;

use crate::utils::bruteforce::backoff_delay;

/// Configuration for [`with_backoff`]. Use [`BackoffConfig::default`] for
/// a sensible 5-attempt / 30-second-cap policy.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    /// Base delay used when the server omits `Retry-After`. Scaled
    /// exponentially per attempt with jitter.
    pub base_ms: u64,
    /// Cap on the exponential multiplier (`2^attempt` clamped to this).
    pub max_multiplier: u64,
    /// Hard cap on any single sleep — bounds adversarial `Retry-After: 86400`.
    pub max_wait: Duration,
    /// Maximum total retries before giving up and returning the last response.
    pub max_retries: u32,
    /// If true, also retry 503 responses, not just 429.
    pub retry_503: bool,
    /// If true, log each backoff to the operator.
    pub verbose: bool,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base_ms: 500,
            max_multiplier: 16,
            max_wait: Duration::from_secs(30),
            max_retries: 5,
            retry_503: true,
            verbose: true,
        }
    }
}

impl BackoffConfig {
    /// Aggressive policy for endpoints that throttle hard (e.g. M365
    /// `GetCredentialType` past ~5 rps).
    pub fn aggressive() -> Self {
        Self {
            base_ms: 1_000,
            max_multiplier: 32,
            max_wait: Duration::from_secs(60),
            max_retries: 8,
            retry_503: true,
            verbose: true,
        }
    }

    /// Conservative one-shot policy: try the request, retry once if 429.
    /// Used by light-weight probes that prefer to skip a host rather than
    /// retry through a long Retry-After.
    pub fn lenient() -> Self {
        Self {
            base_ms: 250,
            max_multiplier: 4,
            max_wait: Duration::from_secs(10),
            max_retries: 1,
            retry_503: false,
            verbose: false,
        }
    }
}

/// Returns `true` if `status` represents a throttle/back-off condition that
/// `with_backoff` should retry.
fn is_throttle(status: StatusCode, retry_503: bool) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || (retry_503 && status == StatusCode::SERVICE_UNAVAILABLE)
}

/// Parse a `Retry-After` header value. Per RFC 7231 it can be either an
/// integer count of seconds or an HTTP-date. The integer form is what every
/// real-world rate limiter sends; we accept that and ignore the date form
/// (rather than pulling in `httpdate` for an edge case).
fn parse_retry_after(value: &str) -> Option<Duration> {
    let trimmed = value.trim();
    trimmed.parse::<u64>().ok().map(Duration::from_secs)
}

/// Run `f` to produce a `reqwest::Response`, retrying on 429/503 with the
/// server's `Retry-After` header (or jittered exponential backoff) until
/// `cfg.max_retries` is exhausted.
///
/// `label` is a short string used only in the verbose log line so the
/// operator can see which call is being throttled. It is not interpolated
/// into the request — pass anything meaningful (e.g. a username being
/// enumerated, or a URL path). Owned `String` to keep the returned future
/// `'static`, which matters when the caller is itself spawned via
/// `tokio::spawn` (the framework's mass-scan / batch dispatch).
///
/// # Example
///
/// ```ignore
/// use crate::utils::throttle::{with_backoff, BackoffConfig};
///
/// let resp = with_backoff(BackoffConfig::default(), "list-users".into(), || async {
///     client.get("https://api.example.com/users").send().await
/// }).await?;
/// ```
pub async fn with_backoff<F, Fut>(
    cfg: BackoffConfig,
    label: String,
    mut f: F,
) -> reqwest::Result<Response>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = reqwest::Result<Response>>,
{
    let mut attempt: u32 = 0;
    loop {
        let resp = f().await?;
        let status = resp.status();
        if !is_throttle(status, cfg.retry_503) || attempt >= cfg.max_retries {
            return Ok(resp);
        }

        // Compute next sleep. Prefer Retry-After when present.
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after);
        let mut wait = retry_after.unwrap_or_else(|| backoff_delay(cfg.base_ms, attempt, cfg.max_multiplier));
        if wait > cfg.max_wait { wait = cfg.max_wait; }

        if cfg.verbose {
            crate::mprintln!(
                "{}",
                format!(
                    "[~] throttle {} status={} attempt={}/{} sleeping {}ms{}",
                    label,
                    status.as_u16(),
                    attempt + 1,
                    cfg.max_retries,
                    wait.as_millis(),
                    if retry_after.is_some() { " (Retry-After)" } else { " (backoff)" },
                )
            );
        }
        // Drop the response so its connection returns to the pool before sleeping.
        drop(resp);
        sleep(wait).await;
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_retry_after_seconds() {
        assert_eq!(parse_retry_after("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after("  0  "), Some(Duration::from_secs(0)));
    }

    #[test]
    fn parse_retry_after_garbage_is_none() {
        assert_eq!(parse_retry_after("not a number, not a date"), None);
    }

    #[test]
    fn is_throttle_classification() {
        assert!(is_throttle(StatusCode::TOO_MANY_REQUESTS, false));
        assert!(is_throttle(StatusCode::SERVICE_UNAVAILABLE, true));
        assert!(!is_throttle(StatusCode::SERVICE_UNAVAILABLE, false));
        assert!(!is_throttle(StatusCode::OK, true));
        assert!(!is_throttle(StatusCode::INTERNAL_SERVER_ERROR, true));
    }
}
