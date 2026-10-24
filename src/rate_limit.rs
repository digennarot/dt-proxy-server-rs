//! In-memory fixed-window rate limiter.
//!
//! Port of `rateLimitBucket` and `createRateLimiter` from `server.js`.
//!
//! Each `(bucket, tenant-or-IP)` pair owns a window of `windowMs`
//! milliseconds. The first request opens the window; once more than the
//! bucket's maximum requests arrive inside it, further requests receive
//! `429 PROXY_RATE_LIMITED` with a `Retry-After` header until the window
//! expires. A maximum of `0` disables the limit.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RateLimits;

/// Maps a request path to its rate-limit bucket (`None` = not limited).
pub fn rate_limit_bucket(path: &str) -> Option<&'static str> {
    match path {
        "/health" => None,
        "/translate" => Some("translate"),
        "/usage" => Some("usage"),
        "/languages" | "/glossary-language-pairs" => Some("languages"),
        "/glossaries" => Some("glossaries"),
        other if other.starts_with("/glossaries/") => Some("glossaries"),
        _ => Some("default"),
    }
}

/// Returned when a request exceeds its limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limited {
    pub bucket: &'static str,
    pub retry_after_seconds: u64,
}

struct Window {
    started_at: Instant,
    count: u64,
}

pub struct RateLimiter {
    limits: RateLimits,
    windows: Mutex<HashMap<String, Window>>,
}

impl RateLimiter {
    pub fn new(limits: RateLimits) -> Self {
        Self {
            limits,
            windows: Mutex::new(HashMap::new()),
        }
    }

    fn window(&self) -> Duration {
        Duration::from_millis(self.limits.window_ms)
    }

    fn maximum(&self, bucket: &str) -> u64 {
        match bucket {
            "translate" => self.limits.translate,
            "usage" => self.limits.usage,
            "languages" => self.limits.languages,
            "glossaries" => self.limits.glossaries,
            _ => self.limits.default,
        }
    }

    /// Counts one request for `bucket` made by `identity` (the tenant id for
    /// authenticated routes, the client IP for the setup page).
    pub fn check(&self, bucket: &'static str, identity: &str) -> Result<(), Limited> {
        self.check_at(bucket, identity, Instant::now())
    }

    /// Same as [`check`](Self::check) with an explicit clock (for tests).
    pub fn check_at(&self, bucket: &'static str, identity: &str, now: Instant) -> Result<(), Limited> {
        let maximum = self.maximum(bucket);
        if maximum == 0 {
            return Ok(());
        }
        let window_length = self.window();
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let window = windows
            .entry(format!("{bucket}:{identity}"))
            .or_insert(Window { started_at: now, count: 0 });
        if now.saturating_duration_since(window.started_at) >= window_length {
            *window = Window { started_at: now, count: 0 };
        }
        window.count += 1;
        if window.count > maximum {
            let remaining = window_length.saturating_sub(now.saturating_duration_since(window.started_at));
            return Err(Limited {
                bucket,
                retry_after_seconds: (remaining.as_secs_f64().ceil() as u64).max(1),
            });
        }
        Ok(())
    }

    /// Drops expired windows (the original does this on a `setInterval`).
    pub fn cleanup(&self, now: Instant) {
        let window_length = self.window();
        self.windows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, window| now.saturating_duration_since(window.started_at) < window_length);
    }

    /// Number of live windows (used by tests and diagnostics).
    pub fn len(&self) -> usize {
        self.windows.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Interval at which [`cleanup`](Self::cleanup) should run.
    pub fn cleanup_interval(&self) -> Duration {
        self.window()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> RateLimits {
        RateLimits {
            window_ms: 60_000,
            default: 1,
            translate: 2,
            usage: 1,
            languages: 1,
            glossaries: 1,
        }
    }

    /// Port of "uses independent configurable limits for each route and
    /// exempts health" (test/security.test.js).
    #[test]
    fn uses_independent_limits_per_route_and_exempts_health() {
        assert_eq!(rate_limit_bucket("/translate"), Some("translate"));
        assert_eq!(rate_limit_bucket("/languages"), Some("languages"));
        assert_eq!(rate_limit_bucket("/glossary-language-pairs"), Some("languages"));
        assert_eq!(rate_limit_bucket("/glossaries/abc"), Some("glossaries"));
        assert_eq!(rate_limit_bucket("/identity"), Some("default"));
        assert_eq!(rate_limit_bucket("/health"), None);

        let limiter = RateLimiter::new(limits());
        let now = Instant::now();
        assert!(limiter.check_at("translate", "tenant", now).is_ok());
        assert!(limiter.check_at("translate", "tenant", now).is_ok());
        let limited = limiter.check_at("translate", "tenant", now).unwrap_err();
        assert_eq!(limited.bucket, "translate");
        assert!(limited.retry_after_seconds >= 1);
        // Other buckets are unaffected.
        assert!(limiter.check_at("usage", "tenant", now).is_ok());
        // Other identities are unaffected.
        assert!(limiter.check_at("translate", "someone-else", now).is_ok());
    }

    #[test]
    fn windows_reset_after_the_configured_duration() {
        let limiter = RateLimiter::new(limits());
        let start = Instant::now();
        assert!(limiter.check_at("usage", "t", start).is_ok());
        assert!(limiter.check_at("usage", "t", start).is_err());
        let later = start + Duration::from_millis(60_000);
        assert!(limiter.check_at("usage", "t", later).is_ok());
    }

    #[test]
    fn zero_disables_a_limit() {
        let limiter = RateLimiter::new(RateLimits { translate: 0, ..limits() });
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(limiter.check_at("translate", "t", now).is_ok());
        }
        assert!(limiter.is_empty());
    }

    #[test]
    fn retry_after_reflects_the_remaining_window() {
        let limiter = RateLimiter::new(limits());
        let start = Instant::now();
        limiter.check_at("usage", "t", start).unwrap();
        let limited = limiter
            .check_at("usage", "t", start + Duration::from_millis(45_500))
            .unwrap_err();
        assert_eq!(limited.retry_after_seconds, 15);
    }

    #[test]
    fn cleanup_removes_expired_windows() {
        let limiter = RateLimiter::new(limits());
        let start = Instant::now();
        limiter.check_at("usage", "a", start).unwrap();
        limiter.check_at("usage", "b", start + Duration::from_millis(50_000)).unwrap();
        limiter.cleanup(start + Duration::from_millis(61_000));
        assert_eq!(limiter.len(), 1);
    }
}
