//! Shared application state.
//!
//! In the Node.js original this state lives in closures inside
//! `startServer()` (`cache`, `activeTranslations`, `setupInProgress`, the
//! setup tokens, `runtime`) and on the Express `app` (`trust proxy`). Rust
//! needs it in one explicit, thread-safe struct that is shared by every
//! request task through an `Arc`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::config::{RateLimits, Runtime};
use crate::deepl::DeepLFactory;
use crate::rate_limit::RateLimiter;
use crate::util::random_base64url;

/// Entries kept in the translation cache before it is wiped (`MAX_CACHE_SIZE`).
pub const MAX_CACHE_SIZE: usize = 5000;
/// Total bytes (keys + values) the cache may hold before it is wiped. Bounds
/// memory when clients cache very large translations (hardening).
pub const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Largest number of texts accepted by `POST /translate` (`MAX_TEXTS`).
pub const MAX_TEXTS: usize = 300;
/// Largest total UTF-16 length of the texts of one request (`MAX_TOTAL_CHARS`).
pub const MAX_TOTAL_CHARS: usize = 120_000;
/// Simultaneous upstream translation calls (`MAX_CONCURRENT_TRANSLATIONS`).
pub const MAX_CONCURRENT_TRANSLATIONS: usize = 5;
/// Request limit of the `/setup` POST endpoint per window (`default: 10`).
pub const SETUP_RATE_LIMIT: u64 = 10;

/// Bounded in-memory translation cache.
///
/// Like the original, it is *not* an LRU: when it reaches [`MAX_CACHE_SIZE`]
/// entries it is cleared entirely. Keys already embed the tenant, the DeepL
/// key scope, languages, glossary, formality and the text hash.
#[derive(Default)]
pub struct ResponseCache {
    entries: Mutex<CacheInner>,
}

#[derive(Default)]
struct CacheInner {
    map: HashMap<String, String>,
    bytes: usize,
}

impl ResponseCache {
    pub fn get(&self, key: &str) -> Option<String> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).map.get(key).cloned()
    }

    pub fn insert(&self, key: String, value: String) {
        let mut inner = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let size = key.len() + value.len();
        if inner.map.len() >= MAX_CACHE_SIZE || inner.bytes + size > MAX_CACHE_BYTES {
            inner.map.clear();
            inner.bytes = 0;
            tracing::warn!("⚠️ Cache cleared");
        }
        if let Some(previous) = inner.map.insert(key, value) {
            inner.bytes = inner.bytes.saturating_sub(previous.len());
        }
        inner.bytes += size;
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// RAII permit for one in-flight upstream translation call; releases the slot
/// on drop (the original decrements `activeTranslations` in a `finally`).
pub struct TranslationPermit<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for TranslationPermit<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct AppState {
    /// Configuration + secrets. Mutated only by the first-run setup and by the
    /// automatic recording of the first Foundry origin.
    runtime: RwLock<Runtime>,
    pub cache: ResponseCache,
    active_translations: AtomicUsize,
    pub rate_limiter: RateLimiter,
    pub setup_rate_limiter: RateLimiter,
    /// Random per-process CSRF token for the setup form.
    pub setup_csrf_token: String,
    /// Random per-process token embedded in the one-time setup URL.
    pub setup_access_token: String,
    pub setup_in_progress: AtomicBool,
    /// Express `app.set("trust proxy", n)`: number of trusted proxy hops. It
    /// can change at the end of the web setup, hence the atomic.
    trust_proxy_hops: AtomicU32,
    /// Serialises the writes that persist newly learned Foundry origins
    /// (`originWriteQueues` in the original).
    pub origin_write_lock: tokio::sync::Mutex<()>,
    pub deepl: DeepLFactory,
}

impl AppState {
    pub fn new(runtime: Runtime, deepl: DeepLFactory) -> Arc<Self> {
        let rate_limits = runtime.config.rate_limits.clone();
        let setup_limits = RateLimits {
            default: SETUP_RATE_LIMIT,
            ..rate_limits.clone()
        };
        Arc::new(Self {
            trust_proxy_hops: AtomicU32::new(runtime.config.trust_proxy_hops),
            runtime: RwLock::new(runtime),
            cache: ResponseCache::default(),
            active_translations: AtomicUsize::new(0),
            rate_limiter: RateLimiter::new(rate_limits),
            setup_rate_limiter: RateLimiter::new(setup_limits),
            setup_csrf_token: random_base64url(32),
            setup_access_token: random_base64url(32),
            setup_in_progress: AtomicBool::new(false),
            origin_write_lock: tokio::sync::Mutex::new(()),
            deepl,
        })
    }

    pub fn runtime(&self) -> RwLockReadGuard<'_, Runtime> {
        self.runtime.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn runtime_mut(&self) -> RwLockWriteGuard<'_, Runtime> {
        self.runtime.write().unwrap_or_else(|e| e.into_inner())
    }

    pub fn trust_proxy_hops(&self) -> u32 {
        self.trust_proxy_hops.load(Ordering::SeqCst)
    }

    pub fn set_trust_proxy_hops(&self, hops: u32) {
        self.trust_proxy_hops.store(hops, Ordering::SeqCst);
    }

    /// Tries to reserve one of the [`MAX_CONCURRENT_TRANSLATIONS`] slots.
    pub fn try_acquire_translation(&self) -> Option<TranslationPermit<'_>> {
        let previous = self.active_translations.fetch_add(1, Ordering::SeqCst);
        if previous >= MAX_CONCURRENT_TRANSLATIONS {
            self.active_translations.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(TranslationPermit {
            counter: &self.active_translations,
        })
    }

    pub fn active_translations(&self) -> usize {
        self.active_translations.load(Ordering::SeqCst)
    }

    /// Starts the background task that evicts expired rate-limit windows.
    pub fn spawn_background_tasks(self: &Arc<Self>) {
        for limiter_of in [
            (|state: &AppState| &state.rate_limiter) as fn(&AppState) -> &RateLimiter,
            |state: &AppState| &state.setup_rate_limiter,
        ] {
            let state = Arc::clone(self);
            tokio::spawn(async move {
                let interval = limiter_of(&state).cleanup_interval();
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // the first tick completes immediately
                loop {
                    ticker.tick().await;
                    limiter_of(&state).cleanup(std::time::Instant::now());
                }
            });
        }
    }
}

/// Express's `req.ip` for `trust proxy = hops`.
///
/// The address chain is `[socket peer, X-Forwarded-For entries right-to-left]`;
/// the first `hops` entries are trusted proxies, so the client is the entry
/// right after them (or the last one when the chain is shorter). With
/// `hops == 0` the header is ignored entirely.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, hops: u32) -> String {
    if hops == 0 {
        return peer.to_string();
    }
    let mut chain = vec![peer.to_string()];
    if let Some(header) = forwarded_for {
        chain.extend(
            header
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .rev()
                .map(str::to_owned),
        );
    }
    let index = (hops as usize).min(chain.len() - 1);
    chain.swap_remove(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_is_cleared_when_it_reaches_its_limit() {
        let cache = ResponseCache::default();
        for index in 0..MAX_CACHE_SIZE {
            cache.insert(format!("k{index}"), "v".into());
        }
        assert_eq!(cache.len(), MAX_CACHE_SIZE);
        cache.insert("one-more".into(), "v".into());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("one-more").as_deref(), Some("v"));
        assert_eq!(cache.get("k0"), None);
    }

    #[test]
    fn the_cache_is_cleared_when_it_exceeds_its_byte_budget() {
        let cache = ResponseCache::default();
        let big = "x".repeat(MAX_CACHE_BYTES / 2 + 1);
        cache.insert("a".into(), big.clone());
        assert_eq!(cache.len(), 1);
        cache.insert("b".into(), big);
        assert_eq!(cache.len(), 1, "the second large entry wipes the first");
        assert_eq!(cache.get("a"), None);
    }

    #[test]
    fn client_ip_honours_the_number_of_trusted_hops() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        // No trust: the header is ignored (a client could forge it).
        assert_eq!(client_ip(proxy, Some("1.2.3.4"), 0), "10.0.0.1");
        // One trusted proxy: the client is the right-most forwarded address.
        assert_eq!(client_ip(proxy, Some("9.9.9.9, 1.2.3.4"), 1), "1.2.3.4");
        // Two trusted proxies.
        assert_eq!(client_ip(proxy, Some("1.2.3.4, 10.0.0.2"), 2), "1.2.3.4");
        // No header at all: fall back to the socket address.
        assert_eq!(client_ip(proxy, None, 1), "10.0.0.1");
        // More hops than addresses: the left-most entry.
        assert_eq!(client_ip(proxy, Some("1.2.3.4"), 5), "1.2.3.4");
    }
}
