//! The request pipeline that runs before any route handler.
//!
//! In `server.js` this is a chain of `app.use(...)` calls whose **order**
//! matters (for example a rejected Origin never receives CORS headers, and the
//! CORS pre-flight is answered before the token is checked). Rather than
//! scattering that order across several tower layers, it is written here as one
//! explicit sequence of steps, numbered like the original chain:
//!
//! | step | original `app.use`                                   | here                    |
//! |------|------------------------------------------------------|-------------------------|
//! | 0    | security headers                                     | [`apply_security_headers`] |
//! | 1    | `GET /` -> `/setup` redirect while unconfigured      | `process`               |
//! | 2    | `/setup` routes (own authentication)                 | passed through          |
//! | 3    | `503 SETUP_REQUIRED` gate                            | `process`               |
//! | 4    | `403 ORIGIN_REQUIRED`                                | `process`               |
//! | 5    | origin allow-list (+ learning in remote mode)        | `process`               |
//! | 6    | `cors({ origin: true })`                             | [`cors_preflight`] / [`add_cors_headers`] |
//! | 7    | Bearer token, DeepL key presence, origin learning    | `process`               |
//! | 8    | per-route rate limiter                               | `process`               |

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use url::Url;

use crate::config::{remember_foundry_origin, ConfigResult, DeploymentMode};
use crate::error::{json_response, ProxyError};
use crate::rate_limit::rate_limit_bucket;
use crate::state::{client_ip, AppState};
use crate::util::constant_time_eq;

/// Identity attached to a request once the proxy token was verified
/// (`req.tenantId` / `req.deepLApiKey` in the original).
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub tenant_id: String,
    pub deepl_api_key: String,
}

/// `getAccessToken`: extracts the token of an `Authorization: Bearer <token>`
/// header (scheme is case-insensitive).
pub fn get_access_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_at_checked(6)?;
    if !scheme.eq_ignore_ascii_case("bearer") || !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// `isAllowedOrigin`. `allowed` is `None` when no allow-list is configured, in
/// which case only loopback origins are accepted.
pub fn is_allowed_origin(origin: Option<&str>, allowed: Option<&[String]>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    if let Some(allowed) = allowed {
        return allowed.iter().any(|candidate| candidate == origin);
    }
    match Url::parse(origin).ok().and_then(|url| url.host_str().map(str::to_owned)) {
        Some(host) => matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]"),
        None => false,
    }
}

/// A redirect with an explicit status (`res.redirect(302, ...)`; axum's
/// built-in `Redirect` cannot produce a plain 302).
pub fn redirect(status: StatusCode, location: &'static str) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    response
}

/// Step 0: the response headers every reply carries. Existing values win, so
/// the stricter headers of the setup page are preserved.
pub fn apply_security_headers(headers: &mut HeaderMap, path: &str) {
    let defaults: [(&str, &str); 5] = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "camera=(), microphone=(), geolocation=()"),
        (
            "cache-control",
            if path == "/health" { "no-cache" } else { "no-store" },
        ),
    ];
    for (name, value) in defaults {
        headers
            .entry(HeaderName::from_static(name))
            .or_insert(HeaderValue::from_static(value));
    }
}

/// Step 6 (pre-flight): what the `cors` package answers to any `OPTIONS`
/// request when configured with `{ origin: true }`: the request origin and
/// requested headers are reflected, status 204.
pub fn cors_preflight(origin: Option<&str>, request_headers: Option<&HeaderValue>) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    if let Some(origin) = origin.and_then(|origin| HeaderValue::from_str(origin).ok()) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,HEAD,PUT,PATCH,POST,DELETE"),
    );
    match request_headers {
        Some(requested) => {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
            headers.insert(
                header::VARY,
                HeaderValue::from_static("Origin, Access-Control-Request-Headers"),
            );
        }
        None => {
            headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

/// Step 6 (actual requests): reflect the origin.
pub fn add_cors_headers(response: &mut Response, origin: Option<&str>) {
    let headers = response.headers_mut();
    if let Some(origin) = origin.and_then(|origin| HeaderValue::from_str(origin).ok()) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
}

/// Immutable view of the configuration taken once per request, so no lock is
/// held while the request is being processed.
struct Policy {
    setup_required: bool,
    allow_no_origin: bool,
    allowed_origins: Vec<String>,
    deployment_mode: DeploymentMode,
    access_token: String,
    account_id: String,
    deepl_api_key: String,
}

fn snapshot(state: &AppState) -> Policy {
    let runtime = state.runtime();
    Policy {
        setup_required: runtime.setup_required,
        allow_no_origin: runtime.config.allow_no_origin,
        allowed_origins: runtime.config.allowed_origins.clone(),
        deployment_mode: runtime.config.deployment_mode,
        access_token: runtime.secrets.access_token.clone(),
        account_id: runtime.secrets.account_id.clone(),
        deepl_api_key: runtime.secrets.deepl_api_key.clone(),
    }
}

/// Persists a newly learned Foundry origin (`rememberFoundryOrigin`).
///
/// Writes are serialised through `origin_write_lock` so that two simultaneous
/// first requests cannot overwrite each other's file contents.
pub async fn remember_origin(state: &Arc<AppState>, origin: &str) -> ConfigResult<String> {
    let _guard = state.origin_write_lock.lock().await;
    let state = Arc::clone(state);
    let origin = origin.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut runtime = state.runtime_mut();
        remember_foundry_origin(&mut runtime, &origin)
    })
    .await
    .map_err(|error| crate::config::ConfigError::new(error.to_string()))?
}

/// The axum middleware wrapping the whole router.
pub async fn gate(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut response = process(&state, req, next).await;
    apply_security_headers(response.headers_mut(), &path);
    response
}

async fn process(state: &Arc<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let policy = snapshot(state);

    // Step 2: `/setup` authenticates itself (one-time token, cookies, CSRF).
    if path == "/setup" {
        return next.run(req).await;
    }

    // Step 1: while unconfigured, the root URL leads to the setup page.
    if method == Method::GET && path == "/" && policy.setup_required {
        return redirect(StatusCode::FOUND, "/setup");
    }

    // Step 3: until the first-run setup is finished only /health answers.
    if policy.setup_required && path != "/health" {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({
                "error": "Use the one-time setup URL shown in the proxy console",
                "code": "SETUP_REQUIRED"
            }),
        );
    }

    // Step 4: browsers always send Origin; non-browser clients must opt in.
    if path != "/health" && origin.is_none() && !policy.allow_no_origin {
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({
                "error": "An Origin header is required for protected routes",
                "code": "ORIGIN_REQUIRED"
            }),
        );
    }

    // Step 5: origin allow-list. In remote mode an unknown origin is accepted
    // (and recorded) when it presents the correct proxy token: this is how the
    // first Foundry connection is learned automatically.
    let mut learn_origin: Option<String> = None;
    if let Some(origin) = origin.as_deref() {
        let allow_list = (!policy.allowed_origins.is_empty()).then_some(policy.allowed_origins.as_slice());
        let skip = method == Method::OPTIONS || path == "/health";
        if !skip && !is_allowed_origin(Some(origin), allow_list) {
            let token_is_valid = get_access_token(req.headers())
                .is_some_and(|token| constant_time_eq(&token, &policy.access_token));
            if policy.deployment_mode == DeploymentMode::Remote && token_is_valid {
                learn_origin = Some(origin.to_owned());
            } else {
                return json_response(StatusCode::FORBIDDEN, &json!({ "error": "Origin not allowed" }));
            }
        }
    }

    // Step 6: CORS. Every OPTIONS request is a pre-flight answered right here,
    // before the token check (browsers cannot attach credentials to it).
    if method == Method::OPTIONS {
        let requested = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS).cloned();
        return cors_preflight(origin.as_deref(), requested.as_ref());
    }

    let mut early_failure: Option<Response> = None;

    // Step 7: authentication of everything except /health.
    if path != "/health" {
        let supplied = get_access_token(req.headers());
        if !supplied.is_some_and(|token| constant_time_eq(&token, &policy.access_token)) {
            let mut response = json_response(
                StatusCode::UNAUTHORIZED,
                &json!({ "error": "Invalid or missing proxy token", "code": "PROXY_TOKEN_INVALID" }),
            );
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"Deep Translate Proxy\""),
            );
            early_failure = Some(response);
        } else if policy.deepl_api_key.is_empty() || policy.deepl_api_key.chars().count() > 200 {
            early_failure = Some(json_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!({ "error": "A valid DeepL API key is required", "code": "DEEPL_KEY_MISSING" }),
            ));
        } else if let Some(origin) = learn_origin {
            match remember_origin(state, &origin).await {
                Ok(origin) => tracing::info!("Foundry origin allowed automatically: {origin}"),
                Err(error) => {
                    tracing::error!("❌ Request error: {error}");
                    early_failure = Some(ProxyError::invalid_request().into_response());
                }
            }
        }
    }
    if let Some(mut response) = early_failure {
        add_cors_headers(&mut response, origin.as_deref());
        return response;
    }

    // Step 8: rate limiting, keyed by tenant (or client IP before auth).
    if let Some(bucket) = rate_limit_bucket(&path) {
        let identity = if policy.account_id.is_empty() {
            let peer = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip())
                .unwrap_or_else(|| std::net::Ipv4Addr::LOCALHOST.into());
            let forwarded = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok());
            client_ip(peer, forwarded, state.trust_proxy_hops())
        } else {
            policy.account_id.clone()
        };
        if let Err(limited) = state.rate_limiter.check(bucket, &identity) {
            let mut response = json_response(
                StatusCode::TOO_MANY_REQUESTS,
                &json!({
                    "error": format!("Too many proxy requests for {bucket}"),
                    "code": "PROXY_RATE_LIMITED",
                    "route": bucket,
                    "retry_after": limited.retry_after_seconds,
                }),
            );
            if let Ok(value) = HeaderValue::from_str(&limited.retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            add_cors_headers(&mut response, origin.as_deref());
            return response;
        }
    }

    if path != "/health" {
        req.extensions_mut().insert(AuthContext {
            tenant_id: policy.account_id,
            deepl_api_key: policy.deepl_api_key,
        });
    }
    let mut response = next.run(req).await;
    add_cors_headers(&mut response, origin.as_deref());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    /// Port of "accepts the Bearer authentication scheme case-insensitively".
    #[test]
    fn accepts_the_bearer_scheme_case_insensitively() {
        assert_eq!(get_access_token(&headers("bearer   dt_secret")).as_deref(), Some("dt_secret"));
        assert_eq!(get_access_token(&headers("Bearer dt_secret")).as_deref(), Some("dt_secret"));
        assert_eq!(get_access_token(&headers("BEARER dt_secret")).as_deref(), Some("dt_secret"));
        assert_eq!(get_access_token(&headers("Basic abc")), None);
        assert_eq!(get_access_token(&headers("Bearer")), None);
        assert_eq!(get_access_token(&headers("Bearer    ")), None);
        assert_eq!(get_access_token(&headers("Bearerdt_secret")), None);
        assert_eq!(get_access_token(&HeaderMap::new()), None);
    }

    #[test]
    fn origin_policy() {
        let allowed = vec!["https://foundry.example.test".to_owned()];
        // No Origin header is decided elsewhere (ORIGIN_REQUIRED), never here.
        assert!(is_allowed_origin(None, Some(&allowed)));
        assert!(is_allowed_origin(Some("https://foundry.example.test"), Some(&allowed)));
        assert!(!is_allowed_origin(Some("https://evil.example.test"), Some(&allowed)));
        // Without a list only loopback origins are accepted.
        assert!(is_allowed_origin(Some("http://localhost:30000"), None));
        assert!(is_allowed_origin(Some("http://127.0.0.1:30000"), None));
        assert!(is_allowed_origin(Some("http://[::1]:30000"), None));
        assert!(!is_allowed_origin(Some("http://192.168.1.10:30000"), None));
        assert!(!is_allowed_origin(Some("http://localhost.evil.test"), None));
        assert!(!is_allowed_origin(Some("null"), None));
    }

    #[test]
    fn security_headers_do_not_overwrite_existing_values() {
        let mut map = HeaderMap::new();
        map.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store, custom"));
        apply_security_headers(&mut map, "/setup");
        assert_eq!(map.get(header::CACHE_CONTROL).unwrap(), "no-store, custom");
        assert_eq!(map.get("x-frame-options").unwrap(), "DENY");
        let mut health = HeaderMap::new();
        apply_security_headers(&mut health, "/health");
        assert_eq!(health.get(header::CACHE_CONTROL).unwrap(), "no-cache");
    }

    #[test]
    fn preflight_reflects_origin_and_requested_headers() {
        let requested = HeaderValue::from_static("authorization,content-type");
        let response = cors_preflight(Some("http://localhost:30000"), Some(&requested));
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let map = response.headers();
        assert_eq!(map.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "http://localhost:30000");
        assert_eq!(map.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(), "authorization,content-type");
        assert_eq!(map.get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap(), "GET,HEAD,PUT,PATCH,POST,DELETE");
    }
}
