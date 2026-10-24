//! `GET /setup` and `POST /setup`: the browser-based first-run assistant.
//!
//! Port of the `/setup` handlers in `server.js`. The security model is kept
//! intact:
//!
//! 1. The console prints a one-time URL `/setup?token=<random>`. A plain
//!    `/setup` is rejected (403).
//! 2. Visiting that URL exchanges the token for an `HttpOnly`,
//!    `SameSite=Strict` cookie scoped to `/setup` and redirects (303) so the
//!    token disappears from the address bar and history.
//! 3. The form carries a CSRF token that must match a second cookie
//!    (double submit).
//! 4. The submitted DeepL key is verified against DeepL *before* it is
//!    stored, and only one setup can run at a time.
//! 5. Once configured, `/setup` answers 404 forever.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::config::{complete_web_setup, connection_string, SetupForm};
use crate::deepl::DeepLError;
use crate::error::{json_response, ProxyError};
use crate::middleware::redirect;
use crate::setup_ui::{
    append_cookie, apply_setup_headers, expired_setup_cookie, setup_access_granted, setup_cookie,
    setup_page, SetupValues, SETUP_ACCESS_COOKIE, SETUP_CSRF_COOKIE,
};
use crate::state::{client_ip, AppState};
use crate::util::{constant_time_eq, js_len, js_trim, parse_cookies};

/// `express.urlencoded({ limit: "16kb" })`.
const MAX_FORM_BYTES: usize = 16 * 1024;

fn with_setup_headers(mut response: Response) -> Response {
    apply_setup_headers(response.headers_mut());
    response
}

fn text(status: StatusCode, message: &str) -> Response {
    let mut response = (status, message.to_owned()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    with_setup_headers(response)
}

fn html(status: StatusCode, page: String) -> Response {
    let mut response = (status, page).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    with_setup_headers(response)
}

fn query_token(req: &Request) -> Option<String> {
    let query = req.uri().query()?;
    serde_urlencoded::from_str::<Vec<(String, String)>>(query)
        .ok()?
        .into_iter()
        .find(|(name, _)| name == "token")
        .map(|(_, value)| value)
}

fn cookie_header(req: &Request) -> Option<String> {
    req.headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Whether the setup page is served over HTTPS (so cookies get `Secure`).
fn setup_uses_https(state: &AppState) -> bool {
    let runtime = state.runtime();
    runtime.config.tls.enabled
        || (runtime.config.behind_trusted_proxy
            && runtime.config.public_url.to_lowercase().starts_with("https://"))
}

pub async fn get_setup(State(state): State<Arc<AppState>>, req: Request) -> Response {
    if !state.runtime().setup_required {
        return text(StatusCode::NOT_FOUND, "Setup is no longer available.");
    }
    let secure = setup_uses_https(&state);
    let cookies = cookie_header(&req);
    let has_access_cookie = constant_time_eq(
        parse_cookies(cookies.as_deref())
            .get(SETUP_ACCESS_COOKIE)
            .map(String::as_str)
            .unwrap_or_default(),
        &state.setup_access_token,
    );
    let token = query_token(&req);
    if !setup_access_granted(cookies.as_deref(), token.as_deref(), &state.setup_access_token) {
        return text(
            StatusCode::FORBIDDEN,
            "A valid one-time setup URL is required. Check the proxy console.",
        );
    }
    if !has_access_cookie {
        // First visit through the one-time URL: swap the token for a cookie
        // and drop it from the address bar.
        let mut response = redirect(StatusCode::SEE_OTHER, "/setup");
        append_cookie(
            response.headers_mut(),
            setup_cookie(SETUP_ACCESS_COOKIE, &state.setup_access_token, secure),
        );
        return with_setup_headers(response);
    }
    let mut response = html(
        StatusCode::OK,
        setup_page(&state.setup_csrf_token, "", "", &SetupValues::default()),
    );
    append_cookie(
        response.headers_mut(),
        setup_cookie(SETUP_CSRF_COOKIE, &state.setup_csrf_token, secure),
    );
    response
}

/// Clears `setup_in_progress` when the handler ends, however it ends
/// (`finally { setupInProgress = false }`).
struct InProgress<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for InProgress<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

pub async fn post_setup(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let peer: IpAddr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let forwarded = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let cookies = cookie_header(&req);
    let is_form = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_lowercase().starts_with("application/x-www-form-urlencoded"));

    // The urlencoded body parser runs before the route (and before the rate
    // limiter) in the original; an oversized body is a 400 "Invalid request".
    let bytes = match to_bytes(req.into_body(), MAX_FORM_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!("❌ Request error: {error}");
            return ProxyError::invalid_request().into_response();
        }
    };
    let form: HashMap<String, String> = if is_form {
        serde_urlencoded::from_bytes(&bytes).unwrap_or_default()
    } else {
        HashMap::new()
    };

    // `setupRateLimiter`: 10 requests / window per client IP.
    let ip = client_ip(peer, forwarded.as_deref(), state.trust_proxy_hops());
    if let Err(limited) = state.setup_rate_limiter.check("default", &ip) {
        let mut response = json_response(
            StatusCode::TOO_MANY_REQUESTS,
            &json!({
                "error": "Too many proxy requests for default",
                "code": "PROXY_RATE_LIMITED",
                "route": limited.bucket,
                "retry_after": limited.retry_after_seconds,
            }),
        );
        if let Ok(value) = HeaderValue::from_str(&limited.retry_after_seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }

    if !state.runtime().setup_required {
        return text(StatusCode::NOT_FOUND, "Setup is no longer available.");
    }
    let jar = parse_cookies(cookies.as_deref());
    let cookie = |name: &str| jar.get(name).map(String::as_str).unwrap_or_default();
    if !constant_time_eq(cookie(SETUP_ACCESS_COOKIE), &state.setup_access_token) {
        return text(
            StatusCode::FORBIDDEN,
            "The setup access token is invalid. Use the URL shown in the proxy console.",
        );
    }
    let submitted_csrf = form.get("csrfToken").map(String::as_str).unwrap_or_default();
    if !constant_time_eq(cookie(SETUP_CSRF_COOKIE), &state.setup_csrf_token)
        || !constant_time_eq(submitted_csrf, &state.setup_csrf_token)
    {
        return text(
            StatusCode::FORBIDDEN,
            "The setup session is invalid. Reload the page and try again.",
        );
    }

    let csrf = state.setup_csrf_token.clone();
    let values = SetupValues {
        deployment_mode: form.get("deploymentMode").cloned(),
        public_url: form.get("publicUrl").cloned(),
    };
    let page = |status: StatusCode, error: &str, values: &SetupValues| {
        html(status, setup_page(&csrf, error, "", values))
    };

    if state.setup_in_progress.swap(true, Ordering::SeqCst) {
        return page(
            StatusCode::CONFLICT,
            "Setup is already in progress. Please try again in a few seconds.",
            &SetupValues::default(),
        );
    }
    let _in_progress = InProgress(&state.setup_in_progress);

    let api_key = js_trim(form.get("deeplApiKey").map(String::as_str).unwrap_or_default()).to_owned();
    if api_key.is_empty() || js_len(&api_key) > 500 {
        return page(StatusCode::BAD_REQUEST, "Enter a valid DeepL API key.", &SetupValues::default());
    }

    // Verify the key with DeepL before storing anything.
    let verification = match state.deepl.client(&api_key) {
        Ok(client) => client.get_usage().await.map(|_| ()),
        Err(error) => Err(error),
    };
    if let Err(error) = verification {
        let rejected = matches!(error, DeepLError::Authorization(_));
        tracing::error!("❌ Setup key verification failed: {}", error.message());
        return page(
            if rejected { StatusCode::UNAUTHORIZED } else { StatusCode::BAD_GATEWAY },
            if rejected {
                "This DeepL API key was rejected."
            } else {
                "The key could not be verified with DeepL. Check your connection and try again."
            },
            &values,
        );
    }

    // Persist (file I/O and, on Windows, `icacls`) off the async threads.
    let setup_form = SetupForm {
        deployment_mode: values.deployment_mode.clone(),
        public_url: values.public_url.clone(),
    };
    let outcome = {
        let state = Arc::clone(&state);
        tokio::task::spawn_blocking(move || {
            let mut runtime = state.runtime_mut();
            complete_web_setup(&mut runtime, &api_key, &setup_form)?;
            Ok::<_, crate::config::ConfigError>((
                connection_string(&runtime),
                runtime.config.trust_proxy_hops,
            ))
        })
        .await
    };
    let (connection, hops) = match outcome {
        Ok(Ok(done)) => done,
        Ok(Err(error)) => return page(StatusCode::BAD_REQUEST, &error.0, &values),
        Err(error) => {
            tracing::error!("❌ Setup task failed: {error}");
            return page(StatusCode::BAD_REQUEST, "Setup failed. Check the proxy console.", &values);
        }
    };

    // `app.set("trust proxy", hops || false)`
    state.set_trust_proxy_hops(hops);
    println!("✅ Web setup completed");
    println!("Connection string to copy into Foundry VTT:");
    println!("{connection}");

    let mut response = html(StatusCode::OK, setup_page("", "", &connection, &SetupValues::default()));
    append_cookie(response.headers_mut(), expired_setup_cookie(SETUP_ACCESS_COOKIE));
    append_cookie(response.headers_mut(), expired_setup_cookie(SETUP_CSRF_COOKIE));
    response
}
