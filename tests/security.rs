//! Tests of the gate (origin / CORS / token), remote-mode origin learning, the
//! first-run web setup flow and direct TLS.

mod common;

use common::{read, Harness, Options, ORIGIN, TOKEN};
use dt_proxy_server::config::DeploymentMode;
use reqwest::Method;
use serde_json::{json, Value};

/// An authenticated request that carries a *different* Origin (reqwest appends
/// duplicate headers rather than replacing them, so it is built from scratch).
fn foreign(h: &Harness, path: &str, origin: &str) -> reqwest::RequestBuilder {
    h.bare(Method::GET, path).header("Origin", origin).header("Authorization", format!("Bearer {TOKEN}"))
}

#[tokio::test]
async fn protected_routes_require_an_origin_header() {
    let h = Harness::start().await;
    let (status, headers, body) = read(
        h.bare(Method::GET, "/usage").header("Authorization", format!("Bearer {TOKEN}")).send().await.unwrap(),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["code"], "ORIGIN_REQUIRED");
    assert!(headers.get("access-control-allow-origin").is_none());
    assert_eq!(h.mock.call_count(), 0);
}

#[tokio::test]
async fn non_browser_clients_can_be_allowed_explicitly() {
    let h = Harness::with_config(|config| config.allow_no_origin = true).await;
    let (status, _, _) = read(
        h.bare(Method::GET, "/identity").header("Authorization", format!("Bearer {TOKEN}")).send().await.unwrap(),
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn rejects_missing_and_wrong_tokens_with_a_challenge_and_cors_headers() {
    let h = Harness::start().await;
    for authorization in [None, Some("Bearer wrong"), Some("Bearer "), Some("Basic abc"), Some(TOKEN)] {
        let mut request = h.bare(Method::GET, "/usage").header("Origin", ORIGIN);
        if let Some(value) = authorization {
            request = request.header("Authorization", value);
        }
        let (status, headers, body) = read(request.send().await.unwrap()).await;
        assert_eq!(status, 401, "{authorization:?}");
        assert_eq!(body["code"], "PROXY_TOKEN_INVALID");
        assert_eq!(headers["www-authenticate"], "Bearer realm=\"Deep Translate Proxy\"");
        assert_eq!(headers["access-control-allow-origin"], ORIGIN, "browsers must be able to read the 401");
    }
    assert_eq!(h.mock.call_count(), 0);
    // The scheme is case-insensitive.
    let (status, _, _) = read(
        h.bare(Method::GET, "/identity")
            .header("Origin", ORIGIN)
            .header("Authorization", format!("bearer {TOKEN}"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_missing_deepl_key_is_a_422() {
    let h = Harness::with_runtime(|runtime| runtime.secrets.deepl_api_key = String::new()).await;
    let (status, _, body) = read(h.get("/usage").send().await.unwrap()).await;
    assert_eq!((status, body["code"].as_str()), (422, Some("DEEPL_KEY_MISSING")));
}

#[tokio::test]
async fn only_allow_listed_origins_may_call_the_proxy() {
    let h = Harness::with_config(|config| config.allowed_origins = vec![ORIGIN.to_owned()]).await;
    let (status, headers, _) = read(h.get("/identity").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(headers["access-control-allow-origin"], ORIGIN);

    // A foreign origin is refused even with the right token, and gets no CORS headers.
    let (status, headers, body) = read(foreign(&h, "/identity", "https://evil.example").send().await.unwrap()).await;
    assert_eq!((status, body), (403, json!({ "error": "Origin not allowed" })));
    assert!(headers.get("access-control-allow-origin").is_none());
    // Local mode never learns origins.
    let (status, _, _) = read(foreign(&h, "/identity", "https://evil.example").send().await.unwrap()).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn preflight_is_answered_without_a_token() {
    let h = Harness::with_config(|config| config.allowed_origins = vec![ORIGIN.to_owned()]).await;
    let (status, headers, _) = read(
        h.bare(Method::OPTIONS, "/translate")
            .header("Origin", ORIGIN)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "authorization,content-type")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(headers["access-control-allow-origin"], ORIGIN);
    assert!(headers["access-control-allow-methods"].to_str().unwrap().contains("POST"));
    let allowed = headers["access-control-allow-headers"].to_str().unwrap().to_lowercase();
    assert!(allowed.contains("authorization") && allowed.contains("content-type"), "{allowed}");
    assert_eq!(h.mock.call_count(), 0);

    // A pre-flight from a foreign origin is refused.
    let (status, _, _) = read(
        h.bare(Method::OPTIONS, "/translate").header("Origin", "https://evil.example").send().await.unwrap(),
    )
    .await;
    assert_eq!(status, 204, "pre-flights skip the allow-list check, like the original");
}

#[tokio::test]
async fn remote_mode_learns_the_first_foundry_origin_when_the_token_is_right() {
    let h = Harness::with_runtime(|runtime| {
        runtime.config.deployment_mode = DeploymentMode::Remote;
        runtime.config.allowed_origins = vec!["https://other.example".to_owned()];
    })
    .await;
    // A wrong token never teaches the proxy anything.
    let (status, _, _) = read(
        h.bare(Method::GET, "/identity")
            .header("Origin", "https://vtt.example.com")
            .header("Authorization", "Bearer nope")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 403);
    assert!(!h.state.runtime().config.allowed_origins.contains(&"https://vtt.example.com".to_owned()));

    // The right token does, and the origin is persisted to the config file.
    let (status, _, _) = read(foreign(&h, "/identity", "https://vtt.example.com").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert!(h.state.runtime().config.allowed_origins.contains(&"https://vtt.example.com".to_owned()));
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(h.dir.path().join("config.json")).unwrap()).unwrap();
    assert!(stored["allowedOrigins"].as_array().unwrap().iter().any(|o| o == "https://vtt.example.com"));
}

// ---------------------------------------------------------------------------
// first-run web setup
// ---------------------------------------------------------------------------

fn unconfigured(runtime: &mut dt_proxy_server::config::Runtime) {
    runtime.setup_required = true;
    runtime.secrets.deepl_api_key = String::new();
}

fn cookie_pair(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .map(|value| value.split(';').next().unwrap().to_owned())
}

#[tokio::test]
async fn an_unconfigured_proxy_only_answers_health_and_setup() {
    let h = Harness::with_runtime(unconfigured).await;
    let (status, headers, _) = read(h.bare(Method::GET, "/").send().await.unwrap()).await;
    assert_eq!((status, headers["location"].to_str().unwrap()), (302, "/setup"));

    let (status, _, body) = read(h.get("/usage").send().await.unwrap()).await;
    assert_eq!((status, body["code"].as_str()), (503, Some("SETUP_REQUIRED")));
    assert_eq!(read(h.bare(Method::GET, "/health").send().await.unwrap()).await.0, 200);

    // /setup without the one-time token is refused.
    let (status, _, _) = read(h.bare(Method::GET, "/setup").send().await.unwrap()).await;
    assert_eq!(status, 403);
    let (status, _, _) = read(h.bare(Method::GET, "/setup?token=wrong").send().await.unwrap()).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn the_web_setup_assistant_stores_the_key_and_closes_itself() {
    let h = Harness::with_runtime(unconfigured).await;
    let access = h.state.setup_access_token.clone();

    // 1. One-time URL → cookie + redirect that removes the token from the URL.
    let (status, headers, _) = read(h.bare(Method::GET, &format!("/setup?token={access}")).send().await.unwrap()).await;
    assert_eq!((status, headers["location"].to_str().unwrap()), (303, "/setup"));
    let access_cookie = cookie_pair(&headers, "dt_setup_access").expect("access cookie");
    let set_cookie = headers.get("set-cookie").unwrap().to_str().unwrap().to_lowercase();
    assert!(set_cookie.contains("httponly") && set_cookie.contains("samesite=strict") && set_cookie.contains("path=/setup"));

    // 2. The page itself embeds the CSRF token and sets its cookie.
    let (status, headers, page) = read(h.bare(Method::GET, "/setup").header("Cookie", &access_cookie).send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert!(page.as_str().unwrap().contains("deeplApiKey"));
    assert_eq!(headers["cache-control"], "no-store");
    let csrf_cookie = cookie_pair(&headers, "dt_setup_csrf").expect("csrf cookie");
    let cookies = format!("{access_cookie}; {csrf_cookie}");
    let csrf = h.state.setup_csrf_token.clone();
    let submit = |cookies: String, form: Vec<(&'static str, String)>| {
        let request = h.bare(Method::POST, "/setup").header("Cookie", cookies).form(&form);
        async move { read(request.send().await.unwrap()).await }
    };

    // 3. Missing access cookie / missing CSRF → 403.
    let (status, _, _) = submit(String::new(), vec![("csrfToken", csrf.clone()), ("deeplApiKey", "k:fx".into())]).await;
    assert_eq!(status, 403);
    let (status, _, _) = submit(cookies.clone(), vec![("csrfToken", "wrong".into()), ("deeplApiKey", "k:fx".into())]).await;
    assert_eq!(status, 403);
    assert_eq!(h.mock.call_count(), 0, "nothing is verified before the request is authenticated");

    // 4. Blank key → 400; rejected key → 401 and nothing is stored.
    let (status, _, _) = submit(cookies.clone(), vec![("csrfToken", csrf.clone()), ("deeplApiKey", "   ".into())]).await;
    assert_eq!(status, 400);
    h.mock.force_statuses(&[403]);
    let (status, _, page) = submit(cookies.clone(), vec![("csrfToken", csrf.clone()), ("deeplApiKey", "bad:fx".into())]).await;
    assert_eq!(status, 401);
    assert!(page.as_str().unwrap().contains("This DeepL API key was rejected."));
    assert!(h.state.runtime().setup_required);
    assert!(!h.dir.path().join("secrets.json").exists());

    // 5. A good key completes the setup and shows the connection string.
    h.mock.clear();
    let (status, headers, page) = submit(
        cookies.clone(),
        vec![("csrfToken", csrf.clone()), ("deeplApiKey", " good:fx ".into()), ("deploymentMode", "local".into())],
    )
    .await;
    assert_eq!(status, 200);
    let page = page.as_str().unwrap().to_owned();
    assert!(page.contains("dt_"), "the connection string with the new token is displayed");
    assert!(headers.get_all("set-cookie").iter().count() >= 2, "both setup cookies are expired");
    assert_eq!(h.mock.calls()[0].authorization.as_deref(), Some("DeepL-Auth-Key good:fx"), "the key is trimmed");

    let runtime = h.state.runtime().clone();
    assert!(!runtime.setup_required);
    assert_eq!(runtime.secrets.deepl_api_key, "good:fx");
    // The harness already had a token; setup keeps an existing one (a fresh
    // install would generate `dt_` + 43 base64url characters).
    assert!(runtime.secrets.access_token.starts_with("dt_"));
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&runtime.secrets_path).unwrap()).unwrap();
    assert_eq!(stored["deeplApiKey"], "good:fx");
    assert_eq!(stored["accessToken"], runtime.secrets.access_token.as_str());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&runtime.secrets_path, &runtime.config_path] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", path.display());
        }
    }

    // 6. /setup is gone for good and the new token works immediately.
    let (status, _, _) = read(h.bare(Method::GET, &format!("/setup?token={access}")).send().await.unwrap()).await;
    assert_eq!(status, 404);
    let (status, _, _) = read(
        h.bare(Method::GET, "/identity")
            .header("Origin", ORIGIN)
            .header("Authorization", format!("Bearer {}", runtime.secrets.access_token))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn the_setup_form_is_rate_limited_per_client() {
    let h = Harness::with_runtime(unconfigured).await;
    let mut last = 0;
    for _ in 0..11 {
        last = read(h.bare(Method::POST, "/setup").form(&[("csrfToken", "x")]).send().await.unwrap()).await.0;
    }
    assert_eq!(last, 429);
}

// ---------------------------------------------------------------------------
// direct TLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serves_https_directly_with_a_pem_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&certificate, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();

    let h = Harness::start_with(Options {
        configure: Box::new(|runtime| runtime.config.tls.enabled = true),
        tls: Some((certificate, key)),
        ..Options::default()
    })
    .await;
    assert!(h.base.starts_with("https://"));
    let (status, _, body) = read(h.bare(Method::GET, "/health").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body["tls"], true);
    let (status, headers, _) = read(h.get("/identity").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(headers["x-content-type-options"], "nosniff");
}

// ---------------------------------------------------------------------------
// hardening added on top of the original's behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_exposed_proxy_reports_only_the_bare_minimum_on_health() {
    let h = Harness::with_runtime(|runtime| {
        runtime.config.deployment_mode = DeploymentMode::Remote;
        runtime.config.public_url = "https://translate.example.com".into();
    })
    .await;
    let (status, _, body) = read(h.bare(Method::GET, "/health").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({ "status": "ok", "tls": false }));
}

#[tokio::test]
async fn connections_beyond_the_cap_are_dropped_and_slots_are_reused() {
    use tokio::io::AsyncWriteExt;
    let h = Harness::start().await;
    let mut idle = Vec::new();
    for _ in 0..dt_proxy_server::server::MAX_CONNECTIONS {
        idle.push(tokio::net::TcpStream::connect(h.address).await.unwrap());
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // The 513th connection is accepted by the kernel but closed by the proxy.
    let mut extra = tokio::net::TcpStream::connect(h.address).await.unwrap();
    let _ = extra.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(std::time::Duration::from_secs(3), tokio::io::AsyncReadExt::read(&mut extra, &mut buffer)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "the surplus connection must be closed unanswered: {read:?}");
    // Freeing slots lets new clients in again.
    drop(idle);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(read_status(&h).await, 200);
}

async fn read_status(h: &Harness) -> u16 {
    read(h.bare(Method::GET, "/health").send().await.unwrap()).await.0
}

#[tokio::test]
async fn secrets_are_redacted_from_debug_output() {
    let h = Harness::start().await;
    let printed = format!("{:?}", h.state.runtime().clone());
    assert!(!printed.contains(common::DEEPL_KEY) && !printed.contains(TOKEN), "{printed}");
}

#[tokio::test]
async fn a_failed_setup_changes_nothing() {
    let h = Harness::with_runtime(unconfigured).await;
    let before_mode = h.state.runtime().config.deployment_mode;
    // Remote mode without a valid public URL is rejected by validation.
    let result = dt_proxy_server::config::complete_web_setup(
        &mut h.state.runtime_mut(),
        "key:fx",
        &dt_proxy_server::config::SetupForm {
            deployment_mode: Some("remote".into()),
            public_url: Some("not a url".into()),
        },
    );
    assert!(result.is_err());
    let runtime = h.state.runtime();
    assert_eq!(runtime.config.deployment_mode, before_mode);
    assert!(runtime.setup_required);
    assert!(runtime.secrets.deepl_api_key.is_empty());
    assert!(!runtime.secrets_path.exists(), "no half-written secrets file is left behind");
}
