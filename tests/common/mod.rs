//! Test harness: a fake DeepL server plus a real proxy bound to a random local
//! port, so the tests exercise the complete HTTP pipeline (hyper, middleware
//! chain, routes, DeepL client, retries) without touching the internet.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use dt_proxy_server::config::{Config, Runtime, Secrets};
use dt_proxy_server::deepl::{DeepLFactory, RetryPolicy};
use dt_proxy_server::routes::build_router;
use dt_proxy_server::server::{install_crypto_provider, serve};
use dt_proxy_server::state::AppState;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

pub const TOKEN: &str = "dt_test_token";
pub const ORIGIN: &str = "http://localhost:30000";
pub const DEEPL_KEY: &str = "test-key:fx";

/// One request received by the fake DeepL server.
#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    /// Path and query, e.g. `/v2/languages?type=target`.
    pub target: String,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    pub form: Vec<(String, String)>,
}

impl Call {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.form.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    pub fn fields(&self, name: &str) -> Vec<&str> {
        self.form
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

#[derive(Clone, Default)]
pub struct Mock {
    calls: Arc<Mutex<Vec<Call>>>,
    forced: Arc<Mutex<VecDeque<u16>>>,
    delay: Arc<Mutex<Duration>>,
}

impl Mock {
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    /// The next `statuses.len()` requests fail with these statuses.
    pub fn force_statuses(&self, statuses: &[u16]) {
        self.forced.lock().unwrap().extend(statuses.iter().copied());
    }

    pub fn set_delay(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }

    pub fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
}

fn glossary_json(id: &str, name: &str, dictionaries: Vec<Value>) -> Value {
    json!({
        "glossary_id": id,
        "name": name,
        "dictionaries": dictionaries,
        "creation_time": "2021-08-03T14:16:18.329Z"
    })
}

fn json_reply(status: u16, body: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn mock_handler(State(mock): State<Mock>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 32 * 1024 * 1024).await.unwrap();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let form: Vec<(String, String)> = if content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"))
    {
        serde_urlencoded::from_bytes(&bytes).unwrap_or_default()
    } else {
        Vec::new()
    };
    let target = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_default();
    let call = Call {
        method: parts.method.to_string(),
        target: target.clone(),
        authorization: parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        content_type,
        form,
    };
    mock.calls.lock().unwrap().push(call.clone());

    let delay = *mock.delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    if let Some(status) = mock.forced.lock().unwrap().pop_front() {
        return json_reply(status, json!({ "message": "forced failure", "detail": "from the test" }));
    }

    let path = parts.uri.path().to_owned();
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (call.method.as_str(), segments.as_slice()) {
        ("POST", ["v2", "translate"]) => {
            let target_lang = call.field("target_lang").unwrap_or("??").to_owned();
            let translations: Vec<Value> = call
                .fields("text")
                .into_iter()
                .map(|text| {
                    json!({
                        "detected_source_language": "EN",
                        "text": format!("[{target_lang}] {text}"),
                        "billed_characters": text.chars().count(),
                    })
                })
                .collect();
            json_reply(200, json!({ "translations": translations }))
        }
        ("GET", ["v2", "usage"]) => {
            json_reply(200, json!({ "character_count": 123, "character_limit": 500000 }))
        }
        ("GET", ["v2", "languages"]) => {
            if target.contains("type=target") {
                json_reply(
                    200,
                    json!([
                        {"language": "EN-US", "name": "English (American)", "supports_formality": false},
                        {"language": "FR", "name": "French", "supports_formality": true}
                    ]),
                )
            } else {
                json_reply(200, json!([{"language": "EN", "name": "English"}, {"language": "FR", "name": "French"}]))
            }
        }
        ("GET", ["v2", "glossary-language-pairs"]) => json_reply(
            200,
            json!({ "supported_languages": [{"source_lang": "en", "target_lang": "fr"}] }),
        ),
        ("GET", ["v3", "glossaries"]) => json_reply(
            200,
            json!({ "glossaries": [glossary_json("g-1", "D&D", vec![
                json!({"source_lang": "en", "target_lang": "fr", "entry_count": 2})
            ])] }),
        ),
        ("POST", ["v3", "glossaries"]) => {
            let name = call.field("name").unwrap_or_default().to_owned();
            let mut dictionaries = Vec::new();
            let mut index = 0;
            while let Some(source) = call.field(&format!("dictionaries[{index}].source_lang")) {
                let entries = call.field(&format!("dictionaries[{index}].entries")).unwrap_or_default();
                dictionaries.push(json!({
                    "source_lang": source.to_lowercase(),
                    "target_lang": call.field(&format!("dictionaries[{index}].target_lang")).unwrap_or_default().to_lowercase(),
                    "entry_count": entries.lines().count(),
                }));
                index += 1;
            }
            json_reply(201, glossary_json("g-new", &name, dictionaries))
        }
        ("GET", ["v3", "glossaries", id]) | ("PATCH", ["v3", "glossaries", id]) => {
            if *id == "missing" {
                return json_reply(404, json!({ "message": "Glossary not found" }));
            }
            let name = call.field("name").unwrap_or("Existing").to_owned();
            json_reply(
                200,
                glossary_json(id, &name, vec![json!({"source_lang": "en", "target_lang": "fr", "entry_count": 1})]),
            )
        }
        ("PUT", ["v3", "glossaries", id, "dictionaries"]) => {
            if *id == "missing" {
                return json_reply(404, json!({ "message": "Glossary not found" }));
            }
            json_reply(200, json!({ "source_lang": "en", "target_lang": "fr", "entry_count": 1 }))
        }
        ("DELETE", ["v3", "glossaries", id]) => {
            if *id == "missing" {
                json_reply(404, json!({ "message": "Glossary not found" }))
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        _ => json_reply(404, json!({ "message": "unknown mock route" })),
    }
}

async fn start_mock() -> (SocketAddr, Mock) {
    let mock = Mock::default();
    let app = Router::new().fallback(mock_handler).with_state(mock.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, mock)
}

/// Keeps the process-wide proxy settings from sending loopback traffic to the
/// sandbox's outbound proxy.
fn prepare_environment() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
        std::env::set_var("no_proxy", "127.0.0.1,localhost");
        install_crypto_provider();
    });
}

/// Fast retries so failure-path tests do not sleep for seconds.
pub fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        max_retries: 5,
        min_timeout: Duration::from_secs(3),
        backoff_initial: Duration::from_millis(1),
        backoff_max: Duration::from_millis(5),
    }
}

pub struct Harness {
    pub base: String,
    pub mock: Mock,
    pub state: Arc<AppState>,
    pub dir: tempfile::TempDir,
    pub client: reqwest::Client,
    pub address: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

pub struct Options {
    pub configure: Box<dyn FnOnce(&mut Runtime)>,
    pub retry: RetryPolicy,
    pub tls: Option<(PathBuf, PathBuf)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            configure: Box::new(|_| {}),
            retry: fast_retry(),
            tls: None,
        }
    }
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn with_config(configure: impl FnOnce(&mut Config) + 'static) -> Self {
        Self::start_with(Options {
            configure: Box::new(move |runtime| configure(&mut runtime.config)),
            ..Options::default()
        })
        .await
    }

    pub async fn with_runtime(configure: impl FnOnce(&mut Runtime) + 'static) -> Self {
        Self::start_with(Options {
            configure: Box::new(configure),
            ..Options::default()
        })
        .await
    }

    pub async fn start_with(options: Options) -> Self {
        prepare_environment();
        let (mock_address, mock) = start_mock().await;
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let mut runtime = Runtime {
            config: Config { port: address.port(), ..Config::default() },
            secrets: Secrets {
                deepl_api_key: DEEPL_KEY.to_owned(),
                access_token: TOKEN.to_owned(),
                account_id: "account_test".to_owned(),
                deepl_key_fingerprint: None,
            },
            config_path: dir.path().join("config.json"),
            secrets_path: dir.path().join("secrets.json"),
            setup_required: false,
            deepl_key_from_env: false,
            token_from_env: false,
        };
        (options.configure)(&mut runtime);

        let tls: Option<TlsAcceptor> = options
            .tls
            .as_ref()
            .map(|(certificate, key)| dt_proxy_server::server::load_tls_acceptor(certificate, key).unwrap());
        let https = tls.is_some();

        let factory = DeepLFactory::new(Some(format!("http://{mock_address}")), options.retry);
        let state = AppState::new(runtime, factory);
        state.spawn_background_tasks();
        let router = build_router(state.clone());
        let (shutdown, stop) = oneshot::channel::<()>();
        tokio::spawn(serve(listener, router, tls, async move {
            let _ = stop.await;
        }));

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        Self {
            base: format!("{}://localhost:{}", if https { "https" } else { "http" }, address.port()),
            mock,
            state,
            dir,
            client,
            address,
            _shutdown: shutdown,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// An authenticated request as Foundry VTT would send it.
    pub fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.url(path))
            .header("Origin", ORIGIN)
            .header("Authorization", format!("Bearer {TOKEN}"))
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }

    /// A request carrying no credentials at all.
    pub fn bare(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client.request(method, self.url(path))
    }

    pub async fn translate(&self, body: Value) -> (u16, Value) {
        let (status, _, value) = read(self.post("/translate").json(&body).send().await.unwrap()).await;
        (status, value)
    }
}

/// Status, headers and (JSON or plain-text) body of a response.
pub async fn read(response: reqwest::Response) -> (u16, reqwest::header::HeaderMap, Value) {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response.text().await.unwrap();
    let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, headers, value)
}
