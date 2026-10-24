//! HTTP route handlers.
//!
//! Port of the route section of `server.js`:
//!
//! | Express                         | handler here                |
//! |---------------------------------|-----------------------------|
//! | `POST /translate`               | [`translate`]               |
//! | `GET /usage`                    | [`usage`]                   |
//! | `GET /health`                   | [`health`]                  |
//! | `GET /identity`                 | [`identity`]                |
//! | `GET/POST /glossaries`          | [`list_glossaries`], [`create_glossary`] |
//! | `PUT/DELETE /glossaries/:id`    | [`update_glossary`], [`delete_glossary`] |
//! | `GET /glossary-language-pairs`  | [`glossary_language_pairs`] |
//! | `GET /languages`                | [`languages`]               |
//!
//! Error handling follows the original's two styles: validation failures are
//! explicit `{"error": ...}` replies ([`ProxyError::bad_request`]); anything
//! raised by the DeepL layer goes through
//! [`service_error_response`](crate::error::service_error_response) with the
//! service label the original passed to `deepLServiceError`.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::{Extension, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::{json, Value};

use crate::config::is_loopback_host;
use crate::deepl::{is_free_account_key, DeepLError, TranslateOptions};
use crate::error::{json_response, ProxyError};
use crate::glossary::{
    has_dictionary_fields, normalize_formality, parse_dictionaries, serialize_glossary,
    serialize_language, validate_glossary_name,
};
use crate::middleware::{gate, AuthContext};
use crate::setup_routes;
use crate::state::{AppState, MAX_TEXTS, MAX_TOTAL_CHARS};
use crate::util::{escape_html, js_len, js_trim, js_truthy, sha256_hex};

/// Body size limit of the JSON parser (`express.json({ limit: "10mb" })`).
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
/// Time allowed to receive a request body (`server.requestTimeout`, 120 s).
const BODY_TIMEOUT: Duration = Duration::from_secs(120);

/// Builds the complete application (routes + the request pipeline).
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/setup", get(setup_routes::get_setup).post(setup_routes::post_setup))
        .route("/translate", post(translate))
        .route("/usage", get(usage))
        .route("/health", get(health))
        .route("/identity", get(identity))
        .route("/glossaries", get(list_glossaries).post(create_glossary))
        .route("/glossaries/{id}", put(update_glossary).delete(delete_glossary))
        .route("/glossary-language-pairs", get(glossary_language_pairs))
        .route("/languages", get(languages))
        .fallback(not_found)
        .layer(from_fn_with_state(state.clone(), gate))
        .with_state(state)
}

/// Express' default 404 page (`Cannot GET /path`).
async fn not_found(req: Request) -> Response {
    let body = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot {} {}</pre>\n</body>\n</html>\n",
        escape_html(req.method().as_str()),
        escape_html(req.uri().path())
    );
    let mut response = (StatusCode::NOT_FOUND, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

// ---------------------------------------------------------------------------
// request helpers
// ---------------------------------------------------------------------------

/// `application/json` or any `+json` media type (what body-parser accepts).
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let media_type = value.split(';').next().unwrap_or_default().trim().to_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

/// `express.json({ limit: "10mb" })` + the failure modes of the handlers.
///
/// * Not a JSON content type: Express leaves `req.body` undefined and the
///   handler's destructuring throws a `TypeError` -> `400 INVALID_REQUEST`.
/// * Empty body: `{}`.
/// * Malformed JSON, a top-level scalar (body-parser is strict), or a body
///   over 10 MB: the global error handler answers `400 {"error":"Invalid
///   request"}`.
async fn read_json(req: Request, service: &'static str) -> Result<Value, ProxyError> {
    let (parts, body) = req.into_parts();
    let bytes = match tokio::time::timeout(BODY_TIMEOUT, to_bytes(body, MAX_BODY_BYTES)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            tracing::error!("❌ Request error: {error}");
            return Err(ProxyError::invalid_request());
        }
        Err(_) => return Err(ProxyError::message(StatusCode::REQUEST_TIMEOUT, "Request timeout")),
    };
    if !is_json_content_type(&parts.headers) {
        return Err(ProxyError::Service(
            DeepLError::Invalid("Request body must be application/json".to_owned()),
            service,
        ));
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = js_trim(&text);
    if trimmed.is_empty() {
        return Ok(json!({}));
    }
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        tracing::error!("❌ Request error: body is not a JSON object or array");
        return Err(ProxyError::invalid_request());
    }
    serde_json::from_str(trimmed).map_err(|error| {
        tracing::error!("❌ Request error: {error}");
        ProxyError::invalid_request()
    })
}

/// Maps a DeepL-layer error to a [`ProxyError`] carrying the service label.
fn service(label: &'static str) -> impl Fn(DeepLError) -> ProxyError {
    move |error| ProxyError::Service(error, label)
}

fn account_type(api_key: &str) -> &'static str {
    if is_free_account_key(api_key) {
        "free"
    } else {
        "pro"
    }
}

/// Cache key: `tenant::keyScope::source::glossary::formality::target::sha256`.
///
/// Every dimension that changes the translation result (or who may see it) is
/// part of the key, which is what isolates tenants and DeepL keys from each
/// other.
fn cache_key(
    tenant_id: &str,
    key_scope: &str,
    source_lang: Option<&str>,
    glossary_id: Option<&str>,
    formality: &str,
    target_lang: &str,
    text: &str,
) -> String {
    format!(
        "{tenant_id}::{key_scope}::{}::{}::{formality}::{target_lang}::{}",
        source_lang.unwrap_or("auto"),
        glossary_id.unwrap_or("none"),
        sha256_hex(text),
    )
}

// ---------------------------------------------------------------------------
// POST /translate
// ---------------------------------------------------------------------------

pub async fn translate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    req: Request,
) -> Result<Response, ProxyError> {
    const LABEL: &str = "Translation";
    let body = read_json(req, LABEL).await?;

    let texts = match body.get("texts").and_then(Value::as_array) {
        Some(texts) if !texts.is_empty() => texts,
        _ => return Err(ProxyError::bad_request("Invalid texts")),
    };
    let mut strings: Vec<&str> = Vec::with_capacity(texts.len());
    for text in texts {
        match text.as_str() {
            Some(text) => strings.push(text),
            None => return Err(ProxyError::bad_request("Every text must be a string")),
        }
    }
    let Some(target_lang) = body.get("target_lang").and_then(Value::as_str) else {
        return Err(ProxyError::bad_request("Invalid target_lang"));
    };
    if body.get("source_lang").is_some_and(|value| !value.is_string()) {
        return Err(ProxyError::bad_request("Invalid source_lang"));
    }
    if let Some(glossary) = body.get("glossary_id") {
        if !glossary.as_str().is_some_and(|text| !js_trim(text).is_empty()) {
            return Err(ProxyError::bad_request("Invalid glossary_id"));
        }
    }
    // `source_lang || null`: an empty string means "auto-detect".
    let source_lang = body
        .get("source_lang")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty());
    let glossary_id = body.get("glossary_id").and_then(Value::as_str);
    if glossary_id.is_some() && source_lang.is_none() {
        return Err(ProxyError::bad_request("source_lang is required with glossary_id"));
    }
    let formality = normalize_formality(body.get("formality")).map_err(service(LABEL))?;

    if strings.len() > MAX_TEXTS {
        return Err(ProxyError::bad_request("Too many texts"));
    }
    // JavaScript `.length` semantics (UTF-16 code units), like the original.
    let total_chars: usize = strings.iter().map(|text| js_len(text)).sum();
    if total_chars > MAX_TOTAL_CHARS {
        return Err(ProxyError::bad_request("Payload too large"));
    }

    let client = state.deepl.client(&auth.deepl_api_key).map_err(service(LABEL))?;
    let key_scope: String = sha256_hex(&auth.deepl_api_key).chars().take(16).collect();
    let key_for = |text: &str| {
        cache_key(
            &auth.tenant_id,
            &key_scope,
            source_lang,
            glossary_id,
            &formality,
            target_lang,
            text,
        )
    };

    // 1. Serve what is already cached.
    let mut results: Vec<Option<String>> = vec![None; strings.len()];
    let mut pending_indexes: Vec<usize> = Vec::new();
    let mut pending_texts: Vec<String> = Vec::new();
    for (index, text) in strings.iter().enumerate() {
        match state.cache.get(&key_for(text)) {
            Some(cached) => results[index] = Some(cached),
            None => {
                pending_indexes.push(index);
                pending_texts.push((*text).to_owned());
            }
        }
    }

    // 2. Translate the rest in one upstream call (bounded concurrency).
    if !pending_texts.is_empty() {
        let Some(_permit) = state.try_acquire_translation() else {
            return Err(ProxyError::message(
                StatusCode::SERVICE_UNAVAILABLE,
                "Translation service is busy",
            ));
        };
        let translated = client
            .translate_text(
                &pending_texts,
                &TranslateOptions {
                    source_lang,
                    target_lang,
                    formality: &formality,
                    glossary_id,
                },
            )
            .await
            .map_err(service(LABEL))?;
        for (position, translation) in translated.into_iter().enumerate() {
            let index = pending_indexes[position];
            state.cache.insert(key_for(strings[index]), translation.clone());
            results[index] = Some(translation);
        }
    }

    let translations: Vec<Value> = results
        .into_iter()
        .map(|text| json!({ "text": text }))
        .collect();
    Ok(json_response(StatusCode::OK, &json!({ "translations": translations })))
}

// ---------------------------------------------------------------------------
// GET /usage, /health, /identity
// ---------------------------------------------------------------------------

pub async fn usage(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Response, ProxyError> {
    let client = state.deepl.client(&auth.deepl_api_key).map_err(service("Usage"))?;
    let usage = client.get_usage().await.map_err(service("Usage"))?;
    // `usage.character?.count || 0`
    let or_zero = |value: Option<Value>| match value {
        Some(value) if js_truthy(Some(&value)) => value,
        _ => json!(0),
    };
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "character_count": or_zero(usage.character_count),
            "character_limit": or_zero(usage.character_limit),
            "account_type": account_type(&auth.deepl_api_key),
        }),
    ))
}

pub async fn health(State(state): State<Arc<AppState>>) -> Response {
    let runtime = state.runtime();
    let status = if runtime.setup_required { "setup_required" } else { "ok" };
    // /health is unauthenticated: only a purely local proxy reports its
    // configuration; an exposed one answers with the bare minimum.
    let local_only = runtime.config.deployment_mode == crate::config::DeploymentMode::Local
        && is_loopback_host(&runtime.config.host);
    if !local_only {
        let body = json!({ "status": status, "tls": runtime.config.tls.enabled });
        drop(runtime);
        return json_response(StatusCode::OK, &body);
    }
    let body = json!({
        "status": status,
        "cache_size": state.cache.len(),
        "tls": runtime.config.tls.enabled,
        "deployment_mode": runtime.config.deployment_mode.as_str(),
        "public_url": if runtime.config.public_url.is_empty() {
            Value::Null
        } else {
            json!(runtime.config.public_url)
        },
        "loopback_only": is_loopback_host(&runtime.config.host),
    });
    drop(runtime);
    json_response(StatusCode::OK, &body)
}

pub async fn identity(Extension(auth): Extension<AuthContext>) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "account_id": auth.tenant_id,
            "account_type": account_type(&auth.deepl_api_key),
        }),
    )
}

// ---------------------------------------------------------------------------
// glossaries
// ---------------------------------------------------------------------------

const GLOSSARY: &str = "Glossary";

pub async fn list_glossaries(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Response, ProxyError> {
    let client = state.deepl.client(&auth.deepl_api_key).map_err(service(GLOSSARY))?;
    let glossaries = client.list_multilingual_glossaries().await.map_err(service(GLOSSARY))?;
    Ok(json_response(
        StatusCode::OK,
        &json!({ "glossaries": glossaries.iter().map(serialize_glossary).collect::<Vec<_>>() }),
    ))
}

pub async fn create_glossary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    req: Request,
) -> Result<Response, ProxyError> {
    let client = state.deepl.client(&auth.deepl_api_key).map_err(service(GLOSSARY))?;
    let body = read_json(req, GLOSSARY).await?;
    let name = validate_glossary_name(body.get("name"), "Glossary name is required")
        .map_err(ProxyError::bad_request)?;
    let object = body.as_object().cloned().unwrap_or_default();
    let dictionaries = parse_dictionaries(&object).map_err(service(GLOSSARY))?;
    let glossary = client
        .create_multilingual_glossary(&name, &dictionaries)
        .await
        .map_err(service(GLOSSARY))?;
    Ok(json_response(StatusCode::CREATED, &serialize_glossary(&glossary)))
}

pub async fn update_glossary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, ProxyError> {
    let client = state.deepl.client(&auth.deepl_api_key).map_err(service(GLOSSARY))?;
    let body = read_json(req, GLOSSARY).await?;
    let object = body.as_object().cloned().unwrap_or_default();

    // Validate *everything* before the first call to DeepL. (The original
    // renames the glossary first and only then validates the dictionaries, so
    // a bad dictionary left the rename applied; the HTTP responses are the same.)
    let new_name = match object.get("name") {
        None => None,
        Some(value) => Some(
            validate_glossary_name(Some(value), "Invalid glossary name")
                .map_err(ProxyError::bad_request)?,
        ),
    };
    let dictionaries = if has_dictionary_fields(&object) {
        Some(parse_dictionaries(&object).map_err(service(GLOSSARY))?)
    } else {
        None
    };
    if new_name.is_none() && dictionaries.is_none() {
        return Err(ProxyError::bad_request("No glossary changes supplied"));
    }

    if let Some(name) = &new_name {
        client
            .update_multilingual_glossary_name(&id, name)
            .await
            .map_err(service(GLOSSARY))?;
    }
    for dictionary in dictionaries.iter().flatten() {
        client
            .replace_multilingual_glossary_dictionary(&id, dictionary)
            .await
            .map_err(service(GLOSSARY))?;
    }
    let glossary = client.get_multilingual_glossary(&id).await.map_err(service(GLOSSARY))?;
    Ok(json_response(StatusCode::OK, &serialize_glossary(&glossary)))
}

pub async fn delete_glossary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Response, ProxyError> {
    let client = state.deepl.client(&auth.deepl_api_key).map_err(service(GLOSSARY))?;
    client.delete_multilingual_glossary(&id).await.map_err(service(GLOSSARY))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn glossary_language_pairs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Response, ProxyError> {
    const LABEL: &str = "Glossary languages";
    let client = state.deepl.client(&auth.deepl_api_key).map_err(service(LABEL))?;
    let pairs = client.get_glossary_language_pairs().await.map_err(service(LABEL))?;
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "language_pairs": pairs
                .into_iter()
                .map(|(source, target)| json!({ "source_lang": source, "target_lang": target }))
                .collect::<Vec<_>>()
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET /languages?type=source|target
// ---------------------------------------------------------------------------

/// The values of the `type` query parameter (several `type=` parameters make
/// Express' query parser return an array, which fails the equality checks).
fn query_type(uri: &Uri) -> Vec<String> {
    uri.query()
        .map(|query| {
            serde_urlencoded::from_str::<Vec<(String, String)>>(query)
                .unwrap_or_default()
                .into_iter()
                .filter(|(name, _)| name == "type")
                .map(|(_, value)| value)
                .collect()
        })
        .unwrap_or_default()
}

pub async fn languages(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    req: Request,
) -> Result<Response, ProxyError> {
    const LABEL: &str = "Languages";
    let client = state.deepl.client(&auth.deepl_api_key).map_err(service(LABEL))?;
    let types = query_type(req.uri());
    let languages = match types.as_slice() {
        [kind] if kind == "source" => client.get_source_languages().await,
        [kind] if kind == "target" => client.get_target_languages().await,
        _ => return Err(ProxyError::bad_request("type must be source or target")),
    }
    .map_err(service(LABEL))?;
    Ok(json_response(
        StatusCode::OK,
        &json!({ "languages": languages.iter().map(serialize_language).collect::<Vec<_>>() }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of "keeps semantically distinct HTML whitespace out of the same
    /// cache entry".
    #[test]
    fn keeps_distinct_html_whitespace_out_of_the_same_cache_entry() {
        let key = |text: &str| cache_key("t", "s", None, None, "default", "FR", text);
        assert_ne!(key("<pre>one  two</pre>"), key("<pre>one two</pre>"));
        assert_eq!(key("<p>Hello</p>"), key("<p>Hello</p>"));
    }

    #[test]
    fn cache_keys_isolate_tenants_languages_glossaries_and_formality() {
        let base = cache_key("a", "k", None, None, "default", "FR", "Hi");
        assert_ne!(base, cache_key("b", "k", None, None, "default", "FR", "Hi"));
        assert_ne!(base, cache_key("a", "other-key", None, None, "default", "FR", "Hi"));
        assert_ne!(base, cache_key("a", "k", Some("EN"), None, "default", "FR", "Hi"));
        assert_ne!(base, cache_key("a", "k", None, Some("g1"), "default", "FR", "Hi"));
        assert_ne!(base, cache_key("a", "k", None, None, "more", "FR", "Hi"));
        assert_ne!(base, cache_key("a", "k", None, None, "default", "DE", "Hi"));
        assert!(base.starts_with("a::k::auto::none::default::FR::"));
    }

    #[test]
    fn recognises_json_content_types() {
        let mut headers = HeaderMap::new();
        assert!(!is_json_content_type(&headers));
        headers.insert(header::CONTENT_TYPE, "application/json; charset=utf-8".parse().unwrap());
        assert!(is_json_content_type(&headers));
        headers.insert(header::CONTENT_TYPE, "application/vnd.api+json".parse().unwrap());
        assert!(is_json_content_type(&headers));
        headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert!(!is_json_content_type(&headers));
    }

    #[test]
    fn parses_the_languages_type_parameter() {
        let uri = |text: &str| text.parse::<Uri>().unwrap();
        assert_eq!(query_type(&uri("/languages?type=source")), vec!["source"]);
        assert_eq!(query_type(&uri("/languages")), Vec::<String>::new());
        assert_eq!(query_type(&uri("/languages?type=source&type=target")).len(), 2);
    }
}
