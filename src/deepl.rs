//! Minimal DeepL REST client.
//!
//! The original proxy delegates every upstream call to the official
//! `deepl-node` SDK (`new deepl.Translator(key)` / `new deepl.DeepLClient(key)`).
//! There is no Rust SDK from DeepL, so this module re-implements exactly the
//! subset of the SDK that the proxy uses, reproducing the SDK's *observable*
//! behaviour (read from `deepl-node@1.26.0`):
//!
//! | proxy feature            | DeepL endpoint                                   |
//! |--------------------------|--------------------------------------------------|
//! | `POST /translate`        | `POST /v2/translate` (form-encoded)              |
//! | `GET /usage`             | `GET /v2/usage`                                  |
//! | `GET /languages`         | `GET /v2/languages[?type=target]`                |
//! | `GET /glossary-language-pairs` | `GET /v2/glossary-language-pairs`          |
//! | glossaries (v3)          | `/v3/glossaries[/{id}[/dictionaries]]`           |
//!
//! SDK behaviour reproduced here:
//! * server selection by key suffix (`:fx` -> `api-free.deepl.com`);
//! * `Authorization: DeepL-Auth-Key <key>` header;
//! * retries with exponential back-off on HTTP 429 / 5xx and on timeouts
//!   (5 attempts, 5 s minimum per-attempt timeout, 1.6x growth, 23 % jitter);
//! * status-code -> error mapping (`checkStatusCode`);
//! * language-code normalisation (`standardizeLanguageCode`).

use std::time::{Duration, Instant};

use reqwest::{Client, Method};
use serde_json::Value;

use crate::util;

/// Base URL used for free-plan keys (the ones ending in `:fx`).
pub const FREE_API_URL: &str = "https://api-free.deepl.com";
/// Base URL used for paid-plan keys.
pub const PRO_API_URL: &str = "https://api.deepl.com";

/// Errors raised while preparing or performing a DeepL call.
///
/// This enum collapses the SDK's error class hierarchy (plus the `TypeError`s
/// thrown by the proxy's own validation code) into the cases that
/// `deepLServiceError` in `server.js` distinguishes when choosing an HTTP
/// status code. See [`crate::error::service_error_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeepLError {
    /// `TypeError` raised by the proxy or `deepl.ArgumentError` -> HTTP 400.
    Invalid(String),
    /// `deepl.GlossaryNotFoundError` -> HTTP 404.
    GlossaryNotFound(String),
    /// `deepl.AuthorizationError` (DeepL answered 403) -> HTTP 401.
    Authorization(String),
    /// `deepl.QuotaExceededError` (DeepL answered 456) -> HTTP 429.
    QuotaExceeded(String),
    /// `deepl.TooManyRequestsError` (DeepL answered 429) -> HTTP 429.
    TooManyRequests(String),
    /// Any other `deepl.DeepLError` / `ConnectionError` -> HTTP 502.
    Other(String),
}

impl DeepLError {
    /// The human readable message (what `err.message` is in JavaScript).
    pub fn message(&self) -> &str {
        match self {
            DeepLError::Invalid(m)
            | DeepLError::GlossaryNotFound(m)
            | DeepLError::Authorization(m)
            | DeepLError::QuotaExceeded(m)
            | DeepLError::TooManyRequests(m)
            | DeepLError::Other(m) => m,
        }
    }
}

impl std::fmt::Display for DeepLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for DeepLError {}

/// Retry configuration. [`RetryPolicy::default`] equals the SDK defaults; the
/// fields are public so tests can shrink the delays.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// SDK `maxRetries` (default 5; note the SDK performs `max_retries`
    /// attempts in total, i.e. 4 retries).
    pub max_retries: u32,
    /// SDK `minTimeout` (default 5 s): minimum per-attempt timeout.
    pub min_timeout: Duration,
    /// First back-off delay (SDK: 1 s).
    pub backoff_initial: Duration,
    /// Upper bound of the back-off delay (SDK: 120 s).
    pub backoff_max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 5,
            min_timeout: Duration::from_millis(5_000),
            backoff_initial: Duration::from_millis(1_000),
            backoff_max: Duration::from_millis(120_000),
        }
    }
}

/// Port of the SDK's internal `BackoffTimer`.
struct BackoffTimer {
    backoff_ms: f64,
    max_ms: f64,
    deadline: Instant,
    num_retries: u32,
}

impl BackoffTimer {
    const JITTER: f64 = 0.23;
    const MULTIPLIER: f64 = 1.6;

    fn new(policy: &RetryPolicy) -> Self {
        let backoff_ms = policy.backoff_initial.as_secs_f64() * 1000.0;
        Self {
            backoff_ms,
            max_ms: policy.backoff_max.as_secs_f64() * 1000.0,
            deadline: Instant::now() + Duration::from_secs_f64(backoff_ms / 1000.0),
            num_retries: 0,
        }
    }

    fn time_until_deadline(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Sleeps until the current deadline, then grows the back-off and applies
    /// jitter to compute the next deadline (same maths as the SDK).
    async fn sleep_until_deadline(&mut self) {
        tokio::time::sleep(self.time_until_deadline()).await;
        self.backoff_ms = (self.backoff_ms * Self::MULTIPLIER).min(self.max_ms);
        let random = u32::from_le_bytes(util::random_bytes(4).try_into().unwrap()) as f64
            / (u32::MAX as f64 + 1.0);
        let jittered = self.backoff_ms * (1.0 + Self::JITTER * (2.0 * random - 1.0));
        self.deadline = Instant::now() + Duration::from_secs_f64(jittered / 1000.0);
        self.num_retries += 1;
    }
}

/// A transport-level failure (no HTTP status available).
struct ConnectionFailure {
    message: String,
    /// The SDK only retries timeouts (`ETIMEDOUT` / `ECONNABORTED`).
    should_retry: bool,
}

struct RawResponse {
    status: u16,
    body: String,
}

/// Normalises a language code the way the SDK does: lower-case language,
/// upper-case region (`"EN-us"` -> `"en-US"`).
///
/// Like the SDK, only the first two `-` separated pieces are kept.
pub fn standardize_language_code(code: &str) -> Result<String, DeepLError> {
    if code.is_empty() {
        return Err(DeepLError::Other(
            "langCode must be a non-empty string".to_owned(),
        ));
    }
    let mut parts = code.split('-');
    let language = parts.next().unwrap_or_default().to_lowercase();
    Ok(match parts.next() {
        Some(region) => format!("{language}-{}", region.to_uppercase()),
        None => language,
    })
}

/// True for DeepL free-plan keys (`isFreeAccountAuthKey`).
pub fn is_free_account_key(api_key: &str) -> bool {
    api_key.ends_with(":fx")
}

/// A supported source/target language (`GET /v2/languages`).
#[derive(Debug, Clone, PartialEq)]
pub struct Language {
    pub code: String,
    pub name: String,
    pub supports_formality: Option<bool>,
}

/// The character counters of `GET /v2/usage`; `None` when DeepL omitted them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Usage {
    pub character_count: Option<Value>,
    pub character_limit: Option<Value>,
}

/// One dictionary inside a multilingual glossary (info only, no entries).
#[derive(Debug, Clone, PartialEq)]
pub struct DictionaryInfo {
    pub source_lang: Value,
    pub target_lang: Value,
    pub entry_count: Value,
}

/// A multilingual (v3) glossary description.
#[derive(Debug, Clone, PartialEq)]
pub struct GlossaryInfo {
    pub glossary_id: Value,
    pub name: Value,
    /// ISO-8601 with millisecond precision (JS `Date#toJSON`), or `None` when
    /// the date could not be parsed (JS serialises an invalid `Date` as `null`).
    pub creation_time: Option<String>,
    pub dictionaries: Vec<DictionaryInfo>,
}

/// A dictionary prepared for upload. `entries_tsv` has already been validated
/// (see [`crate::glossary::entries_to_tsv`]).
#[derive(Debug, Clone, PartialEq)]
pub struct DictionaryInput {
    pub source_lang_code: String,
    pub target_lang_code: String,
    pub entries_tsv: String,
}

/// Options for a translation call (the subset the proxy passes to the SDK).
#[derive(Debug, Clone)]
pub struct TranslateOptions<'a> {
    pub source_lang: Option<&'a str>,
    pub target_lang: &'a str,
    pub formality: &'a str,
    pub glossary_id: Option<&'a str>,
}

/// Cheap, cloneable handle bound to one DeepL API key.
///
/// Equivalent of `new deepl.DeepLClient(apiKey)`; creating one does not hit
/// the network.
#[derive(Clone)]
pub struct DeepLClient {
    http: Client,
    base_url: String,
    api_key: String,
    retry: RetryPolicy,
}

/// Factory that holds the shared connection pool and the settings that do not
/// depend on the key (server override, retry policy).
#[derive(Clone)]
pub struct DeepLFactory {
    http: Client,
    base_url_override: Option<String>,
    retry: RetryPolicy,
}

impl DeepLFactory {
    pub fn new(base_url_override: Option<String>, retry: RetryPolicy) -> Self {
        Self::try_new(base_url_override, retry).expect("failed to build the HTTP client")
    }

    /// Like [`DeepLFactory::new`], but reports a missing system CA store (for
    /// example a minimal host without the `ca-certificates` package) as an
    /// error instead of panicking.
    pub fn try_new(base_url_override: Option<String>, retry: RetryPolicy) -> Result<Self, String> {
        // reqwest is built without a bundled TLS provider (see Cargo.toml);
        // make sure the `ring` provider is registered. Idempotent.
        crate::server::install_crypto_provider();
        let http = Client::builder()
            .user_agent(concat!("dt-proxy-server-rs/", env!("CARGO_PKG_VERSION")))
            // DeepL never redirects; refusing to follow keeps the key on one host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                format!("Unable to initialise the HTTPS client (is the ca-certificates package installed?): {error}")
            })?;
        Ok(Self {
            http,
            base_url_override: base_url_override
                .map(|url| url.trim_end_matches('/').to_owned())
                .filter(|url| !url.is_empty()),
            retry,
        })
    }

    /// `new deepl.Translator(key)`: fails like the SDK when the key is empty.
    pub fn client(&self, api_key: &str) -> Result<DeepLClient, DeepLError> {
        if api_key.is_empty() {
            return Err(DeepLError::Other(
                "authKey must be a non-empty string".to_owned(),
            ));
        }
        let base_url = self.base_url_override.clone().unwrap_or_else(|| {
            if is_free_account_key(api_key) {
                FREE_API_URL.to_owned()
            } else {
                PRO_API_URL.to_owned()
            }
        });
        Ok(DeepLClient {
            http: self.http.clone(),
            base_url,
            api_key: api_key.to_owned(),
            retry: self.retry.clone(),
        })
    }
}

/// Port of the SDK's `checkStatusCode`: statuses 200..=399 are fine, anything
/// else is mapped to a [`DeepLError`].
pub fn check_status(status: u16, body: &str, using_glossary: bool) -> Result<(), DeepLError> {
    if (200..400).contains(&status) {
        return Ok(());
    }
    let mut message = String::new();
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(object)) => {
            if let Some(value) = object.get("message") {
                message.push_str(&format!(", message: {}", display_json(value)));
            }
            if let Some(value) = object.get("detail") {
                message.push_str(&format!(", detail: {}", display_json(value)));
            }
        }
        Ok(Value::Null) => message = format!(", {body}"),
        Ok(_) => {}
        // Not JSON: fall back to the raw content.
        Err(_) => message = format!(", {body}"),
    }
    Err(match status {
        403 => DeepLError::Authorization(format!("Authorization failure, check auth_key{message}")),
        456 => DeepLError::QuotaExceeded(format!(
            "Quota for this billing period has been exceeded{message}"
        )),
        404 if using_glossary => DeepLError::GlossaryNotFound(format!("Glossary not found{message}")),
        404 => DeepLError::Other(format!("Not found{message}")),
        400 => DeepLError::Other(format!("Bad request{message}")),
        429 => DeepLError::TooManyRequests(format!(
            "Too many requests, DeepL servers are currently experiencing high load{message}"
        )),
        503 => DeepLError::Other(format!("Service unavailable{message}")),
        other => DeepLError::Other(format!(
            "Unexpected status code: {other}{message}, content: {body}"
        )),
    })
}

fn display_json(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn parse_error(error: impl std::fmt::Display) -> DeepLError {
    DeepLError::Other(format!("Error parsing response JSON: {error}"))
}

/// `new Date(text).toJSON()`: normalises an RFC 3339 timestamp to UTC with
/// millisecond precision, or `None` for an unparseable date.
pub fn to_js_iso_string(text: &str) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    use time::{OffsetDateTime, UtcOffset};
    let parsed = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    let utc = parsed.to_offset(UtcOffset::UTC);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond()
    ))
}

impl DeepLClient {
    // ------------------------------------------------------------------
    // transport
    // ------------------------------------------------------------------

    async fn attempt(
        &self,
        method: &Method,
        path: &str,
        form: Option<&[(String, String)]>,
        timeout: Duration,
    ) -> Result<RawResponse, ConnectionFailure> {
        let mut request = self
            .http
            .request(method.clone(), format!("{}{}", self.base_url, path))
            .header("Authorization", format!("DeepL-Auth-Key {}", self.api_key))
            .timeout(timeout);
        if let Some(form) = form {
            request = request.form(form);
        }
        let failure = |error: reqwest::Error| ConnectionFailure {
            message: error.to_string(),
            should_retry: error.is_timeout(),
        };
        let response = request.send().await.map_err(failure)?;
        let status = response.status().as_u16();
        let body = response.text().await.map_err(failure)?;
        Ok(RawResponse { status, body })
    }

    /// Port of `HttpClient.sendRequestWithBackoff` + `checkStatusCode`.
    /// Returns the response body for 2xx/3xx statuses.
    async fn send(
        &self,
        method: Method,
        path: &str,
        form: Option<&[(String, String)]>,
        using_glossary: bool,
    ) -> Result<String, DeepLError> {
        tracing::debug!("Request to DeepL API {method} {path}");
        let mut backoff = BackoffTimer::new(&self.retry);
        let outcome = loop {
            let timeout = self.retry.min_timeout.max(backoff.time_until_deadline());
            let attempt = self.attempt(&method, path, form, timeout).await;
            let should_retry = match &attempt {
                // Retry on Too-Many-Requests and server-side errors.
                Ok(response) => response.status == 429 || response.status >= 500,
                Err(failure) => failure.should_retry,
            };
            if !should_retry || backoff.num_retries + 1 >= self.retry.max_retries {
                break attempt;
            }
            tracing::debug!(
                "Starting retry {} for request {method} {path}",
                backoff.num_retries + 1
            );
            backoff.sleep_until_deadline().await;
        };
        match outcome {
            Ok(response) => {
                check_status(response.status, &response.body, using_glossary)?;
                Ok(response.body)
            }
            Err(failure) => Err(DeepLError::Other(format!(
                "Connection failure: {}",
                failure.message
            ))),
        }
    }

    // ------------------------------------------------------------------
    // /v2 endpoints
    // ------------------------------------------------------------------

    /// `translator.getUsage()`.
    pub async fn get_usage(&self) -> Result<Usage, DeepLError> {
        let body = self.send(Method::GET, "/v2/usage", None, false).await?;
        let object: Value = serde_json::from_str(&body).map_err(parse_error)?;
        // `parseUsageDetail` yields `undefined` unless *both* members exist.
        let detail = |prefix: &str| {
            let count = object.get(format!("{prefix}_count"));
            let limit = object.get(format!("{prefix}_limit"));
            match (count, limit) {
                (Some(count), Some(limit)) => (Some(count.clone()), Some(limit.clone())),
                _ => (None, None),
            }
        };
        let (character_count, character_limit) = detail("character");
        Ok(Usage {
            character_count,
            character_limit,
        })
    }

    async fn languages(&self, path: &str) -> Result<Vec<Language>, DeepLError> {
        let body = self.send(Method::GET, path, None, false).await?;
        let list: Value = serde_json::from_str(&body).map_err(parse_error)?;
        let items = list
            .as_array()
            .ok_or_else(|| parse_error("expected an array"))?;
        items
            .iter()
            .map(|item| {
                let code = standardize_language_code(
                    item.get("language").and_then(Value::as_str).unwrap_or_default(),
                )
                .map_err(|error| parse_error(error))?;
                Ok(Language {
                    code,
                    name: item
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    supports_formality: item.get("supports_formality").and_then(Value::as_bool),
                })
            })
            .collect()
    }

    /// `getSourceLanguages()` (`GET /v2/languages`).
    pub async fn get_source_languages(&self) -> Result<Vec<Language>, DeepLError> {
        self.languages("/v2/languages").await
    }

    /// `getTargetLanguages()` (`GET /v2/languages?type=target`).
    pub async fn get_target_languages(&self) -> Result<Vec<Language>, DeepLError> {
        self.languages("/v2/languages?type=target").await
    }

    /// `getGlossaryLanguagePairs()`.
    pub async fn get_glossary_language_pairs(&self) -> Result<Vec<(Value, Value)>, DeepLError> {
        let body = self
            .send(Method::GET, "/v2/glossary-language-pairs", None, false)
            .await?;
        let object: Value = serde_json::from_str(&body).map_err(parse_error)?;
        let pairs = object
            .get("supported_languages")
            .and_then(Value::as_array)
            .ok_or_else(|| parse_error("missing supported_languages"))?;
        Ok(pairs
            .iter()
            .map(|pair| {
                (
                    pair.get("source_lang").cloned().unwrap_or(Value::Null),
                    pair.get("target_lang").cloned().unwrap_or(Value::Null),
                )
            })
            .collect())
    }

    /// `translator.translateText(texts, source, target, { tagHandling: "html",
    /// formality, glossary })`.
    ///
    /// Reproduces the SDK's parameter checks (and its quirks: a bare `en` or
    /// `pt` target and empty texts are rejected *by the SDK*, which the proxy
    /// reports as a 502).
    pub async fn translate_text(
        &self,
        texts: &[String],
        options: &TranslateOptions<'_>,
    ) -> Result<Vec<String>, DeepLError> {
        // buildURLSearchParams
        let target = standardize_language_code(options.target_lang)?;
        let source = options
            .source_lang
            .map(standardize_language_code)
            .transpose()?;
        if options.glossary_id.is_some() && source.is_none() {
            return Err(DeepLError::Other(
                "sourceLang is required if using a glossary".to_owned(),
            ));
        }
        if target == "en" {
            return Err(DeepLError::Other(
                "targetLang='en' is deprecated, please use 'en-GB' or 'en-US' instead.".to_owned(),
            ));
        }
        if target == "pt" {
            return Err(DeepLError::Other(
                "targetLang='pt' is deprecated, please use 'pt-PT' or 'pt-BR' instead.".to_owned(),
            ));
        }
        let mut form: Vec<(String, String)> = vec![("target_lang".to_owned(), target)];
        if let Some(source) = source {
            form.push(("source_lang".to_owned(), source));
        }
        form.push(("formality".to_owned(), options.formality.to_lowercase()));
        if let Some(glossary_id) = options.glossary_id {
            form.push(("glossary_id".to_owned(), glossary_id.to_owned()));
        }
        // The SDK always asks for billed characters.
        form.push(("show_billed_characters".to_owned(), "1".to_owned()));
        // appendTextsAndReturnIsSingular
        for text in texts {
            if text.is_empty() {
                return Err(DeepLError::Other(
                    "texts parameter must be a non-empty string or array of non-empty strings"
                        .to_owned(),
                ));
            }
            form.push(("text".to_owned(), text.clone()));
        }
        // validateAndAppendTextOptions({ tagHandling: "html" })
        form.push(("tag_handling".to_owned(), "html".to_owned()));

        let body = self.send(Method::POST, "/v2/translate", Some(&form), false).await?;
        let object: Value = serde_json::from_str(&body).map_err(parse_error)?;
        let translations = object
            .get("translations")
            .and_then(Value::as_array)
            .ok_or_else(|| parse_error("missing translations"))?;
        let results: Vec<String> = translations
            .iter()
            .map(|translation| {
                translation
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        if results.len() != texts.len() {
            return Err(DeepLError::Other(format!(
                "DeepL returned {} translations for {} texts",
                results.len(),
                texts.len()
            )));
        }
        Ok(results)
    }

    // ------------------------------------------------------------------
    // /v3 multilingual glossaries
    // ------------------------------------------------------------------

    fn parse_dictionary_info(object: &Value) -> DictionaryInfo {
        let field = |name: &str| object.get(name).cloned().unwrap_or(Value::Null);
        DictionaryInfo {
            source_lang: field("source_lang"),
            target_lang: field("target_lang"),
            entry_count: field("entry_count"),
        }
    }

    fn parse_glossary_info(object: &Value) -> Result<GlossaryInfo, DeepLError> {
        let dictionaries = object
            .get("dictionaries")
            .and_then(Value::as_array)
            .ok_or_else(|| parse_error("missing dictionaries"))?
            .iter()
            .map(Self::parse_dictionary_info)
            .collect();
        Ok(GlossaryInfo {
            glossary_id: object.get("glossary_id").cloned().unwrap_or(Value::Null),
            name: object.get("name").cloned().unwrap_or(Value::Null),
            creation_time: object
                .get("creation_time")
                .and_then(Value::as_str)
                .and_then(to_js_iso_string),
            dictionaries,
        })
    }

    fn parse_glossary_body(body: &str) -> Result<GlossaryInfo, DeepLError> {
        let object: Value = serde_json::from_str(body).map_err(parse_error)?;
        Self::parse_glossary_info(&object)
    }

    /// Percent-encodes a glossary id before it is placed in a URL path.
    ///
    /// The SDK interpolates the id verbatim (`/v3/glossaries/${id}`); encoding
    /// it keeps a crafted id such as `a%2F..%2Fb` from escaping the intended
    /// path segment. Real ids (UUIDs) are unaffected.
    fn glossary_path(id: &str) -> String {
        // RFC 3986 "unreserved" characters stay as they are.
        const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'_')
            .remove(b'.')
            .remove(b'~');
        format!(
            "/v3/glossaries/{}",
            percent_encoding::utf8_percent_encode(id, PATH_SEGMENT)
        )
    }

    /// `listMultilingualGlossaries()`.
    pub async fn list_multilingual_glossaries(&self) -> Result<Vec<GlossaryInfo>, DeepLError> {
        let body = self.send(Method::GET, "/v3/glossaries", None, false).await?;
        let object: Value = serde_json::from_str(&body).map_err(parse_error)?;
        object
            .get("glossaries")
            .and_then(Value::as_array)
            .ok_or_else(|| parse_error("missing glossaries"))?
            .iter()
            .map(Self::parse_glossary_info)
            .collect()
    }

    /// `createMultilingualGlossary(name, dictionaries)`.
    pub async fn create_multilingual_glossary(
        &self,
        name: &str,
        dictionaries: &[DictionaryInput],
    ) -> Result<GlossaryInfo, DeepLError> {
        if name.is_empty() {
            return Err(DeepLError::Invalid("glossary name must not be empty".to_owned()));
        }
        let mut form = vec![("name".to_owned(), name.to_owned())];
        for (index, dictionary) in dictionaries.iter().enumerate() {
            form.push((format!("dictionaries[{index}].source_lang"), dictionary.source_lang_code.clone()));
            form.push((format!("dictionaries[{index}].target_lang"), dictionary.target_lang_code.clone()));
            form.push((format!("dictionaries[{index}].entries"), dictionary.entries_tsv.clone()));
            form.push((format!("dictionaries[{index}].entries_format"), "tsv".to_owned()));
        }
        let body = self.send(Method::POST, "/v3/glossaries", Some(&form), false).await?;
        Self::parse_glossary_body(&body)
    }

    /// `getMultilingualGlossary(id)`.
    pub async fn get_multilingual_glossary(&self, id: &str) -> Result<GlossaryInfo, DeepLError> {
        if id.is_empty() {
            return Err(DeepLError::Invalid("glossaryId must not be empty".to_owned()));
        }
        let body = self
            .send(Method::GET, &Self::glossary_path(id), None, true)
            .await?;
        Self::parse_glossary_body(&body)
    }

    /// `deleteMultilingualGlossary(id)`.
    pub async fn delete_multilingual_glossary(&self, id: &str) -> Result<(), DeepLError> {
        self.send(Method::DELETE, &Self::glossary_path(id), None, true)
            .await
            .map(|_| ())
    }

    /// `updateMultilingualGlossaryName(id, name)` (`PATCH /v3/glossaries/{id}`).
    pub async fn update_multilingual_glossary_name(
        &self,
        id: &str,
        name: &str,
    ) -> Result<GlossaryInfo, DeepLError> {
        if name.is_empty() {
            return Err(DeepLError::Invalid("Parameter \"name\" must not be empty".to_owned()));
        }
        let form = vec![("name".to_owned(), name.to_owned())];
        let body = self
            .send(Method::PATCH, &Self::glossary_path(id), Some(&form), true)
            .await?;
        Self::parse_glossary_body(&body)
    }

    /// `replaceMultilingualGlossaryDictionary(id, dictionary)`
    /// (`PUT /v3/glossaries/{id}/dictionaries`).
    pub async fn replace_multilingual_glossary_dictionary(
        &self,
        id: &str,
        dictionary: &DictionaryInput,
    ) -> Result<DictionaryInfo, DeepLError> {
        let form = vec![
            ("source_lang".to_owned(), dictionary.source_lang_code.clone()),
            ("target_lang".to_owned(), dictionary.target_lang_code.clone()),
            ("entries".to_owned(), dictionary.entries_tsv.clone()),
            ("entries_format".to_owned(), "tsv".to_owned()),
        ];
        let path = format!("{}/dictionaries", Self::glossary_path(id));
        let body = self.send(Method::PUT, &path, Some(&form), true).await?;
        let object: Value = serde_json::from_str(&body).map_err(parse_error)?;
        Ok(Self::parse_dictionary_info(&object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standardizes_language_codes_like_the_sdk() {
        assert_eq!(standardize_language_code("FR").unwrap(), "fr");
        assert_eq!(standardize_language_code("EN-us").unwrap(), "en-US");
        assert_eq!(standardize_language_code("zh-Hans").unwrap(), "zh-HANS");
        // `split('-', 2)` keeps only two pieces.
        assert_eq!(standardize_language_code("en-US-x").unwrap(), "en-US");
        assert!(standardize_language_code("").is_err());
    }

    #[test]
    fn selects_the_server_from_the_key_suffix() {
        let factory = DeepLFactory::new(None, RetryPolicy::default());
        assert_eq!(factory.client("abc:fx").unwrap().base_url, FREE_API_URL);
        assert_eq!(factory.client("abc").unwrap().base_url, PRO_API_URL);
        assert!(factory.client("").is_err());
    }

    /// Port of "keeps proxy authentication distinct from DeepL
    /// authentication" (the status -> error part).
    #[test]
    fn maps_deepl_statuses_to_error_kinds() {
        assert!(check_status(200, "", false).is_ok());
        assert!(check_status(204, "", true).is_ok());
        assert!(matches!(check_status(403, "{}", false), Err(DeepLError::Authorization(_))));
        assert!(matches!(check_status(456, "{}", false), Err(DeepLError::QuotaExceeded(_))));
        assert!(matches!(check_status(429, "{}", false), Err(DeepLError::TooManyRequests(_))));
        assert!(matches!(check_status(404, "{}", true), Err(DeepLError::GlossaryNotFound(_))));
        assert!(matches!(check_status(404, "{}", false), Err(DeepLError::Other(_))));
        assert!(matches!(check_status(400, "{}", false), Err(DeepLError::Other(_))));
        assert!(matches!(check_status(500, "oops", false), Err(DeepLError::Other(_))));
    }

    #[test]
    fn error_messages_include_deepl_details() {
        let error = check_status(403, r#"{"message":"Forbidden","detail":"bad key"}"#, false)
            .unwrap_err();
        assert!(error.message().contains("message: Forbidden"));
        assert!(error.message().contains("detail: bad key"));
    }

    #[test]
    fn formats_dates_like_javascript() {
        assert_eq!(
            to_js_iso_string("2026-07-18T20:00:00Z").as_deref(),
            Some("2026-07-18T20:00:00.000Z")
        );
        assert_eq!(
            to_js_iso_string("2021-08-03T14:16:18.329Z").as_deref(),
            Some("2021-08-03T14:16:18.329Z")
        );
        assert_eq!(
            to_js_iso_string("2021-08-03T16:16:18+02:00").as_deref(),
            Some("2021-08-03T14:16:18.000Z")
        );
        assert_eq!(to_js_iso_string("not a date"), None);
    }

    #[test]
    fn encodes_glossary_ids_in_paths() {
        assert_eq!(DeepLClient::glossary_path("abc-123"), "/v3/glossaries/abc-123");
        // A crafted id cannot add path segments or climb out of /v3/glossaries.
        assert_eq!(
            DeepLClient::glossary_path("a/../b"),
            "/v3/glossaries/a%2F..%2Fb"
        );
    }
}
