//! Runtime configuration: file + environment + CLI loading, validation and
//! persistence.
//!
//! Port of `runtime-config.js`. The on-disk formats are **byte-compatible**
//! with the Node.js version (same file names, same JSON keys), so an existing
//! `deep-translate-proxy-config.json` / `deep-translate-proxy-secrets.json`
//! pair can be reused as-is.
//!
//! Precedence, from strongest to weakest (identical to the original):
//! environment variables > `--port=` argument (port only) > config file >
//! built-in defaults.
//!
//! Where the Node.js code says …                       the Rust code is …
//! * `DEFAULT_CONFIG`                                   -> [`Config::default`]
//! * `loadRuntimeConfiguration`                         -> [`load_runtime_configuration`]
//! * `promptForSetup`                                   -> [`prompt_for_setup`]
//! * `persistRuntimeSecrets`                            -> [`persist_runtime_secrets`]
//! * `completeWebSetup`                                 -> [`complete_web_setup`]
//! * `rememberFoundryOrigin`                            -> [`remember_foundry_origin`]
//! * `connectionString` / `regenerateAccessToken`       -> same names, snake_case
//! * `validate*` helpers                                -> `validate_*`

use std::collections::HashMap;
use std::fmt;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use url::Url;

use crate::util::{
    encode_uri_component, generate_access_token, generate_account_id, js_integer, js_trim,
    sha256_hex,
};

pub const DEFAULT_CONFIG_FILE: &str = "deep-translate-proxy-config.json";
pub const DEFAULT_SECRETS_FILE: &str = "deep-translate-proxy-secrets.json";

/// Error type for everything configuration related. The message is shown to
/// the operator verbatim (as `❌ <message>`), exactly like the original's
/// `throw new Error(...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

pub type ConfigResult<T> = Result<T, ConfigError>;

// ---------------------------------------------------------------------------
// Environment access (injectable so tests do not touch the process env)
// ---------------------------------------------------------------------------

/// A snapshot of environment variables.
///
/// JavaScript's `process.env.X ?? fallback` treats an *empty* variable as set
/// (only `undefined` falls back); [`Env::get`] keeps that distinction by
/// returning `Some("")`.
#[derive(Debug, Clone, Default)]
pub struct Env(HashMap<String, String>);

impl Env {
    pub fn from_process() -> Self {
        Self(
            std::env::vars_os()
                .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
                .collect(),
        )
    }

    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
        )
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

/// `environmentBoolean`: `1/true/yes/on` (case-insensitive) are true; unset or
/// empty falls back; anything else is false.
pub fn environment_boolean(value: Option<&str>, fallback: bool) -> bool {
    match value {
        None | Some("") => fallback,
        Some(text) => matches!(js_trim(text).to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

// ---------------------------------------------------------------------------
// Configuration model
// ---------------------------------------------------------------------------

/// How the (self-hosted) proxy is reached over the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeploymentMode {
    /// Reached from the computer running it (loopback). Recommended.
    #[default]
    Local,
    /// Reached through a public HTTPS address operated by the user.
    Remote,
}

impl DeploymentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DeploymentMode::Local => "local",
            DeploymentMode::Remote => "remote",
        }
    }

    /// `normalizeDeploymentMode`: trims and lower-cases; rejects other values.
    pub fn parse(value: &str) -> ConfigResult<Self> {
        match js_trim(value).to_lowercase().as_str() {
            "local" => Ok(DeploymentMode::Local),
            "remote" => Ok(DeploymentMode::Remote),
            _ => Err(ConfigError::new(
                "Deployment mode must be either \"local\" or \"remote\"",
            )),
        }
    }
}

impl Serialize for DeploymentMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeploymentMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        DeploymentMode::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Per-route request limits (`rateLimits`). `0` disables a limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RateLimits {
    pub window_ms: u64,
    pub default: u64,
    pub translate: u64,
    pub usage: u64,
    pub languages: u64,
    pub glossaries: u64,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            window_ms: 60_000,
            default: 60,
            translate: 180,
            usage: 240,
            languages: 120,
            glossaries: 120,
        }
    }
}

/// Direct TLS termination settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub certificate_file: String,
    pub private_key_file: String,
}

/// The non-secret settings stored in `deep-translate-proxy-config.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub deployment_mode: DeploymentMode,
    pub host: String,
    pub port: u16,
    pub public_url: String,
    pub allowed_origins: Vec<String>,
    pub allow_no_origin: bool,
    pub allow_insecure_network: bool,
    pub behind_trusted_proxy: bool,
    pub trust_proxy_hops: u32,
    pub rate_limits: RateLimits,
    pub tls: TlsConfig,
    pub secrets_file: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            deployment_mode: DeploymentMode::Local,
            host: "127.0.0.1".to_owned(),
            port: 3001,
            public_url: String::new(),
            allowed_origins: Vec::new(),
            allow_no_origin: false,
            allow_insecure_network: false,
            behind_trusted_proxy: false,
            trust_proxy_hops: 0,
            rate_limits: RateLimits::default(),
            tls: TlsConfig::default(),
            secrets_file: DEFAULT_SECRETS_FILE.to_owned(),
        }
    }
}

/// The secrets held in memory. `deepl_key_fingerprint` is the SHA-256 of the
/// DeepL key, used to rotate the account id when the key changes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secrets {
    pub deepl_api_key: String,
    pub access_token: String,
    pub account_id: String,
    pub deepl_key_fingerprint: Option<String>,
}

/// `Debug` never prints secret values, so a stray `{:?}` cannot leak them.
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("deepl_api_key", &"<redacted>")
            .field("access_token", &"<redacted>")
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

/// Shape of `deep-translate-proxy-secrets.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredSecrets {
    #[serde(rename = "deeplApiKey", default, skip_serializing_if = "Option::is_none")]
    deepl_api_key: Option<String>,
    #[serde(rename = "accessToken", default, skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    // Note the capital "L": that is the key the Node.js version writes.
    #[serde(rename = "deepLKeyFingerprint", default, skip_serializing_if = "Option::is_none")]
    deepl_key_fingerprint: Option<String>,
}

/// Everything the server needs at run time.
#[derive(Debug, Clone)]
pub struct Runtime {
    pub config: Config,
    pub secrets: Secrets,
    pub config_path: PathBuf,
    pub secrets_path: PathBuf,
    /// True until a DeepL key is available (first-run state).
    pub setup_required: bool,
    /// `DEEPL_API_KEY` is set: the key must never be written to disk.
    pub deepl_key_from_env: bool,
    /// `DT_PROXY_TOKEN` is set: the token must never be written to disk.
    pub token_from_env: bool,
}

// ---------------------------------------------------------------------------
// Validation (pure functions; unit-tested below)
// ---------------------------------------------------------------------------

/// `isLoopbackHost`.
pub fn is_loopback_host(host: &str) -> bool {
    matches!(js_trim(host).to_lowercase().as_str(), "127.0.0.1" | "localhost" | "::1")
}

/// `validatePublicProxyUrl`: returns the URL without trailing slashes.
pub fn validate_public_proxy_url(value: &str, mode: DeploymentMode) -> ConfigResult<String> {
    let invalid = || ConfigError::new("The proxy public URL is invalid");
    let url = Url::parse(js_trim(value)).map_err(|_| invalid())?;
    let has_query = url.query().is_some_and(|query| !query.is_empty());
    let has_fragment = url.fragment().is_some_and(|fragment| !fragment.is_empty());
    let host_missing = url.host_str().map_or(true, str::is_empty);
    if host_missing
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || has_query
        || has_fragment
    {
        return Err(invalid());
    }
    if mode == DeploymentMode::Remote && url.scheme() != "https" {
        return Err(ConfigError::new("Remote mode requires a public HTTPS URL"));
    }
    // `host_str()` keeps the brackets of IPv6 literals (like Node's
    // `URL#hostname`), so `https://[::1]` is *not* detected as loopback here
    // either - same as the original.
    if mode == DeploymentMode::Remote && is_loopback_host(url.host_str().unwrap_or_default()) {
        return Err(ConfigError::new(
            "Remote mode does not allow localhost or loopback public URLs",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// `validateFoundryOrigin`: only `scheme://host[:port]` is accepted.
pub fn validate_foundry_origin(value: &str) -> ConfigResult<String> {
    let invalid = || ConfigError::new("The Foundry origin is invalid");
    let url = Url::parse(js_trim(value)).map_err(|_| invalid())?;
    let has_query = url.query().is_some_and(|query| !query.is_empty());
    let has_fragment = url.fragment().is_some_and(|fragment| !fragment.is_empty());
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || has_query
        || has_fragment
    {
        return Err(ConfigError::new(
            "The Foundry origin must contain only its scheme, host, and optional port",
        ));
    }
    Ok(url.origin().ascii_serialization())
}

/// `validateDeploymentSecurity`.
pub fn validate_deployment_security(config: &mut Config) -> ConfigResult<()> {
    if config.deployment_mode == DeploymentMode::Local {
        return Ok(());
    }
    config.public_url = validate_public_proxy_url(&config.public_url, DeploymentMode::Remote)?;
    config.allowed_origins = config
        .allowed_origins
        .iter()
        .map(|origin| validate_foundry_origin(origin))
        .collect::<ConfigResult<Vec<_>>>()?;
    if !config.tls.enabled && !config.behind_trusted_proxy {
        return Err(ConfigError::new(
            "Remote mode requires direct TLS or a trusted HTTPS reverse proxy",
        ));
    }
    Ok(())
}

/// `validateNetworkSecurity`: listening outside loopback is fail-closed.
pub fn validate_network_security(config: &Config) -> ConfigResult<()> {
    if is_loopback_host(&config.host) {
        return Ok(());
    }
    if config.allowed_origins.is_empty() && config.deployment_mode != DeploymentMode::Remote {
        return Err(ConfigError::new(
            "ALLOWED_ORIGINS must contain the exact Foundry origin when listening outside loopback",
        ));
    }
    if config.tls.enabled {
        return Ok(());
    }
    if config.behind_trusted_proxy && config.public_url.to_lowercase().starts_with("https://") {
        return Ok(());
    }
    if !config.allow_insecure_network {
        return Err(ConfigError::new(
            "Refusing an unencrypted non-loopback listener. Configure TLS, a trusted HTTPS reverse proxy, or explicitly set DT_PROXY_ALLOW_INSECURE_NETWORK=true for a trusted LAN",
        ));
    }
    Ok(())
}

/// `validatePort` for textual input (environment variable, CLI, prompt).
pub fn validate_port(value: &str) -> ConfigResult<u16> {
    match js_integer(value) {
        Some(port) if (1..=65535).contains(&port) => Ok(port as u16),
        _ => Err(ConfigError::new("Port must be an integer between 1 and 65535")),
    }
}

/// `validateNonNegativeInteger` for textual input.
pub fn validate_non_negative_integer(value: &str, field: &str, minimum: u64) -> ConfigResult<u64> {
    match js_integer(value) {
        Some(number) if number >= 0 && (number as u64) >= minimum => Ok(number as u64),
        _ => Err(ConfigError::new(format!(
            "{field} must be an integer greater than or equal to {minimum}"
        ))),
    }
}

/// `normalizeOrigins` for the comma-separated environment variable.
fn split_origins(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|origin| js_trim(origin).to_owned())
        .filter(|origin| !origin.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// `readJson`: `Ok(None)` when the file does not exist.
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> ConfigResult<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| ConfigError::new(format!("Unable to read {}: {error}", path.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ConfigError::new(format!(
            "Unable to read {}: {error}",
            path.display()
        ))),
    }
}

/// `writePrivateJson`: atomic write (temp file + rename) of pretty-printed
/// JSON, readable by the current user only.
pub fn write_private_json<T: Serialize>(path: &Path, value: &T) -> ConfigResult<()> {
    let io_error = |error: std::io::Error| {
        ConfigError::new(format!("Unable to write {}: {error}", path.display()))
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let mut temporary = path.as_os_str().to_owned();
    // Unpredictable name + `create_new` below: a pre-planted symlink or file
    // can never redirect the write (hardening).
    temporary.push(format!(".{}.tmp", crate::util::random_base64url(9)));
    let temporary = PathBuf::from(temporary);

    let mut contents = serde_json::to_string_pretty(value)
        .map_err(|error| ConfigError::new(error.to_string()))?;
    contents.push('\n');

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(io_error)?;
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            std::fs::rename(&temporary, path)
        });
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    secure_file_permissions(path)
}

/// `secureFilePermissions`: `chmod 600` on POSIX, an ACL restricted to the
/// current user (`icacls`) on Windows.
fn secure_file_permissions(path: &Path) -> ConfigResult<()> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let whoami = Command::new("whoami.exe")
            .output()
            .map_err(|error| ConfigError::new(error.to_string()))?;
        let mut username = String::from_utf8_lossy(&whoami.stdout).trim().to_owned();
        if username.is_empty() {
            username = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
                (Ok(domain), Ok(user)) => format!("{domain}\\{user}"),
                (_, Ok(user)) => user,
                _ => {
                    return Err(ConfigError::new(
                        "Unable to determine the Windows user for secret-file permissions",
                    ))
                }
            };
        }
        let status = Command::new("icacls.exe")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{username}:(F)"))
            .status()
            .map_err(|error| ConfigError::new(error.to_string()))?;
        if !status.success() {
            return Err(ConfigError::new("icacls.exe failed to restrict the file permissions"));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| ConfigError::new(format!("Unable to secure {}: {error}", path.display())))
    }
}

/// `resolvePaths`.
///
/// Difference from the original: the default directory is the **current
/// working directory** instead of "next to `server.js` / the packaged
/// executable". A `cargo run` binary lives in `target/`, which is the wrong
/// place for secrets; the CWD is predictable and `DT_PROXY_CONFIG` still
/// overrides it.
pub fn resolve_paths(env: &Env) -> ConfigResult<(PathBuf, PathBuf)> {
    let absolute = |path: &Path| {
        std::path::absolute(path)
            .map_err(|error| ConfigError::new(format!("Unable to resolve {}: {error}", path.display())))
    };
    let config_path = match env.get("DT_PROXY_CONFIG").filter(|value| !value.is_empty()) {
        Some(path) => absolute(Path::new(path))?,
        None => absolute(Path::new(DEFAULT_CONFIG_FILE))?,
    };
    let default_secrets = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(DEFAULT_SECRETS_FILE);
    Ok((config_path, default_secrets))
}

// ---------------------------------------------------------------------------
// Interactive first-run assistant
// ---------------------------------------------------------------------------

/// Reads one trimmed line after printing `question`. EOF is an error so the
/// retry loops below cannot spin forever when stdin is closed.
fn ask(question: &str) -> ConfigResult<String> {
    print!("{question}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| ConfigError::new(format!("Unable to read from the terminal: {error}")))?;
    if read == 0 {
        return Err(ConfigError::new("The terminal input was closed during setup"));
    }
    Ok(js_trim(&line).to_owned())
}

/// `promptForSetup`: asks for the deployment mode, port, public URL (remote)
/// and DeepL key. Returns whether anything was changed.
fn prompt_for_setup(
    config: &mut Config,
    secrets: &mut Secrets,
    needs_config: bool,
    needs_api_key: bool,
) -> ConfigResult<bool> {
    let mut changed = false;
    if needs_config {
        loop {
            let answer = ask(&format!(
                "Deployment mode (type \"local\" or \"remote\") [{}]: ",
                config.deployment_mode.as_str()
            ))?;
            let candidate = if answer.is_empty() {
                Ok(config.deployment_mode)
            } else {
                DeploymentMode::parse(&answer)
            };
            match candidate {
                Ok(mode) => {
                    config.deployment_mode = mode;
                    break;
                }
                Err(error) => eprintln!("{error}"),
            }
        }
        loop {
            let answer = ask(&format!("Proxy port [{}]: ", config.port))?;
            let candidate = if answer.is_empty() {
                Ok(config.port)
            } else {
                validate_port(&answer)
            };
            match candidate {
                Ok(port) => {
                    config.port = port;
                    break;
                }
                Err(error) => eprintln!("{error}"),
            }
        }
        if config.deployment_mode == DeploymentMode::Remote {
            loop {
                let answer = ask("Public HTTPS proxy URL: ")?;
                match validate_public_proxy_url(&answer, DeploymentMode::Remote) {
                    Ok(url) => {
                        config.public_url = url;
                        break;
                    }
                    Err(error) => eprintln!("{error}"),
                }
            }
            config.behind_trusted_proxy = !config.tls.enabled;
            config.trust_proxy_hops = u32::from(config.behind_trusted_proxy);
        }
        changed = true;
    }
    if needs_api_key {
        while secrets.deepl_api_key.is_empty() {
            secrets.deepl_api_key = ask("DeepL API key: ")?;
            if secrets.deepl_api_key.is_empty() {
                eprintln!("The DeepL API key is required.");
            }
        }
        changed = true;
    }
    Ok(changed)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

fn parse_rate_value(env: &Env, name: &str, stored: u64, minimum: u64) -> ConfigResult<u64> {
    match env.get(name) {
        Some(value) => validate_non_negative_integer(value, name, minimum),
        None if stored >= minimum => Ok(stored),
        None => Err(ConfigError::new(format!(
            "{name} must be an integer greater than or equal to {minimum}"
        ))),
    }
}

/// `loadRuntimeConfiguration`.
///
/// `interactive` tells whether stdin is a terminal (the first-run prompts only
/// appear then); it is a parameter so tests stay non-interactive.
pub fn load_runtime_configuration(
    env: &Env,
    args: &[String],
    interactive: bool,
) -> ConfigResult<Runtime> {
    let (config_path, _default_secrets_path) = resolve_paths(env)?;
    let stored_value: Option<Value> = read_json(&config_path)?;
    let mut config: Config = match &stored_value {
        Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
            ConfigError::new(format!("Unable to read {}: {error}", config_path.display()))
        })?,
        None => Config::default(),
    };

    // Deployment mode: env > stored value > inferred from the stored public URL.
    let stored_mode = stored_value
        .as_ref()
        .and_then(|value| value.get("deploymentMode"))
        .and_then(Value::as_str);
    let inferred = match stored_mode {
        Some(mode) => mode.to_owned(),
        None => {
            let stored_public_url = stored_value
                .as_ref()
                .and_then(|value| value.get("publicUrl"))
                .and_then(Value::as_str)
                .filter(|url| !url.is_empty());
            match stored_public_url {
                Some(url) => {
                    let hostname = Url::parse(url)
                        .ok()
                        .and_then(|parsed| parsed.host_str().map(str::to_owned))
                        .unwrap_or_default();
                    if is_loopback_host(&hostname) { "local" } else { "remote" }.to_owned()
                }
                None => "local".to_owned(),
            }
        }
    };
    config.deployment_mode = DeploymentMode::parse(env.get("DT_PROXY_MODE").unwrap_or(&inferred))?;

    // Port: PORT > --port=NNNN > stored.
    let port_argument = args
        .iter()
        .find_map(|argument| argument.strip_prefix("--port="))
        .map(str::to_owned);
    config.port = match (env.get("PORT"), &port_argument) {
        (Some(value), _) => validate_port(value)?,
        (None, Some(value)) => validate_port(value)?,
        (None, None) => validate_port(&config.port.to_string())?,
    };

    config.host = match env.get("HOST") {
        Some(value) => js_trim(value).to_owned(),
        None => js_trim(&config.host).to_owned(),
    };
    if config.host.is_empty() {
        config.host = Config::default().host;
    }
    config.public_url = env
        .get("DT_PROXY_PUBLIC_URL")
        .unwrap_or(&config.public_url)
        .trim_end_matches('/')
        .to_owned();
    if let Some(origins) = env.get("ALLOWED_ORIGINS") {
        config.allowed_origins = split_origins(origins);
    } else {
        config.allowed_origins = config
            .allowed_origins
            .iter()
            .map(|origin| js_trim(origin).to_owned())
            .filter(|origin| !origin.is_empty())
            .collect();
    }
    config.allow_no_origin =
        environment_boolean(env.get("DT_PROXY_ALLOW_NO_ORIGIN"), config.allow_no_origin);
    config.allow_insecure_network = environment_boolean(
        env.get("DT_PROXY_ALLOW_INSECURE_NETWORK"),
        config.allow_insecure_network,
    );
    config.behind_trusted_proxy = environment_boolean(
        env.get("DT_PROXY_BEHIND_TRUSTED_PROXY"),
        config.behind_trusted_proxy,
    );
    config.trust_proxy_hops = match env.get("DT_PROXY_TRUST_PROXY_HOPS") {
        Some(value) => u32::try_from(validate_non_negative_integer(
            value,
            "DT_PROXY_TRUST_PROXY_HOPS",
            0,
        )?)
        .map_err(|_| ConfigError::new("DT_PROXY_TRUST_PROXY_HOPS is too large"))?,
        None => config.trust_proxy_hops,
    };
    if !config.behind_trusted_proxy && config.trust_proxy_hops > 0 {
        return Err(ConfigError::new(
            "DT_PROXY_TRUST_PROXY_HOPS requires DT_PROXY_BEHIND_TRUSTED_PROXY=true",
        ));
    }
    if config.behind_trusted_proxy && config.trust_proxy_hops < 1 {
        return Err(ConfigError::new(
            "DT_PROXY_TRUST_PROXY_HOPS must be at least 1 behind a trusted reverse proxy",
        ));
    }

    let limits = config.rate_limits.clone();
    config.rate_limits.window_ms =
        parse_rate_value(env, "DT_PROXY_RATE_WINDOW_MS", limits.window_ms, 1000)?;
    config.rate_limits.default = parse_rate_value(env, "DT_PROXY_RATE_DEFAULT", limits.default, 0)?;
    config.rate_limits.translate = parse_rate_value(env, "DT_PROXY_RATE_TRANSLATE", limits.translate, 0)?;
    config.rate_limits.usage = parse_rate_value(env, "DT_PROXY_RATE_USAGE", limits.usage, 0)?;
    config.rate_limits.languages = parse_rate_value(env, "DT_PROXY_RATE_LANGUAGES", limits.languages, 0)?;
    config.rate_limits.glossaries = parse_rate_value(env, "DT_PROXY_RATE_GLOSSARIES", limits.glossaries, 0)?;

    config.tls.enabled = environment_boolean(env.get("DT_PROXY_TLS_ENABLED"), config.tls.enabled);
    config.tls.certificate_file = js_trim(
        env.get("DT_PROXY_TLS_CERT").unwrap_or(&config.tls.certificate_file),
    )
    .to_owned();
    config.tls.private_key_file = js_trim(
        env.get("DT_PROXY_TLS_KEY").unwrap_or(&config.tls.private_key_file),
    )
    .to_owned();
    if config.tls.enabled
        && (config.tls.certificate_file.is_empty() || config.tls.private_key_file.is_empty())
    {
        return Err(ConfigError::new(
            "TLS is enabled but DT_PROXY_TLS_CERT or DT_PROXY_TLS_KEY is missing",
        ));
    }
    validate_deployment_security(&mut config)?;
    validate_network_security(&config)?;

    // Secrets.
    // `path.resolve(dirname(configPath), env.DT_PROXY_SECRETS || config.secretsFile)`:
    // `join` replaces the base when the right-hand side is absolute, like
    // `path.resolve` does.
    let secrets_file = env
        .get("DT_PROXY_SECRETS")
        .filter(|value| !value.is_empty())
        .unwrap_or(&config.secrets_file);
    let secrets_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(secrets_file);
    let stored_secrets: StoredSecrets = read_json(&secrets_path)?.unwrap_or_default();
    let mut secrets = Secrets {
        deepl_api_key: js_trim(
            env.get("DEEPL_API_KEY")
                .or(stored_secrets.deepl_api_key.as_deref())
                .unwrap_or_default(),
        )
        .to_owned(),
        access_token: js_trim(
            env.get("DT_PROXY_TOKEN")
                .or(stored_secrets.access_token.as_deref())
                .unwrap_or_default(),
        )
        .to_owned(),
        account_id: js_trim(stored_secrets.account_id.as_deref().unwrap_or_default()).to_owned(),
        deepl_key_fingerprint: None,
    };

    // First-run prompts (only on a terminal).
    let mut changed = false;
    if interactive {
        let needs_config = stored_value.is_none() && !env.has("PORT") && port_argument.is_none();
        let needs_api_key = secrets.deepl_api_key.is_empty();
        changed = prompt_for_setup(&mut config, &mut secrets, needs_config, needs_api_key)?;
    }
    validate_deployment_security(&mut config)?;
    validate_network_security(&config)?;

    let mut runtime = Runtime {
        setup_required: secrets.deepl_api_key.is_empty(),
        config,
        secrets,
        config_path,
        secrets_path,
        deepl_key_from_env: env.has("DEEPL_API_KEY"),
        token_from_env: env.has("DT_PROXY_TOKEN"),
    };
    if !runtime.setup_required {
        persist_runtime_secrets(&mut runtime, &stored_secrets)?;
    }
    if (stored_value.is_none() || changed) && !runtime.setup_required {
        write_private_json(&runtime.config_path, &runtime.config)?;
    }
    Ok(runtime)
}

/// `persistRuntimeSecrets`: fills in the generated token / account id and
/// writes the secrets file. Variables supplied through the environment are
/// never written to disk.
fn persist_runtime_secrets(runtime: &mut Runtime, previous: &StoredSecrets) -> ConfigResult<()> {
    if runtime.secrets.deepl_api_key.is_empty() {
        return Err(ConfigError::new("A DeepL API key is required"));
    }
    if runtime.secrets.access_token.is_empty() {
        runtime.secrets.access_token = generate_access_token();
    }
    let fingerprint = sha256_hex(&runtime.secrets.deepl_api_key);
    // A different DeepL key means a different "tenant": cache entries and rate
    // limit windows must not carry over.
    if runtime.secrets.account_id.is_empty()
        || previous.deepl_key_fingerprint.as_deref() != Some(fingerprint.as_str())
    {
        runtime.secrets.account_id = generate_account_id();
    }
    runtime.secrets.deepl_key_fingerprint = Some(fingerprint.clone());

    write_private_json(&runtime.secrets_path, &stored_secrets_for(runtime))
}

fn stored_secrets_for(runtime: &Runtime) -> StoredSecrets {
    StoredSecrets {
        deepl_api_key: (!runtime.deepl_key_from_env).then(|| runtime.secrets.deepl_api_key.clone()),
        access_token: (!runtime.token_from_env).then(|| runtime.secrets.access_token.clone()),
        account_id: Some(runtime.secrets.account_id.clone()),
        deepl_key_fingerprint: runtime.secrets.deepl_key_fingerprint.clone(),
    }
}

/// The values submitted by the browser-based setup form.
#[derive(Debug, Clone, Default)]
pub struct SetupForm {
    pub deployment_mode: Option<String>,
    pub public_url: Option<String>,
}

/// `completeWebSetup`: applies the first-run form and persists everything.
pub fn complete_web_setup(
    runtime: &mut Runtime,
    deepl_api_key: &str,
    deployment: &SetupForm,
) -> ConfigResult<()> {
    // Work on a copy: a failed attempt leaves the live runtime untouched, and
    // the secrets file is rolled back to what it was.
    let previous_secrets = std::fs::read(&runtime.secrets_path).ok();
    let mut next = runtime.clone();
    match complete_web_setup_inner(&mut next, deepl_api_key, deployment) {
        Ok(()) => {
            *runtime = next;
            Ok(())
        }
        Err(error) => {
            match previous_secrets {
                Some(bytes) => {
                    if std::fs::write(&runtime.secrets_path, bytes).is_ok() {
                        let _ = secure_file_permissions(&runtime.secrets_path);
                    }
                }
                None => {
                    let _ = std::fs::remove_file(&runtime.secrets_path);
                }
            }
            Err(error)
        }
    }
}

fn complete_web_setup_inner(
    runtime: &mut Runtime,
    deepl_api_key: &str,
    deployment: &SetupForm,
) -> ConfigResult<()> {
    if !runtime.setup_required {
        return Err(ConfigError::new("The proxy is already configured"));
    }
    let key = js_trim(deepl_api_key);
    if key.is_empty() || key.chars().count() > 500 {
        return Err(ConfigError::new("A valid DeepL API key is required"));
    }

    let mode = match deployment.deployment_mode.as_deref() {
        Some(mode) => DeploymentMode::parse(mode)?,
        None => runtime.config.deployment_mode,
    };
    runtime.config.deployment_mode = mode;
    if mode == DeploymentMode::Remote {
        runtime.config.public_url = validate_public_proxy_url(
            deployment.public_url.as_deref().unwrap_or_default(),
            DeploymentMode::Remote,
        )?;
        runtime.config.behind_trusted_proxy = !runtime.config.tls.enabled;
        runtime.config.trust_proxy_hops = u32::from(runtime.config.behind_trusted_proxy);
    } else {
        runtime.config.public_url = String::new();
    }
    validate_deployment_security(&mut runtime.config)?;
    validate_network_security(&runtime.config)?;

    runtime.secrets.deepl_api_key = key.to_owned();
    persist_runtime_secrets(runtime, &StoredSecrets::default())?;
    write_private_json(&runtime.config_path, &runtime.config)?;
    runtime.setup_required = false;
    Ok(())
}

/// `rememberFoundryOrigin` (the synchronous core): records a new Foundry
/// origin in the config file. The caller serialises concurrent calls.
pub fn remember_foundry_origin(runtime: &mut Runtime, value: &str) -> ConfigResult<String> {
    let origin = validate_foundry_origin(value)?;
    if runtime.config.allowed_origins.contains(&origin) {
        return Ok(origin);
    }
    runtime.config.allowed_origins.push(origin.clone());
    write_private_json(&runtime.config_path, &runtime.config)?;
    Ok(origin)
}

/// `connectionString`: the `address#token` string to paste into Foundry VTT.
pub fn connection_string(runtime: &Runtime) -> String {
    let host = match runtime.config.host.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1",
        other => other,
    };
    let protocol = if runtime.config.tls.enabled { "https" } else { "http" };
    let base = if runtime.config.public_url.is_empty() {
        format!("{protocol}://{host}:{}", runtime.config.port)
    } else {
        runtime.config.public_url.clone()
    };
    format!("{base}#{}", encode_uri_component(&runtime.secrets.access_token))
}

/// `regenerateAccessToken`.
pub fn regenerate_access_token(runtime: &mut Runtime) -> ConfigResult<String> {
    if runtime.token_from_env {
        return Err(ConfigError::new(
            "Cannot regenerate a token supplied by DT_PROXY_TOKEN.",
        ));
    }
    runtime.secrets.access_token = generate_access_token();
    write_private_json(&runtime.secrets_path, &stored_secrets_for(runtime))?;
    Ok(runtime.secrets.access_token.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_runtime(directory: &Path, config: Config) -> Runtime {
        Runtime {
            config,
            secrets: Secrets::default(),
            config_path: directory.join("config.json"),
            secrets_path: directory.join("secrets.json"),
            setup_required: true,
            deepl_key_from_env: false,
            token_from_env: false,
        }
    }

    /// Port of "validates configured ports".
    #[test]
    fn validates_configured_ports() {
        assert_eq!(validate_port("3001").unwrap(), 3001);
        assert!(validate_port("0").is_err());
        assert!(validate_port("65536").is_err());
        assert!(validate_port("not-a-port").is_err());
    }

    /// Port of "remote mode requires a non-loopback HTTPS public URL".
    #[test]
    fn remote_mode_requires_a_non_loopback_https_public_url() {
        assert_eq!(
            validate_public_proxy_url("https://translate.example.test/", DeploymentMode::Remote).unwrap(),
            "https://translate.example.test"
        );
        assert!(validate_public_proxy_url("http://translate.example.test", DeploymentMode::Remote)
            .unwrap_err()
            .0
            .contains("HTTPS"));
        assert!(validate_public_proxy_url("https://127.0.0.1:3001", DeploymentMode::Remote)
            .unwrap_err()
            .0
            .contains("loopback"));
        assert_eq!(
            validate_public_proxy_url("http://127.0.0.1:3001", DeploymentMode::Local).unwrap(),
            "http://127.0.0.1:3001"
        );
        assert!(validate_public_proxy_url("https://user:pw@example.test", DeploymentMode::Remote).is_err());
        assert!(validate_public_proxy_url("https://example.test/?q=1", DeploymentMode::Remote).is_err());
        assert!(validate_public_proxy_url("nonsense", DeploymentMode::Remote).is_err());
    }

    /// Port of "accepts only exact HTTP or HTTPS Foundry origins".
    #[test]
    fn accepts_only_exact_foundry_origins() {
        assert_eq!(
            validate_foundry_origin("https://foundry.example.test:30000").unwrap(),
            "https://foundry.example.test:30000"
        );
        assert!(validate_foundry_origin("https://foundry.example.test/game")
            .unwrap_err()
            .0
            .contains("scheme, host"));
        assert!(validate_foundry_origin("ftp://foundry.example.test")
            .unwrap_err()
            .0
            .contains("scheme, host"));
    }

    /// Port of "remote deployment can learn origins but still requires a
    /// secured frontend".
    #[test]
    fn remote_deployment_requires_a_secured_frontend() {
        let base = Config {
            deployment_mode: DeploymentMode::Remote,
            public_url: "https://translate.example.test".into(),
            allowed_origins: vec!["https://foundry.example.test".into()],
            behind_trusted_proxy: true,
            trust_proxy_hops: 1,
            ..Config::default()
        };
        assert!(validate_deployment_security(&mut base.clone()).is_ok());
        assert!(validate_deployment_security(&mut Config { allowed_origins: vec![], ..base.clone() }).is_ok());
        let error = validate_deployment_security(&mut Config { behind_trusted_proxy: false, ..base }).unwrap_err();
        assert!(error.0.contains("TLS"));
    }

    /// Port of "refuses unsafe non-loopback listeners by default".
    #[test]
    fn refuses_unsafe_non_loopback_listeners_by_default() {
        let base = Config {
            host: "0.0.0.0".into(),
            allowed_origins: vec!["https://foundry.example.test".into()],
            ..Config::default()
        };
        assert!(validate_network_security(&Config { allowed_origins: vec![], ..base.clone() })
            .unwrap_err()
            .0
            .contains("ALLOWED_ORIGINS"));
        assert!(validate_network_security(&base).unwrap_err().0.contains("Refusing an unencrypted"));
        assert!(validate_network_security(&Config { allow_insecure_network: true, ..base.clone() }).is_ok());
        assert!(validate_network_security(&Config {
            tls: TlsConfig { enabled: true, ..TlsConfig::default() },
            ..base.clone()
        })
        .is_ok());
        assert!(validate_network_security(&Config {
            behind_trusted_proxy: true,
            public_url: "https://proxy.example.test".into(),
            ..base.clone()
        })
        .is_ok());
        assert!(validate_network_security(&Config {
            host: "127.0.0.1".into(),
            allowed_origins: vec![],
            ..base.clone()
        })
        .is_ok());
        assert!(validate_network_security(&Config {
            deployment_mode: DeploymentMode::Remote,
            allowed_origins: vec![],
            behind_trusted_proxy: true,
            public_url: "https://proxy.example.test".into(),
            ..base
        })
        .is_ok());
    }

    /// Port of "uses product-specific files by default so colocated
    /// executables cannot collide".
    #[test]
    fn uses_product_specific_file_names_by_default() {
        let (config, secrets) = resolve_paths(&Env::default()).unwrap();
        assert_eq!(config.file_name().unwrap(), "deep-translate-proxy-config.json");
        assert_eq!(secrets.file_name().unwrap(), "deep-translate-proxy-secrets.json");
    }

    /// Port of "persists web setup secrets and marks the runtime configured".
    #[test]
    fn persists_web_setup_secrets_and_marks_the_runtime_configured() {
        let directory = tempfile::tempdir().unwrap();
        let mut runtime = temp_runtime(directory.path(), Config::default());

        complete_web_setup(&mut runtime, "test-key:fx", &SetupForm::default()).unwrap();

        let config: Value = serde_json::from_str(&std::fs::read_to_string(&runtime.config_path).unwrap()).unwrap();
        let secrets: Value = serde_json::from_str(&std::fs::read_to_string(&runtime.secrets_path).unwrap()).unwrap();
        assert!(!runtime.setup_required);
        assert!(config.get("deeplApiKey").is_none());
        assert_eq!(secrets["deeplApiKey"], "test-key:fx");
        let token = secrets["accessToken"].as_str().unwrap();
        assert!(token.starts_with("dt_") && token.len() == 46);
        assert!(secrets["accountId"].as_str().unwrap().starts_with("account_"));
        assert!(secrets["deepLKeyFingerprint"].is_string());
        assert!(complete_web_setup(&mut runtime, "another-key", &SetupForm::default())
            .unwrap_err()
            .0
            .contains("already configured"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&runtime.secrets_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the secrets file must be owner-only");
        }
    }

    /// Port of "persists a secure remote web setup".
    #[test]
    fn persists_a_secure_remote_web_setup() {
        let directory = tempfile::tempdir().unwrap();
        let mut runtime = temp_runtime(
            directory.path(),
            Config { host: "0.0.0.0".into(), ..Config::default() },
        );

        complete_web_setup(
            &mut runtime,
            "test-key:fx",
            &SetupForm {
                deployment_mode: Some("remote".into()),
                public_url: Some("https://translate.example.test/".into()),
            },
        )
        .unwrap();

        let config: Value = serde_json::from_str(&std::fs::read_to_string(&runtime.config_path).unwrap()).unwrap();
        assert_eq!(config["deploymentMode"], "remote");
        assert_eq!(config["host"], "0.0.0.0");
        assert_eq!(config["publicUrl"], "https://translate.example.test");
        assert_eq!(config["allowedOrigins"], serde_json::json!([]));
        assert_eq!(config["behindTrustedProxy"], true);
        assert_eq!(config["trustProxyHops"], 1);

        remember_foundry_origin(&mut runtime, "https://foundry.example.test").unwrap();
        remember_foundry_origin(&mut runtime, "https://foundry.example.test").unwrap();
        let learned: Value = serde_json::from_str(&std::fs::read_to_string(&runtime.config_path).unwrap()).unwrap();
        assert_eq!(learned["allowedOrigins"], serde_json::json!(["https://foundry.example.test"]));
    }

    #[test]
    fn the_config_file_keeps_the_original_key_names() {
        let value = serde_json::to_value(Config::default()).unwrap();
        for key in [
            "deploymentMode", "host", "port", "publicUrl", "allowedOrigins", "allowNoOrigin",
            "allowInsecureNetwork", "behindTrustedProxy", "trustProxyHops", "rateLimits", "tls",
            "secretsFile",
        ] {
            assert!(value.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(value["rateLimits"]["windowMs"], 60000);
        assert_eq!(value["rateLimits"]["translate"], 180);
        assert_eq!(value["tls"]["certificateFile"], "");
    }

    #[test]
    fn loads_defaults_and_applies_environment_overrides() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("cfg.json");
        let env = Env::from_pairs([
            ("DT_PROXY_CONFIG", config_path.to_str().unwrap()),
            ("DEEPL_API_KEY", "key:fx"),
            ("PORT", "4000"),
            ("DT_PROXY_RATE_TRANSLATE", "5"),
            ("ALLOWED_ORIGINS", "http://localhost:30000, http://127.0.0.1:30000 ,"),
        ]);
        let runtime = load_runtime_configuration(&env, &[], false).unwrap();
        assert!(!runtime.setup_required);
        assert_eq!(runtime.config.port, 4000);
        assert_eq!(runtime.config.rate_limits.translate, 5);
        assert_eq!(
            runtime.config.allowed_origins,
            vec!["http://localhost:30000", "http://127.0.0.1:30000"]
        );
        // The env-supplied key is never written to disk.
        let secrets = std::fs::read_to_string(&runtime.secrets_path).unwrap();
        assert!(!secrets.contains("key:fx"));
        assert!(secrets.contains("accessToken"));
        // And a second load reuses the generated token and account id.
        let again = load_runtime_configuration(&env, &[], false).unwrap();
        assert_eq!(again.secrets.access_token, runtime.secrets.access_token);
        assert_eq!(again.secrets.account_id, runtime.secrets.account_id);
    }

    #[test]
    fn missing_key_means_setup_is_required() {
        let directory = tempfile::tempdir().unwrap();
        let env = Env::from_pairs([("DT_PROXY_CONFIG", directory.path().join("c.json").to_str().unwrap())]);
        let runtime = load_runtime_configuration(&env, &[], false).unwrap();
        assert!(runtime.setup_required);
        assert!(!directory.path().join("c.json").exists());
    }

    #[test]
    fn port_argument_is_used_but_environment_wins() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("c.json");
        let args = vec!["--port=4100".to_owned()];
        let env = Env::from_pairs([("DT_PROXY_CONFIG", path.to_str().unwrap())]);
        assert_eq!(load_runtime_configuration(&env, &args, false).unwrap().config.port, 4100);
        let env = Env::from_pairs([("DT_PROXY_CONFIG", path.to_str().unwrap()), ("PORT", "4200")]);
        assert_eq!(load_runtime_configuration(&env, &args, false).unwrap().config.port, 4200);
    }

    #[test]
    fn refuses_unsafe_environment_combinations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("c.json");
        let load = |extra: &[(&str, &str)]| {
            let mut pairs = vec![("DT_PROXY_CONFIG", path.to_str().unwrap()), ("DEEPL_API_KEY", "k")];
            pairs.extend_from_slice(extra);
            load_runtime_configuration(&Env::from_pairs(pairs), &[], false)
        };
        assert!(load(&[("HOST", "0.0.0.0")]).unwrap_err().0.contains("ALLOWED_ORIGINS"));
        assert!(load(&[("HOST", "0.0.0.0"), ("ALLOWED_ORIGINS", "https://f.test")])
            .unwrap_err()
            .0
            .contains("Refusing an unencrypted"));
        assert!(load(&[("DT_PROXY_TRUST_PROXY_HOPS", "1")]).unwrap_err().0.contains("requires"));
        assert!(load(&[("DT_PROXY_BEHIND_TRUSTED_PROXY", "true")]).unwrap_err().0.contains("at least 1"));
        assert!(load(&[("DT_PROXY_MODE", "bogus")]).is_err());
        assert!(load(&[("DT_PROXY_RATE_WINDOW_MS", "10")]).is_err());
        assert!(load(&[("DT_PROXY_TLS_ENABLED", "true")]).unwrap_err().0.contains("DT_PROXY_TLS_CERT"));
    }

    #[test]
    fn builds_the_connection_string() {
        let directory = tempfile::tempdir().unwrap();
        let mut runtime = temp_runtime(directory.path(), Config::default());
        runtime.secrets.access_token = "dt_abc".into();
        assert_eq!(connection_string(&runtime), "http://127.0.0.1:3001#dt_abc");
        runtime.config.host = "0.0.0.0".into();
        assert_eq!(connection_string(&runtime), "http://127.0.0.1:3001#dt_abc");
        runtime.config.public_url = "https://translate.example.test".into();
        assert_eq!(connection_string(&runtime), "https://translate.example.test#dt_abc");
    }

    #[test]
    fn regenerates_tokens_unless_supplied_by_the_environment() {
        let directory = tempfile::tempdir().unwrap();
        let mut runtime = temp_runtime(directory.path(), Config::default());
        complete_web_setup(&mut runtime, "key", &SetupForm::default()).unwrap();
        let before = runtime.secrets.access_token.clone();
        let after = regenerate_access_token(&mut runtime).unwrap();
        assert_ne!(before, after);
        let stored: Value = serde_json::from_str(&std::fs::read_to_string(&runtime.secrets_path).unwrap()).unwrap();
        assert_eq!(stored["accessToken"], after);
        runtime.token_from_env = true;
        assert!(regenerate_access_token(&mut runtime).is_err());
    }

    #[test]
    fn environment_booleans() {
        assert!(environment_boolean(Some("TRUE"), false));
        assert!(environment_boolean(Some(" yes "), false));
        assert!(!environment_boolean(Some("no"), true));
        assert!(environment_boolean(None, true));
        assert!(environment_boolean(Some(""), true));
    }
}
