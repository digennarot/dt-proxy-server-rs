//! Executable entry point.
//!
//! Port of `startServer()` and its CLI handling in `server.js`:
//!
//! ```text
//! dt-proxy-server [--port=3001] [--show-token] [--regenerate-token] [--start]
//! ```
//!
//! * `--show-token`        print the `address#token` string for Foundry VTT and exit
//! * `--regenerate-token`  create a new proxy token, print the new string and exit
//! * `--start`             combine with the two flags above to keep running afterwards
//! * `--port=N`            listening port (lower priority than the `PORT` variable)
//!
//! Everything else is configured through environment variables and the JSON
//! configuration file; see `README.md`.

use std::io::IsTerminal;
use std::process::ExitCode;

use dt_proxy_server::config::{
    connection_string, load_runtime_configuration, regenerate_access_token, DeploymentMode, Env,
    Runtime,
};
use dt_proxy_server::deepl::{DeepLFactory, RetryPolicy};
use dt_proxy_server::routes::build_router;
use dt_proxy_server::server::{install_crypto_provider, load_tls_acceptor, serve, shutdown_signal};
use dt_proxy_server::should_show_connection_at_startup;
use dt_proxy_server::state::AppState;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// `banner()`.
fn banner() {
    println!("====================================");
    println!("   Deep Translate Proxy");
    println!("====================================");
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        // No colour codes when stderr is a file or the systemd journal.
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    install_crypto_provider();

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // `startServer().catch(error => console.error("\n❌ ..."))`
            eprintln!("\n❌ {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    let has = |flag: &str| arguments.iter().any(|argument| argument == flag);
    if has("--version") || has("-V") {
        println!("dt-proxy-server {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if has("--help") || has("-h") {
        println!(
            "dt-proxy-server {}\n\nUSAGE: dt-proxy-server [--port=N] [--show-token] [--regenerate-token] [--start]\n\n\
             Configuration comes from environment variables (see README.md) and the JSON file\n\
             named by DT_PROXY_CONFIG (default: ./deep-translate-proxy-config.json).",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    banner();

    let env = Env::from_process();
    let interactive = std::io::stdin().is_terminal();
    let mut runtime =
        load_runtime_configuration(&env, arguments, interactive).map_err(|error| error.0)?;

    // Administrative commands (they run to completion unless `--start` is given).
    if has("--show-token") || has("--regenerate-token") {
        if runtime.setup_required {
            return Err("The proxy is not configured yet. Start it and open /setup first.".to_owned());
        }
        if has("--regenerate-token") {
            regenerate_access_token(&mut runtime).map_err(|error| error.0)?;
        }
        println!("Connection string to copy into Foundry VTT:");
        println!("{}", connection_string(&runtime));
        if !has("--start") {
            return Ok(());
        }
    }

    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Unable to start the async runtime: {error}"))?;
    tokio_runtime.block_on(run_server(runtime, &env))
}

async fn run_server(runtime: Runtime, env: &Env) -> Result<(), String> {
    let config = runtime.config.clone();
    let setup_required = runtime.setup_required;
    let connection = (!setup_required).then(|| connection_string(&runtime));

    // Direct TLS: certificate paths are relative to the config file directory.
    let tls = if config.tls.enabled {
        let directory = runtime.config_path.parent().unwrap_or(std::path::Path::new("."));
        let certificate = directory.join(&config.tls.certificate_file);
        let private_key = directory.join(&config.tls.private_key_file);
        Some(load_tls_acceptor(&certificate, &private_key).map_err(|error| error.0)?)
    } else {
        None
    };

    // Extension (not in the original): point the proxy at another DeepL
    // compatible server, e.g. a local mock. Off by default.
    let api_override = env.get("DT_PROXY_DEEPL_API_URL").map(str::to_owned);
    if let Some(url) = api_override.as_deref().filter(|url| !url.is_empty()) {
        // Never ship the DeepL key over cleartext to a non-loopback host.
        let parsed = url::Url::parse(url).map_err(|_| "DT_PROXY_DEEPL_API_URL is not a valid URL".to_owned())?;
        let loopback = parsed.host_str().is_some_and(dt_proxy_server::config::is_loopback_host);
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
            return Err("DT_PROXY_DEEPL_API_URL must be https:// (http:// is allowed only for localhost)".to_owned());
        }
        tracing::warn!("⚠️ DT_PROXY_DEEPL_API_URL is set: DeepL requests go to {url}");
    }
    let factory = DeepLFactory::try_new(api_override, RetryPolicy::default())?;
    let state = AppState::new(runtime, factory);
    let setup_token = state.setup_access_token.clone();
    state.spawn_background_tasks();
    let router = build_router(state);

    let listener = TcpListener::bind((config.host.as_str(), config.port))
        .await
        .map_err(|error| format!("Unable to listen on {}:{}: {error}", config.host, config.port))?;

    let protocol = if config.tls.enabled { "https" } else { "http" };
    println!("Deep Translate Proxy is listening on {}:{}", config.host, config.port);
    if config.deployment_mode == DeploymentMode::Remote {
        println!("Public proxy URL: {}", config.public_url);
    } else {
        println!("Local proxy URL: {protocol}://{}:{}", config.host, config.port);
    }
    println!("Deployment mode: {}", config.deployment_mode.as_str());
    if config.allow_insecure_network && !config.tls.enabled {
        tracing::warn!("⚠️ Unencrypted non-loopback access was explicitly enabled. Use only on a trusted LAN.");
    }
    if setup_required {
        println!("🔧 First-time setup required");
        println!("Open this one-time setup URL in your browser:");
        println!(
            "{protocol}://localhost:{}/setup?token={}\n",
            config.port,
            crate::encode(&setup_token)
        );
    } else {
        println!();
        if should_show_connection_at_startup(true, std::io::stdout().is_terminal()) {
            println!("Connection string to copy into Foundry VTT:");
            println!("{}\n", connection.unwrap_or_default());
        } else {
            println!("Use --show-token to display the Foundry connection string.\n");
        }
    }

    serve(listener, router, tls, shutdown_signal()).await;
    println!("Deep Translate Proxy stopped.");
    Ok(())
}

/// `encodeURIComponent` for the setup URL token.
fn encode(value: &str) -> String {
    dt_proxy_server::util::encode_uri_component(value)
}
