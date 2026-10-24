//! TCP/TLS listener and HTTP/1.1 connection handling.
//!
//! The original relies on Node's `http`/`https` servers and sets four
//! per-connection limits at the end of `startServer()`:
//!
//! ```js
//! activeServer.requestTimeout      = 120_000;
//! activeServer.headersTimeout      = 15_000;
//! activeServer.keepAliveTimeout    = 10_000;
//! activeServer.maxRequestsPerSocket = 500;
//! ```
//!
//! `axum::serve` does not expose such knobs, so this module runs hyper
//! directly and reproduces them:
//!
//! | Node option             | here                                              |
//! |-------------------------|---------------------------------------------------|
//! | `headersTimeout`        | hyper `header_read_timeout` (15 s)                |
//! | `keepAliveTimeout`      | idle connections are closed after 10 s            |
//! | `maxRequestsPerSocket`  | `Connection: close` on the 500th response         |
//! | `requestTimeout`        | body read timeout in the route layer (120 s)      |
//!
//! TLS (the original's `https.createServer({ cert, key })`) is provided by
//! `tokio-rustls`; only HTTP/1.1 is offered, like Node's `https` module.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::http::{header, HeaderValue, Request};
use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

use crate::config::{ConfigError, ConfigResult};

/// `server.headersTimeout`.
pub const HEADERS_TIMEOUT: Duration = Duration::from_secs(15);
/// `server.keepAliveTimeout`.
pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// `server.maxRequestsPerSocket`.
pub const MAX_REQUESTS_PER_CONNECTION: usize = 500;
/// Hard cap on simultaneously open connections. Connections beyond it are
/// closed immediately, so unauthenticated clients cannot exhaust file
/// descriptors (hardening; the Node.js original has no such cap).
pub const MAX_CONNECTIONS: usize = 512;
/// How long a graceful shutdown waits for in-flight requests.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Installs the `ring` crypto provider used by both the inbound TLS listener
/// and the outbound `reqwest` client. Safe to call more than once.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds a TLS acceptor from PEM files (certificate chain + private key).
pub fn load_tls_acceptor(certificate: &Path, private_key: &Path) -> ConfigResult<TlsAcceptor> {
    let failure = |what: &str, path: &Path, error: &dyn std::fmt::Display| {
        ConfigError::new(format!("Unable to read the TLS {what} {}: {error}", path.display()))
    };
    let certificates = CertificateDer::pem_file_iter(certificate)
        .map_err(|error| failure("certificate", certificate, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| failure("certificate", certificate, &error))?;
    if certificates.is_empty() {
        return Err(ConfigError::new(format!(
            "The TLS certificate file {} contains no certificate",
            certificate.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(private_key)
        .map_err(|error| failure("private key", private_key, &error))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| ConfigError::new(format!("TLS configuration error: {error}")))?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|error| ConfigError::new(format!("Invalid TLS certificate or key: {error}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Per-connection bookkeeping used to implement keep-alive limits.
struct ConnectionStats {
    started: Instant,
    in_flight: AtomicUsize,
    served: AtomicUsize,
    last_activity_ms: AtomicU64,
}

impl ConnectionStats {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            in_flight: AtomicUsize::new(0),
            served: AtomicUsize::new(0),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        self.last_activity_ms
            .store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let now = self.started.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.last_activity_ms.load(Ordering::Relaxed)))
    }
}

async fn serve_connection<S>(
    stream: S,
    peer: SocketAddr,
    router: Router,
    mut shutdown: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stats = Arc::new(ConnectionStats::new());
    let service = {
        let stats = Arc::clone(&stats);
        service_fn(move |mut request: Request<Incoming>| {
            let mut router = router.clone();
            let stats = Arc::clone(&stats);
            async move {
                stats.in_flight.fetch_add(1, Ordering::SeqCst);
                stats.touch();
                // Makes the peer address available to handlers (used for the
                // per-IP limits of the setup page).
                request.extensions_mut().insert(ConnectInfo(peer));
                let result = router.call(request).await;
                let mut response = match result {
                    Ok(response) => response,
                    Err(never) => match never {},
                };
                if stats.served.fetch_add(1, Ordering::SeqCst) + 1 >= MAX_REQUESTS_PER_CONNECTION {
                    response
                        .headers_mut()
                        .insert(header::CONNECTION, HeaderValue::from_static("close"));
                }
                stats.in_flight.fetch_sub(1, Ordering::SeqCst);
                stats.touch();
                Ok::<_, Infallible>(response)
            }
        })
    };

    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADERS_TIMEOUT)
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut watching_shutdown = true;
    loop {
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(error) = result {
                    tracing::debug!("connection from {peer} closed with an error: {error}");
                }
                break;
            }
            _ = ticker.tick() => {
                if stats.in_flight.load(Ordering::SeqCst) == 0 && stats.idle_for() >= KEEP_ALIVE_TIMEOUT {
                    connection.as_mut().graceful_shutdown();
                }
            }
            changed = shutdown.changed(), if watching_shutdown => {
                match changed {
                    Ok(()) if *shutdown.borrow() => connection.as_mut().graceful_shutdown(),
                    Ok(()) => {}
                    Err(_) => watching_shutdown = false,
                }
            }
        }
    }
}

async fn accept_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls: Option<TlsAcceptor>,
    router: Router,
    shutdown: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) {
    let _ = stream.set_nodelay(true);
    match tls {
        None => serve_connection(stream, peer, router, shutdown).await,
        Some(acceptor) => match tokio::time::timeout(HEADERS_TIMEOUT, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => serve_connection(stream, peer, router, shutdown).await,
            Ok(Err(error)) => tracing::debug!("TLS handshake with {peer} failed: {error}"),
            Err(_) => tracing::debug!("TLS handshake with {peer} timed out"),
        },
    }
}

/// Serves `router` on `listener` until `shutdown` resolves, then stops
/// accepting and gives in-flight requests a few seconds to finish.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    tls: Option<TlsAcceptor>,
    shutdown: impl Future<Output = ()>,
) {
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut connections: JoinSet<()> = JoinSet::new();
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => match Arc::clone(&slots).try_acquire_owned() {
                    Ok(permit) => {
                        connections.spawn(accept_connection(
                            stream,
                            peer,
                            tls.clone(),
                            router.clone(),
                            stop_rx.clone(),
                            permit,
                        ));
                    }
                    Err(_) => {
                        tracing::warn!("connection limit reached, dropping {peer}");
                        drop(stream);
                    }
                },
                Err(error) => {
                    // e.g. EMFILE: back off briefly instead of spinning.
                    tracing::warn!("accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            // Reap finished connection tasks so the set does not grow.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            _ = &mut shutdown => break,
        }
    }
    let _ = stop_tx.send(true);
    let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!("forcing shutdown with connections still open");
        connections.abort_all();
    }
}

/// Resolves when the process receives Ctrl-C or (on Unix) SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
