//! Deep Translate Proxy — Rust port.
//!
//! A self-hosted, authenticated proxy between the *Deep Translate* module of
//! Foundry VTT and the DeepL API. This crate is a from-scratch Rust rewrite of
//! [`YanKlInnomme/dt-proxy-server`](https://github.com/YanKlInnomme/dt-proxy-server)
//! (Node.js, MIT licensed). The doc comment of every module names the part of
//! the original it corresponds to.
//!
//! ```text
//! Foundry VTT ──► [ gate: origin, CORS, token, rate limit ] ──► routes ──► DeepL API
//!                                   ▲                              │
//!                          config / secrets (JSON files, env)      └─ cache (in memory)
//! ```
//!
//! Module map:
//!
//! | module         | original                         | role                                   |
//! |----------------|----------------------------------|----------------------------------------|
//! | [`config`]     | `runtime-config.js`              | settings, secrets, first-run prompts   |
//! | [`middleware`] | the `app.use(...)` chain         | origin / CORS / token / rate limiting  |
//! | [`routes`]     | route handlers of `server.js`    | `/translate`, `/usage`, glossaries, …  |
//! | [`setup_routes`] / [`setup_ui`] | `setup-ui.js` + `/setup` | browser first-run assistant      |
//! | [`deepl`]      | the `deepl-node` SDK             | upstream HTTP client                   |
//! | [`glossary`]   | glossary helpers of `server.js`  | request validation / serialisation     |
//! | [`rate_limit`] | `createRateLimiter`              | fixed-window limiter                   |
//! | [`server`]     | `http`/`https` server setup      | listener, TLS, connection limits       |
//! | [`state`]      | closure state in `startServer`   | cache, counters, setup tokens          |

pub mod config;
pub mod deepl;
pub mod error;
pub mod glossary;
pub mod middleware;
pub mod rate_limit;
pub mod routes;
pub mod server;
pub mod setup_routes;
pub mod setup_ui;
pub mod state;
pub mod util;

/// `shouldShowConnectionAtStartup`: the connection string is printed
/// automatically only for an interactive, packaged executable (a user who
/// double-clicks the program cannot add `--show-token`). This crate always
/// builds a standalone executable, so `packaged` is `true` in `main`; the
/// parameter keeps the original's truth table testable.
pub fn should_show_connection_at_startup(packaged: bool, interactive: bool) -> bool {
    packaged && interactive
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of "shows the connection automatically only in an interactive
    /// packaged executable".
    #[test]
    fn shows_the_connection_only_in_an_interactive_packaged_executable() {
        assert!(should_show_connection_at_startup(true, true));
        assert!(!should_show_connection_at_startup(true, false));
        assert!(!should_show_connection_at_startup(false, true));
    }
}
