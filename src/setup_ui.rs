//! The browser-based first-run setup page.
//!
//! Port of `setup-ui.js`: HTML rendering plus the small helpers used to
//! authenticate access to `/setup` (one-time URL token, cookies, CSRF).
//!
//! Only wording was changed relative to the original: the form hint no longer
//! says the key "remains in the Docker volume" (this port has no container
//! runtime); it says it stays in the proxy's private secrets file.

use axum::http::{header, HeaderMap, HeaderName, HeaderValue};

use crate::util::{constant_time_eq, escape_html, parse_cookies};

/// Name of the cookie that proves the one-time setup URL was used.
pub const SETUP_ACCESS_COOKIE: &str = "dt_setup_access";
/// Name of the CSRF cookie (double-submit with the hidden form field).
pub const SETUP_CSRF_COOKIE: &str = "dt_setup_csrf";

/// `setupAccessGranted`: valid cookie *or* valid `?token=` query parameter.
pub fn setup_access_granted(
    cookie_header: Option<&str>,
    query_token: Option<&str>,
    expected: &str,
) -> bool {
    let cookies = parse_cookies(cookie_header);
    let cookie = cookies.get(SETUP_ACCESS_COOKIE).map(String::as_str).unwrap_or_default();
    constant_time_eq(cookie, expected) || constant_time_eq(query_token.unwrap_or_default(), expected)
}

/// Values echoed back into the form after a validation error.
#[derive(Debug, Clone, Default)]
pub struct SetupValues {
    pub deployment_mode: Option<String>,
    pub public_url: Option<String>,
}

/// `setupPage`.
pub fn setup_page(
    csrf_token: &str,
    error: &str,
    connection: &str,
    values: &SetupValues,
) -> String {
    let finished = !connection.is_empty();
    let remote = values.deployment_mode.as_deref() == Some("remote");
    let (local_checked, remote_checked) = if remote { ("", "checked") } else { ("checked", "") };

    let message = if finished {
        format!(
            "<div class=\"success\"><strong>Setup complete.</strong><p>Copy this address into the Deep Translate settings:</p><code>{}</code></div>",
            escape_html(connection)
        )
    } else {
        let error_block = if error.is_empty() {
            String::new()
        } else {
            format!("<p class=\"error\" role=\"alert\">{}</p>", escape_html(error))
        };
        format!(
            r#"<form method="post" action="/setup" autocomplete="off">
        <input type="hidden" name="csrfToken" value="{csrf}">
        <fieldset>
          <legend>Deployment mode</legend>
          <label class="choice"><input name="deploymentMode" type="radio" value="local" {local_checked}> Local (recommended)</label>
          <p class="hint">Use the proxy only from this computer.</p>
          <label class="choice"><input name="deploymentMode" type="radio" value="remote" {remote_checked}> Remote (advanced)</label>
          <p class="hint">Use the proxy through an existing HTTPS reverse proxy.</p>
        </fieldset>
        <label for="publicUrl">Public HTTPS proxy URL <span>(remote only)</span></label>
        <input id="publicUrl" name="publicUrl" type="url" value="{public_url}" placeholder="https://translate.example.com">
        <p class="hint">Keep the proxy port private behind the HTTPS reverse proxy. The first authenticated Foundry connection will be allowed automatically.</p>
        <label for="deeplApiKey">DeepL API key</label>
        <input id="deeplApiKey" name="deeplApiKey" type="password" required maxlength="500" autofocus>
        <p class="hint">The key stays in the proxy's private secrets file and is never sent to Foundry.</p>
        {error_block}
        <button type="submit">Configure proxy</button>
      </form>"#,
            csrf = escape_html(csrf_token),
            public_url = escape_html(values.public_url.as_deref().unwrap_or_default()),
        )
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Deep Translate Proxy Setup</title>
  <style>
    :root{{color-scheme:light dark;font-family:system-ui,sans-serif}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#111827;color:#e5e7eb}}.card{{box-sizing:border-box;width:min(92vw,600px);margin:2rem;padding:2rem;border:1px solid #374151;border-radius:16px;background:#1f2937;box-shadow:0 20px 50px #0006}}h1{{margin-top:0;font-size:1.55rem}}label{{display:block;margin:1.5rem 0 .5rem;font-weight:700}}label span{{color:#9ca3af;font-size:.85em;font-weight:400}}input{{box-sizing:border-box;width:100%;padding:.8rem;border:1px solid #6b7280;border-radius:8px;background:#111827;color:#fff;font:inherit}}fieldset{{margin:1.5rem 0;padding:1rem;border:1px solid #4b5563;border-radius:10px}}legend{{padding:0 .4rem;font-weight:700}}.choice{{display:flex;gap:.6rem;align-items:center;margin:.7rem 0 .2rem}}.choice input{{width:auto}}.choice+.hint{{margin:.2rem 0 .8rem 1.5rem}}button{{margin-top:1rem;padding:.8rem 1rem;border:0;border-radius:8px;background:#2563eb;color:#fff;font:inherit;font-weight:700;cursor:pointer}}.hint{{color:#9ca3af;font-size:.9rem}}.error{{color:#fca5a5}}.success{{padding:1rem;border-radius:10px;background:#064e3b}}.success code{{display:block;margin-top:1rem;padding:.8rem;overflow-wrap:anywhere;border-radius:6px;background:#022c22;color:#d1fae5}}</style>
</head>
<body><main class="card"><h1>Deep Translate Proxy</h1><p>{intro}</p>{message}</main></body>
</html>"#,
        intro = if finished { "The proxy is ready to use." } else { "Initial setup for the proxy." },
    )
}

/// `setSetupHeaders`: strict headers for every `/setup` response.
pub fn apply_setup_headers(headers: &mut HeaderMap) {
    const PAIRS: [(&str, &str); 5] = [
        ("cache-control", "no-store"),
        (
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ];
    for (name, value) in PAIRS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
}

/// Builds a `Set-Cookie` value scoped to `/setup` (15 minutes, `HttpOnly`,
/// `SameSite=Strict`, `Secure` when the setup page is served over HTTPS).
pub fn setup_cookie(name: &str, value: &str, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/setup; HttpOnly; SameSite=Strict; Max-Age=900{secure}"
    ))
    .expect("cookie values are ASCII")
}

/// A `Set-Cookie` value that deletes one of the setup cookies.
pub fn expired_setup_cookie(name: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("{name}=; Path=/setup; HttpOnly; SameSite=Strict; Max-Age=0"))
        .expect("cookie values are ASCII")
}

/// Convenience used by handlers: append a cookie header.
pub fn append_cookie(headers: &mut HeaderMap, value: HeaderValue) {
    headers.append(header::SET_COOKIE, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of "keeps the proxy setup interface in English with a prominent
    /// product title".
    #[test]
    fn keeps_the_setup_interface_in_english_with_a_product_title() {
        let page = setup_page("token", "", "", &SetupValues::default());
        assert!(page.contains("<title>Deep Translate Proxy Setup</title>"));
        assert!(page.contains("<h1>Deep Translate Proxy</h1>"));
        assert!(page.contains("Initial setup for the proxy."));
        for french in ["Configuration", "Clé API", "Enregistrer", "Proxy personnel"] {
            assert!(!page.to_lowercase().contains(&french.to_lowercase()), "{french}");
        }
        assert!(!page.to_lowercase().contains("docker"));
    }

    /// Port of "requires the unguessable setup token independently of the
    /// Host header".
    #[test]
    fn requires_the_setup_token() {
        assert!(setup_access_granted(None, Some("setup-secret"), "setup-secret"));
        assert!(setup_access_granted(Some("dt_setup_access=setup-secret"), None, "setup-secret"));
        assert!(!setup_access_granted(Some("dt_setup_access=wrong"), Some("wrong"), "setup-secret"));
        assert!(!setup_access_granted(None, None, "setup-secret"));
        assert!(!setup_access_granted(None, Some(""), ""));
    }

    /// Port of "escapes setup-page values".
    #[test]
    fn escapes_setup_page_values() {
        let page = setup_page("\"><script>", "<bad>", "", &SetupValues::default());
        assert!(!page.contains("<script>"));
        assert!(page.contains("&lt;bad&gt;"));
        let remote = setup_page(
            "token",
            "",
            "",
            &SetupValues {
                deployment_mode: Some("remote".into()),
                public_url: Some("\"><script>".into()),
            },
        );
        assert!(remote.contains("value=\"remote\" checked"));
        assert!(!remote.contains("<script>"));
    }

    #[test]
    fn shows_the_connection_string_when_finished() {
        let page = setup_page("", "", "http://127.0.0.1:3001#dt_abc", &SetupValues::default());
        assert!(page.contains("Setup complete."));
        assert!(page.contains("http://127.0.0.1:3001#dt_abc"));
        assert!(page.contains("The proxy is ready to use."));
        assert!(!page.contains("<form"));
    }

    #[test]
    fn cookies_are_scoped_and_hardened() {
        let value = setup_cookie("dt_setup_access", "abc", true);
        let text = value.to_str().unwrap();
        assert!(text.contains("Path=/setup") && text.contains("HttpOnly"));
        assert!(text.contains("SameSite=Strict") && text.contains("Max-Age=900") && text.ends_with("; Secure"));
        assert!(!setup_cookie("a", "b", false).to_str().unwrap().contains("Secure"));
        assert!(expired_setup_cookie("a").to_str().unwrap().contains("Max-Age=0"));
    }
}
