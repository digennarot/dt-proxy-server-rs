//! Small helpers shared by the whole crate.
//!
//! The original Node.js proxy relies on a handful of JavaScript semantics
//! (UTF-16 string lengths, `String.prototype.trim`, truthiness, `Number()`
//! coercion, `crypto.timingSafeEqual`, ...). Their observable effects (limits,
//! validation results, error messages) are part of the proxy's behaviour, so
//! this module reproduces them explicitly instead of approximating them with
//! "close enough" Rust idioms.
//!
//! Mapping to the original sources:
//! * `tokensEqual` / `safeTokenEqual`   -> [`constant_time_eq`]
//! * `generateAccessToken`              -> [`generate_access_token`]
//! * `generateAccountId`                -> [`generate_account_id`]
//! * `escapeHtml` (setup-ui.js)         -> [`escape_html`]
//! * `parseCookies` (setup-ui.js)       -> [`parse_cookies`]

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// JavaScript `string.length`: the number of UTF-16 code units.
///
/// The original enforces every size limit (texts, glossary terms, ...) with
/// `.length`, so an emoji counts as 2 there. Using `str::len` (UTF-8 bytes) or
/// `chars().count()` would make the Rust proxy accept or reject different
/// payloads.
pub fn js_len(value: &str) -> usize {
    value.encode_utf16().count()
}

/// Characters removed by JavaScript's `String.prototype.trim()`
/// (WhiteSpace + LineTerminator from the ECMAScript spec). This differs from
/// Rust's `char::is_whitespace` (e.g. U+FEFF is trimmed by JS but not by Rust,
/// U+0085 is the opposite).
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// JavaScript `String.prototype.trim()`.
pub fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

/// JavaScript truthiness of an (optional) JSON value; `None` models
/// `undefined`.
pub fn js_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        // Arrays and objects are always truthy in JavaScript, even when empty.
        Some(Value::Array(_)) | Some(Value::Object(_)) => true,
    }
}

/// `Number(text)` followed by `Number.isInteger(...)`, as used by the original
/// `validatePort` / `validateNonNegativeInteger` on environment variables.
///
/// Notably `Number("")` is `0` in JavaScript, so an empty-but-set variable is
/// accepted as `0` (which, for the rate limits, disables the limit).
pub fn js_integer(text: &str) -> Option<i64> {
    let trimmed = js_trim(text);
    if trimmed.is_empty() {
        return Some(0);
    }
    let number: f64 = trimmed.parse().ok()?;
    if number.is_finite() && number.fract() == 0.0 && number.abs() <= 9_007_199_254_740_991.0 {
        Some(number as i64)
    } else {
        None
    }
}

/// Constant-time comparison of two secrets.
///
/// Mirrors the original `tokensEqual` / `safeTokenEqual`: both values must be
/// non-empty and of equal length (length itself is not hidden, exactly like
/// `crypto.timingSafeEqual` after the explicit length check).
pub fn constant_time_eq(supplied: &str, expected: &str) -> bool {
    let supplied = supplied.as_bytes();
    let expected = expected.as_bytes();
    !expected.is_empty() && supplied.len() == expected.len() && bool::from(supplied.ct_eq(expected))
}

/// `n` random bytes from the operating system's CSPRNG.
pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; count];
    getrandom::fill(&mut buffer).expect("the operating system random number generator failed");
    buffer
}

/// `crypto.randomBytes(n).toString("base64url")`.
pub fn random_base64url(count: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(count))
}

/// `dt_` + 32 random bytes in unpadded base64url (46 characters in total).
pub fn generate_access_token() -> String {
    format!("dt_{}", random_base64url(32))
}

/// `account_` + 16 random bytes in hex. The account id isolates cache entries
/// and rate-limit windows; it changes whenever the DeepL key changes.
pub fn generate_account_id() -> String {
    format!("account_{}", hex::encode(random_bytes(16)))
}

/// Lower-case hexadecimal SHA-256 of a UTF-8 string.
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Escapes a value for inclusion in HTML text or a double-quoted attribute.
pub fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Parses a `Cookie` header. Values are percent-decoded; a value that is not
/// valid percent-encoding becomes an empty string (as the original's
/// `try { decodeURIComponent } catch { "" }`).
pub fn parse_cookies(header: Option<&str>) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for part in header.unwrap_or_default().split(';') {
        let Some(separator) = part.find('=') else {
            continue;
        };
        if separator < 1 {
            continue;
        }
        let name = part[..separator].trim().to_owned();
        let raw = part[separator + 1..].trim();
        let value = percent_decode_str(raw)
            .decode_utf8()
            .map(|decoded| decoded.into_owned())
            .unwrap_or_default();
        cookies.insert(name, value);
    }
    cookies
}

/// Characters that JavaScript's `encodeURIComponent` leaves untouched.
const URI_COMPONENT_SAFE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

/// `encodeURIComponent`.
pub fn encode_uri_component(value: &str) -> String {
    utf8_percent_encode(value, URI_COMPONENT_SAFE).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_length_counts_utf16_code_units() {
        assert_eq!(js_len("abc"), 3);
        assert_eq!(js_len("é"), 1);
        // An emoji outside the BMP is two UTF-16 code units in JavaScript.
        assert_eq!(js_len("😀"), 2);
    }

    #[test]
    fn js_trim_matches_ecmascript_whitespace() {
        assert_eq!(js_trim("\u{FEFF} x \u{00A0}"), "x");
        // U+0085 (NEL) is *not* whitespace for JavaScript.
        assert_eq!(js_trim("\u{0085}x"), "\u{0085}x");
    }

    #[test]
    fn js_integer_follows_number_coercion() {
        assert_eq!(js_integer("3001"), Some(3001));
        assert_eq!(js_integer(" 12 "), Some(12));
        assert_eq!(js_integer(""), Some(0));
        assert_eq!(js_integer("1e3"), Some(1000));
        assert_eq!(js_integer("1.5"), None);
        assert_eq!(js_integer("not-a-port"), None);
    }

    #[test]
    fn truthiness_matches_javascript() {
        use serde_json::json;
        assert!(!js_truthy(None));
        assert!(!js_truthy(Some(&json!(null))));
        assert!(!js_truthy(Some(&json!(""))));
        assert!(!js_truthy(Some(&json!(0))));
        assert!(js_truthy(Some(&json!([]))));
        assert!(js_truthy(Some(&json!({}))));
        assert!(js_truthy(Some(&json!("x"))));
    }

    /// Port of "compares proxy tokens without accepting prefixes or empty
    /// values" (test/security.test.js).
    #[test]
    fn compares_tokens_without_accepting_prefixes_or_empty_values() {
        assert!(constant_time_eq("dt_secret", "dt_secret"));
        assert!(!constant_time_eq("dt_secre", "dt_secret"));
        assert!(!constant_time_eq("", ""));
    }

    /// Port of "generates a high-entropy proxy token".
    #[test]
    fn generates_a_high_entropy_proxy_token() {
        let first = generate_access_token();
        let second = generate_access_token();
        assert!(first.starts_with("dt_"));
        assert_eq!(first.len(), 3 + 43);
        assert!(first[3..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(first, second);
        let account = generate_account_id();
        assert_eq!(account.len(), "account_".len() + 32);
    }

    /// Port of "parses and compares the setup CSRF cookie safely".
    #[test]
    fn parses_cookies() {
        let cookies = parse_cookies(Some("other=1; dt_setup_csrf=abc%20123"));
        assert_eq!(cookies.get("other").map(String::as_str), Some("1"));
        assert_eq!(cookies.get("dt_setup_csrf").map(String::as_str), Some("abc 123"));
        assert!(parse_cookies(None).is_empty());
    }

    /// Port of "escapes setup-page values".
    #[test]
    fn escapes_html() {
        assert_eq!(
            escape_html("<script>\"x\"</script>"),
            "&lt;script&gt;&quot;x&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn encodes_uri_components_like_javascript() {
        assert_eq!(encode_uri_component("dt_abc-DEF.~*!'()"), "dt_abc-DEF.~*!'()");
        assert_eq!(encode_uri_component("a b/c?"), "a%20b%2Fc%3F");
    }
}
