//! HTTP error responses.
//!
//! The original answers errors in three different ways, all reproduced here:
//!
//! 1. ad-hoc `res.status(n).json({ error: "..." })` calls inside the route
//!    handlers ([`ProxyError::Json`]);
//! 2. `deepLServiceError(res, err, service)`, which maps SDK errors to a status
//!    and a machine readable `code` ([`service_error_response`]);
//! 3. the final Express error handler, which turns anything else (body-parser
//!    failures, I/O errors) into `400 {"error":"Invalid request"}`
//!    ([`ProxyError::invalid_request`]).

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::deepl::DeepLError;

/// A JSON response with the same `Content-Type` Express sends
/// (`application/json; charset=utf-8`).
pub fn json_response(status: StatusCode, body: &Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

/// Port of `deepLServiceError`.
///
/// | error                         | status | `code`                  |
/// |-------------------------------|--------|-------------------------|
/// | `TypeError` / `ArgumentError` | 400    | `INVALID_REQUEST`       |
/// | glossary not found            | 404    | `GLOSSARY_NOT_FOUND`    |
/// | DeepL rejected the key (403)  | 401    | `DEEPL_AUTH_FAILED`     |
/// | quota exceeded (456)          | 429    | `DEEPL_QUOTA_EXCEEDED`  |
/// | too many requests (429)       | 429    | `DEEPL_RATE_LIMITED`    |
/// | anything else                 | 502    | `DEEPL_SERVICE_ERROR`   |
pub fn service_error_response(error: &DeepLError, service: &str) -> Response {
    tracing::error!("❌ {service} error: {}", error.message());
    match error {
        DeepLError::Invalid(message) => json_response(
            StatusCode::BAD_REQUEST,
            &json!({ "error": message, "code": "INVALID_REQUEST" }),
        ),
        DeepLError::GlossaryNotFound(_) => json_response(
            StatusCode::NOT_FOUND,
            &json!({ "error": "Glossary not found", "code": "GLOSSARY_NOT_FOUND" }),
        ),
        DeepLError::Authorization(_) => json_response(
            StatusCode::UNAUTHORIZED,
            &json!({
                "error": "The DeepL API key configured in the proxy was rejected",
                "code": "DEEPL_AUTH_FAILED"
            }),
        ),
        DeepLError::QuotaExceeded(_) => json_response(
            StatusCode::TOO_MANY_REQUESTS,
            &json!({ "error": "DeepL quota exceeded", "code": "DEEPL_QUOTA_EXCEEDED" }),
        ),
        DeepLError::TooManyRequests(_) => json_response(
            StatusCode::TOO_MANY_REQUESTS,
            &json!({
                "error": "DeepL is receiving too many requests",
                "code": "DEEPL_RATE_LIMITED"
            }),
        ),
        DeepLError::Other(_) => json_response(
            StatusCode::BAD_GATEWAY,
            &json!({
                "error": format!("{service} service request failed"),
                "code": "DEEPL_SERVICE_ERROR"
            }),
        ),
    }
}

/// Error type returned by the route handlers.
#[derive(Debug)]
pub enum ProxyError {
    /// An explicit `status` + JSON body, e.g. `400 {"error":"Invalid texts"}`.
    Json(StatusCode, Value),
    /// A DeepL/validation error to be mapped by [`service_error_response`];
    /// the string is the service label used in logs and error messages
    /// ("Translation", "Usage", "Glossary", ...).
    Service(DeepLError, &'static str),
}

impl ProxyError {
    /// `{ "error": message }` with the given status.
    pub fn message(status: StatusCode, message: impl Into<String>) -> Self {
        ProxyError::Json(status, json!({ "error": message.into() }))
    }

    /// 400 with a plain message (the most common shape in the original).
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::message(StatusCode::BAD_REQUEST, message)
    }

    /// The Express error handler's catch-all: `400 {"error":"Invalid request"}`.
    pub fn invalid_request() -> Self {
        Self::bad_request("Invalid request")
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        match self {
            ProxyError::Json(status, body) => json_response(status, &body),
            ProxyError::Service(error, service) => service_error_response(&error, service),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_json(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Port of "keeps proxy authentication distinct from DeepL authentication".
    #[tokio::test]
    async fn keeps_proxy_authentication_distinct_from_deepl_authentication() {
        let response = service_error_response(&DeepLError::Authorization("rejected".into()), "Translation");
        let (status, body) = body_json(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "DEEPL_AUTH_FAILED");
    }

    #[tokio::test]
    async fn maps_every_error_kind() {
        let cases = [
            (DeepLError::Invalid("bad".into()), 400, "INVALID_REQUEST"),
            (DeepLError::GlossaryNotFound("x".into()), 404, "GLOSSARY_NOT_FOUND"),
            (DeepLError::QuotaExceeded("x".into()), 429, "DEEPL_QUOTA_EXCEEDED"),
            (DeepLError::TooManyRequests("x".into()), 429, "DEEPL_RATE_LIMITED"),
            (DeepLError::Other("x".into()), 502, "DEEPL_SERVICE_ERROR"),
        ];
        for (error, status, code) in cases {
            let (actual_status, body) = body_json(service_error_response(&error, "Glossary")).await;
            assert_eq!(actual_status.as_u16(), status);
            assert_eq!(body["code"], code);
        }
    }

    #[tokio::test]
    async fn json_responses_carry_a_charset() {
        let response = json_response(StatusCode::OK, &json!({"a": 1}));
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
    }
}
