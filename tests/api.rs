//! End-to-end tests of the proxy API: translation, caching, usage, languages,
//! glossaries, DeepL error mapping, retries, limits.

mod common;

use std::time::Duration;

use common::{read, Harness, Options, DEEPL_KEY};
use reqwest::Method;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// /health, /identity, 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_is_public_and_reports_the_configuration() {
    let h = Harness::start().await;
    // No Origin, no token: /health is exempt from both.
    let (status, headers, body) = read(h.bare(Method::GET, "/health").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({
            "status": "ok",
            "cache_size": 0,
            "tls": false,
            "deployment_mode": "local",
            "public_url": null,
            "loopback_only": true
        })
    );
    assert_eq!(headers["content-type"], "application/json; charset=utf-8");
    assert_eq!(headers["cache-control"], "no-cache");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["permissions-policy"], "camera=(), microphone=(), geolocation=()");
    assert!(headers.get("x-powered-by").is_none());
}

#[tokio::test]
async fn identity_exposes_the_tenant_and_the_plan() {
    let h = Harness::start().await;
    let (status, headers, body) = read(h.get("/identity").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({ "account_id": "account_test", "account_type": "free" }));
    assert_eq!(headers["cache-control"], "no-store");
}

#[tokio::test]
async fn unknown_routes_answer_like_express_once_authenticated() {
    let h = Harness::start().await;
    let (status, headers, body) = read(h.get("/does-not-exist").send().await.unwrap()).await;
    assert_eq!(status, 404);
    assert!(headers["content-type"].to_str().unwrap().starts_with("text/html"));
    assert!(body.as_str().unwrap().contains("Cannot GET /does-not-exist"));
    // Unauthenticated callers cannot probe routes: they get 401, not 404.
    let (status, _, _) = read(
        h.bare(Method::GET, "/does-not-exist").header("Origin", common::ORIGIN).send().await.unwrap(),
    )
    .await;
    assert_eq!(status, 401);
}

// ---------------------------------------------------------------------------
// /translate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn translates_in_one_batch_and_sends_the_expected_deepl_request() {
    let h = Harness::start().await;
    let (status, body) = h
        .translate(json!({ "texts": ["Hello world", "<p>Some HTML</p>"], "target_lang": "FR", "formality": "default" }))
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({ "translations": [{ "text": "[fr] Hello world" }, { "text": "[fr] <p>Some HTML</p>" }] })
    );

    let calls = h.mock.calls();
    assert_eq!(calls.len(), 1, "both texts travel in a single DeepL call");
    let call = &calls[0];
    assert_eq!((call.method.as_str(), call.target.as_str()), ("POST", "/v2/translate"));
    // The key never reaches Foundry but is what authenticates the upstream call.
    assert_eq!(call.authorization.as_deref(), Some(format!("DeepL-Auth-Key {DEEPL_KEY}").as_str()));
    assert_eq!(call.content_type.as_deref(), Some("application/x-www-form-urlencoded"));
    assert_eq!(call.field("target_lang"), Some("fr"), "codes are normalised like the SDK does");
    assert_eq!(call.field("source_lang"), None);
    assert_eq!(call.field("formality"), Some("default"));
    assert_eq!(call.field("tag_handling"), Some("html"));
    assert_eq!(call.field("show_billed_characters"), Some("1"));
    assert_eq!(call.fields("text"), vec!["Hello world", "<p>Some HTML</p>"]);
}

#[tokio::test]
async fn forwards_source_language_formality_and_glossary() {
    let h = Harness::start().await;
    let (status, _) = h
        .translate(json!({
            "texts": ["Armor Class"], "source_lang": "EN", "target_lang": "fr",
            "glossary_id": "g-1", "formality": "prefer_more"
        }))
        .await;
    assert_eq!(status, 200);
    let call = &h.mock.calls()[0];
    assert_eq!(call.field("source_lang"), Some("en"));
    assert_eq!(call.field("target_lang"), Some("fr"));
    assert_eq!(call.field("glossary_id"), Some("g-1"));
    assert_eq!(call.field("formality"), Some("prefer_more"));
    // Regional variants keep their region upper-cased.
    h.translate(json!({ "texts": ["x"], "target_lang": "en-us" })).await;
    assert_eq!(h.mock.calls()[1].field("target_lang"), Some("en-US"));
}

#[tokio::test]
async fn caches_translations_and_only_asks_deepl_for_the_missing_texts() {
    let h = Harness::start().await;
    let request = |texts: Value| json!({ "texts": texts, "target_lang": "FR" });

    let (_, first) = h.translate(request(json!(["a", "b"]))).await;
    assert_eq!(h.mock.call_count(), 1);

    // Same texts again: served from the cache, DeepL is not called.
    let (_, second) = h.translate(request(json!(["a", "b"]))).await;
    assert_eq!(first, second);
    assert_eq!(h.mock.call_count(), 1);

    // Partially cached: only the new text is sent, order is preserved.
    let (_, third) = h.translate(request(json!(["a", "c", "b"]))).await;
    assert_eq!(h.mock.call_count(), 2);
    assert_eq!(h.mock.calls()[1].fields("text"), vec!["c"]);
    assert_eq!(
        third,
        json!({ "translations": [{"text": "[fr] a"}, {"text": "[fr] c"}, {"text": "[fr] b"}] })
    );

    let (_, _, health) = read(h.bare(Method::GET, "/health").send().await.unwrap()).await;
    assert_eq!(health["cache_size"], 3);
}

#[tokio::test]
async fn cache_entries_are_separated_by_language_formality_glossary_and_source() {
    let h = Harness::start().await;
    h.translate(json!({ "texts": ["hi"], "target_lang": "FR" })).await;
    h.translate(json!({ "texts": ["hi"], "target_lang": "DE" })).await;
    h.translate(json!({ "texts": ["hi"], "target_lang": "FR", "formality": "more" })).await;
    h.translate(json!({ "texts": ["hi"], "target_lang": "FR", "source_lang": "EN" })).await;
    h.translate(json!({ "texts": ["hi"], "target_lang": "FR", "source_lang": "EN", "glossary_id": "g" })).await;
    assert_eq!(h.mock.call_count(), 5, "no variant may be served from another variant's cache entry");
    // Null / empty formality is the same as "default".
    h.translate(json!({ "texts": ["hi"], "target_lang": "FR", "formality": null })).await;
    h.translate(json!({ "texts": ["hi"], "target_lang": "FR", "formality": "" })).await;
    assert_eq!(h.mock.call_count(), 5);
}

#[tokio::test]
async fn translate_validates_its_input() {
    let h = Harness::start().await;
    let long_text = "x".repeat(50_000);
    let cases: Vec<(Value, u16, &str)> = vec![
        (json!({}), 400, "Invalid texts"),
        (json!({ "texts": [], "target_lang": "FR" }), 400, "Invalid texts"),
        (json!({ "texts": "hello", "target_lang": "FR" }), 400, "Invalid texts"),
        (json!({ "texts": ["a", 1], "target_lang": "FR" }), 400, "Every text must be a string"),
        (json!({ "texts": ["a"] }), 400, "Invalid target_lang"),
        (json!({ "texts": ["a"], "target_lang": 5 }), 400, "Invalid target_lang"),
        (json!({ "texts": ["a"], "target_lang": "FR", "source_lang": 5 }), 400, "Invalid source_lang"),
        (json!({ "texts": ["a"], "target_lang": "FR", "source_lang": null }), 400, "Invalid source_lang"),
        (json!({ "texts": ["a"], "target_lang": "FR", "glossary_id": "" }), 400, "Invalid glossary_id"),
        (json!({ "texts": ["a"], "target_lang": "FR", "glossary_id": "  " }), 400, "Invalid glossary_id"),
        (json!({ "texts": ["a"], "target_lang": "FR", "glossary_id": 7 }), 400, "Invalid glossary_id"),
        (
            json!({ "texts": ["a"], "target_lang": "FR", "glossary_id": "g" }),
            400,
            "source_lang is required with glossary_id",
        ),
        (
            json!({ "texts": ["a"], "target_lang": "FR", "glossary_id": "g", "source_lang": "" }),
            400,
            "source_lang is required with glossary_id",
        ),
        (json!({ "texts": vec!["a"; 301], "target_lang": "FR" }), 400, "Too many texts"),
        (
            json!({ "texts": [long_text.clone(), long_text.clone(), long_text.clone()], "target_lang": "FR" }),
            400,
            "Payload too large",
        ),
    ];
    for (body, expected_status, expected_error) in cases {
        let (status, value) = h.translate(body.clone()).await;
        assert_eq!(status, expected_status, "{body}");
        assert_eq!(value["error"], expected_error, "{body}");
        assert!(value.get("code").is_none(), "plain validation errors carry no code: {body}");
    }
    // Formality is validated by the shared TypeError path, which has a code.
    let (status, value) = h.translate(json!({ "texts": ["a"], "target_lang": "FR", "formality": "formal-ish" })).await;
    assert_eq!((status, value["code"].as_str(), value["error"].as_str()), (400, Some("INVALID_REQUEST"), Some("Invalid formality")));
    assert_eq!(h.mock.call_count(), 0, "nothing invalid ever reaches DeepL");
}

#[tokio::test]
async fn the_payload_limit_counts_utf16_code_units() {
    let h = Harness::start().await;
    // 3 x 20,001 emoji = 120,006 UTF-16 units (> 120,000) but only 60,003 chars.
    let emoji = "😀".repeat(20_001);
    let (status, value) = h.translate(json!({ "texts": [emoji.clone(), emoji.clone(), emoji], "target_lang": "FR" })).await;
    assert_eq!((status, value["error"].as_str()), (400, Some("Payload too large")));
    // Exactly at the limit is accepted.
    let ok = "x".repeat(40_000);
    let (status, _) = h.translate(json!({ "texts": [ok.clone(), ok.clone(), ok], "target_lang": "FR" })).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn request_bodies_must_be_json() {
    let h = Harness::start().await;
    // Malformed JSON / scalar JSON: the global handler's generic answer.
    for body in ["{not json", "42", "\"text\""] {
        let (status, _, value) = read(
            h.post("/translate").header("Content-Type", "application/json").body(body).send().await.unwrap(),
        )
        .await;
        assert_eq!((status, value["error"].as_str()), (400, Some("Invalid request")), "{body}");
    }
    // Wrong content type: the body is never parsed.
    let (status, _, value) = read(
        h.post("/translate").header("Content-Type", "text/plain").body("{}").send().await.unwrap(),
    )
    .await;
    assert_eq!((status, value["code"].as_str()), (400, Some("INVALID_REQUEST")));
    // An empty JSON body is `{}`.
    let (status, _, value) = read(
        h.post("/translate").header("Content-Type", "application/json").body("").send().await.unwrap(),
    )
    .await;
    assert_eq!((status, value["error"].as_str()), (400, Some("Invalid texts")));
}

#[tokio::test]
async fn bodies_over_ten_megabytes_are_rejected() {
    let h = Harness::start().await;
    let big = format!("{{\"texts\":[\"{}\"],\"target_lang\":\"FR\"}}", "x".repeat(10 * 1024 * 1024 + 16));
    let (status, _, value) = read(
        h.post("/translate").header("Content-Type", "application/json").body(big).send().await.unwrap(),
    )
    .await;
    assert_eq!((status, value["error"].as_str()), (400, Some("Invalid request")));
}

/// The SDK (not DeepL) rejects these, and the proxy reports SDK errors that are
/// not `TypeError`/`ArgumentError` as a 502 — behaviour kept from the original.
#[tokio::test]
async fn sdk_level_rejections_surface_as_502_like_in_the_original() {
    let h = Harness::start().await;
    for body in [
        json!({ "texts": ["a"], "target_lang": "EN" }),
        json!({ "texts": ["a"], "target_lang": "PT" }),
        json!({ "texts": [""], "target_lang": "FR" }),
    ] {
        let (status, value) = h.translate(body.clone()).await;
        assert_eq!(status, 502, "{body}");
        assert_eq!(value, json!({ "error": "Translation service request failed", "code": "DEEPL_SERVICE_ERROR" }));
    }
    assert_eq!(h.mock.call_count(), 0);
}

// ---------------------------------------------------------------------------
// DeepL error mapping and retries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn maps_deepl_failures_to_the_proxy_error_contract() {
    let h = Harness::start().await;
    let translate = |text: &'static str| h.translate(json!({ "texts": [text], "target_lang": "FR" }));

    h.mock.force_statuses(&[403]);
    let (status, body) = translate("one").await;
    assert_eq!(status, 401);
    assert_eq!(body["code"], "DEEPL_AUTH_FAILED");
    assert_eq!(body["error"], "The DeepL API key configured in the proxy was rejected");
    assert_eq!(h.mock.call_count(), 1, "authentication failures are not retried");

    h.mock.clear();
    h.mock.force_statuses(&[456]);
    let (status, body) = translate("two").await;
    assert_eq!((status, body["code"].as_str()), (429, Some("DEEPL_QUOTA_EXCEEDED")));
    assert_eq!(h.mock.call_count(), 1);

    h.mock.clear();
    h.mock.force_statuses(&[400]);
    let (status, body) = translate("three").await;
    assert_eq!((status, body["code"].as_str()), (502, Some("DEEPL_SERVICE_ERROR")));
    assert_eq!(h.mock.call_count(), 1, "client errors are not retried");

    // Nothing failed was cached.
    h.mock.clear();
    let (status, _) = translate("one").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn retries_429_and_5xx_with_the_sdk_attempt_budget() {
    let h = Harness::start().await;

    // Rate-limited five times in a row: the SDK gives up after 5 attempts.
    h.mock.force_statuses(&[429; 5]);
    let (status, body) = h.translate(json!({ "texts": ["a"], "target_lang": "FR" })).await;
    assert_eq!((status, body["code"].as_str()), (429, Some("DEEPL_RATE_LIMITED")));
    assert_eq!(h.mock.call_count(), 5);

    // A transient failure that clears up is invisible to the caller.
    h.mock.clear();
    h.mock.force_statuses(&[503, 500]);
    let (status, body) = h.translate(json!({ "texts": ["b"], "target_lang": "FR" })).await;
    assert_eq!(status, 200);
    assert_eq!(body["translations"][0]["text"], "[fr] b");
    assert_eq!(h.mock.call_count(), 3);

    // Persistent 5xx: five attempts, then a 502.
    h.mock.clear();
    h.mock.force_statuses(&[500; 5]);
    let (status, body) = h.translate(json!({ "texts": ["c"], "target_lang": "FR" })).await;
    assert_eq!((status, body["code"].as_str()), (502, Some("DEEPL_SERVICE_ERROR")));
    assert_eq!(h.mock.call_count(), 5);
}

#[tokio::test]
async fn an_unreachable_deepl_is_a_502_without_retries() {
    // Point the proxy at a closed port: connection errors are not retried.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = listener.local_addr().unwrap();
    drop(listener);
    let h = Harness::start().await;
    let factory = dt_proxy_server::deepl::DeepLFactory::new(Some(format!("http://{dead}")), common::fast_retry());
    let client = factory.client("k:fx").unwrap();
    let error = client.get_usage().await.unwrap_err();
    assert!(error.message().starts_with("Connection failure"), "{error}");
    drop(h);
}

#[tokio::test]
async fn at_most_five_upstream_translations_run_at_once() {
    let h = std::sync::Arc::new(Harness::start().await);
    h.mock.set_delay(Duration::from_millis(600));
    let mut tasks = Vec::new();
    for index in 0..7 {
        let h = h.clone();
        tasks.push(tokio::spawn(async move {
            h.translate(json!({ "texts": [format!("text {index}")], "target_lang": "FR" })).await
        }));
    }
    let mut ok = 0;
    let mut busy = 0;
    for task in tasks {
        let (status, body) = task.await.unwrap();
        match status {
            200 => ok += 1,
            503 => {
                busy += 1;
                assert_eq!(body, json!({ "error": "Translation service is busy" }));
            }
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!((ok, busy), (5, 2));
    // The slots are released afterwards.
    h.mock.set_delay(Duration::ZERO);
    let (status, _) = h.translate(json!({ "texts": ["after"], "target_lang": "FR" })).await;
    assert_eq!(status, 200);
    assert_eq!(h.state.active_translations(), 0);
}

// ---------------------------------------------------------------------------
// /usage, /languages, /glossary-language-pairs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn usage_reports_characters_and_plan() {
    let h = Harness::start().await;
    let (status, _, body) = read(h.get("/usage").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({ "character_count": 123, "character_limit": 500000, "account_type": "free" })
    );
    let call = &h.mock.calls()[0];
    assert_eq!((call.method.as_str(), call.target.as_str()), ("GET", "/v2/usage"));

    // A paid key talks to the paid plan and is reported as such.
    let pro = Harness::with_runtime(|runtime| runtime.secrets.deepl_api_key = "paid-key".into()).await;
    let (_, _, body) = read(pro.get("/identity").send().await.unwrap()).await;
    assert_eq!(body["account_type"], "pro");
}

#[tokio::test]
async fn languages_are_listed_by_type() {
    let h = Harness::start().await;
    let (status, _, body) = read(h.get("/languages?type=source").send().await.unwrap()).await;
    assert_eq!(status, 200);
    // The SDK lower-cases the language part: that is what Foundry receives.
    assert_eq!(
        body,
        json!({ "languages": [{"language": "en", "name": "English"}, {"language": "fr", "name": "French"}] })
    );
    assert_eq!(h.mock.calls()[0].target, "/v2/languages");

    let (status, _, body) = read(h.get("/languages?type=target").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["languages"],
        json!([
            {"language": "en-US", "name": "English (American)", "supports_formality": false},
            {"language": "fr", "name": "French", "supports_formality": true}
        ])
    );
    assert_eq!(h.mock.calls()[1].target, "/v2/languages?type=target");

    for path in ["/languages", "/languages?type=other", "/languages?type=source&type=target"] {
        let (status, _, body) = read(h.get(path).send().await.unwrap()).await;
        assert_eq!((status, body["error"].as_str()), (400, Some("type must be source or target")), "{path}");
    }
}

#[tokio::test]
async fn glossary_language_pairs_are_listed() {
    let h = Harness::start().await;
    let (status, _, body) = read(h.get("/glossary-language-pairs").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({ "language_pairs": [{ "source_lang": "en", "target_lang": "fr" }] }));
}

// ---------------------------------------------------------------------------
// glossaries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lists_glossaries_in_the_proxy_contract() {
    let h = Harness::start().await;
    let (status, _, body) = read(h.get("/glossaries").send().await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({ "glossaries": [{
            "glossary_id": "g-1", "name": "D&D", "creation_time": "2021-08-03T14:16:18.329Z",
            "dictionaries": [{ "source_lang": "en", "target_lang": "fr", "entry_count": 2 }]
        }] })
    );
}

#[tokio::test]
async fn creates_a_glossary_with_the_v3_form_encoding() {
    let h = Harness::start().await;
    let (status, _, body) = read(
        h.post("/glossaries")
            .json(&json!({
                "name": "  D&D 5e — EN to FR  ",
                "dictionaries": [{
                    "source_lang": "en", "target_lang": "fr",
                    "entries": [
                        { "source": " Saving Throw ", "target": "Jet de sauvegarde" },
                        { "source": "Armor Class", "target": "Classe d’armure" }
                    ]
                }]
            }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(body["glossary_id"], "g-new");
    assert_eq!(body["name"], "D&D 5e — EN to FR");
    assert_eq!(body["dictionaries"], json!([{ "source_lang": "en", "target_lang": "fr", "entry_count": 2 }]));

    let call = &h.mock.calls()[0];
    assert_eq!((call.method.as_str(), call.target.as_str()), ("POST", "/v3/glossaries"));
    assert_eq!(call.field("name"), Some("D&D 5e — EN to FR"));
    assert_eq!(call.field("dictionaries[0].source_lang"), Some("EN"));
    assert_eq!(call.field("dictionaries[0].target_lang"), Some("FR"));
    assert_eq!(
        call.field("dictionaries[0].entries"),
        Some("Saving Throw\tJet de sauvegarde\nArmor Class\tClasse d’armure")
    );
    assert_eq!(call.field("dictionaries[0].entries_format"), Some("tsv"));
}

#[tokio::test]
async fn creates_a_glossary_from_the_single_dictionary_shorthand() {
    let h = Harness::start().await;
    let (status, _, _) = read(
        h.post("/glossaries")
            .json(&json!({
                "name": "Short", "source_lang": "EN", "target_lang": "FR",
                "entries": [{ "source": "Spell", "target": "Sort" }]
            }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(h.mock.calls()[0].field("dictionaries[0].entries"), Some("Spell\tSort"));
}

#[tokio::test]
async fn rejects_invalid_glossary_creations_before_calling_deepl() {
    let h = Harness::start().await;
    let entry = json!([{ "source": "a", "target": "b" }]);
    let cases: Vec<(Value, u16, &str)> = vec![
        (json!({}), 400, "Glossary name is required"),
        (json!({ "name": "   ", "source_lang": "EN", "target_lang": "FR", "entries": entry }), 400, "Glossary name is required"),
        (json!({ "name": 5 }), 400, "Glossary name is required"),
        (
            json!({ "name": "n".repeat(201), "source_lang": "EN", "target_lang": "FR", "entries": entry }),
            400,
            "Glossary name must not exceed 200 characters",
        ),
        (json!({ "name": "ok" }), 400, "At least one glossary dictionary is required"),
        (json!({ "name": "ok", "source_lang": "english", "target_lang": "FR", "entries": entry }), 400, "Invalid source_lang"),
        (json!({ "name": "ok", "source_lang": "EN", "target_lang": "FR", "entries": [] }), 400, "Glossary entries must be a non-empty array"),
        (
            json!({ "name": "ok", "source_lang": "EN", "target_lang": "FR",
                    "entries": [{"source": "Spell", "target": "x"}, {"source": "spell", "target": "y"}] }),
            400,
            "Duplicate glossary source term: spell",
        ),
        (
            json!({ "name": "ok", "source_lang": "EN", "target_lang": "FR", "entries": [{"source": " ", "target": "y"}] }),
            400,
            "Glossary terms must not be empty",
        ),
        (
            json!({ "name": "ok", "source_lang": "EN", "target_lang": "FR", "entries": [{"source": "a"}] }),
            400,
            "Every glossary entry must contain source and target strings",
        ),
    ];
    for (body, status, message) in cases {
        let (actual, _, value) = read(h.post("/glossaries").json(&body).send().await.unwrap()).await;
        assert_eq!(actual, status, "{body}");
        assert_eq!(value["error"], message, "{body}");
    }
    assert_eq!(h.mock.call_count(), 0);
}

#[tokio::test]
async fn control_characters_in_terms_are_a_502_like_in_the_original() {
    let h = Harness::start().await;
    let (status, _, value) = read(
        h.post("/glossaries")
            .json(&json!({ "name": "x", "source_lang": "EN", "target_lang": "FR",
                           "entries": [{ "source": "bad\u{0007}", "target": "y" }] }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!((status, value["code"].as_str()), (502, Some("DEEPL_SERVICE_ERROR")));
}

#[tokio::test]
async fn updates_a_glossary_name_and_dictionaries_then_returns_it() {
    let h = Harness::start().await;
    let (status, _, body) = read(
        h.request(Method::PUT, "/glossaries/g-42")
            .json(&json!({
                "name": " Renamed ",
                "dictionaries": [
                    { "source_lang": "en", "target_lang": "fr", "entries": [{ "source": "a", "target": "b" }] },
                    { "source_lang": "en", "target_lang": "de", "entries": [{ "source": "c", "target": "d" }] }
                ]
            }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["glossary_id"], "g-42");

    let sequence: Vec<(String, String)> = h.mock.calls().into_iter().map(|c| (c.method, c.target)).collect();
    assert_eq!(
        sequence,
        vec![
            ("PATCH".to_owned(), "/v3/glossaries/g-42".to_owned()),
            ("PUT".to_owned(), "/v3/glossaries/g-42/dictionaries".to_owned()),
            ("PUT".to_owned(), "/v3/glossaries/g-42/dictionaries".to_owned()),
            ("GET".to_owned(), "/v3/glossaries/g-42".to_owned()),
        ]
    );
    let calls = h.mock.calls();
    assert_eq!(calls[0].field("name"), Some("Renamed"));
    assert_eq!(calls[1].field("source_lang"), Some("EN"));
    assert_eq!(calls[1].field("target_lang"), Some("FR"));
    assert_eq!(calls[1].field("entries"), Some("a\tb"));
    assert_eq!(calls[1].field("entries_format"), Some("tsv"));
    assert_eq!(calls[2].field("target_lang"), Some("DE"));
}

#[tokio::test]
async fn update_validates_before_touching_deepl() {
    let h = Harness::start().await;
    let put = |body: Value| {
        let request = h.request(Method::PUT, "/glossaries/g-1").json(&body);
        async move { read(request.send().await.unwrap()).await }
    };
    let (status, _, body) = put(json!({})).await;
    assert_eq!((status, body["error"].as_str()), (400, Some("No glossary changes supplied")));
    let (status, _, body) = put(json!({ "name": null })).await;
    assert_eq!((status, body["error"].as_str()), (400, Some("Invalid glossary name")));
    let (status, _, body) = put(json!({ "name": "  " })).await;
    assert_eq!((status, body["error"].as_str()), (400, Some("Invalid glossary name")));
    let (status, _, body) = put(json!({ "name": "n".repeat(201) })).await;
    assert_eq!(status, 400);
    assert!(body["error"].as_str().unwrap().contains("must not exceed 200"));
    // A valid rename combined with an invalid dictionary changes nothing.
    let (status, _, body) = put(json!({ "name": "ok", "dictionaries": [{ "source_lang": "x" }] })).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("INVALID_REQUEST")));
    assert_eq!(h.mock.call_count(), 0, "the rename must not have been sent");
}

#[tokio::test]
async fn deletes_glossaries_and_reports_missing_ones() {
    let h = Harness::start().await;
    let (status, _, body) = read(h.request(Method::DELETE, "/glossaries/g-1").send().await.unwrap()).await;
    assert_eq!((status, body), (204, Value::String(String::new())));
    let call = &h.mock.calls()[0];
    assert_eq!((call.method.as_str(), call.target.as_str()), ("DELETE", "/v3/glossaries/g-1"));

    let (status, _, body) = read(h.request(Method::DELETE, "/glossaries/missing").send().await.unwrap()).await;
    assert_eq!(status, 404);
    assert_eq!(body, json!({ "error": "Glossary not found", "code": "GLOSSARY_NOT_FOUND" }));
    let (status, _, body) = read(
        h.request(Method::PUT, "/glossaries/missing").json(&json!({ "name": "x" })).send().await.unwrap(),
    )
    .await;
    assert_eq!((status, body["code"].as_str()), (404, Some("GLOSSARY_NOT_FOUND")));
}

#[tokio::test]
async fn glossary_ids_cannot_escape_their_path_segment() {
    let h = Harness::start().await;
    // %2F decodes to "/" in the router; the client must re-encode it.
    let (_, _, _) = read(h.request(Method::DELETE, "/glossaries/a%2F..%2F..%2Fv2%2Fusage").send().await.unwrap()).await;
    let call = &h.mock.calls()[0];
    assert_eq!(call.target, "/v3/glossaries/a%2F..%2F..%2Fv2%2Fusage");
}

// ---------------------------------------------------------------------------
// rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limits_each_route_independently_and_exempts_health() {
    let h = Harness::with_config(|config| {
        config.rate_limits.translate = 2;
        config.rate_limits.usage = 1;
        config.rate_limits.window_ms = 60_000;
    })
    .await;
    for _ in 0..2 {
        let (status, _) = h.translate(json!({ "texts": ["a"], "target_lang": "FR" })).await;
        assert_eq!(status, 200);
    }
    let response = h.post("/translate").json(&json!({ "texts": ["a"], "target_lang": "FR" })).send().await.unwrap();
    let (status, headers, body) = read(response).await;
    assert_eq!(status, 429);
    assert_eq!(body["code"], "PROXY_RATE_LIMITED");
    assert_eq!(body["route"], "translate");
    assert_eq!(body["error"], "Too many proxy requests for translate");
    assert!(body["retry_after"].as_u64().unwrap() >= 1);
    assert!(headers["retry-after"].to_str().unwrap().parse::<u64>().unwrap() >= 1);
    // The 429 still carries CORS headers (the limiter runs after CORS).
    assert_eq!(headers["access-control-allow-origin"], common::ORIGIN);

    // Other routes have their own counters.
    assert_eq!(read(h.get("/usage").send().await.unwrap()).await.0, 200);
    assert_eq!(read(h.get("/usage").send().await.unwrap()).await.0, 429);
    assert_eq!(read(h.get("/identity").send().await.unwrap()).await.0, 200);
    // /health is never limited.
    for _ in 0..20 {
        assert_eq!(read(h.bare(Method::GET, "/health").send().await.unwrap()).await.0, 200);
    }
}

#[tokio::test]
async fn a_limit_of_zero_disables_rate_limiting() {
    let h = Harness::with_config(|config| config.rate_limits.usage = 0).await;
    for _ in 0..30 {
        assert_eq!(read(h.get("/usage").send().await.unwrap()).await.0, 200);
    }
}

#[tokio::test]
async fn unused_options_struct_default_is_usable() {
    // Guards the harness itself: Options::default() must stay constructible.
    let _ = Options::default();
}
