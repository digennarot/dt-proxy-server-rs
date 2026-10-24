//! Request validation and response serialisation for glossaries, languages and
//! translation options.
//!
//! Port of these helpers from the original `server.js`:
//! `GLOSSARY_LIMITS`, `validateLanguageCode`, `normalizeFormality`,
//! `parseEntries`, `parseDictionary`, `parseDictionaries`, `serializeGlossary`,
//! `serializeLanguage`.
//!
//! All validators operate on `serde_json::Value` rather than typed structs on
//! purpose: the original checks JavaScript types dynamically
//! (`typeof x === "string"`, truthiness, ...) and the exact failure messages
//! are part of the API. A typed `serde` model would reject malformed payloads
//! with different status codes and messages.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::deepl::{DeepLError, DictionaryInput, GlossaryInfo, Language};
use crate::util::{js_len, js_trim, js_truthy};

/// Limits applied to glossary requests (`GLOSSARY_LIMITS`).
pub struct GlossaryLimits {
    pub max_dictionaries: usize,
    pub max_entries: usize,
    pub max_term_length: usize,
    pub max_total_term_characters: usize,
    pub max_name_length: usize,
}

pub const GLOSSARY_LIMITS: GlossaryLimits = GlossaryLimits {
    max_dictionaries: 20,
    max_entries: 10_000,
    max_term_length: 1024,
    max_total_term_characters: 1_000_000,
    max_name_length: 200,
};

/// `new TypeError(message)` in the original: reported as HTTP 400.
fn invalid(message: impl Into<String>) -> DeepLError {
    DeepLError::Invalid(message.into())
}

static LANGUAGE_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$").unwrap());

/// `validateLanguageCode`: shape check + upper-casing.
pub fn validate_language_code(value: Option<&Value>, field: &str) -> Result<String, DeepLError> {
    match value.and_then(Value::as_str) {
        Some(code) if LANGUAGE_CODE.is_match(code) => Ok(code.to_uppercase()),
        _ => Err(invalid(format!("Invalid {field}"))),
    }
}

/// `normalizeFormality`: absent / `null` / `""` mean `"default"`.
pub fn normalize_formality(value: Option<&Value>) -> Result<String, DeepLError> {
    const ALLOWED: [&str; 5] = ["default", "more", "less", "prefer_more", "prefer_less"];
    match value {
        None | Some(Value::Null) => Ok("default".to_owned()),
        Some(Value::String(text)) if text.is_empty() => Ok("default".to_owned()),
        Some(Value::String(text)) if ALLOWED.contains(&text.as_str()) => Ok(text.clone()),
        Some(_) => Err(invalid("Invalid formality")),
    }
}

/// `GlossaryEntries.toTsv()` including the SDK's term validation.
///
/// A term containing control characters makes the SDK throw a generic
/// `DeepLError` (not a `TypeError`), so the proxy answers 502 for it — this
/// port keeps that behaviour by returning [`DeepLError::Other`].
pub fn entries_to_tsv(entries: &[(String, String)]) -> Result<String, DeepLError> {
    fn validate_term(term: &str) -> Result<(), DeepLError> {
        if term.is_empty() {
            return Err(DeepLError::Other(format!("'{term}' is not a valid term.")));
        }
        for c in term.chars() {
            let code = c as u32;
            // C0 and C1 control characters and the Unicode line separators.
            if code <= 31 || (128..=159).contains(&code) || code == 0x2028 || code == 0x2029 {
                return Err(DeepLError::Other(format!(
                    "Term '{term}' contains invalid character: '{c}' ({code})"
                )));
            }
        }
        Ok(())
    }
    let mut lines = Vec::with_capacity(entries.len());
    for (source, target) in entries {
        validate_term(source)?;
        validate_term(target)?;
        lines.push(format!("{source}\t{target}"));
    }
    Ok(lines.join("\n"))
}

/// `parseEntries`: validates `[{source, target}, ...]` and returns the ordered
/// (trimmed) pairs.
pub fn parse_entries(entries: Option<&Value>) -> Result<Vec<(String, String)>, DeepLError> {
    let list = match entries.and_then(Value::as_array) {
        Some(list) if !list.is_empty() => list,
        _ => return Err(invalid("Glossary entries must be a non-empty array")),
    };
    if list.len() > GLOSSARY_LIMITS.max_entries {
        return Err(invalid(format!(
            "A glossary dictionary cannot contain more than {} entries",
            GLOSSARY_LIMITS.max_entries
        )));
    }

    let mut parsed = Vec::with_capacity(list.len());
    let mut sources = HashSet::new();
    let mut total_characters = 0usize;
    for entry in list {
        let (source, target) = match (
            entry.get("source").and_then(Value::as_str),
            entry.get("target").and_then(Value::as_str),
        ) {
            (Some(source), Some(target)) => (js_trim(source), js_trim(target)),
            _ => {
                return Err(invalid(
                    "Every glossary entry must contain source and target strings",
                ))
            }
        };
        if source.is_empty() || target.is_empty() {
            return Err(invalid("Glossary terms must not be empty"));
        }
        // JavaScript `.length` counts UTF-16 code units.
        if js_len(source) > GLOSSARY_LIMITS.max_term_length
            || js_len(target) > GLOSSARY_LIMITS.max_term_length
        {
            return Err(invalid(format!(
                "Glossary terms must not exceed {} characters",
                GLOSSARY_LIMITS.max_term_length
            )));
        }
        total_characters += js_len(source) + js_len(target);
        if total_characters > GLOSSARY_LIMITS.max_total_term_characters {
            return Err(invalid(format!(
                "Glossary terms must not exceed {} characters in total",
                GLOSSARY_LIMITS.max_total_term_characters
            )));
        }
        // Duplicate detection is case-insensitive (`toLocaleLowerCase()`).
        if !sources.insert(source.to_lowercase()) {
            return Err(invalid(format!("Duplicate glossary source term: {source}")));
        }
        parsed.push((source.to_owned(), target.to_owned()));
    }
    // The original calls `toTsv()` here purely to validate the terms.
    entries_to_tsv(&parsed)?;
    Ok(parsed)
}

/// `parseDictionary`: one `{source_lang, target_lang, entries}` object.
pub fn parse_dictionary(dictionary: &Value) -> Result<DictionaryInput, DeepLError> {
    let object = match dictionary {
        Value::Object(_) | Value::Array(_) => dictionary,
        _ => return Err(invalid("Invalid glossary dictionary")),
    };
    let source_lang_code = validate_language_code(object.get("source_lang"), "source_lang")?;
    let target_lang_code = validate_language_code(object.get("target_lang"), "target_lang")?;
    let entries = parse_entries(object.get("entries"))?;
    Ok(DictionaryInput {
        source_lang_code,
        target_lang_code,
        entries_tsv: entries_to_tsv(&entries)?,
    })
}

/// True when the body carries any glossary dictionary data (the condition the
/// original spells `body.dictionaries || body.source_lang || ...`).
pub fn has_dictionary_fields(body: &Map<String, Value>) -> bool {
    js_truthy(body.get("dictionaries"))
        || js_truthy(body.get("source_lang"))
        || js_truthy(body.get("target_lang"))
        || js_truthy(body.get("entries"))
}

/// `parseDictionaries`: accepts either `dictionaries: [...]` or the
/// single-dictionary shorthand (`source_lang`, `target_lang`, `entries` at the
/// top level).
pub fn parse_dictionaries(body: &Map<String, Value>) -> Result<Vec<DictionaryInput>, DeepLError> {
    let shorthand;
    let dictionaries: Option<&Value> = if js_truthy(body.get("dictionaries")) {
        body.get("dictionaries")
    } else if js_truthy(body.get("source_lang"))
        || js_truthy(body.get("target_lang"))
        || js_truthy(body.get("entries"))
    {
        let mut single = Map::new();
        for key in ["source_lang", "target_lang", "entries"] {
            if let Some(value) = body.get(key) {
                single.insert(key.to_owned(), value.clone());
            }
        }
        shorthand = Value::Array(vec![Value::Object(single)]);
        Some(&shorthand)
    } else {
        None
    };

    let list = match dictionaries.and_then(Value::as_array) {
        Some(list) if !list.is_empty() => list,
        _ => return Err(invalid("At least one glossary dictionary is required")),
    };
    if list.len() > GLOSSARY_LIMITS.max_dictionaries {
        return Err(invalid(format!(
            "A glossary cannot contain more than {} dictionaries",
            GLOSSARY_LIMITS.max_dictionaries
        )));
    }
    list.iter().map(parse_dictionary).collect()
}

/// Validates a glossary name from a request and returns it trimmed.
///
/// `Err` carries the exact `{"error": ...}` message of the original, which
/// answers these cases with a plain 400 (no `code` field).
pub fn validate_glossary_name(value: Option<&Value>, missing_message: &str) -> Result<String, String> {
    let name = match value.and_then(Value::as_str) {
        Some(name) if !js_trim(name).is_empty() => js_trim(name),
        _ => return Err(missing_message.to_owned()),
    };
    if js_len(name) > GLOSSARY_LIMITS.max_name_length {
        return Err(format!(
            "Glossary name must not exceed {} characters",
            GLOSSARY_LIMITS.max_name_length
        ));
    }
    Ok(name.to_owned())
}

/// `serializeGlossary`: the SDK object -> the proxy's snake_case contract.
pub fn serialize_glossary(glossary: &GlossaryInfo) -> Value {
    json!({
        "glossary_id": glossary.glossary_id,
        "name": glossary.name,
        "creation_time": glossary.creation_time,
        "dictionaries": glossary.dictionaries.iter().map(|dictionary| json!({
            "source_lang": dictionary.source_lang,
            "target_lang": dictionary.target_lang,
            "entry_count": dictionary.entry_count,
        })).collect::<Vec<_>>(),
    })
}

/// `serializeLanguage`.
pub fn serialize_language(language: &Language) -> Value {
    let mut object = Map::new();
    object.insert("language".to_owned(), json!(language.code));
    object.insert("name".to_owned(), json!(language.name));
    if let Some(supports_formality) = language.supports_formality {
        object.insert("supports_formality".to_owned(), json!(supports_formality));
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deepl::DictionaryInfo;

    fn error_message(result: Result<impl std::fmt::Debug, DeepLError>) -> String {
        result.unwrap_err().message().to_owned()
    }

    /// Port of "treats null formality as absent and rejects unknown values".
    #[test]
    fn normalizes_formality() {
        assert_eq!(normalize_formality(None).unwrap(), "default");
        assert_eq!(normalize_formality(Some(&json!(null))).unwrap(), "default");
        assert_eq!(normalize_formality(Some(&json!(""))).unwrap(), "default");
        assert_eq!(normalize_formality(Some(&json!("prefer_more"))).unwrap(), "prefer_more");
        assert!(error_message(normalize_formality(Some(&json!("formal-ish")))).contains("Invalid formality"));
        assert!(normalize_formality(Some(&json!(3))).is_err());
    }

    /// Port of "normalizes glossary language codes and entries".
    #[test]
    fn normalizes_glossary_language_codes_and_entries() {
        let dictionary = parse_dictionary(&json!({
            "source_lang": "en",
            "target_lang": "fr",
            "entries": [{"source": " Saving Throw ", "target": " Jet de sauvegarde "}]
        }))
        .unwrap();
        assert_eq!(dictionary.source_lang_code, "EN");
        assert_eq!(dictionary.target_lang_code, "FR");
        assert_eq!(dictionary.entries_tsv, "Saving Throw\tJet de sauvegarde");
    }

    /// Port of "accepts the shorthand single-dictionary request".
    #[test]
    fn accepts_the_shorthand_single_dictionary_request() {
        let body = json!({
            "source_lang": "EN",
            "target_lang": "FR",
            "entries": [{"source": "Armor Class", "target": "Classe d’armure"}]
        });
        let dictionaries = parse_dictionaries(body.as_object().unwrap()).unwrap();
        assert_eq!(dictionaries.len(), 1);
    }

    /// Port of "rejects duplicate and empty source terms".
    #[test]
    fn rejects_duplicate_and_empty_source_terms() {
        let duplicate = |a: &str, b: &str| {
            parse_dictionary(&json!({
                "source_lang": "EN", "target_lang": "FR",
                "entries": [{"source": a, "target": "x"}, {"source": b, "target": "y"}]
            }))
        };
        assert!(error_message(duplicate("Spell Slot", "Spell Slot")).contains("Duplicate glossary source term"));
        assert!(error_message(duplicate("Spell", "spell")).contains("Duplicate glossary source term"));
        let empty = parse_dictionary(&json!({
            "source_lang": "EN", "target_lang": "FR",
            "entries": [{"source": " ", "target": "Vide"}]
        }));
        assert!(error_message(empty).contains("must not be empty"));
    }

    /// Port of "validates language codes".
    #[test]
    fn validates_language_codes() {
        let code = |text: &str| validate_language_code(Some(&json!(text)), "source_lang");
        assert_eq!(code("en-us").unwrap(), "EN-US");
        assert_eq!(code("es-419").unwrap(), "ES-419");
        assert_eq!(code("zh-Hans").unwrap(), "ZH-HANS");
        assert!(error_message(code("english")).contains("Invalid source_lang"));
        assert!(validate_language_code(None, "x").is_err());
    }

    /// Port of "enforces dedicated glossary limits".
    #[test]
    fn enforces_glossary_limits() {
        let long_term = "x".repeat(GLOSSARY_LIMITS.max_term_length + 1);
        let result = parse_dictionary(&json!({
            "source_lang": "EN", "target_lang": "FR",
            "entries": [{"source": long_term, "target": "Test"}]
        }));
        assert!(error_message(result).contains("must not exceed"));

        let dictionary = json!({
            "source_lang": "EN", "target_lang": "FR",
            "entries": [{"source": "One", "target": "Un"}]
        });
        let body = json!({ "dictionaries": vec![dictionary; GLOSSARY_LIMITS.max_dictionaries + 1] });
        assert!(error_message(parse_dictionaries(body.as_object().unwrap())).contains("cannot contain more"));
    }

    #[test]
    fn counts_term_length_in_utf16_units() {
        // 513 emoji = 1026 UTF-16 units > 1024, although only 513 `char`s.
        let term = "😀".repeat(513);
        let result = parse_dictionary(&json!({
            "source_lang": "EN", "target_lang": "FR",
            "entries": [{"source": term, "target": "ok"}]
        }));
        assert!(error_message(result).contains("must not exceed"));
    }

    #[test]
    fn control_characters_are_reported_as_service_errors() {
        // Mirrors the SDK throwing a plain DeepLError (-> HTTP 502).
        let result = parse_dictionary(&json!({
            "source_lang": "EN", "target_lang": "FR",
            "entries": [{"source": "bad\u{0001}term", "target": "ok"}]
        }));
        assert!(matches!(result, Err(DeepLError::Other(_))));
    }

    #[test]
    fn requires_a_dictionary() {
        let body = json!({});
        assert!(error_message(parse_dictionaries(body.as_object().unwrap()))
            .contains("At least one glossary dictionary is required"));
        let body = json!({ "dictionaries": [] });
        assert!(parse_dictionaries(body.as_object().unwrap()).is_err());
    }

    /// Port of "serializes supported languages for the module".
    #[test]
    fn serializes_languages() {
        let language = Language {
            code: "EN-US".to_owned(),
            name: "English (American)".to_owned(),
            supports_formality: Some(false),
        };
        assert_eq!(
            serialize_language(&language),
            json!({"language": "EN-US", "name": "English (American)", "supports_formality": false})
        );
        let without = Language { supports_formality: None, ..language };
        assert!(serialize_language(&without).get("supports_formality").is_none());
    }

    /// Port of "serializes the DeepL SDK glossary shape as the proxy contract".
    #[test]
    fn serializes_glossaries() {
        let glossary = GlossaryInfo {
            glossary_id: json!("glossary-1"),
            name: json!("D&D 5e — EN to FR"),
            creation_time: Some("2026-07-18T20:00:00.000Z".to_owned()),
            dictionaries: vec![DictionaryInfo {
                source_lang: json!("en"),
                target_lang: json!("fr"),
                entry_count: json!(3),
            }],
        };
        assert_eq!(
            serialize_glossary(&glossary),
            json!({
                "glossary_id": "glossary-1",
                "name": "D&D 5e — EN to FR",
                "creation_time": "2026-07-18T20:00:00.000Z",
                "dictionaries": [{"source_lang": "en", "target_lang": "fr", "entry_count": 3}]
            })
        );
    }

    #[test]
    fn validates_glossary_names() {
        assert_eq!(validate_glossary_name(Some(&json!("  Name ")), "x").unwrap(), "Name");
        assert!(validate_glossary_name(Some(&json!("   ")), "required").is_err());
        assert!(validate_glossary_name(None, "required").is_err());
        let long = "n".repeat(GLOSSARY_LIMITS.max_name_length + 1);
        assert!(validate_glossary_name(Some(&json!(long)), "required")
            .unwrap_err()
            .contains("must not exceed"));
    }
}
