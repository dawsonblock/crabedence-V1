// SPDX-License-Identifier: Apache-2.0

//! Strict capability-invocation ABI scanning.
//!
//! This module is the Rust mirror of the authoritative Go parser
//! (`internal/execution/invocation_abi.go`) and the NEMO TypeScript validator
//! (`nemo/contracts/invocation-abi.ts`). All three consume the shared
//! conformance corpus
//! (`internal/execution/testdata/invocation-abi-conformance/vectors.json`) and
//! must accept or reject each raw wire request identically, with the same
//! rule-level error phrases.
//!
//! The rules:
//!
//! - R1: the request is valid UTF-8
//! - R2: exactly one JSON value; nothing follows it
//! - R3: the request is a JSON object
//! - R4: no object repeats a key
//! - R5: nesting depth is at most [`MAX_INVOCATION_DEPTH`]
//! - R6: root and `authority` keys are from the known sets
//! - R7: explicit `null` is rejected for every known field
//! - R8: known fields carry their declared JSON types
//!
//! A generic JSON parser is deliberately not used: `serde_json` (like
//! `encoding/json` and `JSON.parse`) silently takes the last value for a
//! duplicate key, ignores unknown fields, and accepts trailing data. Those are
//! exactly the ambiguities the ABI refuses.

use std::collections::HashSet;

/// Maximum container nesting depth accepted by the ABI.
pub const MAX_INVOCATION_DEPTH: usize = 64;

/// The declared JSON type of a known ABI field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    /// A JSON string.
    String,
    /// A JSON object.
    Object,
    /// A JSON integer literal that fits in a signed 64-bit integer.
    Integer,
}

/// Which known-field set governs the object currently being scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fields {
    /// The request root: the complete known-field set, nothing else.
    Root,
    /// The `authority` object: the complete known-field set, nothing else.
    Authority,
    /// The `mediation` object: the complete known-field set, nothing else.
    Mediation,
    /// An argument subtree or array: no field set applies.
    None,
}

fn root_field(name: &str) -> Option<FieldType> {
    match name {
        "capability" | "execution_class" | "idempotency_key" | "deadline" => {
            Some(FieldType::String)
        }
        "arguments" | "authority" | "mediation" => Some(FieldType::Object),
        _ => None,
    }
}

fn authority_field(name: &str) -> Option<FieldType> {
    match name {
        "principal" | "authority_ref" | "grant_id" | "authority_digest" => Some(FieldType::String),
        "authority_generation" => Some(FieldType::Integer),
        _ => None,
    }
}

fn mediation_field(name: &str) -> Option<FieldType> {
    match name {
        "middleware_set_digest"
        | "original_args_digest"
        | "release_root_digest"
        | "plugin_manifest_sha256"
        | "plugin_library_sha256"
        | "activation_config_sha256" => Some(FieldType::String),
        _ => None,
    }
}

/// Enforces field presence rules the type map cannot express: a
/// `mediation` object that omits either required digest is malformed
/// evidence — the pre-mediation argument digest is what makes the
/// mediation claim verifiable. Mirrors serde's required-field refusal
/// on `RequestMediation` and the Go parser's presence probe so all
/// validators refuse the same input with the same phrase.
fn check_required_fields(path: &str, fields: Fields, keys: &HashSet<String>) -> Result<(), String> {
    if fields == Fields::Mediation {
        for required in ["middleware_set_digest", "original_args_digest"] {
            if !keys.contains(required) {
                return Err(format!("{path}.{required} is required"));
            }
        }
    }
    Ok(())
}

fn type_error(path: &str, expected: FieldType) -> String {
    match expected {
        FieldType::String => format!("{path} must be a JSON string"),
        FieldType::Object => format!("{path} must be a JSON object"),
        FieldType::Integer => format!("{path} must be a JSON integer"),
    }
}

/// Validates one raw wire request against the strict ABI rules.
///
/// Returns `Ok(())` when the request is a well-formed invocation, or the
/// rule-level refusal phrase when it is not. The phrase is the same one the Go
/// kernel and the NEMO TypeScript validator produce for the same input.
pub fn validate_invocation_request(bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "request is not valid UTF-8".to_string())?;
    Scanner::new(text.as_bytes()).scan()
}

/// Validates one raw wire request, returning the decoded capability and
/// arguments when it is well formed.
///
/// The scanner is the authority on shape; this helper exists so a caller that
/// needs the request's content does not parse it a second time with a
/// permissive parser.
pub fn decode_invocation_request(bytes: &[u8]) -> Result<serde_json::Value, String> {
    validate_invocation_request(bytes)?;
    serde_json::from_slice(bytes).map_err(|error| format!("invalid JSON: {error}"))
}

struct Scanner<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Scanner<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    fn scan(mut self) -> Result<(), String> {
        self.skip_whitespace();
        if self.peek() != Some(b'{') {
            return Err("request must be a JSON object".to_string());
        }
        self.parse_object("request", Fields::Root, 1)?;
        self.skip_whitespace();
        if self.index < self.bytes.len() {
            return Err("trailing data after the request object".to_string());
        }
        Ok(())
    }

    fn parse_value(
        &mut self,
        path: &str,
        expected: Option<FieldType>,
        depth: usize,
        child_fields: Fields,
    ) -> Result<(), String> {
        let Some(byte) = self.peek() else {
            return Err("invalid JSON: unexpected end of input".to_string());
        };
        match byte {
            b'n' => {
                if !self.consume_literal(b"null") {
                    return Err("invalid JSON: invalid literal".to_string());
                }
                match expected {
                    None => Ok(()),
                    Some(_) => Err(format!(
                        "null is not accepted for {path} (omit the field instead)"
                    )),
                }
            }
            b'{' => {
                if let Some(expected) = expected
                    && expected != FieldType::Object
                {
                    return Err(type_error(path, expected));
                }
                if depth >= MAX_INVOCATION_DEPTH {
                    return Err(format!(
                        "request nesting exceeds {MAX_INVOCATION_DEPTH} levels"
                    ));
                }
                self.parse_object(path, child_fields, depth + 1)
            }
            b'[' => {
                if let Some(expected) = expected {
                    return Err(type_error(path, expected));
                }
                if depth >= MAX_INVOCATION_DEPTH {
                    return Err(format!(
                        "request nesting exceeds {MAX_INVOCATION_DEPTH} levels"
                    ));
                }
                self.parse_array(path, depth + 1)
            }
            b'"' => {
                if self.parse_string().is_none() {
                    return Err("invalid JSON: invalid string".to_string());
                }
                match expected {
                    None | Some(FieldType::String) => Ok(()),
                    Some(expected) => Err(type_error(path, expected)),
                }
            }
            b't' | b'f' => {
                let literal: &[u8] = if byte == b't' { b"true" } else { b"false" };
                if !self.consume_literal(literal) {
                    return Err("invalid JSON: invalid literal".to_string());
                }
                match expected {
                    None => Ok(()),
                    Some(expected) => Err(type_error(path, expected)),
                }
            }
            b'-' | b'0'..=b'9' => {
                let Some(literal) = self.parse_number() else {
                    return Err("invalid JSON: invalid number".to_string());
                };
                let Some(expected) = expected else {
                    return Ok(());
                };
                if expected != FieldType::Integer {
                    return Err(type_error(path, expected));
                }
                if !is_integer_literal(literal) {
                    return Err(format!("{path} must be a JSON integer literal"));
                }
                if literal.parse::<i64>().is_err() {
                    return Err(format!("{path} must fit in a signed 64-bit integer"));
                }
                Ok(())
            }
            _ => Err("invalid JSON: unexpected character".to_string()),
        }
    }

    fn parse_object(&mut self, path: &str, fields: Fields, depth: usize) -> Result<(), String> {
        self.index += 1; // consume '{'
        let mut keys: HashSet<String> = HashSet::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.index += 1;
            return check_required_fields(path, fields, &keys);
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err("invalid JSON: expected an object key".to_string());
            }
            let Some(key) = self.parse_string() else {
                return Err("invalid JSON: invalid string".to_string());
            };
            if !keys.insert(key.clone()) {
                return Err(format!("duplicate key {} in {path}", json_quoted(&key)));
            }
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err("invalid JSON: expected ':'".to_string());
            }
            self.index += 1;
            self.skip_whitespace();

            let expected = match fields {
                Fields::Root => root_field(&key),
                Fields::Authority => authority_field(&key),
                Fields::Mediation => mediation_field(&key),
                Fields::None => None,
            };
            if fields != Fields::None && expected.is_none() {
                return Err(format!("unknown field {} in {path}", json_quoted(&key)));
            }
            let key_path = format!("{path}.{key}");
            let child_fields = if path == "request" && key == "authority" {
                Fields::Authority
            } else if path == "request" && key == "mediation" {
                Fields::Mediation
            } else {
                Fields::None
            };
            self.parse_value(&key_path, expected, depth, child_fields)?;

            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.index += 1;
                }
                Some(b'}') => {
                    self.index += 1;
                    return check_required_fields(path, fields, &keys);
                }
                _ => return Err("invalid JSON: expected ',' or '}'".to_string()),
            }
        }
    }

    fn parse_array(&mut self, path: &str, depth: usize) -> Result<(), String> {
        self.index += 1; // consume '['
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.index += 1;
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let element_path = format!("{path}[]");
            self.parse_value(&element_path, None, depth, Fields::None)?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.index += 1;
                }
                Some(b']') => {
                    self.index += 1;
                    return Ok(());
                }
                _ => return Err("invalid JSON: expected ',' or ']'".to_string()),
            }
        }
    }

    /// Parses one JSON string, returning its decoded value.
    fn parse_string(&mut self) -> Option<String> {
        let raw = self.read_string_token()?;
        serde_json::from_slice::<String>(raw).ok()
    }

    /// Returns the raw token (with quotes) or `None` when it is not a
    /// well-formed string token.
    fn read_string_token(&mut self) -> Option<&'a [u8]> {
        let start = self.index;
        self.index += 1; // opening quote
        while self.index < self.bytes.len() {
            match self.bytes[self.index] {
                b'\\' => {
                    self.index += 2;
                }
                b'"' => {
                    self.index += 1;
                    return Some(&self.bytes[start..self.index]);
                }
                byte if byte < 0x20 => return None,
                _ => {
                    self.index += 1;
                }
            }
        }
        None
    }

    fn parse_number(&mut self) -> Option<&'a str> {
        let start = self.index;
        while let Some(byte) = self.peek() {
            if matches!(byte, b'-' | b'+' | b'0'..=b'9' | b'.' | b'e' | b'E') {
                self.index += 1;
            } else {
                break;
            }
        }
        let literal = std::str::from_utf8(&self.bytes[start..self.index]).ok()?;
        if is_number_literal(literal) {
            Some(literal)
        } else {
            None
        }
    }

    fn consume_literal(&mut self, literal: &[u8]) -> bool {
        if self.bytes[self.index..].starts_with(literal) {
            self.index += literal.len();
            return true;
        }
        false
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                self.index += 1;
            } else {
                break;
            }
        }
    }
}

/// Renders a key the way the Go and TypeScript validators do, so refusal
/// phrases stay comparable across the three implementations.
fn json_quoted(key: &str) -> String {
    serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\""))
}

/// `^-?(0|[1-9][0-9]*)$`
fn is_integer_literal(literal: &str) -> bool {
    let digits = literal.strip_prefix('-').unwrap_or(literal);
    if digits == "0" {
        return true;
    }
    if digits.is_empty() || digits.starts_with('0') {
        return false;
    }
    digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// `^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`
fn is_number_literal(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    let mut index = 0;
    if bytes.first() == Some(&b'-') {
        index += 1;
    }
    match bytes.get(index) {
        Some(b'0') => index += 1,
        Some(b'1'..=b'9') => {
            while matches!(bytes.get(index), Some(b'0'..=b'9')) {
                index += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let start = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    index == bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_minimal_request() {
        let wire =
            br#"{"capability":"system.echo","arguments":{},"authority":{"principal":"alice"}}"#;
        assert_eq!(validate_invocation_request(wire), Ok(()));
    }

    #[test]
    fn refuses_duplicate_keys() {
        let wire = br#"{"capability":"system.echo","capability":"system.info","arguments":{},"authority":{"principal":"alice"}}"#;
        let error = validate_invocation_request(wire).unwrap_err();
        assert!(error.contains("duplicate key"), "{error}");
    }

    #[test]
    fn refuses_unknown_root_fields() {
        let wire = br#"{"capability":"system.echo","execution_route":"LOCAL","arguments":{},"authority":{"principal":"alice"}}"#;
        let error = validate_invocation_request(wire).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn refuses_null_for_known_fields() {
        let wire = br#"{"capability":null,"arguments":{},"authority":{"principal":"alice"}}"#;
        let error = validate_invocation_request(wire).unwrap_err();
        assert!(error.contains("null is not accepted"), "{error}");
    }

    #[test]
    fn refuses_trailing_data() {
        let wire =
            br#"{"capability":"system.echo","arguments":{},"authority":{"principal":"alice"}}{}"#;
        let error = validate_invocation_request(wire).unwrap_err();
        assert!(error.contains("trailing data"), "{error}");
    }

    #[test]
    fn refuses_excessive_nesting() {
        // `arguments` must itself be an object, so the depth is built from
        // nested arrays inside one of its properties.
        let mut wire = String::from(
            r#"{"capability":"system.echo","authority":{"principal":"alice"},"arguments":{"n":"#,
        );
        wire.push_str(&"[".repeat(MAX_INVOCATION_DEPTH + 2));
        wire.push_str(&"]".repeat(MAX_INVOCATION_DEPTH + 2));
        wire.push_str("}}");
        let error = validate_invocation_request(wire.as_bytes()).unwrap_err();
        assert!(error.contains("nesting exceeds"), "{error}");
    }

    #[test]
    fn refuses_non_integer_authority_generation() {
        let wire = br#"{"capability":"system.echo","arguments":{},"authority":{"principal":"alice","authority_generation":1.5}}"#;
        let error = validate_invocation_request(wire).unwrap_err();
        assert!(error.contains("must be a JSON integer"), "{error}");
    }

    #[test]
    fn refuses_out_of_range_authority_generation() {
        let wire = br#"{"capability":"system.echo","arguments":{},"authority":{"principal":"alice","authority_generation":9223372036854775808}}"#;
        let error = validate_invocation_request(wire).unwrap_err();
        assert!(
            error.contains("must fit in a signed 64-bit integer"),
            "{error}"
        );
    }

    #[test]
    fn refuses_invalid_utf8() {
        let wire = b"{\"capability\":\"\xff\xfe\"}";
        let error = validate_invocation_request(wire).unwrap_err();
        assert!(error.contains("UTF-8"), "{error}");
    }

    #[test]
    fn number_literal_forms() {
        assert!(is_number_literal("0"));
        assert!(is_number_literal("-1"));
        assert!(is_number_literal("1.5"));
        assert!(is_number_literal("1e10"));
        assert!(is_number_literal("1E+10"));
        assert!(!is_number_literal("01"));
        assert!(!is_number_literal("1."));
        assert!(!is_number_literal(".5"));
        assert!(!is_number_literal("1e"));
    }

    #[test]
    fn integer_literal_forms() {
        assert!(is_integer_literal("0"));
        assert!(is_integer_literal("-0"));
        assert!(is_integer_literal("123"));
        assert!(!is_integer_literal("01"));
        assert!(!is_integer_literal("1.0"));
        assert!(!is_integer_literal(""));
    }
}
