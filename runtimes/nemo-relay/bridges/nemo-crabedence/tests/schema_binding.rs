// SPDX-License-Identifier: Apache-2.0

//! The published schema and the Rust scanner must not drift.
//!
//! `schemas/capability-invocation-v1.json` is the one canonical description of
//! the wire contract. The Go parser
//! (`internal/execution/invocation_schema_test.go`) and the TypeScript
//! validator (`nemo/test/invocation-schema.test.ts`) are bound to the same
//! file by their own tests.
//!
//! The binding is behavioral rather than structural on purpose: this test asks
//! the scanner, not a private constant, so a refactor cannot silently
//! disconnect the schema from what actually runs.

use std::path::PathBuf;

use nemo_crabedence_bridge::abi::validate_invocation_request;
use serde_json::{Value, json};

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("schemas")
        .join("capability-invocation-v1.json")
}

fn load_schema() -> Value {
    let path = schema_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the canonical invocation schema is required at {}: {error}",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).expect("the schema is valid JSON")
}

/// A structurally valid value for one schema-declared field type.
/// Objects carry every `required` subfield so the synthesized value
/// satisfies presence rules like the mediation object's digest pair.
/// A declared `pattern` is honored for the digest shape the schema
/// uses; any other pattern fails here so a new constraint is noticed.
fn value_for(field: &Value) -> Value {
    if let Some(pattern) = field.get("pattern").and_then(Value::as_str) {
        assert_eq!(
            pattern, "^[0-9a-f]{64}$",
            "value_for cannot synthesize pattern {pattern}"
        );
        return json!("0".repeat(64));
    }
    match field.get("type").and_then(Value::as_str) {
        Some("object") => {
            let mut obj = serde_json::Map::new();
            if let Some(required) = field.get("required").and_then(Value::as_array) {
                for key in required.iter().filter_map(Value::as_str) {
                    obj.insert(key.to_string(), value_for(&field["properties"][key]));
                }
            }
            Value::Object(obj)
        }
        Some("integer") => json!(1),
        _ => json!("x"),
    }
}

fn accepts(wire: &Value) -> bool {
    validate_invocation_request(&serde_json::to_vec(wire).expect("serialize")).is_ok()
}

fn refusal(wire: &Value) -> String {
    validate_invocation_request(&serde_json::to_vec(wire).expect("serialize")).unwrap_err()
}

#[test]
fn describes_a_closed_object() {
    let schema = load_schema();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["properties"].is_object());
}

#[test]
fn accepts_every_field_the_schema_describes() {
    let schema = load_schema();
    let properties = schema["properties"].as_object().expect("properties");
    for (name, field) in properties {
        if name == "capability" {
            continue; // the base request already carries it
        }
        let wire = json!({ "capability": "system.echo", name: value_for(field) });
        assert!(
            accepts(&wire),
            "schema field {name} must be accepted: {wire}"
        );
    }
}

#[test]
fn accepts_every_authority_field_the_schema_describes() {
    let schema = load_schema();
    let authority = &schema["properties"]["authority"];
    assert_eq!(authority["type"], "object");
    assert_eq!(authority["additionalProperties"], false);
    let properties = authority["properties"].as_object().expect("authority");
    assert!(!properties.is_empty(), "authority must declare fields");
    for (name, field) in properties {
        let wire = json!({
            "capability": "system.echo",
            "authority": { name: value_for(field) },
        });
        assert!(accepts(&wire), "authority.{name} must be accepted: {wire}");
    }
}

#[test]
fn accepts_every_mediation_field_the_schema_describes() {
    let schema = load_schema();
    let mediation = &schema["properties"]["mediation"];
    assert_eq!(mediation["type"], "object");
    assert_eq!(mediation["additionalProperties"], false);
    // The schema must declare the two digests the validators require —
    // a mediation object without both is malformed evidence (R9).
    let required = mediation["required"]
        .as_array()
        .expect("mediation required");
    for name in ["middleware_set_digest", "original_args_digest"] {
        assert!(
            required.iter().any(|r| r == name),
            "mediation.{name} must be required"
        );
    }
    let properties = mediation["properties"].as_object().expect("mediation");
    assert!(!properties.is_empty(), "mediation must declare fields");
    for (name, field) in properties {
        // Fill the required pair first, then the field under test —
        // the ABI rejects a mediation object missing either digest.
        let mut mediation_value = value_for(mediation);
        mediation_value[name] = value_for(field);
        let wire = json!({
            "capability": "system.echo",
            "mediation": mediation_value,
        });
        assert!(accepts(&wire), "mediation.{name} must be accepted: {wire}");
    }
}

#[test]
fn refuses_every_server_resolved_field_the_schema_names() {
    let schema = load_schema();
    let server_resolved = schema["x-crabedence-server-resolved"]
        .as_array()
        .expect("the schema names the fields the planner may not supply");
    assert!(!server_resolved.is_empty());
    for name in server_resolved {
        let name = name.as_str().expect("field name");
        assert!(
            schema["properties"].get(name).is_none(),
            "{name} is declared server-resolved and must not be accepted"
        );
        let error = refusal(&json!({ "capability": "system.echo", name: "x" }));
        assert!(
            error.contains("unknown field"),
            "{name} must be refused as an unknown field, got {error}"
        );
    }
}

#[test]
fn refuses_an_unknown_field_the_schema_does_not_name() {
    let error = refusal(&json!({ "capability": "system.echo", "not_a_field": "x" }));
    assert!(error.contains("unknown field"), "{error}");
}
