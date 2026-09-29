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
fn value_for(field: &Value) -> Value {
    match field.get("type").and_then(Value::as_str) {
        Some("object") => json!({}),
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
