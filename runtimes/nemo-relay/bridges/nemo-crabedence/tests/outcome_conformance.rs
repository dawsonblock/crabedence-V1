// SPDX-License-Identifier: Apache-2.0

//! Outcome conformance against the shared corpus.
//!
//! `internal/execution/testdata/outcome-conformance/vectors.json` is owned by
//! the Go execution kernel and is also consumed by the TypeScript reference
//! adapter (`nemo/test/outcome-conformance.test.ts`). The Go test binds the
//! corpus to `classifyPostDispatch`; this test binds the Rust bridge to the
//! same expectations, in NeMo Relay's contract vocabulary.

use std::path::PathBuf;

use nemo_crabedence_bridge::outcome_mapping::{map_outcome, parse_outcome};
use nemo_relay_executor::unstable::{EffectExecutionError, OutcomeCertainty};
use serde_json::Value;

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("internal")
        .join("execution")
        .join("testdata")
        .join("outcome-conformance")
        .join("vectors.json")
}

fn load_vectors() -> Vec<Value> {
    let path = corpus_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the shared outcome corpus is required at {}: {error}",
            path.display()
        )
    });
    let document: Value = serde_json::from_slice(&bytes).expect("corpus is valid JSON");
    document["vectors"]
        .as_array()
        .expect("corpus carries a vectors array")
        .clone()
}

/// The vocabulary spelling of an enum value, as the corpus writes it.
fn spelling<T: serde::Serialize>(value: T) -> String {
    match serde_json::to_value(value).expect("serialize") {
        Value::String(text) => text,
        other => panic!("expected a string spelling, got {other}"),
    }
}

/// The status a planner would report for one mapped error.
///
/// This is the cross-language tie: the TypeScript adapter reports a status
/// directly, and the Rust error contract has to imply the same one.
fn derived_status(error: &EffectExecutionError) -> &'static str {
    match error.outcome_certainty {
        OutcomeCertainty::Unknown => "UNKNOWN",
        OutcomeCertainty::ConfirmedSuccess => "SUCCEEDED",
        OutcomeCertainty::ConfirmedFailure => match error.code.as_str() {
            "UNAUTHORIZED" | "ADMISSION_DENIED" => "DENIED",
            _ => "FAILED",
        },
    }
}

#[test]
fn matches_the_shared_outcome_corpus() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "the corpus must not be empty");

    let mut accepted = 0;
    let mut rejected = 0;
    for vector in &vectors {
        let name = vector["name"].as_str().expect("vector name");
        let response = &vector["response"];
        let shape = vector["shape"].as_str().expect("vector shape");

        match shape {
            "reject" => {
                let error = parse_outcome(response).err().unwrap_or_else(|| {
                    panic!("vector {name}: a malformed response must be refused")
                });
                let phrase = vector["error_contains"]
                    .as_str()
                    .expect("rejections carry the refusal phrase");
                assert!(
                    error.message.contains(phrase),
                    "vector {name}: expected the refusal to contain {phrase:?}, got {:?}",
                    error.message
                );
                rejected += 1;
            }
            "accept" => {
                let outcome = parse_outcome(response)
                    .unwrap_or_else(|error| panic!("vector {name}: {error}"));
                let expected_status = vector["nemo_status"]
                    .as_str()
                    .expect("accepted vectors declare the reported status");
                match map_outcome(&outcome, false) {
                    Ok(result) => {
                        assert_eq!(expected_status, "SUCCEEDED", "vector {name}");
                        assert_eq!(
                            spelling(result.outcome_certainty),
                            vector["outcome_certainty"].as_str().expect("certainty"),
                            "vector {name}"
                        );
                    }
                    Err(error) => {
                        assert_eq!(
                            spelling(error.outcome_certainty),
                            vector["outcome_certainty"].as_str().expect("certainty"),
                            "vector {name}"
                        );
                        assert_eq!(
                            spelling(error.dispatch_state),
                            vector["dispatch_state"].as_str().expect("dispatch state"),
                            "vector {name}"
                        );
                        assert_eq!(
                            error.retryable,
                            vector["retryable"].as_bool().expect("retryable"),
                            "vector {name}"
                        );
                        assert_eq!(
                            error.reconciliation_required,
                            vector["reconciliation_required"]
                                .as_bool()
                                .expect("reconciliation_required"),
                            "vector {name}"
                        );
                        assert_eq!(
                            derived_status(&error),
                            expected_status,
                            "vector {name}: the mapped error must imply the reported status"
                        );
                    }
                }
                accepted += 1;
            }
            other => panic!("vector {name}: unknown shape {other:?}"),
        }
    }

    assert!(
        accepted > 0 && rejected > 0,
        "the corpus covers both outcomes"
    );
    println!("outcome corpus: {accepted} accepted, {rejected} rejected");
}
