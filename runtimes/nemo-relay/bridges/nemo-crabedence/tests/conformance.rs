// SPDX-License-Identifier: Apache-2.0

//! Cross-language conformance against the shared capability-invocation corpus.
//!
//! The corpus at
//! `internal/execution/testdata/invocation-abi-conformance/vectors.json` is
//! owned by the Go execution kernel and is also consumed by the NEMO TypeScript
//! validator (`nemo/test/invocation-abi-conformance.test.ts`). Every vector is
//! one raw wire request; all three implementations must accept or reject it
//! identically, and every rejection must carry the rule-level error phrase.
//!
//! The corpus is read from its canonical location rather than copied, so a
//! divergence cannot hide behind a stale duplicate.

use std::path::PathBuf;

use base64::Engine as _;
use nemo_crabedence_bridge::abi::validate_invocation_request;

/// Decodes one vector's wire bytes.
///
/// Most vectors carry the request as a JSON string; the invalid-UTF-8 vector
/// carries base64 instead, because it cannot be represented as a JSON string.
fn wire_bytes(vector: &serde_json::Value, name: &str) -> Vec<u8> {
    if let Some(wire) = vector["wire"].as_str() {
        return wire.as_bytes().to_vec();
    }
    let encoded = vector["wire_b64"]
        .as_str()
        .unwrap_or_else(|| panic!("vector {name} carries neither wire nor wire_b64"));
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap_or_else(|error| panic!("vector {name}: wire_b64 is not valid base64: {error}"))
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("internal")
        .join("execution")
        .join("testdata")
        .join("invocation-abi-conformance")
        .join("vectors.json")
}

fn load_vectors() -> Vec<serde_json::Value> {
    let path = corpus_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the shared conformance corpus is required at {}: {error}",
            path.display()
        )
    });
    let document: serde_json::Value = serde_json::from_slice(&bytes).expect("corpus is valid JSON");
    document["vectors"]
        .as_array()
        .expect("corpus carries a vectors array")
        .clone()
}

#[test]
fn matches_the_shared_conformance_corpus() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "the corpus must not be empty");

    let mut accepted = 0;
    let mut rejected = 0;
    for vector in &vectors {
        let name = vector["name"].as_str().expect("vector name");
        let wire = wire_bytes(vector, name);
        let expected = vector["expected"].as_str().expect("vector expectation");
        let result = validate_invocation_request(&wire);
        match expected {
            "accept" => {
                assert!(
                    result.is_ok(),
                    "vector {name}: the Rust validator rejected a request the kernel accepts: {}",
                    result.unwrap_err()
                );
                accepted += 1;
            }
            "reject" => {
                let error = match result {
                    Ok(()) => panic!(
                        "vector {name}: the Rust validator accepted a request the kernel rejects"
                    ),
                    Err(error) => error,
                };
                let phrase = vector["error_contains"]
                    .as_str()
                    .expect("rejections carry the rule-level phrase");
                assert!(
                    error.contains(phrase),
                    "vector {name}: expected the refusal to contain {phrase:?}, got {error:?}"
                );
                rejected += 1;
            }
            other => panic!("vector {name}: unknown expectation {other:?}"),
        }
    }

    assert!(
        accepted > 0 && rejected > 0,
        "the corpus covers both outcomes"
    );
    println!("conformance corpus: {accepted} accepted, {rejected} rejected");
}
