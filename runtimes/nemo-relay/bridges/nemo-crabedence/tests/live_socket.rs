// SPDX-License-Identifier: Apache-2.0

//! Live integration against a running Crabedence execution service.
//!
//! Gated on `NEMO_CRABEDENCE_LIVE_SOCKET`, the path to a `crabbox serve-exec`
//! socket. When the variable is unset the test reports that it was skipped
//! rather than pretending to have run — the same convention the repository's
//! other externally-gated qualification tests use.
//!
//! The assertions here are the ones that cannot be made against a fixture:
//!
//! - the service's own `capabilities.json` verifies against its digest and
//!   parses into descriptors (the Rust verifier accepts real Go canonical
//!   bytes);
//! - a tampered copy of that snapshot is refused;
//! - a capability the registry pins to a non-CRABEDENCE route is refused
//!   locally, without a socket hop;
//! - a real dispatch reaches the kernel and its typed refusal is mapped onto
//!   NeMo Relay's error contract.

use std::path::PathBuf;

use base64::Engine as _;
use nemo_crabedence_bridge::capability_snapshot::load_catalog_from_path;
use nemo_crabedence_bridge::execution_port::NemoCrabedenceExecutionPort;
use nemo_crabedence_bridge::transport::ExecutionSocketClient;
use nemo_relay_executor::unstable::{
    CapabilityIdentity, ExecutionBackend, ExecutionClass, ExecutionIdentity, ExecutionRequest,
    OutcomeCertainty, RuntimeIdentity, state_for_error,
};
use nemo_relay_ledger::unstable::ExecutionState;

/// Resolves the live socket path, or `None` when the test is not configured.
fn live_socket() -> Option<PathBuf> {
    match std::env::var_os("NEMO_CRABEDENCE_LIVE_SOCKET") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        _ => {
            eprintln!(
                "skipping live integration: set NEMO_CRABEDENCE_LIVE_SOCKET to a running \
                 `crabbox serve-exec` socket to enable it"
            );
            None
        }
    }
}

fn snapshot_path(socket: &std::path::Path) -> PathBuf {
    socket
        .parent()
        .expect("socket has a parent directory")
        .join("capabilities.json")
}

fn request_for(capability: &str, class: ExecutionClass) -> ExecutionRequest {
    ExecutionRequest {
        identity: ExecutionIdentity {
            execution_id: "exec-live-1".to_string(),
            invocation_id: "inv-live-1".to_string(),
            action_id: "action-live-1".to_string(),
            idempotency_key: format!("live-{capability}-1"),
            runtime: RuntimeIdentity {
                principal_id: "alice@example.com".to_string(),
                tenant_id: None,
                runtime_id: "nemo-live-test".to_string(),
                environment: "test".to_string(),
                session_id: None,
            },
            runtime_binding_digest: "runtime-digest".to_string(),
            capability: CapabilityIdentity {
                capability_id: capability.to_string(),
                capability_generation: 1,
                registration_digest: "registration-digest".to_string(),
                execution_class: class,
                operation: capability.to_string(),
                route_digest: "route-digest".to_string(),
            },
            admission_id: "admission-live-1".to_string(),
            policy_version: "1".to_string(),
            policy_epoch: "1".to_string(),
            args_digest: "args-digest".to_string(),
            grant_digest: None,
            approval_reference: None,
            deadline_unix_ms: 0,
        },
        args: serde_json::json!({ "counter": "live", "by": 1 }),
        grant: None,
        trace_id: None,
    }
}

#[test]
fn verifies_the_services_own_registry_snapshot() {
    let Some(socket) = live_socket() else {
        return;
    };
    let catalog = load_catalog_from_path(&snapshot_path(&socket))
        .expect("the service's own snapshot must verify");
    assert_eq!(catalog.registry_sha256().len(), 64);
    assert!(
        catalog.descriptor("test.counter.increment").is_some(),
        "the built-in mutation capability must be in the verified catalog"
    );
    let counter = catalog
        .descriptor("test.counter.increment")
        .expect("counter");
    assert_eq!(
        counter.execution_class,
        nemo_crabedence_bridge::capability_snapshot::RegistryExecutionClass::Mutation
    );
    assert_eq!(
        counter.execution_route,
        nemo_crabedence_bridge::capability_snapshot::RegistryExecutionRoute::Crabedence
    );
    assert_eq!(counter.adapter_id, "test-counter");
}

#[test]
fn refuses_a_tampered_copy_of_the_live_snapshot() {
    let Some(socket) = live_socket() else {
        return;
    };
    let source = snapshot_path(&socket);
    let raw = std::fs::read(&source).expect("read snapshot");
    let mut envelope: serde_json::Value = serde_json::from_slice(&raw).expect("snapshot is JSON");
    let payload = base64::engine::general_purpose::STANDARD
        .decode(envelope["canonical_payload"].as_str().expect("payload"))
        .expect("payload decodes");
    let mut descriptors: serde_json::Value =
        serde_json::from_slice(&payload).expect("payload is a descriptor array");

    // Rewrite one classification without producing the matching digest: the
    // exact "MUTATION → READ" tamper the trust model names.
    let mut rewritten = false;
    if let Some(entries) = descriptors.as_array_mut() {
        for entry in entries {
            if entry["id"] == "test.counter.increment" {
                entry["execution_class"] = serde_json::Value::String("READ".to_string());
                entry["execution_route"] = serde_json::Value::String("DIRECT".to_string());
                rewritten = true;
            }
        }
    }
    assert!(
        rewritten,
        "the counter descriptor must exist to tamper with"
    );

    envelope["canonical_payload"] = serde_json::Value::String(
        base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&descriptors).expect("re-encode")),
    );
    let tampered = std::env::temp_dir().join(format!(
        "nemo-tampered-snapshot-{}.json",
        std::process::id()
    ));
    std::fs::write(&tampered, serde_json::to_vec(&envelope).expect("write")).expect("write");

    let error = load_catalog_from_path(&tampered).expect_err("a tampered snapshot must be refused");
    assert!(
        error.message().contains("digest does not cover"),
        "unexpected refusal: {error}"
    );
    let _ = std::fs::remove_file(&tampered);
}

#[test]
fn refuses_a_locally_routed_capability_without_a_socket_hop() {
    let Some(socket) = live_socket() else {
        return;
    };
    let catalog = load_catalog_from_path(&snapshot_path(&socket)).expect("verified");
    let port = NemoCrabedenceExecutionPort::new(ExecutionSocketClient::new(&socket), catalog);
    // system.echo is pinned PURE / LOCAL: it must never cross the kernel.
    let request = request_for("system.echo", ExecutionClass::Pure);
    let error = port.execute(&request).unwrap_err();
    assert_eq!(error.code, "EXECUTION_ROUTE_MISMATCH");
    assert_eq!(state_for_error(&error), ExecutionState::Failed);
    assert!(!error.retryable);
}

#[test]
fn dispatches_to_the_real_kernel_and_maps_its_refusal() {
    let Some(socket) = live_socket() else {
        return;
    };
    let catalog = load_catalog_from_path(&snapshot_path(&socket)).expect("verified");
    let port = NemoCrabedenceExecutionPort::new(ExecutionSocketClient::new(&socket), catalog);

    // test.counter.increment requires a resolved grant, and this request
    // carries none: the kernel refuses admission and the refusal must arrive
    // as a definitive, non-retryable failure — never as UNKNOWN, and never as
    // a silent success.
    let request = request_for("test.counter.increment", ExecutionClass::Mutation);
    let error = port.execute(&request).unwrap_err();
    assert_eq!(error.code, "UNAUTHORIZED", "{error}");
    assert_eq!(state_for_error(&error), ExecutionState::Failed);
    assert!(!error.retryable);
    assert!(!error.reconciliation_required);
}

#[test]
fn commits_a_mutation_through_the_real_kernel_when_a_grant_is_provided() {
    let Some(socket) = live_socket() else {
        return;
    };
    let Some(grant) = std::env::var_os("NEMO_CRABEDENCE_LIVE_GRANT") else {
        eprintln!(
            "skipping committed-path check: set NEMO_CRABEDENCE_LIVE_GRANT to a grant reference \
             issued for test.counter.increment"
        );
        return;
    };
    let catalog = load_catalog_from_path(&snapshot_path(&socket)).expect("verified");
    let port = NemoCrabedenceExecutionPort::new(ExecutionSocketClient::new(&socket), catalog);

    let mut request = request_for("test.counter.increment", ExecutionClass::Mutation);
    request.grant = Some(grant.to_string_lossy().into_owned());
    request.identity.idempotency_key = format!("live-commit-{}", std::process::id());

    let result = port.execute(&request).expect("the mutation must commit");
    assert_eq!(result.outcome_certainty, OutcomeCertainty::ConfirmedSuccess);
    assert!(
        result.output.is_object(),
        "the counter returns a structured result, got {}",
        result.output
    );
}

/// An authority reference the kernel cannot resolve is refused definitively.
///
/// The kernel resolves `authority_ref` against its authority store. A
/// reference that does not resolve is an authorization failure, not an
/// ambiguous outcome: nothing was dispatched, so nothing can have occurred, and
/// the refusal must not be retryable or reconcilable.
#[test]
fn refuses_an_authority_reference_that_does_not_resolve() {
    let Some(socket) = live_socket() else {
        return;
    };
    let catalog = load_catalog_from_path(&snapshot_path(&socket)).expect("verified");
    let port = NemoCrabedenceExecutionPort::new(ExecutionSocketClient::new(&socket), catalog);

    let mut request = request_for("test.counter.increment", ExecutionClass::Mutation);
    request.grant = Some("no-such-grant".to_string());
    request.identity.idempotency_key = format!("unknown-grant-{}", std::process::id());

    let error = port.execute(&request).unwrap_err();
    assert_eq!(
        error.code, "UNAUTHORIZED",
        "the kernel refuses an unresolvable reference as an authorization failure, got {error}"
    );
    assert_eq!(
        state_for_error(&error),
        ExecutionState::Failed,
        "an unresolvable authority reference is definitive, got {error}"
    );
    assert!(!error.retryable, "{error}");
    assert!(!error.reconciliation_required, "{error}");
}

/// A CRITICAL commit carries evidence across the wire, and the bridge accepts it.
///
/// The built-in registry has no CRITICAL capability, so this needs the service
/// started with the qualification extension
/// (`CRABEDENCE_QUAL_PROVIDER_URL`). It is the only check that exercises the
/// bridge's `requires_evidence` path against a real commit rather than a
/// fixture: a CRITICAL `SUCCEEDED` without a valid digest, receipt version 3,
/// and run id must map to `UNKNOWN`, so an accepted commit proves the whole
/// evidence contract survived the boundary.
#[test]
fn commits_a_critical_mutation_with_evidence() {
    let Some(socket) = live_socket() else {
        return;
    };
    let Some(grant) = std::env::var_os("NEMO_CRABEDENCE_LIVE_CRITICAL_GRANT") else {
        eprintln!(
            "skipping the CRITICAL check: set NEMO_CRABEDENCE_LIVE_CRITICAL_GRANT to a grant \
             reference for qualification.critical.commit, issued against a service started with \
             CRABEDENCE_QUAL_PROVIDER_URL"
        );
        return;
    };
    let catalog = load_catalog_from_path(&snapshot_path(&socket)).expect("verified");
    let port = NemoCrabedenceExecutionPort::new(ExecutionSocketClient::new(&socket), catalog);

    let mut request = request_for("qualification.critical.commit", ExecutionClass::Critical);
    request.grant = Some(grant.to_string_lossy().into_owned());
    request.identity.idempotency_key = format!("critical-{}", std::process::id());
    // The capability's schema requires `operation` and forbids extras, so the
    // kernel's own argument validation is exercised here too.
    request.args = serde_json::json!({ "operation": "nemo-bridge-commit" });

    let result = port
        .execute(&request)
        .unwrap_or_else(|error| panic!("the CRITICAL commit must succeed, got {error}"));
    assert_eq!(
        result.outcome_certainty,
        OutcomeCertainty::ConfirmedSuccess,
        "a committed CRITICAL must be a confirmed success"
    );
    let digest = result
        .receipt_digest
        .as_deref()
        .expect("a CRITICAL commit must carry an evidence digest");
    assert_eq!(
        digest.len(),
        64,
        "the evidence digest is a SHA-256 hex string"
    );
    println!("critical commit: evidence digest {}", &digest[..16]);
}

/// An authority reference that has lapsed is refused definitively.
///
/// Gated separately from the other live checks because it needs a grant that
/// has already expired, and the issuing tool refuses to mint one in the past —
/// so the reference has to be issued with a short future expiry and then
/// allowed to lapse. `scripts/test-nemo-expired-authority.sh` owns that timing;
/// this test asserts only the refusal, so it never sleeps or races a clock.
#[test]
fn refuses_an_expired_authority_reference() {
    let Some(socket) = live_socket() else {
        return;
    };
    let Some(grant) = std::env::var_os("NEMO_CRABEDENCE_LIVE_EXPIRED_GRANT") else {
        eprintln!(
            "skipping the expired-authority check: set NEMO_CRABEDENCE_LIVE_EXPIRED_GRANT to a \
             grant reference that has already lapsed"
        );
        return;
    };
    let catalog = load_catalog_from_path(&snapshot_path(&socket)).expect("verified");
    let port = NemoCrabedenceExecutionPort::new(ExecutionSocketClient::new(&socket), catalog);

    let mut request = request_for("test.counter.increment", ExecutionClass::Mutation);
    request.grant = Some(grant.to_string_lossy().into_owned());
    request.identity.idempotency_key = format!("expired-grant-{}", std::process::id());

    let error = port.execute(&request).unwrap_err();
    assert_eq!(
        error.code, "UNAUTHORIZED",
        "a lapsed grant is an authorization failure, got {error}"
    );
    assert_eq!(
        state_for_error(&error),
        ExecutionState::Failed,
        "a lapsed grant is definitive — nothing was dispatched, got {error}"
    );
    assert!(!error.retryable, "{error}");
    assert!(!error.reconciliation_required, "{error}");
}

/// No repeated key may produce a second real-world effect.
///
/// This is the property the whole consolidation exists to preserve, and it is
/// asserted against the live kernel rather than reasoned about. The second
/// dispatch builds a *fresh* port — the same thing a restarted NeMo Relay
/// process would have — so it proves the guarantee survives a planner restart,
/// not merely a repeated call inside one process.
#[test]
fn a_repeated_idempotency_key_replays_rather_than_duplicating() {
    let Some(socket) = live_socket() else {
        return;
    };
    let Some(grant) = std::env::var_os("NEMO_CRABEDENCE_LIVE_GRANT") else {
        eprintln!(
            "skipping the duplicate-effect check: set NEMO_CRABEDENCE_LIVE_GRANT to a grant \
             reference issued for test.counter.increment"
        );
        return;
    };
    let grant = grant.to_string_lossy().into_owned();
    let snapshot = snapshot_path(&socket);

    // A fresh counter name per run keeps the expected first value at 1. The
    // overrides exist so a restart sequence can re-issue the *same* key from a
    // second process and compare the two observations.
    let counter = std::env::var("NEMO_CRABEDENCE_LIVE_REPLAY_COUNTER")
        .unwrap_or_else(|_| format!("replay-{}", std::process::id()));
    let key = std::env::var("NEMO_CRABEDENCE_LIVE_REPLAY_KEY")
        .unwrap_or_else(|_| format!("replay-key-{}", std::process::id()));
    let replay_request = || {
        let mut request = request_for("test.counter.increment", ExecutionClass::Mutation);
        request.grant = Some(grant.clone());
        request.identity.idempotency_key = key.clone();
        request.args = serde_json::json!({ "counter": counter, "by": 1 });
        request
    };

    let first_port = NemoCrabedenceExecutionPort::new(
        ExecutionSocketClient::new(&socket),
        load_catalog_from_path(&snapshot).expect("verified"),
    );
    let first = first_port
        .execute(&replay_request())
        .expect("the first mutation must commit");
    let first_value = first.output["value"].clone();

    let second_port = NemoCrabedenceExecutionPort::new(
        ExecutionSocketClient::new(&socket),
        load_catalog_from_path(&snapshot).expect("verified"),
    );
    let second = second_port
        .execute(&replay_request())
        .expect("the replay must answer from the durable record");

    assert_eq!(
        second.output["value"], first_value,
        "a repeated idempotency key must replay the committed effect, never apply it twice"
    );
    println!("replay: key {key} observed value {} twice", first_value);
}
