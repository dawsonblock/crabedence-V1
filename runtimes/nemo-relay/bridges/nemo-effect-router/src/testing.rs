// SPDX-License-Identifier: Apache-2.0

//! Test helpers for asserting routing decisions.
//!
//! These mirror NeMo Relay's own `createTestCatalog` / `createTestKernel`
//! convention: a verified catalog can only be produced by the envelope loader,
//! so tests need a way to mint one from descriptors they control. Nothing here
//! is reachable from a production path — the catalog it returns has still
//! passed the same digest verification as any other.

use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use nemo_crabedence_bridge::capability_snapshot::{
    VerifiedCapabilityCatalog, load_catalog_from_snapshot,
};
use nemo_relay_executor::unstable::{
    CapabilityIdentity, ExecutionBackend, ExecutionClass, ExecutionIdentity, ExecutionRequest,
    ExecutionResult, OutcomeCertainty, RuntimeIdentity,
};
use serde_json::json;
use sha2::{Digest, Sha256};

/// A backend that records how often it was entered.
///
/// Routing assertions are about *which* backend ran, so the record is the
/// evidence; the result it returns is deliberately inert.
#[derive(Debug, Default)]
pub struct RecordingBackend {
    calls: AtomicUsize,
}

impl RecordingBackend {
    /// How many invocations reached this backend.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ExecutionBackend for RecordingBackend {
    fn execute(
        &self,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, nemo_relay_executor::unstable::EffectExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ExecutionResult {
            output: json!({
                "entered": true,
                "capability": request.identity.capability.capability_id,
            }),
            outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
            receipt_digest: None,
            receipt: None,
        })
    }
}

/// Builds a verified catalog from descriptors the caller controls.
pub fn catalog_for(descriptors: serde_json::Value) -> VerifiedCapabilityCatalog {
    let payload = serde_json::to_vec(&descriptors).expect("serialize descriptors");
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let envelope = json!({
        "registry_sha256": digest,
        "canonical_payload": base64::engine::general_purpose::STANDARD.encode(&payload),
    });
    load_catalog_from_snapshot(&envelope).expect("verified catalog")
}

/// One canonical descriptor with the given class and route.
pub fn descriptor(id: &str, class: &str, route: &str) -> serde_json::Value {
    json!({
        "id": id,
        "descriptor_version": 1,
        "execution_class": class,
        "assurance_profile": "DURABLE",
        "execution_route": route,
        "authority_policy": { "id": id, "grant_required": false },
        "adapter_id": "test",
    })
}

/// One bound execution request for the given capability and asserted class.
pub fn request_for(capability: &str, class: ExecutionClass) -> ExecutionRequest {
    ExecutionRequest {
        identity: ExecutionIdentity {
            execution_id: "exec-1".to_string(),
            invocation_id: "inv-1".to_string(),
            action_id: "action-1".to_string(),
            idempotency_key: "idem-1".to_string(),
            runtime: RuntimeIdentity {
                principal_id: "alice@example.com".to_string(),
                tenant_id: None,
                runtime_id: "runtime-1".to_string(),
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
            admission_id: "admission-1".to_string(),
            policy_version: "1".to_string(),
            policy_epoch: "1".to_string(),
            args_digest: "args-digest".to_string(),
            grant_digest: None,
            approval_reference: None,
            deadline_unix_ms: 0,
        },
        args: json!({ "value": 1 }),
        grant: None,
        trace_id: None,
    }
}
