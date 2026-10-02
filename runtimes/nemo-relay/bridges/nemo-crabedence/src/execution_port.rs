// SPDX-License-Identifier: Apache-2.0

//! The Crabedence execution port.
//!
//! [`NemoCrabedenceExecutionPort`] is the NeMo Relay
//! [`ExecutionBackend`] that forwards already-authorized execution identities
//! to the Crabedence execution kernel over the capability invocation ABI.
//!
//! # What the port refuses to send
//!
//! The request that crosses the boundary carries the capability, its
//! arguments, authority material, an idempotency key, a deadline, and — when
//! the composing runtime crossed a middleware boundary it can attest — a
//! `mediation` provenance object: which middleware set rewrote the
//! arguments, the pre-middleware argument digest, and the release-root
//! identity of the composing runtime. Mediation is caller-asserted evidence
//! the kernel binds into the durable execution identity; it is never policy.
//! Execution route, provider or adapter selection, assurance profile,
//! approval requirements, retry policy, and receipt requirements are
//! resolved by Crabedence's registry and are never sent.
//!
//! The advisory `execution_class` assertion is not sent either. The port
//! already holds a verified descriptor for the capability, and the registry is
//! authoritative, so omitting the field removes the assertion surface
//! entirely rather than asking the kernel to police it.
//!
//! # Local checks are defense in depth
//!
//! The port refuses a capability that is not in the verified catalog, refuses a
//! request whose class disagrees with the verified descriptor, and refuses a
//! capability whose pinned route is not `CRABEDENCE`. None of these is the
//! authority: Crabedence independently resolves all of them, and a compromised
//! planner cannot make the kernel agree by lying. They exist so a routing
//! defect fails closed and visibly instead of crossing the trust boundary.

use nemo_relay_executor::unstable::{
    EffectExecutionError, ExecutionBackend, ExecutionClass, ExecutionRequest, ExecutionResult,
};

use crate::capability_snapshot::{
    RegistryExecutionClass, RegistryExecutionRoute, VerifiedCapabilityCatalog,
};
use crate::outcome_mapping::{map_outcome, map_transport_failure, parse_outcome, refused_request};
use crate::transport::ExecutionSocketClient;

/// The NeMo Relay execution backend that dispatches through Crabedence.
#[derive(Debug, Clone)]
pub struct NemoCrabedenceExecutionPort {
    client: ExecutionSocketClient,
    catalog: VerifiedCapabilityCatalog,
}

impl NemoCrabedenceExecutionPort {
    /// Builds a port from a socket client and a verified catalog.
    ///
    /// The catalog can only be produced by
    /// [`crate::capability_snapshot::load_catalog_from_snapshot`], so a port
    /// cannot be assembled around unverified descriptors.
    pub fn new(client: ExecutionSocketClient, catalog: VerifiedCapabilityCatalog) -> Self {
        Self { client, catalog }
    }

    /// The transport client this port dispatches through.
    pub fn client(&self) -> &ExecutionSocketClient {
        &self.client
    }

    /// The verified catalog this port routes on.
    pub fn catalog(&self) -> &VerifiedCapabilityCatalog {
        &self.catalog
    }

    /// Builds the capability invocation ABI request for one bound execution.
    ///
    /// Exposed so the wire shape can be asserted directly in tests — the
    /// absence of policy fields is a security property, and it is checked as
    /// one.
    pub fn build_abi_request(
        &self,
        request: &ExecutionRequest,
    ) -> Result<serde_json::Value, EffectExecutionError> {
        let identity = &request.identity;
        let capability_id = &identity.capability.capability_id;
        let descriptor = self.catalog.descriptor(capability_id).ok_or_else(|| {
            refused_request(
                "CAPABILITY_NOT_FOUND",
                format!(
                    "capability {capability_id} is not in the verified registry snapshot — no routing metadata exists for it"
                ),
            )
        })?;

        match descriptor.execution_route {
            RegistryExecutionRoute::Crabedence => {}
            RegistryExecutionRoute::Direct => {
                // The DIRECT route crosses this socket to the service's
                // read path. Mirror the registration invariant here: a
                // snapshot that pinned DIRECT to a consequential class or
                // an assurance the read path cannot carry is refused before
                // it reaches the wire.
                if matches!(
                    descriptor.execution_class,
                    RegistryExecutionClass::Mutation | RegistryExecutionClass::Critical
                ) || matches!(
                    descriptor.assurance_profile.as_str(),
                    "DURABLE" | "HIGH_ASSURANCE"
                ) {
                    return Err(refused_request(
                        "EXECUTION_ROUTE_MISMATCH",
                        format!(
                            "capability {capability_id} is pinned DIRECT but classified {} with {} assurance — DIRECT carries only non-consequential reads at STANDARD or below",
                            descriptor.execution_class, descriptor.assurance_profile
                        ),
                    ));
                }
            }
            RegistryExecutionRoute::Local => {
                return Err(refused_request(
                    "EXECUTION_ROUTE_MISMATCH",
                    format!(
                        "capability {capability_id} is pinned to route {} — it must not be dispatched through the Crabedence execution kernel",
                        descriptor.execution_route
                    ),
                ));
            }
        }

        let registered_class = descriptor.execution_class;
        let requested_class = registry_class_of(identity.capability.execution_class);
        if registered_class != requested_class {
            return Err(refused_request(
                "EXECUTION_CLASS_MISMATCH",
                format!(
                    "capability {capability_id} is registered as {registered_class} but the request asserted {requested_class} — the registry is authoritative"
                ),
            ));
        }

        if !request.args.is_object() {
            return Err(refused_request(
                "INVALID_REQUEST",
                format!(
                    "capability {capability_id} arguments must be a JSON object, got {}",
                    json_kind(&request.args)
                ),
            ));
        }

        let mut authority = serde_json::Map::new();
        authority.insert(
            "principal".to_string(),
            serde_json::Value::String(identity.runtime.principal_id.clone()),
        );
        if let Some(grant) = request.grant.as_deref().filter(|grant| !grant.is_empty()) {
            authority.insert(
                "authority_ref".to_string(),
                serde_json::Value::String(grant.to_string()),
            );
        }

        let mut wire = serde_json::Map::new();
        wire.insert(
            "capability".to_string(),
            serde_json::Value::String(capability_id.clone()),
        );
        wire.insert("arguments".to_string(), request.args.clone());
        wire.insert(
            "authority".to_string(),
            serde_json::Value::Object(authority),
        );
        if !identity.idempotency_key.is_empty() {
            wire.insert(
                "idempotency_key".to_string(),
                serde_json::Value::String(identity.idempotency_key.clone()),
            );
        }
        if let Some(deadline) = deadline_rfc3339(identity.deadline_unix_ms) {
            wire.insert("deadline".to_string(), serde_json::Value::String(deadline));
        }
        // Mediation provenance the composing runtime attests — which
        // middleware set rewrote the arguments, what the caller's arguments
        // digested to before mediation, and which release composed it. It is
        // evidence, never policy: the kernel binds it into the durable
        // execution identity but never routes or authorizes on it.
        if let Some(mediation) = &request.mediation {
            let mut object = serde_json::Map::new();
            object.insert(
                "middleware_set_digest".to_string(),
                serde_json::Value::String(mediation.middleware_set_digest.clone()),
            );
            object.insert(
                "original_args_digest".to_string(),
                serde_json::Value::String(mediation.original_args_digest.clone()),
            );
            if let Some(release_root) = &mediation.release_root_digest {
                object.insert(
                    "release_root_digest".to_string(),
                    serde_json::Value::String(release_root.clone()),
                );
            }
            if let Some(manifest_sha256) = &mediation.plugin_manifest_sha256 {
                object.insert(
                    "plugin_manifest_sha256".to_string(),
                    serde_json::Value::String(manifest_sha256.clone()),
                );
            }
            if let Some(library_sha256) = &mediation.plugin_library_sha256 {
                object.insert(
                    "plugin_library_sha256".to_string(),
                    serde_json::Value::String(library_sha256.clone()),
                );
            }
            if let Some(config_sha256) = &mediation.activation_config_sha256 {
                object.insert(
                    "activation_config_sha256".to_string(),
                    serde_json::Value::String(config_sha256.clone()),
                );
            }
            wire.insert("mediation".to_string(), serde_json::Value::Object(object));
        }
        Ok(serde_json::Value::Object(wire))
    }
}

impl ExecutionBackend for NemoCrabedenceExecutionPort {
    /// Dispatches one already-authorized execution identity through Crabedence.
    ///
    /// This is a blocking call: the ABI is a synchronous request/response
    /// exchange, and the bound deadline in the request is what bounds it.
    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, EffectExecutionError> {
        let wire = self.build_abi_request(request)?;
        let requires_evidence = self
            .catalog
            .descriptor(&request.identity.capability.capability_id)
            .is_some_and(|descriptor| {
                descriptor.execution_class == RegistryExecutionClass::Critical
            });

        let response = match self.client.invoke(&wire) {
            Ok(response) => response,
            Err(error) => return Err(map_transport_failure(&error)),
        };
        let outcome = parse_outcome(&response)?;
        map_outcome(&outcome, requires_evidence)
    }
}

/// Maps NeMo Relay's execution class onto the registry's spelling.
///
/// Exported so the effect router and the port compare classes with one
/// vocabulary rather than two that can drift.
pub fn registry_class_of(class: ExecutionClass) -> RegistryExecutionClass {
    match class {
        ExecutionClass::Pure => RegistryExecutionClass::Pure,
        ExecutionClass::Read => RegistryExecutionClass::Read,
        ExecutionClass::Mutation => RegistryExecutionClass::Mutation,
        ExecutionClass::Critical => RegistryExecutionClass::Critical,
    }
}

/// Renders a JSON value's kind for diagnostics.
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Converts a Unix-millisecond deadline into an RFC3339 timestamp.
///
/// A zero deadline means the host declared none, and an unrepresentable one is
/// dropped rather than sent wrong — the ABI's `deadline` is optional, and the
/// kernel's own admission rules remain the authority on expiry.
fn deadline_rfc3339(deadline_unix_ms: u64) -> Option<String> {
    if deadline_unix_ms == 0 {
        return None;
    }
    let millis = i64::try_from(deadline_unix_ms).ok()?;
    let timestamp = chrono::DateTime::from_timestamp_millis(millis)?;
    Some(
        timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_snapshot::load_catalog_from_snapshot;
    use crate::transport::ExecutionSocketClient;
    use nemo_relay_executor::unstable::{
        CapabilityIdentity, ExecutionIdentity, OutcomeCertainty, RuntimeIdentity, state_for_error,
    };
    use nemo_relay_ledger::unstable::ExecutionState;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    fn temp_socket_path(label: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "nemo-crabedence-port-{label}-{}-{unique}.sock",
            std::process::id()
        ))
    }

    fn catalog_for(descriptors: serde_json::Value) -> VerifiedCapabilityCatalog {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let payload = serde_json::to_vec(&descriptors).expect("serialize");
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let envelope = json!({
            "registry_sha256": digest,
            "canonical_payload": base64::engine::general_purpose::STANDARD.encode(&payload),
        });
        load_catalog_from_snapshot(&envelope).expect("verified catalog")
    }

    fn counter_descriptor() -> serde_json::Value {
        json!([{
            "id": "test.counter.increment",
            "descriptor_version": 1,
            "execution_class": "MUTATION",
            "assurance_profile": "DURABLE",
            "execution_route": "CRABEDENCE",
            "authority_policy": { "id": "test.counter.increment", "grant_required": false },
            "adapter_id": "counter",
        }])
    }

    fn request_for(capability: &str, class: ExecutionClass) -> ExecutionRequest {
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
                    operation: "increment".to_string(),
                    route_digest: "route-digest".to_string(),
                },
                admission_id: "admission-1".to_string(),
                policy_version: "1".to_string(),
                policy_epoch: "1".to_string(),
                args_digest: "args-digest".to_string(),
                grant_digest: None,
                approval_reference: None,
                deadline_unix_ms: 1_800_000_000_000,
            },
            args: json!({ "counter": "c", "by": 1 }),
            grant: Some("grant-1".to_string()),
            trace_id: Some("trace-1".to_string()),
            mediation: None,
        }
    }

    fn port_with_catalog(catalog: VerifiedCapabilityCatalog) -> NemoCrabedenceExecutionPort {
        NemoCrabedenceExecutionPort::new(
            ExecutionSocketClient::new(temp_socket_path("unused")),
            catalog,
        )
    }

    #[test]
    fn builds_a_minimal_abi_request() {
        let port = port_with_catalog(catalog_for(counter_descriptor()));
        let request = request_for("test.counter.increment", ExecutionClass::Mutation);
        let wire = port.build_abi_request(&request).expect("built");

        let object = wire.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "arguments",
                "authority",
                "capability",
                "deadline",
                "idempotency_key"
            ]
        );
        let authority = object["authority"].as_object().expect("authority");
        let mut authority_keys: Vec<&str> = authority.keys().map(String::as_str).collect();
        authority_keys.sort_unstable();
        assert_eq!(authority_keys, ["authority_ref", "principal"]);
        assert_eq!(object["capability"], "test.counter.increment");
        assert_eq!(authority["principal"], "alice@example.com");
        assert_eq!(authority["authority_ref"], "grant-1");
        assert_eq!(object["deadline"], "2027-01-15T08:00:00Z");
    }

    #[test]
    fn never_sends_policy_fields() {
        let port = port_with_catalog(catalog_for(counter_descriptor()));
        let request = request_for("test.counter.increment", ExecutionClass::Mutation);
        let wire = port.build_abi_request(&request).expect("built");
        let object = wire.as_object().expect("object");
        for forbidden in [
            "execution_class",
            "execution_route",
            "assurance_profile",
            "provider",
            "adapter",
            "schema",
            "receipt_version",
            "evidence",
            "authority_policy",
            "authority_generation",
            "authority_digest",
            "retry_policy",
            "approval_reference",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "the ABI request must not carry {forbidden}"
            );
        }
    }

    #[test]
    fn omits_authority_ref_when_no_grant_is_present() {
        let port = port_with_catalog(catalog_for(counter_descriptor()));
        let mut request = request_for("test.counter.increment", ExecutionClass::Mutation);
        request.grant = None;
        let wire = port.build_abi_request(&request).expect("built");
        assert_eq!(
            wire["authority"].as_object().expect("authority").len(),
            1,
            "only principal is present"
        );
    }

    #[test]
    fn refuses_an_unregistered_capability() {
        let port = port_with_catalog(catalog_for(counter_descriptor()));
        let request = request_for("github.issue.create", ExecutionClass::Mutation);
        let error = port.build_abi_request(&request).unwrap_err();
        assert_eq!(error.code, "CAPABILITY_NOT_FOUND");
        assert_eq!(state_for_error(&error), ExecutionState::Failed);
        assert!(!error.retryable);
    }

    #[test]
    fn refuses_a_class_downgrade_attempt() {
        let port = port_with_catalog(catalog_for(counter_descriptor()));
        // The registry pins MUTATION; the request asserts READ.
        let request = request_for("test.counter.increment", ExecutionClass::Read);
        let error = port.build_abi_request(&request).unwrap_err();
        assert_eq!(error.code, "EXECUTION_CLASS_MISMATCH");
        assert_eq!(state_for_error(&error), ExecutionState::Failed);
    }

    #[test]
    fn refuses_a_route_override_attempt() {
        let catalog = catalog_for(json!([{
            "id": "system.echo",
            "descriptor_version": 1,
            "execution_class": "PURE",
            "assurance_profile": "NONE",
            "execution_route": "LOCAL",
            "authority_policy": { "id": "system.echo", "grant_required": false },
            "adapter_id": "echo",
        }]));
        let port = port_with_catalog(catalog);
        let request = request_for("system.echo", ExecutionClass::Pure);
        let error = port.build_abi_request(&request).unwrap_err();
        assert_eq!(error.code, "EXECUTION_ROUTE_MISMATCH");
    }

    #[test]
    fn builds_a_request_for_a_direct_read() {
        // DIRECT-pinned capabilities dispatch over this socket — the service
        // resolves its own read route, the port only checks the pin is legal.
        let catalog = catalog_for(json!([{
            "id": "system.info",
            "descriptor_version": 1,
            "execution_class": "READ",
            "assurance_profile": "STANDARD",
            "execution_route": "DIRECT",
            "authority_policy": { "id": "system.info", "grant_required": false },
            "adapter_id": "system-info",
        }]));
        let port = port_with_catalog(catalog);
        let request = request_for("system.info", ExecutionClass::Read);
        let wire = port.build_abi_request(&request).expect("built");
        assert_eq!(wire["capability"], "system.info");
    }

    #[test]
    fn refuses_a_consequential_direct_pin() {
        // Registration refuses DIRECT for MUTATION/CRITICAL and for the
        // assurance profiles the read path cannot carry; the port mirrors it
        // so a violated snapshot cannot reach the wire.
        for (class, assurance, wire_class) in [
            ("MUTATION", "STANDARD", ExecutionClass::Mutation),
            ("CRITICAL", "STANDARD", ExecutionClass::Critical),
            ("READ", "DURABLE", ExecutionClass::Read),
        ] {
            let catalog = catalog_for(json!([{
                "id": "sneaky",
                "descriptor_version": 1,
                "execution_class": class,
                "assurance_profile": assurance,
                "execution_route": "DIRECT",
                "authority_policy": { "id": "sneaky", "grant_required": false },
                "adapter_id": "test",
            }]));
            let port = port_with_catalog(catalog);
            let request = request_for("sneaky", wire_class);
            let error = port.build_abi_request(&request).unwrap_err();
            assert_eq!(
                error.code, "EXECUTION_ROUTE_MISMATCH",
                "{class}/{assurance}"
            );
        }
    }

    #[test]
    fn refuses_non_object_arguments() {
        let port = port_with_catalog(catalog_for(counter_descriptor()));
        let mut request = request_for("test.counter.increment", ExecutionClass::Mutation);
        request.args = json!([1, 2, 3]);
        let error = port.build_abi_request(&request).unwrap_err();
        assert_eq!(error.code, "INVALID_REQUEST");
    }

    #[test]
    fn dispatches_and_maps_a_successful_mutation() {
        let path = temp_socket_path("success");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).expect("length");
            let length = u32::from_be_bytes(length_bytes) as usize;
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).expect("payload");
            let request: serde_json::Value = serde_json::from_slice(&payload).expect("json");
            assert_eq!(request["capability"], "test.counter.increment");
            assert_eq!(request["idempotency_key"], "idem-1");
            let response = br#"{"status":"SUCCEEDED","result":{"counter":"c","value":2}}"#;
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .expect("length");
            stream.write_all(response).expect("body");
        });

        let port = NemoCrabedenceExecutionPort::new(
            ExecutionSocketClient::new(&path),
            catalog_for(counter_descriptor()),
        );
        let request = request_for("test.counter.increment", ExecutionClass::Mutation);
        let result = port.execute(&request).expect("executed");
        assert_eq!(result.output["value"], 2);
        assert_eq!(result.outcome_certainty, OutcomeCertainty::ConfirmedSuccess);
        server.join().expect("server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn maps_a_lost_response_to_unknown() {
        let path = temp_socket_path("lost");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).expect("length");
            let length = u32::from_be_bytes(length_bytes) as usize;
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).expect("payload");
            // Close without responding: the effect may have occurred.
        });

        let port = NemoCrabedenceExecutionPort::new(
            ExecutionSocketClient::new(&path),
            catalog_for(counter_descriptor()),
        );
        let request = request_for("test.counter.increment", ExecutionClass::Mutation);
        let error = port.execute(&request).unwrap_err();
        assert_eq!(error.code, "EXECUTION_UNKNOWN");
        assert!(error.reconciliation_required);
        assert!(!error.retryable);
        assert_eq!(state_for_error(&error), ExecutionState::Unknown);
        server.join().expect("server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn maps_a_refused_connection_to_a_retryable_failure() {
        let port = NemoCrabedenceExecutionPort::new(
            ExecutionSocketClient::new(temp_socket_path("absent")),
            catalog_for(counter_descriptor()),
        );
        let request = request_for("test.counter.increment", ExecutionClass::Mutation);
        let error = port.execute(&request).unwrap_err();
        assert_eq!(error.code, "TRANSPORT_PRE_DISPATCH");
        assert!(error.retryable);
        assert_eq!(state_for_error(&error), ExecutionState::Failed);
    }
}
