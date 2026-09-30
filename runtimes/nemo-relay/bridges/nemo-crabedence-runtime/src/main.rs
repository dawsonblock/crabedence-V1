// SPDX-License-Identifier: Apache-2.0

//! The NEMO effect runtime: one process that routes capability invocations
//! through the verified registry.
//!
//! This is the composition layer the transfer's architecture calls for. NeMo
//! Relay's own kernel cannot carry consequential execution — its authority path
//! either refuses or requires NeMo Relay to hold authority it must not hold
//! (finding 6 in `docs/plan/nemo-runtime-transfer.md`) — so the router sits
//! above it, and this binary is that router as a running instance rather than a
//! library under test.
//!
//! What it does:
//!
//! 1. verifies the registry envelope next to the socket, and fails closed if it
//!    does not match its digest;
//! 2. resolves the capability's class and route **from that registry**, never
//!    from the caller;
//! 3. routes: `LOCAL` executes in-process, `CRABEDENCE` crosses the kernel,
//!    `DIRECT` fails closed until a read path is wired.
//!
//! It also hosts a real native plugin when asked (`--plugin`): the host is
//! started as a process, the artifact is loaded and activated through it, the
//! registrations are proxied into this process, and an optional managed tool
//! call runs through NeMo Relay's own chain with the plugin's registration
//! executing in the child. That is Phase 1 of the plugin-host composition; see
//! [`plugin_host`] for what it deliberately leaves to Phase 2.
//!
//! What it does **not** do yet: turn a plugin request into an `EffectRouter`
//! request. A plugin cannot today ask for a capability — registrations are
//! middleware and observability, not callables — so that mediation is new
//! protocol surface rather than a wiring gap. The local backend is likewise a
//! placeholder standing in for NeMo Relay's function-hook execution; it exists
//! so the `LOCAL` route has somewhere to go, and it is labelled as such rather
//! than presented as the real path.
//!
//! Usage:
//!
//! ```text
//! nemo-crabedence-runtime --capability <id> [--arguments <json>] [--principal <id>]
//!                         [--grant <authority-ref>] [--idempotency-key <key>]
//!                         [--socket <path>] [--snapshot <path>]
//!
//! nemo-crabedence-runtime --plugin <manifest-or-dir> --plugin-id <id>
//!                         --component <kind> [--tool <name>] [--arguments <json>]
//! ```
//!
//! `--idempotency-key` is required for `MUTATION` and `CRITICAL` capabilities.
//! It is the caller's logical-action key: stable across retries of one action,
//! unique across distinct actions. The runtime namespaces it per principal —
//! the same construction the kernel applies — so two principals cannot collide
//! on one key, and a capability-derived default, which would name every
//! invocation the same operation, is refused.
//!
//! The outcome is printed as JSON on stdout: `{"status": "SUCCEEDED", ...}` or
//! `{"status": "FAILED", "code": ..., "retryable": ..., ...}`, with `UNKNOWN`
//! kept distinct because it must never be retried.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nemo_crabedence_bridge::capability_snapshot::{
    RegistryDescriptor, RegistryExecutionClass, load_catalog_from_path,
};
use nemo_crabedence_bridge::execution_port::NemoCrabedenceExecutionPort;
use nemo_crabedence_bridge::transport::{ExecutionSocketClient, default_socket_path};
use nemo_effect_router::EffectRouter;
use nemo_relay_executor::unstable::{
    CapabilityIdentity, EffectExecutionError, ExecutionBackend, ExecutionClass, ExecutionIdentity,
    ExecutionRequest, ExecutionResult, OutcomeCertainty, RuntimeIdentity,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod plugin_host;

/// The placeholder local executor for `LOCAL`-routed capabilities.
///
/// NeMo Relay's real local path is its function-hook layer, which is not wired
/// here. This stands in so the route has somewhere to go, and returns the
/// arguments as its result — deliberately inert, so a misroute is visible rather
/// than plausible.
struct LocalEchoBackend;

impl ExecutionBackend for LocalEchoBackend {
    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, EffectExecutionError> {
        Ok(ExecutionResult {
            output: json!({
                "local": true,
                "placeholder": true,
                "capability": request.identity.capability.capability_id,
                "arguments": request.args,
            }),
            outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
            receipt_digest: None,
            receipt: None,
        })
    }
}

struct Options {
    capability: Option<String>,
    arguments: serde_json::Value,
    principal: String,
    grant: Option<String>,
    idempotency_key: Option<String>,
    socket: PathBuf,
    snapshot: PathBuf,
    plugin: Option<PathBuf>,
    plugin_id: Option<String>,
    component: Option<String>,
    tool: Option<String>,
}

fn parse_options() -> Result<Options, String> {
    parse_options_from(std::env::args().skip(1))
}

fn parse_options_from<I>(mut args: I) -> Result<Options, String>
where
    I: Iterator<Item = String>,
{
    let mut capability = None;
    let mut arguments = json!({});
    let mut principal = "alice@example.com".to_string();
    let mut grant = None;
    let mut idempotency_key = None;
    let mut socket = None;
    let mut snapshot = None;
    let mut plugin = None;
    let mut plugin_id = None;
    let mut component = None;
    let mut tool = None;

    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--capability" => capability = Some(value()?),
            "--arguments" => {
                arguments = serde_json::from_str(&value()?)
                    .map_err(|error| format!("--arguments must be JSON: {error}"))?
            }
            "--principal" => principal = value()?,
            "--grant" => grant = Some(value()?),
            "--idempotency-key" => idempotency_key = Some(value()?),
            "--socket" => socket = Some(PathBuf::from(value()?)),
            "--snapshot" => snapshot = Some(PathBuf::from(value()?)),
            "--plugin" => plugin = Some(PathBuf::from(value()?)),
            "--plugin-id" => plugin_id = Some(value()?),
            "--component" => component = Some(value()?),
            "--tool" => tool = Some(value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    let socket = socket.unwrap_or_else(default_socket_path);
    let snapshot = snapshot.unwrap_or_else(|| {
        socket
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("capabilities.json")
    });
    match (&plugin, &capability) {
        (Some(_), Some(_)) => {
            return Err(
                "--plugin and --capability are separate modes and cannot be combined".to_string(),
            );
        }
        (None, None) => {
            return Err(
                "--capability is required (or --plugin for the plugin-host mode)".to_string(),
            );
        }
        _ => {}
    }
    if plugin.is_some() {
        plugin_id
            .as_deref()
            .ok_or("--plugin-id is required with --plugin")?;
        component
            .as_deref()
            .ok_or("--component is required with --plugin")?;
    }
    // The key stays the caller's and stays absent when they gave none. Whether
    // one is required depends on the registered class, which is resolved from
    // the verified registry after this parse — see `request_for`.
    Ok(Options {
        capability,
        arguments,
        principal,
        grant,
        idempotency_key,
        socket,
        snapshot,
        plugin,
        plugin_id,
        component,
        tool,
    })
}

/// Maps the registry's class onto NeMo Relay's vocabulary.
///
/// The class comes from the verified descriptor, never from the caller: the
/// kernel refuses a mismatch, and asserting one locally would be the caller
/// choosing its own classification.
const fn execution_class_of(class: RegistryExecutionClass) -> ExecutionClass {
    match class {
        RegistryExecutionClass::Pure => ExecutionClass::Pure,
        RegistryExecutionClass::Read => ExecutionClass::Read,
        RegistryExecutionClass::Mutation => ExecutionClass::Mutation,
        RegistryExecutionClass::Critical => ExecutionClass::Critical,
    }
}

/// The runtime identity this binary executes under.
///
/// The id names this binary, not NeMo Relay's own `nemo-effect-runtime` crate:
/// diagnostics, receipts, and evidence should agree with the executable a
/// caller actually ran.
fn runtime_identity(principal: &str) -> RuntimeIdentity {
    RuntimeIdentity {
        principal_id: principal.to_string(),
        tenant_id: None,
        runtime_id: "nemo-crabedence-runtime".to_string(),
        environment: "runtime".to_string(),
        session_id: None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// SHA-256 over the RFC 8785 canonical JSON of a value.
///
/// Canonical, so two spellings of the same JSON — `{"a":1,"b":2}` and
/// `{"b":2,"a":1}` — digest identically. This is the definition the kernel
/// uses for its own argument and binding digests.
fn canonical_digest(value: &serde_json::Value) -> Result<String, String> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| format!("canonicalizing an identity input failed: {error}"))?;
    Ok(sha256_hex(&bytes))
}

/// The canonical digest binding runtime, environment, and session provenance.
///
/// The same construction the kernel uses, so the binding a host session claims
/// is the binding this runtime publishes.
fn runtime_binding_digest(runtime: &RuntimeIdentity) -> Result<String, String> {
    canonical_digest(&json!({
        "runtime_id": runtime.runtime_id,
        "environment": runtime.environment,
        "session_id": runtime.session_id,
    }))
}

/// The namespace the kernel applies to a caller's logical-action key.
///
/// Scoped by tenant and principal, so the same key from two principals is two
/// operations, and stable for one principal, so a retry of the same action
/// replays rather than duplicating. This mirrors the kernel's own
/// construction, because this runtime stands in for the kernel on the path
/// that reaches the router.
fn scoped_idempotency_key(runtime: &RuntimeIdentity, request_id: &str) -> Result<String, String> {
    canonical_digest(&json!({
        "tenant_id": runtime.tenant_id,
        "principal_id": runtime.principal_id,
        "request_id": request_id,
    }))
}

/// Builds the bound request for one invocation, with the identity every layer
/// downstream sees.
///
/// Identifiers are minted per invocation (UUIDv7, the kernel's own choice) and
/// the idempotency key is the caller's logical-action key — required for
/// `MUTATION` and `CRITICAL`, and the action id for `PURE` and `READ`, exactly
/// as the kernel binds them. The digests are computed over the verified
/// descriptor and the canonical arguments. None of this crosses Crabedence's
/// ABI, which carries only the capability, its arguments, authority material,
/// an idempotency key, and a deadline.
fn request_for(
    options: &Options,
    capability: &str,
    class: ExecutionClass,
    descriptor: &RegistryDescriptor,
    registry_digest: &str,
) -> Result<ExecutionRequest, String> {
    let runtime = runtime_identity(&options.principal);
    let execution_id = Uuid::now_v7().to_string();
    let action_id = Uuid::now_v7().to_string();
    let idempotency_key = match class {
        ExecutionClass::Mutation | ExecutionClass::Critical => {
            let request_id = options.idempotency_key.as_deref().ok_or_else(|| {
                format!(
                    "--idempotency-key is required for {class:?} capabilities: it is the caller's logical-action key, and a capability-derived default would name every invocation the same operation"
                )
            })?;
            scoped_idempotency_key(&runtime, request_id)?
        }
        ExecutionClass::Pure | ExecutionClass::Read => action_id.clone(),
    };

    let args_digest = canonical_digest(&options.arguments)?;
    let registration_digest = canonical_digest(
        &serde_json::to_value(descriptor)
            .map_err(|error| format!("serializing the verified descriptor failed: {error}"))?,
    )?;
    let route_digest = canonical_digest(&json!({
        "execution_route": descriptor.execution_route.as_str(),
        "assurance_profile": descriptor.assurance_profile,
    }))?;
    let runtime_binding_digest = runtime_binding_digest(&runtime)?;

    // The verified snapshot carries no registry-assigned admission identity or
    // policy epoch — those belong to NeMo Relay's own registry, and this
    // snapshot is Crabedence's. They are bound to verified registry content
    // instead of left as constants, so they move when the registry moves and
    // never claim an identity the registry did not issue.
    let admission_id = format!(
        "admission-{}",
        registration_digest
            .get(..16)
            .unwrap_or(&registration_digest)
    );
    let policy_version = descriptor
        .policy_revision
        .as_deref()
        .map(str::trim)
        .filter(|revision| !revision.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("descriptor-v{}", descriptor.descriptor_version));
    let policy_epoch = registry_digest.to_string();

    Ok(ExecutionRequest {
        identity: ExecutionIdentity {
            execution_id: execution_id.clone(),
            invocation_id: execution_id,
            action_id,
            idempotency_key,
            runtime,
            runtime_binding_digest,
            capability: CapabilityIdentity {
                capability_id: capability.to_string(),
                capability_generation: u64::from(descriptor.descriptor_version),
                registration_digest,
                execution_class: class,
                operation: capability.to_string(),
                route_digest,
            },
            admission_id,
            policy_version,
            policy_epoch,
            args_digest,
            grant_digest: None,
            approval_reference: None,
            // This binary declares no deadline: the port omits it from the ABI
            // and Crabedence applies its own bound.
            deadline_unix_ms: 0,
        },
        args: options.arguments.clone(),
        grant: options.grant.clone(),
        trace_id: None,
    })
}

/// Run the plugin-host mode: host a real plugin, and run one managed call
/// through it when a tool was named.
///
/// The host session is bound to the runtime identity this process publishes,
/// so the binding the host verifies is the binding a receipt would name.
fn run_plugin_mode(options: &Options, artifact: &Path) -> ExitCode {
    let (Some(plugin_id), Some(component)) =
        (options.plugin_id.as_deref(), options.component.as_deref())
    else {
        eprintln!(
            "nemo-crabedence-runtime: --plugin-id and --component are required with --plugin"
        );
        return ExitCode::from(2);
    };
    let runtime = runtime_identity(&options.principal);
    let binding = match runtime_binding_digest(&runtime) {
        Ok(binding) => binding,
        Err(message) => {
            eprintln!("nemo-crabedence-runtime: {message}");
            return ExitCode::FAILURE;
        }
    };
    let plugin_options = plugin_host::PluginOptions {
        artifact: artifact.to_path_buf(),
        plugin_id: plugin_id.to_string(),
        component: component.to_string(),
        tool: options.tool.clone(),
        arguments: options.arguments.clone(),
        runtime_binding_digest: binding,
    };
    match plugin_host::host(&plugin_options) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("nemo-crabedence-runtime: {message}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("nemo-crabedence-runtime: {message}");
            return ExitCode::from(2);
        }
    };

    if let Some(artifact) = options.plugin.as_deref() {
        return run_plugin_mode(&options, artifact);
    }
    let capability = match options.capability.as_deref() {
        Some(capability) => capability,
        None => {
            eprintln!(
                "nemo-crabedence-runtime: --capability is required (or --plugin for the plugin-host mode)"
            );
            return ExitCode::from(2);
        }
    };

    // Verification first: an unverified or tampered snapshot never becomes a
    // catalog, so nothing below can route on descriptors the registry did not
    // digest.
    let catalog = match load_catalog_from_path(&options.snapshot) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!(
                "nemo-crabedence-runtime: refusing to route — {error} (snapshot {})",
                options.snapshot.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let descriptor = match catalog.descriptor(capability) {
        Some(descriptor) => descriptor,
        None => {
            eprintln!(
                "nemo-crabedence-runtime: {capability} is not in the verified registry — no routing metadata exists for it"
            );
            return ExitCode::FAILURE;
        }
    };
    let class = execution_class_of(descriptor.execution_class);

    // Identity first, and fail closed: a consequential invocation without a
    // caller-supplied logical-action key is refused before any dispatch, not
    // given a default that would collide across distinct actions.
    let request = match request_for(
        &options,
        capability,
        class,
        descriptor,
        catalog.registry_sha256(),
    ) {
        Ok(request) => request,
        Err(message) => {
            eprintln!("nemo-crabedence-runtime: {message}");
            return ExitCode::from(2);
        }
    };

    let router = EffectRouter::new(
        catalog,
        LocalEchoBackend,
        NemoCrabedenceExecutionPort::new(ExecutionSocketClient::new(&options.socket), {
            // The port re-verifies the catalog itself; loading twice keeps each
            // component's input verified rather than passing one instance
            // around as an assumption.
            match load_catalog_from_path(&options.snapshot) {
                Ok(catalog) => catalog,
                Err(error) => {
                    eprintln!("nemo-crabedence-runtime: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }),
    );

    match router.execute(&request) {
        Ok(result) => {
            println!(
                "{}",
                json!({
                    "status": "SUCCEEDED",
                    "result": result.output,
                    "receipt_digest": result.receipt_digest,
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            let status = match error.outcome_certainty {
                OutcomeCertainty::Unknown => "UNKNOWN",
                OutcomeCertainty::ConfirmedFailure => "FAILED",
                OutcomeCertainty::ConfirmedSuccess => "SUCCEEDED",
            };
            println!(
                "{}",
                json!({
                    "status": status,
                    "code": error.code,
                    "message": error.message,
                    "retryable": error.retryable,
                    "reconciliation_required": error.reconciliation_required,
                })
            );
            // UNKNOWN is not a failure the caller may retry, so it gets its own
            // exit code — the same convention `crabbox invoke` uses.
            if status == "UNKNOWN" {
                ExitCode::from(3)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_crabedence_bridge::capability_snapshot::{RegistryDescriptor, RegistryExecutionRoute};

    fn descriptor(
        class: RegistryExecutionClass,
        route: RegistryExecutionRoute,
        descriptor_version: u32,
    ) -> RegistryDescriptor {
        RegistryDescriptor {
            id: "test.counter.increment".to_string(),
            descriptor_version,
            policy_revision: None,
            execution_class: class,
            assurance_profile: "DURABLE".to_string(),
            execution_route: route,
            schema: None,
            authority_policy: None,
            adapter_id: "test".to_string(),
        }
    }

    fn options(principal: &str, idempotency_key: Option<&str>) -> Options {
        Options {
            capability: Some("test.counter.increment".to_string()),
            arguments: json!({"amount": 1}),
            principal: principal.to_string(),
            grant: None,
            idempotency_key: idempotency_key.map(str::to_string),
            socket: PathBuf::from("/tmp/execution.sock"),
            snapshot: PathBuf::from("/tmp/capabilities.json"),
            plugin: None,
            plugin_id: None,
            component: None,
            tool: None,
        }
    }

    fn request(class: ExecutionClass, options: &Options) -> ExecutionRequest {
        let registered = match class {
            ExecutionClass::Pure => RegistryExecutionClass::Pure,
            ExecutionClass::Read => RegistryExecutionClass::Read,
            ExecutionClass::Mutation => RegistryExecutionClass::Mutation,
            ExecutionClass::Critical => RegistryExecutionClass::Critical,
        };
        request_for(
            options,
            "test.counter.increment",
            class,
            &descriptor(registered, RegistryExecutionRoute::Crabedence, 1),
            "registry-digest",
        )
        .expect("the request must bind")
    }

    #[test]
    fn mutation_and_critical_require_a_caller_supplied_key() {
        for class in [ExecutionClass::Mutation, ExecutionClass::Critical] {
            let error = request_for(
                &options("alice@example.com", None),
                "test.counter.increment",
                class,
                &descriptor(
                    RegistryExecutionClass::Mutation,
                    RegistryExecutionRoute::Crabedence,
                    1,
                ),
                "registry-digest",
            )
            .expect_err("a consequential invocation without a key must be refused");
            assert!(error.contains("--idempotency-key"), "got: {error}");
        }
    }

    #[test]
    fn pure_and_read_bind_the_action_id_as_the_key() {
        for class in [ExecutionClass::Pure, ExecutionClass::Read] {
            let bound = request(class, &options("alice@example.com", None));
            assert_eq!(bound.identity.idempotency_key, bound.identity.action_id);
            assert!(!bound.identity.idempotency_key.is_empty());
        }
    }

    #[test]
    fn one_logical_action_yields_one_scoped_key_across_invocations() {
        let first = request(
            ExecutionClass::Mutation,
            &options("alice@example.com", Some("send-001")),
        );
        let second = request(
            ExecutionClass::Mutation,
            &options("alice@example.com", Some("send-001")),
        );
        assert_eq!(
            first.identity.idempotency_key,
            second.identity.idempotency_key
        );
        assert_ne!(first.identity.execution_id, second.identity.execution_id);
        assert_ne!(first.identity.action_id, second.identity.action_id);

        let other_action = request(
            ExecutionClass::Mutation,
            &options("alice@example.com", Some("send-002")),
        );
        assert_ne!(
            first.identity.idempotency_key,
            other_action.identity.idempotency_key
        );

        let other_principal = request(
            ExecutionClass::Mutation,
            &options("bob@example.com", Some("send-001")),
        );
        assert_ne!(
            first.identity.idempotency_key,
            other_principal.identity.idempotency_key
        );
    }

    #[test]
    fn invocation_ids_are_unique_and_the_invocation_id_is_the_execution_id() {
        let bound = request(ExecutionClass::Read, &options("alice@example.com", None));
        assert_eq!(bound.identity.invocation_id, bound.identity.execution_id);
        assert_ne!(bound.identity.execution_id, bound.identity.action_id);
    }

    #[test]
    fn argument_digests_are_canonical_and_content_sensitive() {
        let mut left = options("alice@example.com", Some("send-001"));
        left.arguments = json!({"b": 1, "a": 2});
        let mut right = options("alice@example.com", Some("send-001"));
        right.arguments = json!({"a": 2, "b": 1});
        let mut changed = options("alice@example.com", Some("send-001"));
        changed.arguments = json!({"a": 2, "b": 2});

        let left = request(ExecutionClass::Mutation, &left);
        let right = request(ExecutionClass::Mutation, &right);
        let changed = request(ExecutionClass::Mutation, &changed);
        assert_eq!(left.identity.args_digest, right.identity.args_digest);
        assert_ne!(left.identity.args_digest, changed.identity.args_digest);
        assert_eq!(left.identity.args_digest.len(), 64);
    }

    #[test]
    fn descriptor_digests_track_the_verified_descriptor() {
        let base = request_for(
            &options("alice@example.com", Some("send-001")),
            "test.counter.increment",
            ExecutionClass::Mutation,
            &descriptor(
                RegistryExecutionClass::Mutation,
                RegistryExecutionRoute::Crabedence,
                1,
            ),
            "registry-digest",
        )
        .expect("the request must bind");
        let next_version = request_for(
            &options("alice@example.com", Some("send-001")),
            "test.counter.increment",
            ExecutionClass::Mutation,
            &descriptor(
                RegistryExecutionClass::Mutation,
                RegistryExecutionRoute::Crabedence,
                2,
            ),
            "registry-digest",
        )
        .expect("the request must bind");
        assert_ne!(
            base.identity.capability.registration_digest,
            next_version.identity.capability.registration_digest
        );
        assert_ne!(
            base.identity.admission_id,
            next_version.identity.admission_id
        );

        let other_route = request_for(
            &options("alice@example.com", Some("send-001")),
            "test.counter.increment",
            ExecutionClass::Mutation,
            &descriptor(
                RegistryExecutionClass::Mutation,
                RegistryExecutionRoute::Direct,
                1,
            ),
            "registry-digest",
        )
        .expect("the request must bind");
        assert_ne!(
            base.identity.capability.route_digest,
            other_route.identity.capability.route_digest
        );
    }

    #[test]
    fn the_runtime_id_names_this_binary() {
        let bound = request(ExecutionClass::Pure, &options("alice@example.com", None));
        assert_eq!(bound.identity.runtime.runtime_id, "nemo-crabedence-runtime");
        assert_eq!(bound.identity.runtime_binding_digest.len(), 64);
    }

    #[test]
    fn option_parsing_keeps_the_key_absent_when_the_caller_gave_none() {
        let parsed = parse_options_from(
            ["--capability", "system.echo"]
                .iter()
                .map(|argument| argument.to_string()),
        )
        .expect("the options must parse");
        assert_eq!(parsed.idempotency_key, None);

        let parsed = parse_options_from(
            [
                "--capability",
                "system.echo",
                "--idempotency-key",
                "send-001",
            ]
            .iter()
            .map(|argument| argument.to_string()),
        )
        .expect("the options must parse");
        assert_eq!(parsed.idempotency_key.as_deref(), Some("send-001"));
    }

    #[test]
    fn plugin_mode_is_separate_from_capability_routing() {
        let parse = |arguments: &[&str]| {
            parse_options_from(arguments.iter().map(|argument| argument.to_string()))
        };

        // A plugin session needs its artifact, the id to load under, and the
        // component to activate.
        assert!(
            parse(&[
                "--plugin",
                "/tmp/plugin",
                "--plugin-id",
                "p",
                "--component",
                "c"
            ])
            .is_ok()
        );
        assert!(parse(&["--plugin", "/tmp/plugin"]).is_err());
        assert!(parse(&["--plugin", "/tmp/plugin", "--plugin-id", "p"]).is_err());

        // The two modes are separate, and neither is assumed.
        assert!(
            parse(&[
                "--plugin",
                "/tmp/plugin",
                "--plugin-id",
                "p",
                "--component",
                "c",
                "--capability",
                "system.echo",
            ])
            .is_err()
        );
        assert!(parse(&[]).is_err());

        let parsed = parse(&[
            "--plugin",
            "/tmp/plugin",
            "--plugin-id",
            "p",
            "--component",
            "c",
            "--tool",
            "example_tool",
            "--arguments",
            "{\"input\":true}",
        ])
        .expect("the plugin options must parse");
        assert_eq!(parsed.capability, None);
        assert_eq!(parsed.tool.as_deref(), Some("example_tool"));
        assert_eq!(parsed.arguments["input"], json!(true));
    }
}
