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
//! What it does **not** do yet: host plugins. The plugin host
//! (`crates/plugin-host`) is not wired to this runtime, so a plugin cannot yet
//! reach the router — which is why the plugin-host gate scenarios remain open.
//! The local backend is likewise a placeholder standing in for NeMo Relay's
//! function-hook execution; it exists so the `LOCAL` route has somewhere to go,
//! and it is labelled as such rather than presented as the real path.
//!
//! Usage:
//!
//! ```text
//! nemo-effect-runtime --capability <id> [--arguments <json>] [--principal <id>]
//!                     [--grant <authority-ref>] [--idempotency-key <key>]
//!                     [--socket <path>] [--snapshot <path>]
//! ```
//!
//! The outcome is printed as JSON on stdout: `{"status": "SUCCEEDED", ...}` or
//! `{"status": "FAILED", "code": ..., "retryable": ..., ...}`, with `UNKNOWN`
//! kept distinct because it must never be retried.

use std::path::PathBuf;
use std::process::ExitCode;

use nemo_crabedence_bridge::capability_snapshot::{RegistryExecutionClass, load_catalog_from_path};
use nemo_crabedence_bridge::execution_port::NemoCrabedenceExecutionPort;
use nemo_crabedence_bridge::transport::{ExecutionSocketClient, default_socket_path};
use nemo_effect_router::EffectRouter;
use nemo_relay_executor::unstable::{
    CapabilityIdentity, EffectExecutionError, ExecutionBackend, ExecutionClass, ExecutionIdentity,
    ExecutionRequest, ExecutionResult, OutcomeCertainty, RuntimeIdentity,
};
use serde_json::json;

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
    capability: String,
    arguments: serde_json::Value,
    principal: String,
    grant: Option<String>,
    idempotency_key: String,
    socket: PathBuf,
    snapshot: PathBuf,
}

fn parse_options() -> Result<Options, String> {
    let mut capability = None;
    let mut arguments = json!({});
    let mut principal = "alice@example.com".to_string();
    let mut grant = None;
    let mut idempotency_key = None;
    let mut socket = None;
    let mut snapshot = None;

    let mut args = std::env::args().skip(1);
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
    let capability = capability.ok_or("--capability is required")?;
    // The key is the caller's, but it must not be empty for a durable route.
    let idempotency_key = idempotency_key.unwrap_or_else(|| format!("runtime-{capability}"));

    Ok(Options {
        capability,
        arguments,
        principal,
        grant,
        idempotency_key,
        socket,
        snapshot,
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

fn request_for(options: &Options, class: ExecutionClass) -> ExecutionRequest {
    let capability = &options.capability;
    ExecutionRequest {
        identity: ExecutionIdentity {
            execution_id: format!("runtime-{capability}"),
            invocation_id: format!("runtime-{capability}"),
            action_id: format!("runtime-{capability}"),
            idempotency_key: options.idempotency_key.clone(),
            runtime: RuntimeIdentity {
                principal_id: options.principal.clone(),
                tenant_id: None,
                runtime_id: "nemo-effect-runtime".to_string(),
                environment: "runtime".to_string(),
                session_id: None,
            },
            runtime_binding_digest: "runtime-binding".to_string(),
            capability: CapabilityIdentity {
                capability_id: capability.clone(),
                capability_generation: 1,
                registration_digest: "registration".to_string(),
                execution_class: class,
                operation: capability.clone(),
                route_digest: "route".to_string(),
            },
            admission_id: "admission".to_string(),
            policy_version: "1".to_string(),
            policy_epoch: "1".to_string(),
            args_digest: "args".to_string(),
            grant_digest: None,
            approval_reference: None,
            deadline_unix_ms: 0,
        },
        args: options.arguments.clone(),
        grant: options.grant.clone(),
        trace_id: None,
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

    let descriptor = match catalog.descriptor(&options.capability) {
        Some(descriptor) => descriptor,
        None => {
            eprintln!(
                "nemo-crabedence-runtime: {} is not in the verified registry — no routing metadata exists for it",
                options.capability
            );
            return ExitCode::FAILURE;
        }
    };
    let class = execution_class_of(descriptor.execution_class);

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

    let request = request_for(&options, class);
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
