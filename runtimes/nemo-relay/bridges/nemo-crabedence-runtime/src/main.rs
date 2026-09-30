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
//! What it does, in the frozen order the integration-closure plan fixes:
//!
//! 1. verifies the registry envelope next to the socket, and fails closed if it
//!    does not match its digest;
//! 2. resolves the capability's class and route **from that registry**, never
//!    from the caller, and fixes the pre-middleware identity — the immutable
//!    facts a plugin can observe but not alter;
//! 3. runs the managed middleware chain — plugins may inspect, deny, or rewrite
//!    the arguments, and nothing else;
//! 4. binds the effective arguments the chain delivered — the original and
//!    effective digests, the active middleware set, and the consequential
//!    idempotency identity — into the request the router sees;
//! 5. routes through `EffectRouter`: `LOCAL` executes through the function-hook
//!    backend, `CRABEDENCE` crosses the kernel, `DIRECT` fails closed until a
//!    read path is wired.
//!
//! A managed call that never reaches the routed dispatch — middleware answered
//! it instead — is refused: a capability result that did not cross the router
//! is not evidence of execution.
//!
//! It can also host a real native plugin (`--plugin`): the host is started as a
//! process under the deployment's resolved isolation policy, the artifact is
//! loaded and activated through it, and the registrations are proxied into this
//! process's chains, where they mediate the managed invocation. With
//! `--capability` the plugin composes into that invocation's chain; without
//! one, the standalone host mode runs an optional tool probe instead.
//!
//! What this binary never does is offer a plugin an effect protocol: a
//! plugin's registrations are middleware and observability, so a plugin may
//! mediate an invocation the runtime already chose and can never name a
//! capability, class, route, authority, principal, or identity. See the
//! integration-closure section of `docs/plan/nemo-runtime-transfer.md`.
//!
//! Usage:
//!
//! ```text
//! nemo-crabedence-runtime --capability <id> [--arguments <json>] [--principal <id>]
//!                         [--grant <authority-ref>] [--idempotency-key <key>]
//!                         [--socket <path>] [--snapshot <path>]
//!                         [--plugin <manifest-or-dir> --plugin-id <id> --component <kind>]
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nemo_crabedence_bridge::capability_snapshot::{
    RegistryDescriptor, RegistryExecutionClass, load_catalog_from_path,
};
use nemo_crabedence_bridge::execution_port::NemoCrabedenceExecutionPort;
use nemo_crabedence_bridge::transport::{ExecutionSocketClient, default_socket_path};
use nemo_effect_router::EffectRouter;
use nemo_relay::api::runtime::with_execution_budget;
use nemo_relay::api::tool::{ToolCallExecuteParams, ToolExecutionResult, tool_call_execute};
use nemo_relay::error::FlowError;
use nemo_relay_executor::unstable::{
    CapabilityIdentity, DispatchState, EffectExecutionError, ExecutionBackend, ExecutionClass,
    ExecutionIdentity, ExecutionRequest, ExecutionResult, FunctionHooksExecutionBackend,
    OutcomeCertainty, RuntimeIdentity,
};
use nemo_relay_plugin_host::isolation_policy::NativeIsolationPolicy;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod plugin_host;

/// The application-owned function behind a `LOCAL`-routed capability.
///
/// This is the function hook the registry's `LOCAL` pin names: the runtime —
/// not a plugin, not the model — owns what a pinned-local capability does.
/// The registry today pins exactly one local capability (`system.echo`, whose
/// function is to answer its effective arguments); anything else pinned LOCAL
/// has no registered function here and is refused rather than improvised.
/// Wrapping it in [`FunctionHooksExecutionBackend`] keeps the class check the
/// adapter already owns — PURE/READ execute, anything else is refused.
fn local_function_hook(
    request: &ExecutionRequest,
) -> Result<ExecutionResult, EffectExecutionError> {
    match request.identity.capability.capability_id.as_str() {
        "system.echo" => Ok(ExecutionResult {
            output: json!({
                "local": true,
                "backend": "function-hooks",
                "capability": request.identity.capability.capability_id,
                "arguments": request.args,
            }),
            outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
            receipt_digest: None,
            receipt: None,
        }),
        capability => Err(EffectExecutionError {
            code: "CAPABILITY_UNAVAILABLE".into(),
            dispatch_state: DispatchState::NotDispatched,
            outcome_certainty: OutcomeCertainty::ConfirmedFailure,
            provider_request_id: None,
            retryable: false,
            reconciliation_required: false,
            message: format!(
                "capability {capability} is pinned LOCAL but this runtime registers no local function for it"
            ),
        }),
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
    plugin_config: Option<String>,
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
    let mut plugin_config = None;
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
            "--plugin-config" => {
                let config = value()?;
                match serde_json::from_str::<Value>(&config) {
                    Ok(parsed) if parsed.is_object() => plugin_config = Some(config),
                    Ok(_) => {
                        return Err("--plugin-config must be a JSON object".to_string());
                    }
                    Err(error) => {
                        return Err(format!("--plugin-config must be JSON: {error}"));
                    }
                }
            }
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
    if plugin.is_none() && capability.is_none() {
        return Err(
            "--capability is required (or --plugin alone for the standalone host mode)".to_string(),
        );
    }
    if plugin.is_some() {
        plugin_id
            .as_deref()
            .ok_or("--plugin-id is required with --plugin")?;
        component
            .as_deref()
            .ok_or("--component is required with --plugin")?;
    }
    if tool.is_some() && capability.is_some() {
        return Err(
            "--tool belongs to the standalone plugin mode; with --capability the managed invocation is the capability"
                .to_string(),
        );
    }
    if plugin_config.is_some() && plugin.is_none() {
        return Err("--plugin-config is only meaningful with --plugin".to_string());
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
        plugin_config,
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

/// The digest that names the active middleware set when no plugin composed.
///
/// An invocation that ran with no plugin session is still bound to *which*
/// plugin set mediated it — the empty set — so the evidence field cannot be
/// filled in after the fact to claim a mediation that did not happen.
fn empty_middleware_set_digest() -> Result<String, String> {
    canonical_digest(&json!({ "plugins": [] }))
}

/// The pre-middleware identity: everything fixed when the runtime chose the
/// capability, before any plugin saw the invocation.
///
/// These are the immutable execution facts — the invocation, this attempt's
/// execution id, the logical action, the principal, the capability, the
/// registry, and the runtime binding — plus the original arguments as the
/// caller gave them. Middleware can observe this stage but cannot alter it,
/// which is what makes a bound request able to prove which input became which
/// effective request under which plugin set.
#[derive(Debug)]
struct InvocationIdentity {
    /// This managed invocation's id — one per runtime call.
    invocation_id: String,
    /// This dispatch attempt's id — minted per attempt, never reused.
    execution_id: String,
    /// The logical action's id: the caller's key for consequential classes, so
    /// a retry of one intended effect is one action however many attempts run
    /// it; a fresh id for `PURE`/`READ`, where nothing external can duplicate.
    logical_action_id: String,
    /// The durable idempotency identity: a stable function of the principal and
    /// the logical action for consequential classes — the same derivation the
    /// kernel applies — and the action id itself otherwise.
    idempotency_key: String,
    runtime: RuntimeIdentity,
    runtime_binding_digest: String,
    capability: CapabilityIdentity,
    admission_id: String,
    policy_version: String,
    policy_epoch: String,
    /// The arguments exactly as the caller gave them, and their digest.
    original_args: Value,
    original_args_digest: String,
    grant: Option<String>,
}

impl InvocationIdentity {
    /// Fix the identity for one invocation, from the verified registry.
    ///
    /// Fails closed: a consequential invocation without the caller's
    /// logical-action key is refused here — before middleware and before any
    /// dispatch — rather than given a default that would name every invocation
    /// the same operation.
    fn mint(
        options: &Options,
        capability: &str,
        class: ExecutionClass,
        descriptor: &RegistryDescriptor,
        registry_digest: &str,
    ) -> Result<Self, String> {
        let runtime = runtime_identity(&options.principal);
        let logical_action_id = match class {
            ExecutionClass::Mutation | ExecutionClass::Critical => {
                options.idempotency_key.as_deref().ok_or_else(|| {
                    format!(
                        "--idempotency-key is required for {class:?} capabilities: it is the caller's logical-action key, and a capability-derived default would name every invocation the same operation"
                    )
                })?.to_string()
            }
            ExecutionClass::Pure | ExecutionClass::Read => Uuid::now_v7().to_string(),
        };
        let idempotency_key = match class {
            ExecutionClass::Mutation | ExecutionClass::Critical => {
                scoped_idempotency_key(&runtime, &logical_action_id)?
            }
            ExecutionClass::Pure | ExecutionClass::Read => logical_action_id.clone(),
        };

        let original_args_digest = canonical_digest(&options.arguments)?;
        let registration_digest =
            canonical_digest(&serde_json::to_value(descriptor).map_err(|error| {
                format!("serializing the verified descriptor failed: {error}")
            })?)?;
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

        Ok(Self {
            invocation_id: Uuid::now_v7().to_string(),
            execution_id: Uuid::now_v7().to_string(),
            logical_action_id,
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
            original_args: options.arguments.clone(),
            original_args_digest,
            grant: options.grant.clone(),
        })
    }
}

/// One dispatch attempt under a pre-middleware identity, bound after
/// middleware delivered the effective arguments.
struct BoundAttempt {
    request: ExecutionRequest,
    /// This attempt's execution id — the pre-middleware one for attempt 1,
    /// freshly minted for any further attempt middleware initiated.
    execution_id: String,
    effective_args_digest: String,
}

/// Bind one attempt: the immutable identity plus the effective arguments the
/// middleware chain delivered.
///
/// This is the post-middleware stage — it runs inside the managed call's
/// execution callback, so what reaches the router is exactly what the chain
/// delivered, and the digest it records is over those bytes.
fn bind_attempt(
    identity: &InvocationIdentity,
    effective_args: Value,
    attempt: u64,
) -> Result<BoundAttempt, String> {
    let effective_args_digest = canonical_digest(&effective_args)?;
    let execution_id = if attempt == 1 {
        identity.execution_id.clone()
    } else {
        Uuid::now_v7().to_string()
    };
    Ok(BoundAttempt {
        request: ExecutionRequest {
            identity: ExecutionIdentity {
                execution_id: execution_id.clone(),
                invocation_id: identity.invocation_id.clone(),
                action_id: identity.logical_action_id.clone(),
                idempotency_key: identity.idempotency_key.clone(),
                runtime: identity.runtime.clone(),
                runtime_binding_digest: identity.runtime_binding_digest.clone(),
                capability: identity.capability.clone(),
                admission_id: identity.admission_id.clone(),
                policy_version: identity.policy_version.clone(),
                policy_epoch: identity.policy_epoch.clone(),
                args_digest: effective_args_digest.clone(),
                grant_digest: None,
                approval_reference: None,
                // This binary declares no deadline: the port omits it from the
                // ABI and Crabedence applies its own bound.
                deadline_unix_ms: 0,
            },
            args: effective_args,
            grant: identity.grant.clone(),
            trace_id: None,
        },
        execution_id,
        effective_args_digest,
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
    // The deployment's isolation policy resolves here, through the same
    // `from_environment()` the other NEMO bindings use: an unset variable
    // selects the documented trusted-process default, a malformed value fails
    // startup before a host exists, and a requested confinement this build
    // cannot honor is refused by the supervisor rather than silently dropped.
    let isolation =
        match nemo_relay_plugin_host::isolation_policy::NativeIsolationPolicy::from_environment() {
            Ok(isolation) => isolation,
            Err(message) => {
                eprintln!("nemo-crabedence-runtime: {message}");
                return ExitCode::from(2);
            }
        };
    let plugin_options = plugin_host::PluginOptions {
        artifact: artifact.to_path_buf(),
        plugin_id: plugin_id.to_string(),
        component: component.to_string(),
        component_config: options
            .plugin_config
            .clone()
            .unwrap_or_else(|| "{}".to_string()),
        tool: options.tool.clone(),
        arguments: options.arguments.clone(),
        runtime_binding_digest: binding,
        isolation,
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

/// What one dispatch attempt produced, recorded for the report.
struct AttemptRecord {
    attempt: u64,
    execution_id: String,
    effective_args_digest: String,
    /// The outcome as the router answered it, rendered for the report.
    outcome: Value,
    /// The outcome's own words, so the exit code can follow the truth of the
    /// last dispatch rather than the chain around it.
    status: &'static str,
}

fn outcome_status(result: Result<&ExecutionResult, &EffectExecutionError>) -> &'static str {
    match result {
        Ok(_) => "SUCCEEDED",
        Err(error) => match error.outcome_certainty {
            OutcomeCertainty::Unknown => "UNKNOWN",
            OutcomeCertainty::ConfirmedFailure => "FAILED",
            OutcomeCertainty::ConfirmedSuccess => "SUCCEEDED",
        },
    }
}

fn outcome_json(result: &Result<ExecutionResult, EffectExecutionError>) -> Value {
    match result {
        Ok(result) => json!({
            "status": "SUCCEEDED",
            "result": result.output,
            "receipt_digest": result.receipt_digest,
        }),
        Err(error) => json!({
            "status": outcome_status(Err(error)),
            "code": error.code,
            "message": error.message,
            "retryable": error.retryable,
            "reconciliation_required": error.reconciliation_required,
        }),
    }
}

/// Run one managed capability invocation: the chain mediates, the router
/// dispatches, and every dispatch attempt is bound and recorded.
///
/// This is the frozen composition. The router executes as the managed call's
/// callback, so the effective arguments are exactly what the middleware
/// delivered — request intercepts and execution intercepts included — and the
/// binding happens in the callback, after middleware and before the route. A
/// call that completes without ever reaching the callback was answered by
/// middleware alone; it is refused, because a capability result that never
/// crossed the router is not evidence of execution.
async fn dispatch_managed(
    options: &Options,
    capability: &str,
    catalog: nemo_crabedence_bridge::capability_snapshot::VerifiedCapabilityCatalog,
    identity: InvocationIdentity,
) -> ExitCode {
    // With `--plugin` the session composes first: the host starts under the
    // deployment's isolation policy and its registrations enter this
    // process's chains before the managed call runs — a host that cannot
    // start fails the invocation, never silently drops the middleware.
    let session = match &options.plugin {
        Some(artifact) => {
            let isolation = match NativeIsolationPolicy::from_environment() {
                Ok(isolation) => isolation,
                Err(message) => {
                    eprintln!("nemo-crabedence-runtime: {message}");
                    return ExitCode::from(2);
                }
            };
            match plugin_host::open(&plugin_host::PluginOptions {
                artifact: artifact.clone(),
                plugin_id: options.plugin_id.clone().unwrap_or_default(),
                component: options.component.clone().unwrap_or_default(),
                component_config: options
                    .plugin_config
                    .clone()
                    .unwrap_or_else(|| "{}".to_string()),
                tool: None,
                arguments: Value::Null,
                runtime_binding_digest: identity.runtime_binding_digest.clone(),
                isolation,
            })
            .await
            {
                Ok(session) => Some(session),
                Err(message) => {
                    eprintln!("nemo-crabedence-runtime: {message}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => None,
    };
    let middleware_set_digest = match session.as_ref() {
        Some(session) => session.middleware_set_digest.clone(),
        None => match empty_middleware_set_digest() {
            Ok(digest) => digest,
            Err(message) => {
                eprintln!("nemo-crabedence-runtime: {message}");
                return ExitCode::FAILURE;
            }
        },
    };

    let router = Arc::new(EffectRouter::new(
        catalog,
        FunctionHooksExecutionBackend::new(local_function_hook),
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
    ));

    // The dispatch runs inside the managed call: the chain's callback binds
    // the effective arguments and routes them. An execution intercept may call
    // the continuation more than once — each call is a real dispatch attempt
    // and is recorded as one.
    let attempts: Arc<Mutex<Vec<AttemptRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let attempt_counter = Arc::new(AtomicU64::new(0));
    let identity = Arc::new(identity);
    let budget = match plugin_host::managed_call_budget() {
        Ok(budget) => budget,
        Err(message) => {
            eprintln!("nemo-crabedence-runtime: {message}");
            return ExitCode::from(2);
        }
    };
    let call = {
        let router = Arc::clone(&router);
        let identity = Arc::clone(&identity);
        let attempts = Arc::clone(&attempts);
        let attempt_counter = Arc::clone(&attempt_counter);
        with_execution_budget(budget, async move {
            tool_call_execute(
                ToolCallExecuteParams::builder()
                    .name(capability.to_string())
                    .args(identity.original_args.clone())
                    .func(Arc::new(move |effective_args: Value| {
                        let router = Arc::clone(&router);
                        let identity = Arc::clone(&identity);
                        let attempts = Arc::clone(&attempts);
                        let attempt_counter = Arc::clone(&attempt_counter);
                        Box::pin(async move {
                            let attempt = attempt_counter.fetch_add(1, Ordering::SeqCst) + 1;
                            let (outcome, execution_id, effective_args_digest) =
                                match bind_attempt(&identity, effective_args, attempt) {
                                    Ok(bound) => {
                                        let execution_id = bound.execution_id.clone();
                                        let digest = bound.effective_args_digest.clone();
                                        (router.execute(&bound.request), execution_id, digest)
                                    }
                                    Err(message) => (
                                        Err(EffectExecutionError {
                                            code: "BINDING_FAILED".into(),
                                            dispatch_state: DispatchState::NotDispatched,
                                            outcome_certainty: OutcomeCertainty::ConfirmedFailure,
                                            provider_request_id: None,
                                            retryable: false,
                                            reconciliation_required: false,
                                            message,
                                        }),
                                        format!("attempt-{attempt}"),
                                        String::new(),
                                    ),
                                };
                            let record = AttemptRecord {
                                attempt,
                                execution_id,
                                effective_args_digest,
                                status: outcome_status(outcome.as_ref()),
                                outcome: outcome_json(&outcome),
                            };
                            attempts
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(record);
                            Ok(ToolExecutionResult::new(outcome_json(&outcome)))
                        })
                    }))
                    .build(),
            )
            .await
        })
        .await
    };

    let attempts: Vec<AttemptRecord> = attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drain(..)
        .collect();

    report(
        identity.as_ref(),
        session.as_ref(),
        &middleware_set_digest,
        attempts,
        call,
    )
}

/// Render the outcome and pick the exit code.
///
/// A recorded dispatch is authoritative: a middleware failure that happened
/// after it does not erase what the router answered. With no recorded dispatch
/// the chain is what failed — a guardrail refusal or middleware error is a safe
/// pre-dispatch failure, and a chain that completed without dispatching is a
/// bypass: the capability never executed.
fn report(
    identity: &InvocationIdentity,
    session: Option<&plugin_host::PluginSession>,
    middleware_set_digest: &str,
    attempts: Vec<AttemptRecord>,
    call: Result<ToolExecutionResult, FlowError>,
) -> ExitCode {
    let identity_evidence = json!({
        "invocation_id": identity.invocation_id,
        "logical_action_id": identity.logical_action_id,
        "principal_id": identity.runtime.principal_id,
        "capability_id": identity.capability.capability_id,
        "execution_class": format!("{:?}", identity.capability.execution_class).to_uppercase(),
        "registry_digest": identity.policy_epoch,
        "runtime_binding_digest": identity.runtime_binding_digest,
        "original_args_digest": identity.original_args_digest,
        "middleware_set_digest": middleware_set_digest,
        "idempotency_key": identity.idempotency_key,
    });
    let plugin_evidence = session.map(|session| {
        json!({
            "process_id": session.process_id,
            "descriptor": session.descriptor,
        })
    });
    let attempts_evidence: Vec<Value> = attempts
        .iter()
        .map(|attempt| {
            json!({
                "attempt": attempt.attempt,
                "execution_id": attempt.execution_id,
                "effective_args_digest": attempt.effective_args_digest,
                "status": attempt.status,
            })
        })
        .collect();

    if let Some(last) = attempts.last() {
        // The report shows what the chain answered — the result the caller is
        // actually given, marks and all — but the dispatch's own verdict always
        // wins the authoritative fields: middleware may shape a result, it may
        // not relabel what the router recorded.
        let mut report = match &call {
            Ok(result) if result.result.is_object() => result.result.clone(),
            _ => last.outcome.clone(),
        };
        let object = report.as_object_mut();
        if let Some(object) = object {
            if let Some(verdict) = last.outcome.as_object() {
                for key in [
                    "status",
                    "code",
                    "receipt_digest",
                    "retryable",
                    "reconciliation_required",
                ] {
                    if let Some(value) = verdict.get(key) {
                        object.insert(key.to_string(), value.clone());
                    }
                }
            }
            // A dispatch that recorded its outcome is authoritative — but a
            // middleware failure after it still happened, and hiding it would
            // make the report less than the truth. The verdict fields stay the
            // dispatch's; this is the evidence that the chain erred anyway.
            if let Err(error) = &call {
                object.insert(
                    "post_dispatch_middleware_error".into(),
                    json!(error.to_string()),
                );
            }
            object.insert("identity".into(), identity_evidence);
            object.insert("attempts".into(), json!(attempts_evidence));
            if let Some(plugin) = plugin_evidence {
                object.insert("plugin".into(), plugin);
            }
        }
        println!("{report}");
        // UNKNOWN is not a failure the caller may retry, so it gets its own
        // exit code — the same convention `crabbox invoke` uses.
        return if last.status == "UNKNOWN" {
            ExitCode::from(3)
        } else if last.status == "SUCCEEDED" {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    // No dispatch was attempted: report the chain's own verdict.
    let (status, code, message) = match &call {
        Err(FlowError::GuardrailRejected(reason)) => (
            "FAILED",
            "GUARDRAIL_REJECTED",
            format!("middleware refused the invocation: {reason}"),
        ),
        Err(error) => (
            "FAILED",
            "MIDDLEWARE_FAILED",
            format!("the middleware chain failed before dispatch: {error}"),
        ),
        Ok(_) => (
            "FAILED",
            "DISPATCH_BYPASSED",
            "middleware answered the invocation without reaching the routed dispatch — a capability result that never crossed the EffectRouter is not evidence of execution".to_string(),
        ),
    };
    println!(
        "{}",
        json!({
            "status": status,
            "code": code,
            "message": message,
            "retryable": false,
            "reconciliation_required": false,
            "identity": identity_evidence,
            "plugin": plugin_evidence,
        })
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("nemo-crabedence-runtime: {message}");
            return ExitCode::from(2);
        }
    };

    let capability = match options.capability.as_deref() {
        Some(capability) => capability,
        None => {
            let Some(artifact) = options.plugin.as_deref() else {
                eprintln!(
                    "nemo-crabedence-runtime: --capability is required (or --plugin for the standalone host mode)"
                );
                return ExitCode::from(2);
            };
            return run_plugin_mode(&options, artifact);
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
    // caller-supplied logical-action key is refused before middleware and
    // before any dispatch, not given a default that would collide across
    // distinct actions.
    let identity = match InvocationIdentity::mint(
        &options,
        capability,
        class,
        descriptor,
        catalog.registry_sha256(),
    ) {
        Ok(identity) => identity,
        Err(message) => {
            eprintln!("nemo-crabedence-runtime: {message}");
            return ExitCode::from(2);
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("nemo-crabedence-runtime: the managed call needs an async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(dispatch_managed(&options, capability, catalog, identity))
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
            plugin_config: None,
            tool: None,
        }
    }

    fn identity(class: ExecutionClass, options: &Options) -> InvocationIdentity {
        let registered = match class {
            ExecutionClass::Pure => RegistryExecutionClass::Pure,
            ExecutionClass::Read => RegistryExecutionClass::Read,
            ExecutionClass::Mutation => RegistryExecutionClass::Mutation,
            ExecutionClass::Critical => RegistryExecutionClass::Critical,
        };
        InvocationIdentity::mint(
            options,
            "test.counter.increment",
            class,
            &descriptor(registered, RegistryExecutionRoute::Crabedence, 1),
            "registry-digest",
        )
        .expect("the identity must mint")
    }

    fn request(class: ExecutionClass, options: &Options) -> ExecutionRequest {
        bind_attempt(&identity(class, options), options.arguments.clone(), 1)
            .expect("the attempt must bind")
            .request
    }

    #[test]
    fn mutation_and_critical_require_a_caller_supplied_key() {
        for class in [ExecutionClass::Mutation, ExecutionClass::Critical] {
            let error = InvocationIdentity::mint(
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
    fn one_logical_action_yields_one_scoped_key_across_retries() {
        let first = identity(
            ExecutionClass::Mutation,
            &options("alice@example.com", Some("send-001")),
        );
        let second = identity(
            ExecutionClass::Mutation,
            &options("alice@example.com", Some("send-001")),
        );
        // A retry of one intended effect is one logical action: the durable
        // key and the action id are stable across attempts, while the
        // invocation and its execution id are minted fresh each time.
        assert_eq!(first.idempotency_key, second.idempotency_key);
        assert_eq!(first.logical_action_id, second.logical_action_id);
        assert_ne!(first.execution_id, second.execution_id);
        assert_ne!(first.invocation_id, second.invocation_id);

        let other_action = identity(
            ExecutionClass::Mutation,
            &options("alice@example.com", Some("send-002")),
        );
        assert_ne!(first.idempotency_key, other_action.idempotency_key);
        assert_ne!(first.logical_action_id, other_action.logical_action_id);

        let other_principal = identity(
            ExecutionClass::Mutation,
            &options("bob@example.com", Some("send-001")),
        );
        // The same logical key under another principal is another operation.
        assert_eq!(first.logical_action_id, other_principal.logical_action_id);
        assert_ne!(first.idempotency_key, other_principal.idempotency_key);
    }

    #[test]
    fn every_attempt_gets_its_own_execution_id_under_one_invocation() {
        let identity = identity(
            ExecutionClass::Mutation,
            &options("alice@example.com", Some("send-001")),
        );
        let first = bind_attempt(&identity, json!({"amount": 1}), 1).expect("bound");
        let second = bind_attempt(&identity, json!({"amount": 1}), 2).expect("bound");
        assert_eq!(
            first.request.identity.invocation_id,
            second.request.identity.invocation_id
        );
        assert_eq!(
            first.request.identity.action_id,
            second.request.identity.action_id
        );
        assert_eq!(
            first.request.identity.idempotency_key,
            second.request.identity.idempotency_key
        );
        assert_ne!(
            first.request.identity.execution_id,
            second.request.identity.execution_id
        );
        assert_eq!(first.execution_id, identity.execution_id);
    }

    #[test]
    fn the_invocation_and_execution_ids_are_distinct() {
        let identity = identity(ExecutionClass::Read, &options("alice@example.com", None));
        assert_ne!(identity.invocation_id, identity.execution_id);
        assert_ne!(identity.execution_id, identity.logical_action_id);
    }

    #[test]
    fn the_binding_proves_original_into_effective_arguments() {
        let options = options("alice@example.com", Some("send-001"));
        let identity = identity(ExecutionClass::Mutation, &options);
        let bound = bind_attempt(&identity, json!({"amount": 1, "native_intercept": true}), 1)
            .expect("the attempt must bind");

        // The evidence must show which input became which effective request:
        // the pre-middleware digest is over the caller's arguments, and the
        // bound request carries the digest of what middleware delivered.
        assert_ne!(identity.original_args_digest, bound.effective_args_digest);
        assert_eq!(
            bound.request.identity.args_digest,
            bound.effective_args_digest
        );
        assert_eq!(bound.request.args["native_intercept"], json!(true));

        let original = canonical_digest(&options.arguments).expect("digest");
        assert_eq!(identity.original_args_digest, original);
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
        let mint = |version: u32, route: RegistryExecutionRoute| {
            InvocationIdentity::mint(
                &options("alice@example.com", Some("send-001")),
                "test.counter.increment",
                ExecutionClass::Mutation,
                &descriptor(RegistryExecutionClass::Mutation, route, version),
                "registry-digest",
            )
            .expect("the identity must mint")
        };
        let base = mint(1, RegistryExecutionRoute::Crabedence);
        let next_version = mint(2, RegistryExecutionRoute::Crabedence);
        assert_ne!(
            base.capability.registration_digest,
            next_version.capability.registration_digest
        );
        assert_ne!(base.admission_id, next_version.admission_id);

        let other_route = mint(1, RegistryExecutionRoute::Direct);
        assert_ne!(
            base.capability.route_digest,
            other_route.capability.route_digest
        );
    }

    #[test]
    fn the_runtime_id_names_this_binary() {
        let bound = request(ExecutionClass::Pure, &options("alice@example.com", None));
        assert_eq!(bound.identity.runtime.runtime_id, "nemo-crabedence-runtime");
        assert_eq!(bound.identity.runtime_binding_digest.len(), 64);
    }

    #[test]
    fn the_local_function_hook_answers_only_registered_local_functions() {
        let echo = InvocationIdentity::mint(
            &options("alice@example.com", None),
            "system.echo",
            ExecutionClass::Pure,
            &descriptor(
                RegistryExecutionClass::Pure,
                RegistryExecutionRoute::Local,
                1,
            ),
            "registry-digest",
        )
        .expect("the identity must mint");
        let bound = bind_attempt(&echo, json!({"amount": 1}), 1).expect("bound");
        let result = local_function_hook(&bound.request).expect("system.echo must answer");
        assert_eq!(result.output["local"], json!(true));
        assert_eq!(result.output["backend"], json!("function-hooks"));
        assert_eq!(result.output["arguments"], json!({"amount": 1}));

        // A capability this runtime has no local function for is refused
        // rather than improvised.
        let mut other = bound.request;
        other.identity.capability.capability_id = "unlisted.local".to_string();
        let error = local_function_hook(&other).expect_err("must be refused");
        assert_eq!(error.code, "CAPABILITY_UNAVAILABLE");
        assert_eq!(error.dispatch_state, DispatchState::NotDispatched);
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
    fn the_plugin_and_capability_modes_compose() {
        let parse = |arguments: &[&str]| {
            parse_options_from(arguments.iter().map(|argument| argument.to_string()))
        };

        // A plugin session needs its artifact, the id to load under, and the
        // component to activate — with or without a capability.
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
            .is_ok()
        );
        assert!(parse(&["--plugin", "/tmp/plugin"]).is_err());
        assert!(parse(&["--plugin", "/tmp/plugin", "--plugin-id", "p"]).is_err());
        assert!(parse(&[]).is_err());

        // --tool is the standalone mode's probe; the capability mode's managed
        // invocation is the capability itself.
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
                "--tool",
                "example_tool",
            ])
            .is_err()
        );

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
