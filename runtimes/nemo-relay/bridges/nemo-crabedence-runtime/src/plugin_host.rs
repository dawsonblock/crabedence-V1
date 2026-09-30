// SPDX-License-Identifier: Apache-2.0

//! Hosting a real native plugin, as a process, from the runtime instance.
//!
//! Phase 1 of the plugin-host composition: the runtime starts the real
//! `nemo-plugin-host` child, loads a plugin artifact through it, activates a
//! component — the plugin's register callbacks run where its library is, in the
//! child — and installs the proxies its registrations report. When asked for a
//! tool call it then runs one managed call through NeMo Relay's own chain: the
//! chain runs in this process, the plugin's registration runs in the child, and
//! the result proves the process boundary end to end.
//!
//! What this module deliberately does **not** do: turn a plugin request into an
//! `EffectRouter` request. A plugin cannot today ask for a capability — what a
//! plugin registers is middleware and observability, and `RuntimeRegistrationKind`
//! has no callable kind — so the mediation between a plugin effect request and
//! the router is new protocol surface, not a wiring gap. That is Phase 2 of the
//! workstream recorded in `docs/plan/nemo-runtime-transfer.md`, together with
//! the canonical invocation envelope it will use.
//!
//! What it also does not do: link the host. `nemo-plugin-host` is started as a
//! process; the native loader is never linked into this binary, which is the
//! invariant the dependency check asserts.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nemo_relay::plugin::execution::{PluginExecutionBackend, PluginManager};
use nemo_relay_plugin_host::continuations::Continuations;
use nemo_relay_plugin_host::off_path::{ObservabilityPolicy, OffPathPluginExecutor};
use nemo_relay_plugin_host::proxy::{ProxyContext, install};
use nemo_relay_plugin_host::supervisor::{PluginHostSupervisorConfig, ProcessPluginBackend};
use nemo_relay_plugin_protocol::{
    PROTOCOL_VERSION, PluginActivateRequest, PluginArtifactIdentity, PluginComponentConfiguration,
    PluginExecutionContext, PluginLoadRequest,
};
use serde_json::{Value, json};
use uuid::Uuid;

/// The budget a managed call runs under, and the window the proxies inherit.
const MANAGED_CALL_BUDGET_MILLIS: u64 = 30_000;

/// The off-path runtime's own budget, for registrations whose answer is
/// published rather than returned.
const OFF_PATH_BUDGET_MILLIS: u64 = 5_000;

/// How much of an invocation's answer this caller will read. Well inside the
/// protocol's frame ceiling, and generous for a tool result.
const MAX_RESPONSE_BYTES: u32 = 1024 * 1024;

/// Everything the plugin mode takes from the command line.
pub struct PluginOptions {
    /// The plugin artifact: a `relay-plugin.toml` manifest, or a directory
    /// holding one.
    pub artifact: PathBuf,
    /// The identifier to load the plugin under.
    pub plugin_id: String,
    /// The component kind to activate, as the plugin declares it.
    pub component: String,
    /// The tool to call through the chain, when one was asked for.
    pub tool: Option<String>,
    /// The tool call's arguments.
    pub arguments: Value,
    /// The runtime binding the host session must claim.
    pub runtime_binding_digest: String,
}

/// Host the plugin and, when asked, run one managed tool call through it.
pub fn host(options: &PluginOptions) -> Result<Value, String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("the plugin host needs an async runtime: {error}"))?;
    runtime.block_on(host_async(options))
}

async fn host_async(options: &PluginOptions) -> Result<Value, String> {
    let artifact = resolve_artifact(&options.artifact)?;
    let artifact_ref = artifact.to_string_lossy();
    let (manifest_sha256, library_sha256) =
        nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact_ref)
            .map_err(|error| format!("the plugin artifact could not be approved: {error}"))?;

    // The host ships beside this binary; `NEMO_RELAY_PLUGIN_HOST` names another
    // one for a deployment that installs it elsewhere.
    let config =
        PluginHostSupervisorConfig::beside_this_executable(options.runtime_binding_digest.clone());
    let backend = ProcessPluginBackend::launch(config)
        .await
        .map_err(|error| format!("the plugin host did not start: {error}"))?;
    let process_id = backend.process_id();

    let loaded = backend
        .load(
            PluginLoadRequest {
                plugin_id: options.plugin_id.clone(),
                artifact: artifact_ref.to_string(),
                identity: PluginArtifactIdentity {
                    manifest_sha256,
                    library_sha256,
                },
            },
            context(options),
        )
        .await
        .map_err(|error| format!("the plugin did not load: {error}"))?;

    let descriptors = backend
        .activate(
            PluginActivateRequest {
                discovery: false,
                components: vec![PluginComponentConfiguration {
                    kind: options.component.clone(),
                    config_json: "{}".to_string(),
                }],
            },
            context(options),
        )
        .await
        .map_err(|error| format!("the plugin did not activate: {error}"))?;
    let descriptor = descriptors
        .into_iter()
        .find(|descriptor| descriptor.plugin_id == options.plugin_id)
        .ok_or_else(|| {
            format!(
                "the host reported no activation for plugin '{}'",
                options.plugin_id
            )
        })?;

    // This process's side of the boundary. The manager owns the backend, the
    // proxy context carries the trusted binding and the off-path runtime the
    // composition owns, and installing the proxies is what puts the plugin's
    // registrations into this process's chains.
    let binding = backend.runtime_binding_digest().to_owned();
    let manager = Arc::new(PluginManager::new(Arc::new(backend)));
    let off_path = Arc::new(
        OffPathPluginExecutor::start(&ObservabilityPolicy {
            budget_millis: OFF_PATH_BUDGET_MILLIS,
            max_in_flight: 8,
        })
        .map_err(|error| format!("the off-path runtime did not start: {error}"))?,
    );
    let proxy_context = ProxyContext::new(manager, binding, OFF_PATH_BUDGET_MILLIS)
        .with_observability_budget(OFF_PATH_BUDGET_MILLIS)
        .with_off_path_executor(off_path)
        .with_continuations(Arc::new(Continuations::new()));
    let proxies = install(proxy_context, &descriptor, loaded.handle.clone()).map_err(|error| {
        format!("this runtime cannot serve what the plugin registered: {error}")
    })?;

    // A managed call, under the trusted budget a runtime publishes for an
    // action: without one the proxy refuses, because a registration reached
    // outside a managed action has no deadline to inherit.
    let tool_call = match &options.tool {
        None => Value::Null,
        Some(tool) => {
            let budget = nemo_relay::api::runtime::ExecutionBudget::new(
                nemo_relay::api::runtime::budget_now_unix_ms() + MANAGED_CALL_BUDGET_MILLIS,
                MANAGED_CALL_BUDGET_MILLIS,
            );
            let arguments = options.arguments.clone();
            let rewritten = nemo_relay::api::runtime::with_execution_budget(budget, async move {
                nemo_relay::api::tool::tool_request_intercepts(tool, arguments).await
            })
            .await
            .map_err(|error| format!("the managed call did not complete: {error}"))?;
            json!({ "tool": tool, "result": rewritten })
        }
    };

    // Dropping the proxies removes the registrations from this process's
    // chains, and dropping the manager kills the host: a plugin's callbacks
    // cannot outlive the runtime that installed them.
    drop(proxies);

    Ok(json!({
        "status": if options.tool.is_some() { "INVOKED" } else { "HOSTED" },
        "host": { "process_id": process_id },
        "plugin": serde_json::to_value(&descriptor).map_err(|error| error.to_string())?,
        "tool_call": tool_call,
    }))
}

/// The context every operation in this session carries.
fn context(options: &PluginOptions) -> PluginExecutionContext {
    PluginExecutionContext {
        operation_request_id: Uuid::now_v7().to_string(),
        protocol_version: PROTOCOL_VERSION,
        runtime_binding_digest: options.runtime_binding_digest.clone(),
        deadline_unix_ms: nemo_relay::api::runtime::budget_now_unix_ms()
            + MANAGED_CALL_BUDGET_MILLIS,
        remaining_budget_millis: MANAGED_CALL_BUDGET_MILLIS,
        max_response_bytes: MAX_RESPONSE_BYTES,
    }
}

/// Resolve the artifact: a manifest path, or a directory holding one.
fn resolve_artifact(path: &Path) -> Result<PathBuf, String> {
    if path.is_dir() {
        let manifest = path.join(nemo_relay::plugin::dynamic::DYNAMIC_PLUGIN_MANIFEST_FILENAME);
        if !manifest.is_file() {
            return Err(format!(
                "{} holds no {}",
                path.display(),
                nemo_relay::plugin::dynamic::DYNAMIC_PLUGIN_MANIFEST_FILENAME
            ));
        }
        return Ok(manifest);
    }
    if !path.is_file() {
        return Err(format!(
            "{} is neither a plugin manifest nor a directory holding one",
            path.display()
        ));
    }
    Ok(path.to_path_buf())
}
