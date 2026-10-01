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
//! `EffectRouter` request. Under the integration-closure plan that boundary is
//! permanent, not deferred — plugins are middleware only, and there is no
//! plugin-effect protocol: a plugin may inspect, deny, sanitize, or rewrite the
//! arguments of a managed invocation whose capability the runtime has already
//! chosen, and it can never name a capability, class, route, authority,
//! principal, or identity. `RuntimeRegistrationKind` having no callable kind is
//! the shape the plan depends on, not a gap to close. See the "Integration
//! closure" section of `docs/plan/nemo-runtime-transfer.md`.
//!
//! What it also does not do: link the host. `nemo-plugin-host` is started as a
//! process; the native loader is never linked into this binary, which is the
//! invariant the dependency check asserts.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nemo_relay::plugin::execution::{PluginExecutionBackend, PluginManager};
use nemo_relay_plugin_host::isolation_policy::NativeIsolationPolicy;
use nemo_relay_plugin_host::off_path::{ObservabilityPolicy, OffPathPluginExecutor};
use nemo_relay_plugin_host::proxy::{ProxyContext, RegistrationProxies, install};
use nemo_relay_plugin_host::supervisor::{PluginHostSupervisorConfig, ProcessPluginBackend};
use nemo_relay_plugin_protocol::{
    PROTOCOL_VERSION, PluginActivateRequest, PluginArtifactIdentity, PluginComponentConfiguration,
    PluginDescriptor, PluginExecutionContext, PluginLoadRequest,
};
use serde_json::{Value, json};
use uuid::Uuid;

/// The budget a managed call runs under, and the window the proxies inherit.
const MANAGED_CALL_BUDGET_MILLIS: u64 = 30_000;

/// The deployment knob for that budget. A managed call's deadline bounds the
/// middleware it crosses — a plugin that holds a call past it fails the call —
/// so a deployment that needs a tighter bound sets it here rather than
/// rebuilding. Malformed values fail startup, like every other env-resolved
/// setting in this composition.
const MANAGED_CALL_BUDGET_ENV: &str = "NEMO_RELAY_MANAGED_CALL_BUDGET_MS";

/// The budget every managed call in this composition runs under: the
/// documented default, or the deployment's override.
///
/// Resolved from the environment at the CLI boundary, the same place the
/// isolation policy resolves — a bad value is a startup failure, not a call
/// that surprises with the wrong deadline.
pub(crate) fn managed_call_budget() -> Result<nemo_relay::api::runtime::ExecutionBudget, String> {
    let millis =
        managed_call_budget_millis(std::env::var(MANAGED_CALL_BUDGET_ENV).ok().as_deref())?;
    Ok(nemo_relay::api::runtime::ExecutionBudget::new(
        nemo_relay::api::runtime::budget_now_unix_ms() + millis,
        millis,
    ))
}

/// The deadline in milliseconds: the default, or the deployment's value.
fn managed_call_budget_millis(value: Option<&str>) -> Result<u64, String> {
    match value {
        None => Ok(MANAGED_CALL_BUDGET_MILLIS),
        Some(raw) => match raw.parse::<u64>() {
            Ok(millis) if millis > 0 => Ok(millis),
            _ => Err(format!(
                "{MANAGED_CALL_BUDGET_ENV} is not a positive millisecond count: {raw:?}"
            )),
        },
    }
}

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
    /// The component's activation configuration (`{}` when unset).
    pub component_config: String,
    /// The tool to call through the chain, when one was asked for.
    pub tool: Option<String>,
    /// The tool call's arguments.
    pub arguments: Value,
    /// The runtime binding the host session must claim.
    pub runtime_binding_digest: String,
    /// How contained the host process must be. The caller resolves this
    /// through `NativeIsolationPolicy::from_environment()` — this module does
    /// not substitute a default for a deployment's stated policy.
    pub isolation: NativeIsolationPolicy,
    /// The digest the executed host binary must carry, when the deployment
    /// pins one (`NEMO_RELAY_PLUGIN_HOST_SHA256`). A qualified distribution
    /// sets it from the component manifest so `NEMO_RELAY_PLUGIN_HOST` can
    /// locate the host without locating a different binary.
    pub host_sha256_pin: Option<String>,
}

/// The executed host binary's identity.
///
/// `executable` is the path the child was spawned from — under the trusted
/// policy that is a staged copy of the resolved host (see [`stage_host`]),
/// under a confinement policy it is the bundle's executable — and the digest
/// is the content of what was executed, computed at session open.
pub struct HostIdentity {
    /// The executable the child was spawned from.
    pub executable: PathBuf,
    /// The executable the deployment's resolution named, before any staging.
    /// Equal to `executable` when nothing was staged.
    pub resolved: PathBuf,
    /// Its SHA-256, hex.
    pub sha256: String,
    /// Whether the deployment pinned the digest (`true` means it matched —
    /// a mismatch never becomes a session).
    pub pinned: bool,
    /// Whether the executed binary is a verified staged copy rather than the
    /// resolved path itself.
    pub staged: bool,
}

/// A verified copy of the host executable, in a directory private to this
/// session.
///
/// This is trusted-process mode's answer to hash-then-spawn: hashing a path
/// and later executing whatever is at that path leaves a window where
/// replacing the file runs something the digest never covered. The host's
/// verified bytes are copied to a directory this session creates, the pin is
/// checked against the copy, and the child is spawned from the copy — so the
/// digest that was approved is the digest of the file `exec` opens. The
/// directory is removed when the session ends; a runtime that dies before it
/// can clean up leaves only inert bytes in a private directory.
struct StagedHost {
    /// The private staging directory.
    dir: PathBuf,
    /// The staged executable inside it.
    executable: PathBuf,
}

impl Drop for StagedHost {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copy the approved host to a private path the spawn will execute.
///
/// The directory's name is unguessable and its mode owner-only, so no other
/// account can preempt or replace the staged copy — the TOCTOU this closes is
/// a mutably-writable release directory, not a same-UID attacker, which a
/// trusted-process deployment already accepts.
fn stage_host(source: &Path) -> Result<StagedHost, String> {
    let dir = std::env::temp_dir().join(format!("nemo-plugin-host-{}", Uuid::now_v7().simple()));
    let executable = dir.join("nemo-plugin-host");
    let staged = (|| -> Result<(), String> {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(&dir).map_err(|error| {
            format!(
                "the plugin host's staging directory '{}' could not be created: {error}",
                dir.display()
            )
        })?;
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                format!("the plugin host's staging directory could not be made private: {error}")
            },
        )?;
        std::fs::copy(source, &executable).map_err(|error| {
            format!(
                "the plugin host '{}' could not be staged for execution: {error}",
                source.display()
            )
        })?;
        // Read and execute, not write: the staged copy is fixed content.
        #[cfg(unix)]
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).map_err(
            |error| format!("the staged plugin host's permissions could not be fixed: {error}"),
        )?;
        Ok(())
    })();
    match staged {
        Ok(()) => Ok(StagedHost { dir, executable }),
        Err(error) => {
            let _ = std::fs::remove_dir_all(&dir);
            Err(error)
        }
    }
}

/// An active plugin-host session.
///
/// The proxies keep the plugin's registrations installed in this process's
/// chains and the manager keeps the host child alive. The session is scoped:
/// dropping it removes the registrations and ends the child, so a plugin's
/// callbacks cannot outlive the runtime that installed them.
pub struct PluginSession {
    /// The activated component's descriptor — the plugin's identity and the
    /// registrations it installed.
    pub descriptor: PluginDescriptor,
    /// The host child's process id, when the host reports one.
    pub process_id: Option<u32>,
    /// The digest naming the active middleware set — which plugin, at which
    /// artifact identity, installed which registrations. A bound invocation
    /// records it, so evidence can prove which plugin set mediated the request.
    pub middleware_set_digest: String,
    /// Explicit plugin artifact identities carried into durable mediation
    /// evidence so operators can inspect them without reversing the set hash.
    pub plugin_manifest_sha256: String,
    pub plugin_library_sha256: String,
    /// Digest of canonical activation configuration; raw configuration can
    /// contain secrets and is never copied into execution evidence.
    pub activation_config_sha256: String,
    /// The host executable the supervisor resolved and its SHA-256 — the
    /// binary that actually holds the plugin, which is what a qualified
    /// deployment's pin binds. Recorded so a receipt can name it.
    pub host: HostIdentity,
    /// Held, not read: the manager owns the backend, so the session's lifetime
    /// is the host child's.
    _manager: Arc<PluginManager>,
    /// Held, not read: dropping the proxies is what removes the plugin's
    /// registrations from this process's chains.
    _proxies: RegistrationProxies,
    /// Held, not read: the staged host copy must live exactly as long as the
    /// child spawned from it — dropping it deletes the running executable's
    /// file (the process keeps running on Unix, but the path's usefulness to
    /// an observer ends).
    _staging: Option<StagedHost>,
}

/// The middleware-set digest for one activated plugin.
///
/// This digest is the composition's answer to "which middleware mediated this
/// request?", so it binds everything that answer could depend on: the plugin's
/// verified artifact identity (manifest and library SHA-256), the component
/// activated and the configuration it was activated with, the complete
/// registration descriptors — operation, ordering, shape, gating — and the
/// host executable that ran them. Two sessions that differ in any of those
/// produce different digests even when their registration ids are the same.
///
/// The registration and capability lists are canonicalized and sorted by
/// their canonical bytes, so the digest names the set rather than the order
/// the host happened to report it in.
fn middleware_set_digest(
    descriptor: &PluginDescriptor,
    manifest_sha256: &str,
    library_sha256: &str,
    component_kind: &str,
    component_config_json: &str,
    host_sha256: &str,
) -> Result<String, String> {
    let canonical_set = |items: Vec<Value>| -> Result<Vec<Value>, String> {
        let mut canonical: Vec<Vec<u8>> = items
            .iter()
            .map(|item| {
                serde_json_canonicalizer::to_vec(item).map_err(|error| {
                    format!("a middleware descriptor could not be canonicalized: {error}")
                })
            })
            .collect::<Result<_, _>>()?;
        canonical.sort();
        canonical
            .iter()
            .map(|bytes| {
                serde_json::from_slice::<Value>(bytes).map_err(|error| {
                    format!("a canonical middleware descriptor did not re-read: {error}")
                })
            })
            .collect()
    };
    let registrations = canonical_set(
        descriptor
            .registrations
            .iter()
            .map(|registration| {
                serde_json::to_value(registration).map_err(|error| {
                    format!("a registration descriptor did not serialize: {error}")
                })
            })
            .collect::<Result<_, _>>()?,
    )?;
    let capabilities = canonical_set(
        descriptor
            .capabilities
            .iter()
            .map(|capability| {
                serde_json::to_value(capability)
                    .map_err(|error| format!("a capability declaration did not serialize: {error}"))
            })
            .collect::<Result<_, _>>()?,
    )?;
    let activation_config: Value = serde_json::from_str(component_config_json)
        .map_err(|error| format!("the activation config is not JSON: {error}"))?;
    crate::canonical_digest(&json!({
        "plugins": [{
            "plugin_id": descriptor.plugin_id,
            "plugin_version": descriptor.plugin_version,
            "manifest_digest": descriptor.manifest_digest,
            "manifest_sha256": manifest_sha256,
            "library_sha256": library_sha256,
            "negotiated_abi_version": descriptor.negotiated_abi_version,
            "activated_component": {
                "kind": component_kind,
                "config": activation_config,
            },
            "registrations": registrations,
            "capabilities": capabilities,
            "host_sha256": host_sha256,
        }]
    }))
}

/// Open a plugin-host session: launch the child under the deployment's
/// isolation policy, load and activate the artifact, and install the
/// registration proxies into this process's chains.
///
/// Failing to open fails closed — a required middleware that cannot be
/// composed is not quietly absent from the chain; the caller decides whether
/// the invocation proceeds at all, and this composition's answer is that it
/// does not.
pub async fn open(options: &PluginOptions) -> Result<PluginSession, String> {
    let artifact = resolve_artifact(&options.artifact)?;
    let artifact_ref = artifact.to_string_lossy();
    let (manifest_sha256, library_sha256) =
        nemo_relay::plugin::dynamic::plugin_artifact_identity(&artifact_ref)
            .map_err(|error| format!("the plugin artifact could not be approved: {error}"))?;
    let activation_config: Value = serde_json::from_str(&options.component_config)
        .map_err(|error| format!("the activation config is not JSON: {error}"))?;
    let activation_config_sha256 = crate::canonical_digest(&activation_config)?;

    let mut config = supervisor_config(options);
    // The binary the child will actually be: resolved the way `spawn`
    // resolves it, then for a trusted host staged into private bytes the
    // spawn itself executes — so the digest and the pin bind the file `exec`
    // opens, not a path that could be replaced between the check and the
    // spawn. Under a confinement policy the executed file is the bundle's
    // signed executable, whose integrity the platform checks at launch;
    // staging a bare copy of it would strip the signature the confinement
    // travels with, so it is the one path that is spawned as resolved.
    let (host, staging) = prepare_host(&mut config, options.host_sha256_pin.as_deref())?;
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
                    manifest_sha256: manifest_sha256.clone(),
                    library_sha256: library_sha256.clone(),
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
                    config_json: options.component_config.clone(),
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
    // The continuations must be the session's own: when the child's intercept
    // calls `next`, the host asks the runtime service the backend started, and
    // that service looks the continuation up in the registry the backend
    // created at launch. Parking into a different registry would leave the
    // continuation reachable to nothing.
    let continuations = backend.continuations();
    let manager = Arc::new(PluginManager::new(Arc::new(backend)));
    let off_path = Arc::new(
        OffPathPluginExecutor::start(&ObservabilityPolicy {
            budget_millis: OFF_PATH_BUDGET_MILLIS,
            max_in_flight: 8,
        })
        .map_err(|error| format!("the off-path runtime did not start: {error}"))?,
    );
    let proxy_context = ProxyContext::new(Arc::clone(&manager), binding, OFF_PATH_BUDGET_MILLIS)
        .with_observability_budget(OFF_PATH_BUDGET_MILLIS)
        .with_off_path_executor(off_path)
        .with_continuations(continuations);
    let proxies = install(proxy_context, &descriptor, loaded.handle.clone()).map_err(|error| {
        format!("this runtime cannot serve what the plugin registered: {error}")
    })?;

    let middleware_set_digest = middleware_set_digest(
        &descriptor,
        &manifest_sha256,
        &library_sha256,
        &options.component,
        &options.component_config,
        &host.sha256,
    )?;
    Ok(PluginSession {
        descriptor,
        process_id,
        middleware_set_digest,
        plugin_manifest_sha256: manifest_sha256,
        plugin_library_sha256: library_sha256,
        activation_config_sha256,
        host,
        _manager: manager,
        _proxies: proxies,
        _staging: staging,
    })
}

/// Host the plugin and, when asked, run one managed tool call through it.
pub fn host(
    options: &PluginOptions,
    release: Option<&crate::release::ReleaseIdentity>,
) -> Result<Value, String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("the plugin host needs an async runtime: {error}"))?;
    runtime.block_on(host_async(options, release))
}

async fn host_async(
    options: &PluginOptions,
    release: Option<&crate::release::ReleaseIdentity>,
) -> Result<Value, String> {
    let session = open(options).await?;

    // A managed call, under the trusted budget a runtime publishes for an
    // action: without one the proxy refuses, because a registration reached
    // outside a managed action has no deadline to inherit.
    let tool_call = match &options.tool {
        None => Value::Null,
        Some(tool) => {
            let budget = managed_call_budget()
                .map_err(|error| format!("the managed call's budget: {error}"))?;
            let arguments = options.arguments.clone();
            let rewritten = nemo_relay::api::runtime::with_execution_budget(budget, async move {
                nemo_relay::api::tool::tool_request_intercepts(tool, arguments).await
            })
            .await
            .map_err(|error| format!("the managed call did not complete: {error}"))?;
            json!({ "tool": tool, "result": rewritten })
        }
    };

    let report = json!({
        "status": if options.tool.is_some() { "INVOKED" } else { "HOSTED" },
        "host": {
            "process_id": session.process_id,
            "executable": session.host.executable,
            "resolved": session.host.resolved,
            "sha256": session.host.sha256,
            "pinned": session.host.pinned,
            "staged": session.host.staged,
        },
        "plugin": serde_json::to_value(&session.descriptor).map_err(|error| error.to_string())?,
        "middleware_set_digest": session.middleware_set_digest,
        "release_root_digest": release.map(|release| release.release_root_digest.clone()),
        "tool_call": tool_call,
    });
    // Dropping the session removes the registrations from this process's
    // chains and ends the host: a plugin's callbacks cannot outlive the
    // runtime that installed them.
    drop(session);
    Ok(report)
}

/// The environment variable a deployment uses to pin the executed host
/// binary's SHA-256. Qualified mode resolves the host flexibly
/// (`NEMO_RELAY_PLUGIN_HOST` or beside-this-binary) and then requires its
/// content to match the release's component manifest, rather than trusting
/// whichever path resolved.
const HOST_SHA256_ENV: &str = "NEMO_RELAY_PLUGIN_HOST_SHA256";

/// Resolve, stage, digest, and pin the executed host binary.
///
/// The path resolution is the same one `spawn` applies — the isolation policy
/// decides which executable the child is — so the digest binds what runs. For
/// a trusted host the spawned file is a private staged copy of the resolved
/// path: hashing a path and later executing whatever is at that path leaves a
/// replacement window, so `config.executable` is rewritten to the staged copy
/// and the digest is computed over the bytes that will actually run. Under a
/// confinement policy the executed file is the bundle's signed executable —
/// staging a bare copy would strip the signature the sandbox travels with —
/// so it is digested and spawned as resolved, with the signature the platform
/// itself enforces at `exec`.
///
/// The pin, when set, is the release's component-manifest value: a host whose
/// content differs is a deployment error that fails the session, never a
/// quieter host.
fn prepare_host(
    config: &mut PluginHostSupervisorConfig,
    pin: Option<&str>,
) -> Result<(HostIdentity, Option<StagedHost>), String> {
    let resolved = config
        .isolation
        .host_executable(
            &config.executable,
            &std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
                .unwrap_or_default(),
        )
        .map_err(|error| error.to_string())?;
    let (executable, staging) = if config.isolation.confines_resources() {
        (resolved.clone(), None)
    } else {
        let staged = stage_host(&resolved)?;
        config.executable = staged.executable.clone();
        (staged.executable.clone(), Some(staged))
    };
    let sha256 = std::fs::read(&executable)
        .map(|bytes| crate::sha256_hex(&bytes))
        .map_err(|error| {
            format!(
                "the plugin host executable '{}' could not be read for its digest: {error}",
                executable.display()
            )
        })?;
    if let Some(expected) = pin {
        if !expected.chars().all(|c| c.is_ascii_hexdigit()) || expected.len() != 64 {
            return Err(format!(
                "{HOST_SHA256_ENV} is not a SHA-256 hex digest: {expected:?}"
            ));
        }
        if !expected.eq_ignore_ascii_case(&sha256) {
            return Err(format!(
                "the plugin host at '{}' digests to {}, but {HOST_SHA256_ENV} requires {} — \
                 the resolved binary is not the one the release declared",
                executable.display(),
                sha256,
                expected
            ));
        }
    }
    Ok((
        HostIdentity {
            executable,
            resolved,
            sha256,
            pinned: pin.is_some(),
            staged: staging.is_some(),
        },
        staging,
    ))
}

/// The pin a deployment configured, resolved at the CLI boundary.
fn host_sha256_pin() -> Result<Option<String>, String> {
    match std::env::var(HOST_SHA256_ENV) {
        Ok(raw) if !raw.trim().is_empty() => Ok(Some(raw.trim().to_string())),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{HOST_SHA256_ENV} is not valid text for a digest"))
        }
    }
}

/// The digest the executed host must carry.
///
/// In a qualified layout the release itself is the pin's source: the
/// component manifest declares which host bytes the distribution ships, so
/// the ordinary case needs no environment at all — running the installed
/// binary is bound to the installed host. Outside a release (a development
/// tree, a side-by-side install) `NEMO_RELAY_PLUGIN_HOST_SHA256` still
/// applies. When both exist they must agree: a deployment that pins a
/// different host than its release declared is a contradiction, not an
/// override — which one lied is a deployer's question, not the runtime's.
pub(crate) fn resolve_host_pin(
    release: Option<&crate::release::ReleaseIdentity>,
) -> Result<Option<String>, String> {
    let configured = host_sha256_pin()?;
    match (release, configured) {
        (Some(release), Some(pin)) if !pin.eq_ignore_ascii_case(&release.plugin_host_sha256) => {
            Err(format!(
                "{HOST_SHA256_ENV} pins {pin} but the release's component manifest declares \
                 {} for bin/nemo-plugin-host — the two disagree, and resolving which one \
                 lied is a deployment decision, not a runtime's",
                release.plugin_host_sha256,
            ))
        }
        (Some(release), _) => Ok(Some(release.plugin_host_sha256.clone())),
        (None, pin) => Ok(pin),
    }
}

/// The supervisor configuration this composition publishes. The host ships
/// beside this binary; `NEMO_RELAY_PLUGIN_HOST` names another one for a
/// deployment that installs it elsewhere. The isolation policy is the one the
/// caller resolved from the deployment — never the supervisor's implicit
/// default — so a confinement requirement that cannot be honored fails the
/// launch rather than silently serving a weaker host.
fn supervisor_config(options: &PluginOptions) -> PluginHostSupervisorConfig {
    PluginHostSupervisorConfig {
        isolation: options.isolation,
        ..PluginHostSupervisorConfig::beside_this_executable(options.runtime_binding_digest.clone())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn options(isolation: NativeIsolationPolicy) -> PluginOptions {
        PluginOptions {
            artifact: PathBuf::from("/nonexistent/plugin"),
            plugin_id: "test_plugin".to_string(),
            component: "test".to_string(),
            component_config: "{}".to_string(),
            tool: None,
            arguments: json!({}),
            runtime_binding_digest: "digest".to_string(),
            isolation,
            host_sha256_pin: None,
        }
    }

    #[test]
    fn the_supervisor_config_carries_the_resolved_policy() {
        // The composition must publish exactly the policy it was given: a
        // config that ignored `options.isolation` and fell back to the
        // supervisor's implicit default would be a silent downgrade.
        for policy in [
            NativeIsolationPolicy::TrustedProcess,
            NativeIsolationPolicy::RestrictedMacOS,
        ] {
            assert_eq!(supervisor_config(&options(policy)).isolation, policy);
        }
    }

    #[test]
    fn an_unhonorable_policy_fails_closed() {
        // `host_executable` is the check `spawn` applies before a process
        // exists; the resolved policy reaches it through this composition's
        // config. Neither input is bundled here, so the restricted policy is
        // unhonorable on every platform — macOS builds lack the bundle, other
        // platforms lack the platform — and the answer must be a refusal.
        let config = supervisor_config(&options(NativeIsolationPolicy::RestrictedMacOS));
        let result = config
            .isolation
            .host_executable(&config.executable, Path::new("/nonexistent/runtime"));
        let error = result.expect_err("an unhonorable policy must be refused");
        assert!(
            error.to_string().contains("restricted-macos"),
            "the refusal must name the policy: {error}"
        );
    }

    #[test]
    fn a_malformed_policy_spelling_is_rejected() {
        // `from_environment()` delegates to `parse` for a configured value, so
        // this is the gate a misspelled deployment hits before a host exists.
        let error = NativeIsolationPolicy::parse("sandboxed").unwrap_err();
        assert!(
            error.contains("NEMO_RELAY_NATIVE_ISOLATION"),
            "the error must name the variable a deployer can fix: {error}"
        );
    }

    #[test]
    fn the_documented_default_is_trusted_process() {
        assert_eq!(
            NativeIsolationPolicy::default(),
            NativeIsolationPolicy::TrustedProcess
        );
    }

    #[test]
    fn the_managed_call_budget_defaults_to_the_documented_window() {
        assert_eq!(managed_call_budget_millis(None), Ok(30_000));
    }

    #[test]
    fn the_managed_call_budget_honors_a_deployment_override() {
        assert_eq!(managed_call_budget_millis(Some("2500")), Ok(2_500));
    }

    #[test]
    fn a_malformed_managed_call_budget_fails_resolution() {
        for bad in ["", "soon", "-1", "0", "1.5"] {
            let error = managed_call_budget_millis(Some(bad))
                .expect_err("a malformed budget must be refused");
            assert!(
                error.contains("NEMO_RELAY_MANAGED_CALL_BUDGET_MS"),
                "the error must name the variable a deployer can fix: {error}"
            );
        }
    }
}
