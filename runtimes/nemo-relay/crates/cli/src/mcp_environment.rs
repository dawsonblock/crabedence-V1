// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Environment names shared by MCP generation and gateway compatibility
//! checks, plus the synthetic-home isolation applied to managed MCP launches.
//!
//! The subprocess environment model has two layers:
//!
//! - *Forwarding* (`env_vars`): an allowlist of names the host may pass
//!   through. Home-pointer variables — `HOME`, `USERPROFILE`, `APPDATA`,
//!   `LOCALAPPDATA`, and the `XDG_*` roots — are not forwarded: forwarding
//!   them would let plugin code rediscover the operator's credential files
//!   through ordinary home-directory lookup.
//! - *Isolation* (`IsolatedHome`): a managed MCP launch switches to a private
//!   per-installation home directory at process start. The real user config
//!   directory is carried through an explicit `NEMO_RELAY_USER_CONFIG_DIR`
//!   pin, so `config.toml`, `plugins.toml`, bootstrap state and managed
//!   plugin environments keep resolving where the installation put them —
//!   while `~/.aws`, `~/.ssh`, `~/.config/gh` and friends resolve into the
//!   private scratch directory.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::installation::generation::{GENERATION_FILE_ENV, GENERATION_TOKEN_ENV};

/// `NEMO_RELAY_MCP_INHERIT_HOME=1` opts a managed launch out of home
/// isolation: the generated launch contract records the operator's real home
/// in `MCP_REAL_HOME_ENV` and the subprocess restores it instead of the
/// synthetic directory. A deployment should only set this for an integration
/// that genuinely needs ambient user files.
pub(crate) const MCP_INHERIT_HOME_ENV: &str = "NEMO_RELAY_MCP_INHERIT_HOME";

/// Carries the operator's real home directory in the generated launch
/// contract so `MCP_INHERIT_HOME_ENV` can restore it on request. This is a
/// path, not credential material.
pub(crate) const MCP_REAL_HOME_ENV: &str = "NEMO_RELAY_REAL_HOME";

/// Name of the private directory created inside the user config directory
/// that serves as `HOME` for managed MCP processes.
const ISOLATED_HOME_DIR: &str = "mcp-home";

const BASE_MCP_ENV_VARS: &[&str] = &[
    "ALL_PROXY",
    "ANTHROPIC_API_KEY",
    "AWS_ALLOW_HTTP",
    "AWS_CA_BUNDLE",
    "AWS_DEFAULT_REGION",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_ENDPOINT_URL",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_SDK_LOAD_CONFIG",
    "AWS_STS_REGIONAL_ENDPOINTS",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NEMO_RELAY_ANTHROPIC_AUTH_HEADER",
    "NEMO_RELAY_ANTHROPIC_BASE_URL",
    "NEMO_RELAY_GATEWAY_URL",
    "NEMO_RELAY_MAX_HOOK_PAYLOAD_BYTES",
    "NEMO_RELAY_MAX_PASSTHROUGH_BODY_BYTES",
    "NEMO_RELAY_OPENAI_AUTH_HEADER",
    "NEMO_RELAY_OPENAI_BASE_URL",
    "NEMO_RELAY_PLUGIN_HEARTBEAT_INTERVAL_SECS",
    "NEMO_RELAY_PLUGIN_IDLE_TIMEOUT_SECS",
    "NEMO_RELAY_PYTHON",
    "NEMO_RELAY_TRANSPARENT_RUN",
    "NO_PROXY",
    "OPENAI_API_KEY",
    "OTEL_EXPORTER_OTLP_COMPRESSION",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TIMEOUT",
    "OTEL_EXPORTER_OTLP_TRACES_COMPRESSION",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_SDK_DISABLED",
    "OTEL_SERVICE_NAME",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TEMP",
    "TMPDIR",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// Names earlier releases forwarded but which must no longer reach an MCP
/// subprocess through the allowlist.
///
/// These stay *previously forwardable* so an install generated before the
/// synthetic-home boundary existed still validates against the new expected
/// set — its stale `env_vars` entry is overridden by the enforced isolated
/// home at process start, so accepting it costs nothing while keeping
/// upgrades a reinstall rather than a repair.
const LEGACY_HOME_POINTER_MCP_ENV_VARS: &[&str] = &[
    "APPDATA",
    "HOME",
    "LOCALAPPDATA",
    "USERPROFILE",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
];

/// Names that must never reach an MCP subprocess.
///
/// The `AWS_*` entries are credential material: static keys, session tokens,
/// container credential endpoints, a web-identity token file, and the shared
/// credentials and config files. The `AWS_` prefix is forwarded for region and
/// endpoint configuration, so the credential names have to be excluded
/// explicitly — a plugin subprocess must not inherit the operator's cloud
/// credentials, because consequential work reaches the external world through
/// Crabedence's provider processes, not from here.
///
/// This list takes precedence over `BASE_MCP_ENV_VARS`: a name that appears in
/// both is never forwarded.
///
/// Environment filtering alone is not a credential boundary — a subprocess
/// that can see the real home directory rediscovers `~/.aws/credentials`,
/// `~/.ssh`, `~/.config/gh` and friends through ordinary home-directory
/// lookup. That residual is closed by `IsolatedHome`, which replaces the home
/// pointers this list cannot strip with a private directory before any MCP
/// work begins.
const BLOCKED_MCP_ENV_VARS: &[&str] = &[
    // The managed-MCP config-directory pin is a literal `env` value, never a
    // forwardable name: forwarding it would hash it into the bootstrap
    // fingerprint on one side of the boundary only, and the managed/unmanaged
    // launch asymmetry would look like a foreign gateway.
    "NEMO_RELAY_USER_CONFIG_DIR",
    "AWS_ACCESS_KEY_ID",
    "AWS_CONFIG_FILE",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "CRABBOX_BROKER_TOKEN",
    "CRABBOX_EVIDENCE_KEY",
    "CRABBOX_OPENCOMPUTER_API_KEY",
    "CRABBOX_TEST_DATABASE_URL",
    "CRABBOX_TOKEN",
    "CRABEDENCE_DATABASE_URL",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "NEMO_RELAY_BINDING_KIND",
    "NEMO_RELAY_BOOTSTRAP_AGENT",
    "NEMO_RELAY_BOOTSTRAP_FINGERPRINT",
    "NEMO_RELAY_BOOTSTRAP_STATE_DIR",
    "NEMO_RELAY_BOOTSTRAP_SHUTDOWN_TOKEN",
    "NEMO_RELAY_FAIL_CLOSED",
    "NEMO_RELAY_GATEWAY_BIND",
    "NEMO_RELAY_HOST_SOCKET",
    "NEMO_RELAY_MCP_GENERATION",
    "NEMO_RELAY_MCP_GENERATION_FILE",
    "NEMO_RELAY_NATIVE_ABI_VERSION",
    "NEMO_RELAY_PLUGIN_BINARY",
    "NEMO_RELAY_PLUGIN_BIND",
    "NEMO_RELAY_SIDECAR_JOB_NAME",
    "NEMO_RELAY_PLUGIN_CONFIG_PATH",
    "NEMO_RELAY_PLUGIN_GATEWAY_URL",
    "NEMO_RELAY_PLUGIN_ID",
    "NEMO_RELAY_RUNTIME_OWNER",
    "NEMO_RELAY_WORKER_ENDPOINT_FILE",
    "NEMO_RELAY_WORKER_ID",
    "NEMO_RELAY_WORKER_SOCKET",
    "NEMO_RELAY_WORKER_TOKEN",
    "OPENCOMPUTER_API_KEY",
];

pub(crate) fn forwarded_names(
    environment: impl IntoIterator<Item = String>,
    config: Option<&Value>,
) -> Vec<String> {
    forwarded_names_for_platform(environment, config, cfg!(windows))
}

pub(crate) fn forwarded_names_for_platform(
    environment: impl IntoIterator<Item = String>,
    config: Option<&Value>,
    windows: bool,
) -> Vec<String> {
    let mut names = BTreeSet::new();
    for name in BASE_MCP_ENV_VARS {
        // The blocklist is authoritative: a name that must never reach a
        // subprocess cannot be reintroduced by the base allowlist.
        if !blocked(name) {
            insert_name(&mut names, (*name).to_string(), windows);
        }
    }
    for name in environment {
        if prefix_allowed(&name, windows) && !blocked(&name) {
            insert_name(&mut names, name, windows);
        }
    }
    if let Some(config) = config {
        collect_config_names(config, &mut names, windows);
    }
    names.into_iter().collect()
}

/// Removes unresolved `${NAME}` values injected by MCP hosts before CLI parsing.
///
/// The generation fence scopes this cleanup to managed persistent MCP launches.
/// Internal variables remain untouched so malformed or retired generation
/// identities fail closed during validation.
pub(crate) fn remove_unresolved_mcp_placeholders() {
    if std::env::var_os(GENERATION_FILE_ENV).is_none()
        || std::env::var_os(GENERATION_TOKEN_ENV).is_none()
    {
        return;
    }
    let unresolved = std::env::vars_os()
        .filter_map(|(name, value)| {
            let name_text = name.to_str()?;
            let value = value.to_str()?;
            (!blocked(name_text)
                && unresolved_self_placeholder_for_platform(name_text, value, cfg!(windows)))
            .then_some(name)
        })
        .collect::<Vec<_>>();
    for name in unresolved {
        // SAFETY: The synchronous CLI entrypoint calls this before constructing the Tokio runtime,
        // so no other thread can read or write the process environment concurrently.
        unsafe { std::env::remove_var(name) };
    }
}

pub(crate) fn forwarded_names_match_for_platform(left: &str, right: &str, windows: bool) -> bool {
    if windows {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

/// Returns whether a name could have been captured from an earlier process environment.
///
/// Arbitrary config-referenced names remain in the current expected set. Historical extras are
/// therefore limited to the static allowlist and approved dynamic prefixes.
pub(crate) fn previously_forwardable_name_for_platform(name: &str, windows: bool) -> bool {
    !blocked(name)
        && (BASE_MCP_ENV_VARS
            .iter()
            .any(|base| forwarded_names_match_for_platform(name, base, windows))
            || LEGACY_HOME_POINTER_MCP_ENV_VARS
                .iter()
                .any(|legacy| forwarded_names_match_for_platform(name, legacy, windows))
            || prefix_allowed(name, windows))
}

pub(crate) fn unresolved_self_placeholder_for_platform(
    name: &str,
    value: &str,
    windows: bool,
) -> bool {
    value
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
        .is_some_and(|placeholder| forwarded_names_match_for_platform(name, placeholder, windows))
}

fn prefix_allowed(name: &str, windows: bool) -> bool {
    ["NEMO_RELAY_", "OTEL_", "AWS_"].iter().any(|prefix| {
        if windows {
            starts_with_ignore_ascii_case(name, prefix)
        } else {
            name.starts_with(prefix)
        }
    })
}

fn blocked(name: &str) -> bool {
    BLOCKED_MCP_ENV_VARS
        .iter()
        .any(|blocked| name.eq_ignore_ascii_case(blocked))
        || starts_with_ignore_ascii_case(name, "NEMO_RELAY_TEST_")
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn insert_name(names: &mut BTreeSet<String>, name: String, windows: bool) {
    if !windows
        || !names
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&name))
    {
        names.insert(name);
    }
}

fn collect_config_names(value: &Value, names: &mut BTreeSet<String>, windows: bool) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                collect_config_field(key, value, names, windows);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_config_names(value, names, windows);
            }
        }
        _ => {}
    }
}

fn collect_config_field(key: &str, value: &Value, names: &mut BTreeSet<String>, windows: bool) {
    match key {
        "header_env" => collect_header_env_names(value, names, windows),
        "secret_access_key_var" | "session_token_var" => {
            if let Some(name) = value.as_str() {
                collect_config_name(name, names, windows);
            }
        }
        _ => collect_config_names(value, names, windows),
    }
}

fn collect_header_env_names(value: &Value, names: &mut BTreeSet<String>, windows: bool) {
    if let Some(headers) = value.as_object() {
        for name in headers.values().filter_map(Value::as_str) {
            collect_config_name(name, names, windows);
        }
    }
}

fn collect_config_name(name: &str, names: &mut BTreeSet<String>, windows: bool) {
    if !name.is_empty() && !blocked(name) && !legacy_home_pointer(name) {
        insert_name(names, name.to_owned(), windows);
    }
}

/// A private directory that substitutes for the operator's home inside a
/// managed MCP process tree.
///
/// `env_vars` filtering alone is not a credential boundary: a subprocess
/// that can see the real home directory rediscovers `~/.aws/credentials`,
/// `~/.ssh`, `~/.config/gh`, cloud CLI state and package-manager tokens
/// through ordinary home-directory lookup. The isolation layer closes that
/// residual by creating a private home inside the real user config directory
/// and pointing `HOME`, `USERPROFILE`, `APPDATA`/`LOCALAPPDATA` and every
/// `XDG_*` root at it. The real config directory itself stays reachable
/// through an explicit `NEMO_RELAY_USER_CONFIG_DIR` pin — the one location
/// managed MCP genuinely needs, carrying `config.toml`, `plugins.toml`,
/// bootstrap state and managed plugin environments.
///
/// The directory is per installation, not per session, because everything
/// the process tree legitimately needs lives under the pinned config
/// directory — a shorter-lived home would only be a different scratch space.
/// Nothing under `root` exists except the standard lookup directories this
/// type creates, so any file a subprocess finds through `HOME` lookup is one
/// it placed there itself.
pub(crate) struct IsolatedHome {
    root: PathBuf,
    user_config_dir: Option<PathBuf>,
}

impl IsolatedHome {
    /// The managed-MCP home: a private directory inside the real user config
    /// directory, which stays reachable through the config-directory pin.
    pub(crate) fn for_managed_mcp(user_config_dir: PathBuf) -> Self {
        Self {
            root: user_config_dir.join(ISOLATED_HOME_DIR),
            user_config_dir: Some(user_config_dir),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Creates `root` and the standard home lookup directories inside it,
    /// owner-only on unix.
    pub(crate) fn create(&self) -> Result<(), String> {
        create_private_dir(&self.root)?;
        for subdir in [
            ".config",
            ".cache",
            ".local/share",
            ".local/state",
            ".run",
            "AppData/Roaming",
            "AppData/Local",
        ] {
            create_private_dir(&self.root.join(subdir))?;
        }
        Ok(())
    }

    /// The environment assignments an isolated process tree should see.
    ///
    /// Emitted unconditionally for every platform so the generated launch
    /// contract and the runtime enforcement agree everywhere; names a
    /// platform never reads are inert. `NEMO_RELAY_USER_CONFIG_DIR` is
    /// present only when this home pins a config directory.
    pub(crate) fn env_pairs(&self) -> Vec<(String, OsString)> {
        let mut pairs: Vec<(String, OsString)> = [
            ("HOME", self.root.as_path()),
            ("USERPROFILE", self.root.as_path()),
            ("APPDATA", &self.root.join("AppData/Roaming")),
            ("LOCALAPPDATA", &self.root.join("AppData/Local")),
            ("XDG_CONFIG_HOME", &self.root.join(".config")),
            ("XDG_CACHE_HOME", &self.root.join(".cache")),
            ("XDG_DATA_HOME", &self.root.join(".local/share")),
            ("XDG_STATE_HOME", &self.root.join(".local/state")),
            ("XDG_RUNTIME_DIR", &self.root.join(".run")),
        ]
        .into_iter()
        .map(|(name, path)| (name.to_string(), path.as_os_str().to_os_string()))
        .collect();
        if let Some(config_dir) = &self.user_config_dir {
            pairs.push((
                nemo_relay::plugin::USER_CONFIG_DIR_ENV.to_string(),
                config_dir.as_os_str().to_os_string(),
            ));
        }
        pairs
    }

    /// Applies the assignments to this process. Callers must run this before
    /// the Tokio runtime and application threads exist.
    pub(crate) fn apply_to_process_env(&self) {
        for (name, value) in self.env_pairs() {
            // SAFETY: callers invoke this in `run_cli` before the Tokio
            // runtime is built, so no other thread observes the process
            // environment concurrently.
            unsafe { std::env::set_var(name, value) };
        }
    }

    /// Applies the assignments to a spawned command — used by the gateway
    /// launch boundary and by tests proving what a child can observe without
    /// mutating this process's environment.
    pub(crate) fn apply_to_command(&self, command: &mut std::process::Command) {
        for (name, value) in self.env_pairs() {
            command.env(name, value);
        }
    }
}

/// The operator's real home directory, when the launch environment exposes
/// one — the value `NEMO_RELAY_REAL_HOME` records in generated contracts.
fn real_home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// Returns true when the operator explicitly opted the managed launch out of
/// home isolation (`NEMO_RELAY_MCP_INHERIT_HOME=1`).
pub(crate) fn inherit_home_requested() -> bool {
    std::env::var(MCP_INHERIT_HOME_ENV).ok().as_deref() == Some("1")
}

/// Literal `env` entries `persistent_server` writes into generated MCP
/// launch contracts, so the isolation boundary is visible in the installed
/// config — and a host that delivers only literal env already gets the
/// synthetic home even where a platform quirk would stop runtime
/// enforcement.
///
/// With `NEMO_RELAY_MCP_INHERIT_HOME=1` in the install environment the
/// contract instead records the opt-out and the real home explicitly — an
/// operator reading the generated file can see which boundary applies.
pub(crate) fn managed_home_env_literals() -> serde_json::Map<String, Value> {
    let mut env = serde_json::Map::new();
    if inherit_home_requested() {
        env.insert(MCP_INHERIT_HOME_ENV.to_string(), Value::from("1"));
        if let Some(home) = real_home_dir() {
            env.insert(MCP_REAL_HOME_ENV.to_string(), json_path(&home));
            env.insert("HOME".to_string(), json_path(&home));
            env.insert("USERPROFILE".to_string(), json_path(&home));
        }
        return env;
    }
    if let Some(home) = real_home_dir() {
        env.insert(MCP_REAL_HOME_ENV.to_string(), json_path(&home));
    }
    if let Some(config_dir) = crate::configuration::user_config_dir() {
        for (name, value) in IsolatedHome::for_managed_mcp(config_dir).env_pairs() {
            env.insert(name, json_path(&value));
        }
    }
    env
}

fn json_path(value: impl AsRef<std::ffi::OsStr>) -> Value {
    Value::from(value.as_ref().to_string_lossy().into_owned())
}

/// `env` keys the generated launch contract owns for the home boundary.
///
/// Readiness comparison ignores them — an install generated before the
/// isolation layer existed, or before a machine moved home directories,
/// still validates because runtime enforcement overrides stale values at
/// process start. Anything else in `env` — the bind, the generation fence —
/// remains exactly compared.
pub(crate) fn managed_home_literal_names() -> &'static [&'static str] {
    &[
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        MCP_INHERIT_HOME_ENV,
        MCP_REAL_HOME_ENV,
        nemo_relay::plugin::USER_CONFIG_DIR_ENV,
    ]
}

/// Switches a managed MCP launch to its isolated home.
///
/// Runs at process entry — before the Tokio runtime exists — so the
/// assignments are visible to everything the session later resolves or
/// spawns: the persistent gateway inherits them, config discovery follows
/// the pinned directory, and any `HOME`-based credential lookup lands in
/// the empty private tree.
///
/// `Ok(None)` means the launch was not managed (the generation fence is
/// absent) or the operator opted out — in which case the real home recorded
/// in `NEMO_RELAY_REAL_HOME` is restored when the launch contract carried
/// the synthetic one. `Ok(Some)` is the synthetic root now assigned as
/// `HOME`. `Err` fails closed: a managed launch that cannot establish its
/// private home must not proceed with the ambient one.
pub(crate) fn enforce_managed_home_isolation() -> Result<Option<PathBuf>, String> {
    if std::env::var_os(GENERATION_FILE_ENV).is_none()
        || std::env::var_os(GENERATION_TOKEN_ENV).is_none()
    {
        return Ok(None);
    }
    if inherit_home_requested() {
        if let Some(real) = std::env::var_os(MCP_REAL_HOME_ENV).filter(|home| !home.is_empty()) {
            // SAFETY: pre-runtime, as in apply_to_process_env.
            unsafe {
                std::env::set_var("HOME", &real);
                std::env::set_var("USERPROFILE", &real);
            }
        }
        return Ok(None);
    }
    let user_config_dir = crate::configuration::user_config_dir().ok_or_else(|| {
        "managed MCP home isolation cannot determine the per-user NeMo Relay config directory; set HOME or USERPROFILE".to_string()
    })?;
    let home = IsolatedHome::for_managed_mcp(user_config_dir);
    home.create()?;
    let root = home.root().to_path_buf();
    home.apply_to_process_env();
    Ok(Some(root))
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("failed to secure {}: {error}", path.display()))?;
    }
    Ok(())
}

/// A name the allowlist must not reintroduce: home-pointer variables are
/// replaced by the isolated home, so forwarding one would only race the
/// runtime's own assignment.
fn legacy_home_pointer(name: &str) -> bool {
    LEGACY_HOME_POINTER_MCP_ENV_VARS
        .iter()
        .any(|legacy| name.eq_ignore_ascii_case(legacy))
}

#[cfg(test)]
#[path = "../tests/coverage/shared/mcp_environment_tests.rs"]
mod mcp_environment_tests;

