// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! How much a host process is contained, and what has to exist before it starts.
//!
//! Process separation is the first bound and it is already here: a plugin that
//! crashes or hangs takes its host down rather than the kernel's process, and the
//! supervisor kills what it started. What separation does *not* do is bound what
//! a plugin may read, write or connect to — the host inherits the kernel's
//! ambient authority, which means a plugin's code does too.
//!
//! The levels below are the deployment's statement about that. They are explicit
//! rather than automatic, because a runtime that silently confined a plugin that
//! needs a network connection would break working installations, and a runtime
//! that silently *did not* confine one whose deployment asked for it would be
//! worse than either: the configuration would describe a boundary that is not
//! there. Selecting a level this build cannot deliver is therefore a failure to
//! start, which is the same rule the resource limits follow.
//!
//! Third level, deliberately not a variant: a VM boundary for code assumed
//! hostile. It is a different mechanism with a different host image, and a
//! variant nothing can honor would read as a feature.

use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

use nemo_relay_plugin_protocol::{PluginFailureCode, PluginProtocolError};

use crate::host_location;

/// Environment variable selecting the host process isolation policy for the
/// CLI and all language bindings.
pub const NATIVE_ISOLATION_ENV: &str = "NEMO_RELAY_NATIVE_ISOLATION";

/// Environment variable the policy uses to ask a host binary whether it can
/// confine here.
///
/// Linux confinement is self-applied by the host, so the only honest probe is
/// to run the binary itself and see whether the confined child survives the
/// checks. The probe variable is read before anything else the binary does.
pub const CONFINEMENT_PROBE_ENV: &str = "NEMO_RELAY_PLUGIN_HOST_PROBE";

/// The probe value [`CONFINEMENT_PROBE_ENV`] carries.
pub const CONFINEMENT_PROBE_VALUE: &str = "confinement";

/// The line the confined probe prints once every denial it attempted held.
///
/// The check is the record, not the exit status: a binary that ignores the
/// environment — a shell builtin standing in, a stale host — also exits
/// success, and only this line distinguishes "confined and verified" from
/// "ran and did nothing".
pub const CONFINEMENT_PROBE_ACK: &str = "NEMO_RELAY_PROBE_CONFINED";

/// Whether the end-to-end approved artifact load path is qualified for restriction.
///
/// The confined host stages to a deterministic path beneath its app container.
/// After the authenticated transfer is approved, the unconfined supervisor opens
/// that path without following symlinks, checks the approved digest again, and
/// removes only the quarantine attribute through the open file descriptor. Keep
/// this enabled only while the signed-bundle end-to-end load remains qualified.
const RESTRICTED_ARTIFACT_LOAD_QUALIFIED: bool = true;

/// How much a host process is contained.
///
/// The name is about the *host*, not the plugin: what changes between the levels
/// is which process the plugin's code runs in and what the platform lets that
/// process do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NativeIsolationPolicy {
    /// The host is an ordinary child process of the runtime.
    ///
    /// Crash and hang containment, the resource ceilings in
    /// [`crate::limits::PluginHostLimits`], and the kernel-side boundary — the
    /// loader is not in this process and the session is authenticated. The plugin
    /// keeps the account's ambient authority: its filesystem, its network, its
    /// credentials. This is process isolation, not security isolation — a plugin
    /// that is not trusted to run with the account's authority does not belong
    /// under this policy.
    #[default]
    TrustedProcess,
    /// The host runs inside the platform's own resource confinement.
    ///
    /// On macOS that is App Sandbox, applied through the entitlements the host
    /// bundle is signed with: the host reaches its container and the files it was
    /// handed, and nothing else — no user files, no devices, no outbound network
    /// unless a later capability grants it. The confinement is a property of the
    /// signature, which is why a restricted host is a bundle rather than a bare
    /// executable.
    RestrictedMacOS,
    /// The host confines itself with the kernel's own mechanisms.
    ///
    /// On Linux the host enters a user namespace and new mount, network, IPC,
    /// UTS and PID namespaces before a plugin byte exists in the process, then
    /// applies a Landlock filesystem allow-list and a seccomp filter that takes
    /// back the escape surface the namespaces granted. The result is a boundary
    /// rather than a courtesy: no outbound network, no process table beyond its
    /// own, and filesystem reach limited to what the session needs — staged
    /// artifacts, the sockets it serves, and the libraries a plugin links.
    ///
    /// It is a namespace sandbox rather than a virtual machine, so the residual
    /// risk is the Linux syscall surface itself; that is the boundary the
    /// seccomp deny-list narrows. Where unprivileged user namespaces are
    /// unavailable or AppArmor-restricted, the policy refuses to start rather
    /// than run unconfined.
    RestrictedLinux,
}

/// Something a restricted host cannot be started without.
///
/// Named individually rather than collapsed into one sentence, because the three
/// have different repairs: one is a different machine, one is a packaging step,
/// and one is a capability of this runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionRequirement {
    /// The platform the confinement is written for.
    MacOS,
    /// A host installed as a bundle, because the sandbox travels with the signature.
    BundledHost,
    /// Approved artifact bytes delivered over the session rather than as a path.
    StagedArtifactTransfer,
    /// The platform the namespace confinement is written for.
    Linux,
    /// The kernel must let this binary create user namespaces, which is where
    /// every other namespace comes from.
    UserNamespaces,
}

impl RestrictionRequirement {
    /// What a caller is told when this is missing.
    pub const fn message(self) -> &'static str {
        match self {
            Self::MacOS => "the platform is not macOS, where this confinement is defined",
            Self::BundledHost => {
                "no bundled host is installed beside this runtime, and the sandbox is applied \
                 through the bundle's signature"
            }
            Self::StagedArtifactTransfer => {
                "this build cannot complete an approved artifact transfer and native load \
                 inside the confined host"
            }
            Self::Linux => "the platform is not Linux, where this confinement is defined",
            Self::UserNamespaces => {
                "the confinement probe could not enter a user namespace — the kernel may \
                 disable unprivileged user namespaces (kernel.unprivileged_userns_clone) or \
                 mediate them per-binary through AppArmor \
                 (kernel.apparmor_restrict_unprivileged_userns), which needs a profile granting \
                 the host binary the userns permission"
            }
        }
    }
}

impl NativeIsolationPolicy {
    /// The spelling a deployment configures this policy by.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedProcess => "trusted-process",
            Self::RestrictedMacOS => "restricted-macos",
            Self::RestrictedLinux => "restricted-linux",
        }
    }

    /// Parse one canonical deployment spelling.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "trusted-process" => Ok(Self::TrustedProcess),
            "restricted-macos" => Ok(Self::RestrictedMacOS),
            "restricted-linux" => Ok(Self::RestrictedLinux),
            other => Err(format!(
                "{NATIVE_ISOLATION_ENV} has unsupported value '{other}'; expected 'trusted-process', 'restricted-macos' or 'restricted-linux'"
            )),
        }
    }

    /// Resolve the policy shared by the CLI and every binding. An absent value
    /// retains the compatible trusted-process default; malformed values fail
    /// instead of silently selecting a weaker mode.
    pub fn from_environment() -> Result<Self, String> {
        match std::env::var(NATIVE_ISOLATION_ENV) {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(format!("{NATIVE_ISOLATION_ENV} is not valid Unicode"))
            }
        }
    }

    /// Whether a host started under this policy is confined rather than only
    /// separated into its own process.
    pub const fn confines_resources(self) -> bool {
        matches!(self, Self::RestrictedMacOS | Self::RestrictedLinux)
    }

    /// Whether the confinement is carried by the executable's signature.
    ///
    /// App Sandbox follows the bytes the signature covers, so a signed bundle
    /// must be exec'd as itself — staging a private copy would strip the
    /// entitlement the sandbox travels with. Linux confinement is applied by
    /// the process at startup instead, which means a staged private copy keeps
    /// it — and the staged copy is what closes the window between digesting a
    /// path and executing it.
    pub const fn confinement_from_signature(self) -> bool {
        matches!(self, Self::RestrictedMacOS)
    }

    /// What this policy needs that the deployment does not have.
    ///
    /// `candidate` is the confined host executable that would be started — the
    /// bundle's executable under `restricted-macos`, the resolved host under
    /// `restricted-linux`, where it is also the probe the requirement check
    /// runs. The empty answer means the policy can be honored.
    pub fn unmet_requirements(self, candidate: Option<&Path>) -> Vec<RestrictionRequirement> {
        match self {
            Self::TrustedProcess => Vec::new(),
            Self::RestrictedMacOS => {
                let mut unmet = Vec::new();
                if !cfg!(target_os = "macos") {
                    unmet.push(RestrictionRequirement::MacOS);
                }
                if candidate.is_none() {
                    unmet.push(RestrictionRequirement::BundledHost);
                }
                if !RESTRICTED_ARTIFACT_LOAD_QUALIFIED {
                    unmet.push(RestrictionRequirement::StagedArtifactTransfer);
                }
                unmet
            }
            Self::RestrictedLinux => {
                let mut unmet = Vec::new();
                if !cfg!(target_os = "linux") {
                    unmet.push(RestrictionRequirement::Linux);
                } else if !linux_confinement_available(candidate) {
                    unmet.push(RestrictionRequirement::UserNamespaces);
                }
                if !RESTRICTED_ARTIFACT_LOAD_QUALIFIED {
                    unmet.push(RestrictionRequirement::StagedArtifactTransfer);
                }
                unmet
            }
        }
    }

    /// The executable to start under this policy: the host it names, or why not.
    ///
    /// The policies start different artifacts. A trusted host is whichever
    /// executable the deployment named or installed — the rule in
    /// [`crate::host_location`] is unchanged, and an override stays authoritative
    /// even when it names nothing that exists. A restricted macOS host has to be
    /// a bundled one, because the confinement is a property of the bundle's
    /// signature: a path the caller resolved is used when it is already that
    /// shape, the bundle installed beside the runtime is used when it is not, and
    /// a deployment that offers neither is refused rather than started — running
    /// a bare executable there would be a host without the confinement the policy
    /// states. A restricted Linux host is the resolved executable, because the
    /// confinement is applied by the binary at startup rather than carried by its
    /// packaging; what is refused there is a machine the binary cannot confine
    /// itself on.
    pub fn host_executable(
        self,
        resolved: &Path,
        beside: &Path,
    ) -> Result<PathBuf, PluginProtocolError> {
        match self {
            Self::TrustedProcess => return Ok(resolved.to_path_buf()),
            Self::RestrictedLinux => {
                let unmet = self.unmet_requirements(Some(resolved));
                if !unmet.is_empty() {
                    let reasons = unmet
                        .iter()
                        .map(|requirement| requirement.message())
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(refused(format!(
                        "the '{}' policy cannot be honored here: {reasons}",
                        self.as_str()
                    )));
                }
                return Ok(resolved.to_path_buf());
            }
            Self::RestrictedMacOS => {}
        }
        if !cfg!(target_os = "macos") {
            return Err(refused(format!(
                "the '{}' policy cannot be honored here: {}",
                self.as_str(),
                RestrictionRequirement::MacOS.message()
            )));
        }
        // A path the caller resolved itself is used when it is already the
        // confined spelling — a package that ships the bundle knows where its own
        // `Contents/MacOS` is. Anything else means the policy has to find the
        // bundle it requires, and a deployment that supplied neither gets a
        // refusal that names what was expected rather than a host without the
        // confinement the policy states.
        let bundle = host_location::bundled_beside(beside);
        let executable = if host_location::is_bundled_executable(resolved) {
            Some(resolved.to_path_buf())
        } else {
            bundle
        };
        let Some(executable) = executable else {
            let looked = host_location::bundle_search_locations(beside)
                .into_iter()
                .map(|location| format!("'{}'", location.display()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(refused(format!(
                "the '{}' policy needs a host inside a bundle: '{}' is not in one, and no \
                 '{}' is installed beside this runtime (looked for {looked})",
                self.as_str(),
                resolved.display(),
                host_location::BUNDLE_NAME
            )));
        };
        // The packaging requirement is answered by what was chosen rather than by
        // what was found: a caller that resolved the bundle's own executable
        // supplied one, whether or not a second copy is installed beside it.
        let unmet = self.unmet_requirements(Some(executable.as_path()));
        if !unmet.is_empty() {
            let reasons = unmet
                .iter()
                .map(|requirement| requirement.message())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(refused(format!(
                "the '{}' policy cannot be honored here: {reasons}",
                self.as_str()
            )));
        }
        Ok(executable)
    }

    /// Verify that a confinement the signature must carry is actually there.
    ///
    /// For `restricted-macos` the sandbox is a property of the bundle's
    /// signature, so the supervisor checks it before the child exists. For
    /// `restricted-linux` there is nothing a signature could carry — the host
    /// confines itself at startup — and the executable's identity is bound by
    /// the component-manifest pin the composition already applies. Trusted
    /// process has no confinement to verify.
    pub fn verify_host_signature(self, executable: &Path) -> Result<(), PluginProtocolError> {
        match self {
            Self::TrustedProcess | Self::RestrictedLinux => Ok(()),
            Self::RestrictedMacOS => {
                #[cfg(target_os = "macos")]
                {
                    verify_restricted_host_signature(executable)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = executable;
                    Err(refused(RestrictionRequirement::MacOS.message().into()))
                }
            }
        }
    }
}

/// Whether the named host can apply the Linux confinement here.
///
/// The honest check is to run it: spawning the candidate with the probe
/// environment makes the binary attempt every step of the sandbox — namespaces,
/// uid mapping, Landlock, seccomp — in a confined child that proves the denials
/// and prints the ack. An executable that is missing, stale, or blocked by
/// kernel policy fails the same way: no ack on a successful exit.
#[cfg(target_os = "linux")]
fn linux_confinement_available(candidate: Option<&Path>) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    let output = std::process::Command::new(candidate)
        .env(CONFINEMENT_PROBE_ENV, CONFINEMENT_PROBE_VALUE)
        .env(
            "NEMO_RELAY_PLUGIN_HOST_SOCKET",
            std::env::temp_dir().join("nemo-probe").join("s"),
        )
        .output();
    match output {
        Ok(output) => {
            let confined = output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line.trim() == CONFINEMENT_PROBE_ACK);
            // The probe's stderr is the difference between "the kernel refused"
            // and "the binary was wrong": a deployment told only that the probe
            // failed could chase a sysctl for a month when the answer was a
            // stale host binary.
            if !confined {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stderr = stderr.trim();
                if !stderr.is_empty() {
                    eprintln!("restricted-linux confinement probe failed: {stderr}");
                }
            }
            confined
        }
        Err(error) => {
            eprintln!("restricted-linux confinement probe could not run: {error}");
            false
        }
    }
}

/// The same function on platforms where the answer is known without asking.
#[cfg(not(target_os = "linux"))]
fn linux_confinement_available(_candidate: Option<&Path>) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn verify_restricted_host_signature(executable: &Path) -> Result<(), PluginProtocolError> {
    let bundle = executable
        .ancestors()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == host_location::BUNDLE_NAME)
        })
        .ok_or_else(|| refused(RestrictionRequirement::BundledHost.message().into()))?;
    let canonical_bundle = std::fs::canonicalize(bundle).map_err(|error| {
        refused(format!(
            "cannot resolve the restricted host bundle: {error}"
        ))
    })?;
    let canonical_executable = std::fs::canonicalize(executable).map_err(|error| {
        refused(format!(
            "cannot resolve the restricted host executable: {error}"
        ))
    })?;
    if !canonical_executable.starts_with(&canonical_bundle) {
        return Err(refused(
            "restricted host executable resolves outside its signed application bundle".into(),
        ));
    }
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--deep"])
        .arg(bundle)
        .output()
        .map_err(|error| {
            refused(format!(
                "cannot verify the restricted host signature: {error}"
            ))
        })?;
    if !verify.status.success() {
        return Err(refused(format!(
            "macOS rejected the restricted host signature: {}",
            String::from_utf8_lossy(&verify.stderr).trim()
        )));
    }

    let details = Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=4"])
        .arg(bundle)
        .output()
        .map_err(|error| {
            refused(format!(
                "cannot inspect the restricted host signature: {error}"
            ))
        })?;
    if !details.status.success() {
        return Err(refused(format!(
            "cannot inspect the restricted host signature: {}",
            String::from_utf8_lossy(&details.stderr).trim()
        )));
    }
    let detail_text = format!(
        "{}{}",
        String::from_utf8_lossy(&details.stdout),
        String::from_utf8_lossy(&details.stderr)
    );
    let has_identifier = detail_text
        .lines()
        .any(|line| line.trim() == format!("Identifier={}", host_location::BUNDLE_IDENTIFIER));
    let has_runtime = detail_text.lines().any(|line| {
        let line = line.trim();
        line.starts_with("CodeDirectory ") && line.contains("flags=") && line.contains("runtime")
    });
    if !has_identifier || !has_runtime {
        return Err(refused(format!(
            "restricted host signature must identify {} and enable Hardened Runtime",
            host_location::BUNDLE_IDENTIFIER
        )));
    }

    let expected_team = std::env::var(host_location::TEAM_ID_ENV).map_err(|error| {
        refused(format!(
            "restricted macOS requires an expected signing Team ID in {}: {error}",
            host_location::TEAM_ID_ENV
        ))
    })?;
    if expected_team.is_empty() {
        return Err(refused(format!(
            "{} must be non-empty",
            host_location::TEAM_ID_ENV
        )));
    }
    let has_expected_team = detail_text
        .lines()
        .any(|line| line.trim() == format!("TeamIdentifier={expected_team}"));
    if !has_expected_team {
        return Err(refused(format!(
            "restricted host Team ID does not match {}",
            host_location::TEAM_ID_ENV
        )));
    }

    let entitlements = Command::new("/usr/bin/codesign")
        .args(["--display", "--entitlements", "-"])
        .arg(bundle)
        .output()
        .map_err(|error| {
            refused(format!(
                "cannot inspect restricted host entitlements: {error}"
            ))
        })?;
    if !entitlements.status.success() {
        return Err(refused(format!(
            "cannot inspect restricted host entitlements: {}",
            String::from_utf8_lossy(&entitlements.stderr).trim()
        )));
    }
    let entitlement_text = format!(
        "{}{}",
        String::from_utf8_lossy(&entitlements.stdout),
        String::from_utf8_lossy(&entitlements.stderr)
    );
    let mut sandbox_key = false;
    let mut sandbox_enabled = false;
    for line in entitlement_text.lines().map(str::trim) {
        if let Some(key) = line.strip_prefix("[Key] ") {
            sandbox_key = key == "com.apple.security.app-sandbox";
        } else if sandbox_key && line == "[Bool] true" {
            sandbox_enabled = true;
        }
    }
    if !sandbox_enabled {
        return Err(refused(
            "restricted host signature does not carry the App Sandbox entitlement".into(),
        ));
    }
    Ok(())
}

/// A configuration this runtime cannot honor, in the code the boundary already uses.
fn refused(message: String) -> PluginProtocolError {
    PluginProtocolError::new(PluginFailureCode::Unavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "nemo-isolation-policy-{name}-{}",
            nemo_relay_plugin_protocol::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&directory).expect("a directory for the policy rule");
        directory
    }

    /// Lay a bundled host out where the resolver looks for one.
    fn install_bundle(beside: &Path) -> PathBuf {
        let inner = beside
            .join(host_location::BUNDLE_NAME)
            .join("Contents")
            .join("MacOS")
            .join("nemo-plugin-host");
        std::fs::create_dir_all(inner.parent().expect("the bundle's MacOS directory"))
            .expect("a bundle directory");
        std::fs::write(&inner, b"a host inside a bundle").expect("a bundled host");
        inner
    }

    #[test]
    fn a_trusted_policy_is_the_rule_that_was_always_there() {
        // The default policy changes nothing: the deployment's override wins, and
        // nothing about bundles is consulted.
        let beside = temporary_directory("trusted");
        let configured = PathBuf::from("/nonexistent/by/override/nemo-plugin-host");
        let resolved = NativeIsolationPolicy::TrustedProcess.host_executable(&configured, &beside);

        std::fs::remove_dir_all(&beside).ok();
        assert_eq!(resolved.expect("a trusted host"), configured);
        assert!(
            NativeIsolationPolicy::default() == NativeIsolationPolicy::TrustedProcess,
            "the policy a runtime gets when it does not choose is the one that was implicit"
        );
    }

    #[test]
    fn deployment_policy_has_one_strict_parser() {
        assert_eq!(
            NativeIsolationPolicy::parse("trusted-process").expect("trusted policy"),
            NativeIsolationPolicy::TrustedProcess
        );
        assert_eq!(
            NativeIsolationPolicy::parse("restricted-macos").expect("restricted policy"),
            NativeIsolationPolicy::RestrictedMacOS
        );
        assert_eq!(
            NativeIsolationPolicy::parse("restricted-linux").expect("linux restricted policy"),
            NativeIsolationPolicy::RestrictedLinux
        );
        let error = NativeIsolationPolicy::parse("restricted").expect_err("unknown spelling");
        assert!(error.contains(NATIVE_ISOLATION_ENV));
        assert!(error.contains("trusted-process"));
        assert!(error.contains("restricted-linux"));
    }

    #[test]
    fn confined_policies_are_confined_but_only_macos_is_signature_bound() {
        assert!(!NativeIsolationPolicy::TrustedProcess.confines_resources());
        assert!(NativeIsolationPolicy::RestrictedMacOS.confines_resources());
        assert!(NativeIsolationPolicy::RestrictedLinux.confines_resources());
        // The staged-copy path is wrong only where the signature is what
        // confines; everywhere else the copy keeps the boundary.
        assert!(NativeIsolationPolicy::RestrictedMacOS.confinement_from_signature());
        assert!(!NativeIsolationPolicy::RestrictedLinux.confinement_from_signature());
        assert!(!NativeIsolationPolicy::TrustedProcess.confinement_from_signature());
    }

    #[test]
    fn a_linux_restricted_host_is_the_resolved_binary_when_confinement_holds() {
        // The policy cannot prove confinement from a path — the binary proves
        // it by probing itself. A path that does not exist fails the probe on
        // every platform, so the refusal is the expected answer wherever this
        // test runs; on a Linux host the message additionally explains the
        // user-namespace knobs a deployer would check.
        let beside = temporary_directory("linux");
        let missing = beside.join("nemo-plugin-host");

        let unmet = NativeIsolationPolicy::RestrictedLinux.unmet_requirements(Some(&missing));
        let resolved = NativeIsolationPolicy::RestrictedLinux.host_executable(&missing, &beside);

        std::fs::remove_dir_all(&beside).ok();
        if cfg!(target_os = "linux") {
            assert!(
                unmet.contains(&RestrictionRequirement::UserNamespaces),
                "a host that cannot be probed cannot promise confinement: {unmet:?}"
            );
        } else {
            assert!(unmet.contains(&RestrictionRequirement::Linux));
        }
        let error = resolved.expect_err("a host that cannot confine must be refused");
        assert!(
            error.failure.message.contains("restricted-linux"),
            "the refusal names the policy a deployment selected: {}",
            error.failure.message
        );
    }

    #[test]
    fn a_restricted_policy_starts_only_when_every_boundary_is_deliverable() {
        let beside = temporary_directory("bundled");
        let inner = install_bundle(&beside);
        let bare = beside.join("nemo-plugin-host");
        std::fs::write(&bare, b"a bare host").expect("a bare host beside the bundle");

        let requirements = NativeIsolationPolicy::RestrictedMacOS
            .unmet_requirements(Some(&beside.join(host_location::BUNDLE_NAME)));
        let resolved = NativeIsolationPolicy::RestrictedMacOS.host_executable(&bare, &beside);

        std::fs::remove_dir_all(&beside).ok();
        assert_eq!(
            host_location::bundled_beside(&beside),
            None,
            "the bundle was removed with its directory"
        );
        assert!(
            !requirements.contains(&RestrictionRequirement::BundledHost),
            "an installed bundle answers the packaging requirement"
        );
        match resolved {
            Err(error) if !cfg!(target_os = "macos") => assert!(
                error
                    .failure
                    .message
                    .contains(RestrictionRequirement::MacOS.message()),
                "a non-macOS host names the platform restriction: {}",
                error.failure.message
            ),
            Err(error) if cfg!(target_os = "macos") => assert!(
                error
                    .failure
                    .message
                    .contains(RestrictionRequirement::StagedArtifactTransfer.message()),
                "the complete restricted artifact load is not qualified: {}",
                error.failure.message
            ),
            Err(error) => panic!("unexpected restricted-host refusal: {error}"),
            Ok(path) => {
                let installed = inner.clone();
                assert_eq!(
                    path, installed,
                    "a restricted host is the bundled executable"
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_restricted_host_outside_a_bundle_is_refused() {
        // Honoring this would run an unconfined host under a policy that says the
        // opposite, which is the failure mode the policy exists to remove.
        let beside = temporary_directory("unbundled");
        let named = beside.join("nemo-plugin-host");
        std::fs::write(&named, b"a host this deployment pointed at").expect("a named host");

        let resolved = NativeIsolationPolicy::RestrictedMacOS.host_executable(&named, &beside);

        std::fs::remove_dir_all(&beside).ok();
        let error = resolved.expect_err("a host outside a bundle is not a confined host");
        assert!(
            error.failure.message.contains(host_location::BUNDLE_NAME),
            "the refusal names the bundle that was expected: {}",
            error.failure.message
        );
    }

    #[test]
    fn the_bundle_layout_is_structurally_recognised() {
        // The check is structural rather than a search for one exact path, because
        // a deployment may install an application bundle anywhere; what it may not
        // do is call a bare executable a confined one.
        assert!(host_location::is_bundled_executable(Path::new(
            "/Applications/nemo-plugin-host.app/Contents/MacOS/nemo-plugin-host"
        )));
        assert!(!host_location::is_bundled_executable(Path::new(
            "/usr/local/bin/nemo-plugin-host"
        )));
        assert!(!host_location::is_bundled_executable(Path::new(
            "/Applications/nemo-plugin-host.app/Contents/Resources/nemo-plugin-host"
        )));
    }
}
