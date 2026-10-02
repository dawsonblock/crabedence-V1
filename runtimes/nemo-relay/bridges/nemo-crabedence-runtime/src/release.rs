// SPDX-License-Identifier: Apache-2.0

//! The release this binary shipped in, when it shipped in one.
//!
//! A qualified distribution lays the runtime out as
//! `<root>/bin/nemo-crabedence-runtime` beside `share/` and `manifests/`, with
//! `manifests/component-manifest.json` declaring every component's digest and
//! `manifests/component-manifest.sha256` binding the manifest itself. When
//! that layout is present this module verifies it and yields what the runtime
//! needs from it — the release-root identity its reports and mediation
//! provenance name, and the digest the plugin host is pinned to, so a
//! qualified deployment does not depend on a caller exporting
//! `NEMO_RELAY_PLUGIN_HOST_SHA256`.
//!
//! When the layout is absent — a development tree, a `cargo` target
//! directory, anywhere a manifest was never installed — the answer is `None`
//! and nothing is enforced: an unpackaged runtime cannot be bound to a
//! release it is not part of. A manifest that exists but does not verify — a
//! missing or disagreeing sidecar, a declaration that names different bytes
//! than this binary's — is an inconsistent release root, which is a tamper
//! signal rather than an absent release and is refused rather than ignored.

use std::path::{Path, PathBuf};

use serde_json::Value;
#[cfg(test)]
use uuid::Uuid;

/// The manifest and its digest sidecar inside a release root.
const MANIFEST_PATH: &str = "manifests/component-manifest.json";
const MANIFEST_SIDECAR_PATH: &str = "manifests/component-manifest.sha256";

/// The component paths this binary's own self-bind and the host pin read.
const RUNTIME_COMPONENT_PATH: &str = "bin/nemo-crabedence-runtime";
const PLUGIN_HOST_COMPONENT_PATH: &str = "bin/nemo-plugin-host";

/// The verified release this executable is part of.
#[derive(Debug)]
pub(crate) struct ReleaseIdentity {
    /// The distribution root — the parent of `bin/`.
    #[allow(dead_code)]
    pub root: PathBuf,
    /// SHA-256 of the component-manifest bytes — the release-root identity
    /// reports and receipts name. Verified against the sidecar, which is the
    /// digest a release signature would bind.
    pub release_root_digest: String,
    /// The distribution's declared name.
    pub name: String,
    /// The integrated target the manifest was assembled for.
    pub platform: String,
    /// The crabbox CLI version the release bound.
    pub crabbox_version: String,
    /// The NEMO runtime source-tree digest the release bound.
    pub nemo_runtime_sha256: String,
    /// The capability-registry envelope digest the release bound.
    pub capability_registry_sha256: String,
    /// The digest the manifest declares for `bin/nemo-plugin-host` — the pin
    /// a spawned host must carry.
    pub plugin_host_sha256: String,
}

/// The release this executable belongs to, when the layout declares one.
///
/// `Err` means a manifest was found and did not verify: the release root
/// exists but is not intact, and continuing under it would report provenance
/// the root does not actually carry.
pub(crate) fn discover() -> Result<Option<ReleaseIdentity>, String> {
    let executable = std::env::current_exe().map_err(|error| {
        format!("the runtime executable's own path could not be resolved: {error}")
    })?;
    discover_from(&executable)
}

/// Split out so the rule is testable: `executable` stands in for
/// `current_exe()`.
fn discover_from(executable: &Path) -> Result<Option<ReleaseIdentity>, String> {
    let Some(bin_dir) = executable.parent() else {
        return Ok(None);
    };
    let Some(root) = bin_dir.parent() else {
        return Ok(None);
    };
    let manifest_path = root.join(MANIFEST_PATH);
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let manifest_bytes = std::fs::read(&manifest_path).map_err(|error| {
        format!(
            "the component manifest '{}' could not be read: {error}",
            manifest_path.display()
        )
    })?;
    let release_root_digest = crate::sha256_hex(&manifest_bytes);

    // A manifest that exists is a declaration the release makes; half of one
    // is not a development layout, it is an inconsistent one.
    let sidecar = std::fs::read_to_string(root.join(MANIFEST_SIDECAR_PATH)).map_err(|error| {
        format!(
            "the component manifest at '{}' has no readable sha256 sidecar ({error}) — \
             the release root is incomplete",
            manifest_path.display()
        )
    })?;
    let declared = sidecar.split_whitespace().next().unwrap_or_default();
    if !declared.eq_ignore_ascii_case(&release_root_digest) {
        return Err(format!(
            "the component manifest digests to {release_root_digest} but its sidecar declares \
             {declared} — the release root is not intact"
        ));
    }

    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("the component manifest is not JSON: {error}"))?;
    let component_sha256 = |path: &str| -> Result<String, String> {
        manifest
            .get("components")
            .and_then(Value::as_array)
            .and_then(|components| {
                components
                    .iter()
                    .find(|component| component.get("path").and_then(Value::as_str) == Some(path))
            })
            .and_then(|component| component.get("sha256"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("the component manifest declares no sha256 for '{path}'"))
    };
    let field = |name: &str| -> Result<String, String> {
        manifest
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("the component manifest carries no '{name}'"))
    };

    let plugin_host_sha256 = component_sha256(PLUGIN_HOST_COMPONENT_PATH)?;
    let runtime_sha256 = component_sha256(RUNTIME_COMPONENT_PATH)?;

    // Self-bind: the running binary must be the component the manifest names.
    // A root that declares different bytes is not this binary's release —
    // reporting its identity while being something else would be a provenance
    // claim the bytes do not support.
    let own = crate::sha256_hex(&std::fs::read(executable).map_err(|error| {
        format!(
            "this runtime executable '{}' could not be read for its digest: {error}",
            executable.display()
        )
    })?);
    if !own.eq_ignore_ascii_case(&runtime_sha256) {
        return Err(format!(
            "this executable digests to {own} but the component manifest declares \
             {runtime_sha256} for {RUNTIME_COMPONENT_PATH} — this binary is not the one \
             its release root shipped"
        ));
    }

    Ok(Some(ReleaseIdentity {
        root: root.to_path_buf(),
        release_root_digest,
        name: field("name")?,
        platform: field("platform")?,
        crabbox_version: field("crabbox_version")?,
        nemo_runtime_sha256: field("nemo_runtime_sha256")?,
        capability_registry_sha256: field("capability_registry_sha256")?,
        plugin_host_sha256,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory no other test touches, removed by the caller.
    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("nemo-release-{name}-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        directory
    }

    /// Lay out the smallest release root the discovery will accept: the
    /// manifest, its sidecar, and a binary component whose bytes the manifest
    /// names.
    fn install_release(root: &Path, binary_contents: &[u8]) -> PathBuf {
        let bin = root.join("bin");
        let manifests = root.join("manifests");
        std::fs::create_dir_all(&bin).expect("bin/");
        std::fs::create_dir_all(&manifests).expect("manifests/");
        let executable = bin.join("nemo-crabedence-runtime");
        std::fs::write(&executable, binary_contents).expect("the runtime binary");
        let manifest = serde_json::json!({
            "name": "nemo-control_0.0.0_test",
            "crabbox_version": "0.0.0",
            "nemo_runtime_sha256": "0".repeat(64),
            "capability_registry_sha256": "1".repeat(64),
            "platform": "test_platform",
            "components": [
                {
                    "name": "nemo-crabedence-runtime",
                    "kind": "binary",
                    "path": RUNTIME_COMPONENT_PATH,
                    "sha256": crate::sha256_hex(binary_contents),
                },
                {
                    "name": "nemo-plugin-host",
                    "kind": "binary",
                    "path": PLUGIN_HOST_COMPONENT_PATH,
                    "sha256": "2".repeat(64),
                },
            ],
        });
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
        std::fs::write(manifests.join("component-manifest.json"), &manifest_bytes)
            .expect("the manifest");
        std::fs::write(
            manifests.join("component-manifest.sha256"),
            format!("{}\n", crate::sha256_hex(&manifest_bytes)),
        )
        .expect("the sidecar");
        executable
    }

    #[test]
    fn no_manifest_is_no_release() {
        // A binary anywhere the layout was never installed — a cargo target
        // dir is the everyday case — binds nothing and is refused nothing.
        let root = scratch("none");
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).expect("bin/");
        let executable = bin.join("nemo-crabedence-runtime");
        std::fs::write(&executable, b"dev binary").expect("a binary");
        assert!(discover_from(&executable).expect("no release").is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_verified_manifest_binds_the_release_identity() {
        let root = scratch("verified");
        let executable = install_release(&root, b"the shipped runtime");
        let release = discover_from(&executable)
            .expect("the manifest verifies")
            .expect("a release is found");
        assert_eq!(release.name, "nemo-control_0.0.0_test");
        assert_eq!(release.plugin_host_sha256, "2".repeat(64));
        assert_eq!(release.release_root_digest.len(), 64);
        assert_eq!(release.root, root);
        std::fs::remove_dir_all(&release.root).ok();
    }

    #[test]
    fn a_disagreeing_sidecar_is_refused() {
        let root = scratch("bad-sidecar");
        let executable = install_release(&root, b"the shipped runtime");
        std::fs::write(
            root.join("manifests/component-manifest.sha256"),
            "0".repeat(64),
        )
        .expect("a rewritten sidecar");
        let error = discover_from(&executable)
            .expect_err("a manifest whose sidecar disagrees is not intact");
        assert!(error.contains("sidecar"), "got: {error}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_missing_sidecar_is_refused() {
        let root = scratch("no-sidecar");
        let executable = install_release(&root, b"the shipped runtime");
        std::fs::remove_file(root.join("manifests/component-manifest.sha256"))
            .expect("remove the sidecar");
        let error = discover_from(&executable).expect_err("half a release is refused, not ignored");
        assert!(error.contains("sidecar"), "got: {error}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_binary_the_manifest_did_not_declare_is_refused() {
        let root = scratch("swapped");
        let executable = install_release(&root, b"the shipped runtime");
        // The manifest declares the original bytes; replacing the binary
        // afterwards is exactly what the self-bind exists to catch.
        std::fs::write(&executable, b"a different binary").expect("swap the binary");
        let error = discover_from(&executable)
            .expect_err("a replaced binary is not its manifest's component");
        assert!(
            error.contains("bin/nemo-crabedence-runtime"),
            "got: {error}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_manifest_without_the_host_component_is_refused() {
        let root = scratch("no-host");
        let bin = root.join("bin");
        let manifests = root.join("manifests");
        std::fs::create_dir_all(&bin).expect("bin/");
        std::fs::create_dir_all(&manifests).expect("manifests/");
        let executable = bin.join("nemo-crabedence-runtime");
        std::fs::write(&executable, b"runtime").expect("the binary");
        let manifest = serde_json::json!({
            "name": "nemo-control_0.0.0_test",
            "crabbox_version": "0.0.0",
            "nemo_runtime_sha256": "0".repeat(64),
            "capability_registry_sha256": "1".repeat(64),
            "platform": "test_platform",
            "components": [{
                "name": "nemo-crabedence-runtime",
                "kind": "binary",
                "path": RUNTIME_COMPONENT_PATH,
                "sha256": crate::sha256_hex(b"runtime"),
            }],
        });
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
        std::fs::write(manifests.join("component-manifest.json"), &manifest_bytes)
            .expect("the manifest");
        std::fs::write(
            manifests.join("component-manifest.sha256"),
            format!("{}\n", crate::sha256_hex(&manifest_bytes)),
        )
        .expect("the sidecar");
        let error =
            discover_from(&executable).expect_err("a release with no declared host cannot pin one");
        assert!(error.contains("bin/nemo-plugin-host"), "got: {error}");
        std::fs::remove_dir_all(&root).ok();
    }
}
