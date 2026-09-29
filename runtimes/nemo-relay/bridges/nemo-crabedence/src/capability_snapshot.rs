// SPDX-License-Identifier: Apache-2.0

//! Registry envelope verification.
//!
//! NEMO does not maintain a capability catalog. It loads the authoritative
//! registry's verifiable export — written by `crabbox serve-exec` next to the
//! socket — and routes on the trusted descriptors.
//!
//! The export is an envelope carrying the registry digest **and** the exact
//! canonical bytes it covers:
//!
//! ```json
//! { "registry_sha256": "<hex>", "canonical_payload": "<base64>" }
//! ```
//!
//! Verification is: base64-decode, SHA-256, compare, and only then parse. The
//! descriptors NEMO routes on are therefore provably the bytes the
//! authoritative registry digested, and a payload that does not match its
//! digest fails closed.
//!
//! Cross-language canonicalization deliberately never enters this boundary:
//! the canonical bytes are produced once, by the authoritative Go
//! implementation, and verified here as bytes. There is no second serializer
//! whose number representation or key order could disagree with Go's.
//!
//! This module is the Rust mirror of `nemo/kernel/snapshot.ts`. It preserves
//! that implementation's exact acceptance surface, including the checks it
//! deliberately does not perform (the assurance profile is carried, not
//! validated — the digest already binds it to a Go-produced registry).

use std::fmt;
use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Execution class pinned by the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryExecutionClass {
    /// Deterministic, side-effect-free computation.
    Pure,
    /// Observational or read-only work.
    Read,
    /// An externally meaningful but non-critical mutation.
    Mutation,
    /// A consequential mutation that requires the authority path.
    Critical,
}

impl RegistryExecutionClass {
    /// The wire spelling of this class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pure => "PURE",
            Self::Read => "READ",
            Self::Mutation => "MUTATION",
            Self::Critical => "CRITICAL",
        }
    }

    /// Parses a wire spelling, returning `None` for an unknown class.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "PURE" => Some(Self::Pure),
            "READ" => Some(Self::Read),
            "MUTATION" => Some(Self::Mutation),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryExecutionClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Execution route pinned by the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryExecutionRoute {
    /// The calling process, with no socket hop.
    Local,
    /// A direct adapter with admission but no durable mutation ledger.
    Direct,
    /// The durable execution kernel.
    Crabedence,
}

impl RegistryExecutionRoute {
    /// The wire spelling of this route.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "LOCAL",
            Self::Direct => "DIRECT",
            Self::Crabedence => "CRABEDENCE",
        }
    }

    /// Parses a wire spelling, returning `None` for an unknown route.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "LOCAL" => Some(Self::Local),
            "DIRECT" => Some(Self::Direct),
            "CRABEDENCE" => Some(Self::Crabedence),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryExecutionRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The registry's authority policy projection for one capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryAuthorityPolicy {
    /// Policy identifier, when the registry names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Whether the capability requires a resolved grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_required: Option<bool>,
}

/// One capability descriptor as it travels in the canonical envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryDescriptor {
    /// Stable capability identifier.
    pub id: String,
    /// Monotonic descriptor version (defaulted to 1 by the registry).
    #[serde(default = "default_descriptor_version")]
    pub descriptor_version: u32,
    /// Registry policy revision, when the registry declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    /// Pinned execution class.
    pub execution_class: RegistryExecutionClass,
    /// Pinned assurance profile. Carried, not interpreted here.
    pub assurance_profile: String,
    /// Pinned execution route.
    pub execution_route: RegistryExecutionRoute,
    /// Argument schema, exactly as the registry canonicalized it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
    /// Authority policy projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_policy: Option<RegistryAuthorityPolicy>,
    /// Adapter binding the service dispatches through.
    pub adapter_id: String,
}

const fn default_descriptor_version() -> u32 {
    1
}

/// The verifiable registry export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEnvelope {
    /// SHA-256 of the decoded canonical payload.
    pub registry_sha256: String,
    /// Base64 of the canonical descriptor array.
    pub canonical_payload: String,
}

/// A snapshot that is not a valid, verified registry envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotError {
    message: String,
}

impl SnapshotError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The refusal detail.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SnapshotError {}

/// A capability catalog that exists only after a passing digest comparison.
///
/// The constructor is private and no public API produces one from unverified
/// bytes, so a hand-built catalog is unrepresentable outside this crate.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedCapabilityCatalog {
    registry_sha256: String,
    descriptors: Vec<RegistryDescriptor>,
}

impl VerifiedCapabilityCatalog {
    fn from_verified_payload(
        registry_sha256: String,
        descriptors: Vec<RegistryDescriptor>,
    ) -> Self {
        Self {
            registry_sha256,
            descriptors,
        }
    }

    /// The digest this catalog's descriptors were verified against.
    pub fn registry_sha256(&self) -> &str {
        &self.registry_sha256
    }

    /// Every verified descriptor, in registry order.
    pub fn descriptors(&self) -> &[RegistryDescriptor] {
        &self.descriptors
    }

    /// Resolves one capability, returning `None` when it is not registered.
    pub fn descriptor(&self, capability_id: &str) -> Option<&RegistryDescriptor> {
        self.descriptors
            .iter()
            .find(|descriptor| descriptor.id == capability_id)
    }
}

/// Loads a catalog from a registry envelope value.
///
/// Verification happens before parsing: the canonical payload is hashed and
/// compared against the envelope digest, and only the verified bytes are
/// parsed. A mismatch, a malformed envelope, or a descriptor the registry
/// itself would refuse fails closed.
pub fn load_catalog_from_snapshot(
    raw: &serde_json::Value,
) -> Result<VerifiedCapabilityCatalog, SnapshotError> {
    let envelope = parse_registry_envelope(raw)?;
    let payload = decode_canonical_payload(&envelope)?;
    let computed = sha256_hex(&payload);
    if !constant_time_equal_hex(&computed, &envelope.registry_sha256) {
        return Err(SnapshotError::new(
            "registry snapshot digest does not cover its payload — refusing to load an unverified or tampered snapshot",
        ));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
        SnapshotError::new(format!(
            "registry snapshot payload is not valid JSON: {error}"
        ))
    })?;
    let descriptors = parse_descriptors(&parsed)?;
    Ok(VerifiedCapabilityCatalog::from_verified_payload(
        envelope.registry_sha256,
        descriptors,
    ))
}

/// Loads and verifies a registry envelope from `path`.
///
/// The caller owns the trust-domain decision that `path` is the service's own
/// snapshot (0600 inside the 0700 socket directory); this function verifies
/// only the envelope's cryptographic integrity.
pub fn load_catalog_from_path(path: &Path) -> Result<VerifiedCapabilityCatalog, SnapshotError> {
    let bytes = std::fs::read(path).map_err(|error| {
        SnapshotError::new(format!(
            "read capability registry snapshot {}: {error}",
            path.display()
        ))
    })?;
    let raw: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        SnapshotError::new(format!(
            "capability registry snapshot {} is not valid JSON: {error}",
            path.display()
        ))
    })?;
    load_catalog_from_snapshot(&raw)
}

const HEX_DIGEST_LENGTH: usize = 64;

/// Validates the envelope shape, failing closed.
fn parse_registry_envelope(raw: &serde_json::Value) -> Result<RegistryEnvelope, SnapshotError> {
    let envelope = raw
        .as_object()
        .ok_or_else(|| SnapshotError::new("registry snapshot must be a JSON object"))?;
    let registry_sha256 = envelope
        .get("registry_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            SnapshotError::new(
                "registry snapshot registry_sha256 must be a 64-character hex digest",
            )
        })?;
    if registry_sha256.len() != HEX_DIGEST_LENGTH
        || !registry_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SnapshotError::new(
            "registry snapshot registry_sha256 must be a 64-character hex digest",
        ));
    }
    let canonical_payload = envelope
        .get("canonical_payload")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            SnapshotError::new("registry snapshot canonical_payload must be a base64 string")
        })?;
    if canonical_payload.is_empty() {
        return Err(SnapshotError::new(
            "registry snapshot canonical_payload must be a base64 string",
        ));
    }
    Ok(RegistryEnvelope {
        registry_sha256: registry_sha256.to_string(),
        canonical_payload: canonical_payload.to_string(),
    })
}

/// Decodes the canonical payload, refusing anything that is not standard
/// base64.
fn decode_canonical_payload(envelope: &RegistryEnvelope) -> Result<Vec<u8>, SnapshotError> {
    if !is_standard_base64(&envelope.canonical_payload) {
        return Err(SnapshotError::new(
            "registry snapshot canonical_payload is not valid base64",
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(&envelope.canonical_payload)
        .map_err(|_| SnapshotError::new("registry snapshot canonical_payload is not valid base64"))
}

/// `^[A-Za-z0-9+/]+={0,2}$` with a whole-block length.
fn is_standard_base64(value: &str) -> bool {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return false;
    }
    let body = value.trim_end_matches('=');
    let padding = value.len() - body.len();
    if padding > 2 {
        return false;
    }
    if body.is_empty() {
        return false;
    }
    body.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(HEX_DIGEST_LENGTH);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Compares two hex digests without an early exit on the first difference.
fn constant_time_equal_hex(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Parses and validates the descriptor array from verified payload bytes.
fn parse_descriptors(value: &serde_json::Value) -> Result<Vec<RegistryDescriptor>, SnapshotError> {
    let entries = value.as_array().ok_or_else(|| {
        SnapshotError::new("registry snapshot payload must be a descriptor array")
    })?;
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_descriptor(index, entry))
        .collect()
}

fn parse_descriptor(
    index: usize,
    entry: &serde_json::Value,
) -> Result<RegistryDescriptor, SnapshotError> {
    let object = entry.as_object().ok_or_else(|| {
        SnapshotError::new(format!(
            "registry snapshot descriptor {index} must be an object"
        ))
    })?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            SnapshotError::new(format!("registry snapshot descriptor {index} has no id"))
        })?
        .to_string();

    let execution_class = object
        .get("execution_class")
        .and_then(serde_json::Value::as_str)
        .and_then(RegistryExecutionClass::parse)
        .ok_or_else(|| {
            SnapshotError::new(format!(
                "capability {id}: invalid execution_class {}",
                object
                    .get("execution_class")
                    .map_or_else(|| "null".to_string(), |value| value.to_string())
            ))
        })?;

    let execution_route = object
        .get("execution_route")
        .and_then(serde_json::Value::as_str)
        .and_then(RegistryExecutionRoute::parse)
        .ok_or_else(|| {
            SnapshotError::new(format!(
                "capability {id}: invalid execution_route {}",
                object
                    .get("execution_route")
                    .map_or_else(|| "null".to_string(), |value| value.to_string())
            ))
        })?;

    let adapter_id = object
        .get("adapter_id")
        .and_then(serde_json::Value::as_str)
        .filter(|adapter| !adapter.is_empty())
        .ok_or_else(|| SnapshotError::new(format!("capability {id}: adapter_id is required")))?
        .to_string();

    // The registry refuses LOCAL + grant-required at registration; a snapshot
    // that carries it anyway is not a registry export and must not become a
    // catalog — LOCAL execution never reaches the authority resolver.
    let grant_required = object
        .get("authority_policy")
        .and_then(|policy| policy.get("grant_required"))
        .and_then(serde_json::Value::as_bool);
    if execution_route == RegistryExecutionRoute::Local && grant_required == Some(true) {
        return Err(SnapshotError::new(format!(
            "capability {id}: LOCAL route cannot require a grant — LOCAL execution never reaches the authority resolver"
        )));
    }

    let descriptor_version = object
        .get("descriptor_version")
        .and_then(serde_json::Value::as_u64)
        .map_or(1, |version| version as u32);
    let policy_revision = object
        .get("policy_revision")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let assurance_profile = object
        .get("assurance_profile")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            SnapshotError::new(format!("capability {id}: assurance_profile is required"))
        })?
        .to_string();
    let schema = object.get("schema").cloned();
    let authority_policy = object
        .get("authority_policy")
        .and_then(|policy| serde_json::from_value::<RegistryAuthorityPolicy>(policy.clone()).ok());

    Ok(RegistryDescriptor {
        id,
        descriptor_version,
        policy_revision,
        execution_class,
        assurance_profile,
        execution_route,
        schema,
        authority_policy,
        adapter_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_payload(descriptors: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(descriptors).expect("serialize")
    }

    fn envelope_for(payload: &[u8]) -> serde_json::Value {
        let digest = sha256_hex(payload);
        serde_json::json!({
            "registry_sha256": digest,
            "canonical_payload": base64::engine::general_purpose::STANDARD.encode(payload),
        })
    }

    fn descriptor(id: &str, class: &str, route: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "descriptor_version": 1,
            "execution_class": class,
            "assurance_profile": "DURABLE",
            "execution_route": route,
            "authority_policy": { "id": id, "grant_required": false },
            "adapter_id": "counter",
        })
    }

    #[test]
    fn verifies_and_parses_a_valid_envelope() {
        let payload = canonical_payload(&serde_json::json!([
            descriptor("system.echo", "PURE", "LOCAL"),
            descriptor("test.counter.increment", "MUTATION", "CRABEDENCE"),
        ]));
        let envelope = envelope_for(&payload);
        let catalog = load_catalog_from_snapshot(&envelope).expect("verified");
        assert_eq!(catalog.descriptors().len(), 2);
        assert_eq!(catalog.registry_sha256().len(), HEX_DIGEST_LENGTH);
        let mutation = catalog
            .descriptor("test.counter.increment")
            .expect("registered");
        assert_eq!(mutation.execution_class, RegistryExecutionClass::Mutation);
        assert_eq!(mutation.execution_route, RegistryExecutionRoute::Crabedence);
        assert!(catalog.descriptor("unregistered.capability").is_none());
    }

    #[test]
    fn refuses_a_tampered_payload() {
        let payload = canonical_payload(&serde_json::json!([descriptor(
            "github.issue.create",
            "MUTATION",
            "CRABEDENCE"
        ),]));
        let mut envelope = envelope_for(&payload);
        // Rewrite the classification without producing the matching digest.
        let tampered = canonical_payload(&serde_json::json!([descriptor(
            "github.issue.create",
            "READ",
            "DIRECT"
        ),]));
        envelope["canonical_payload"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&tampered));
        let error = load_catalog_from_snapshot(&envelope).unwrap_err();
        assert!(error.message().contains("digest does not cover"), "{error}");
    }

    #[test]
    fn refuses_a_malformed_digest() {
        let payload = canonical_payload(&serde_json::json!([]));
        let mut envelope = envelope_for(&payload);
        envelope["registry_sha256"] = serde_json::Value::String("not-a-digest".into());
        let error = load_catalog_from_snapshot(&envelope).unwrap_err();
        assert!(error.message().contains("64-character hex"), "{error}");
    }

    #[test]
    fn refuses_a_non_array_payload() {
        let payload = canonical_payload(&serde_json::json!({ "descriptors": [] }));
        let envelope = envelope_for(&payload);
        let error = load_catalog_from_snapshot(&envelope).unwrap_err();
        assert!(error.message().contains("descriptor array"), "{error}");
    }

    #[test]
    fn refuses_local_with_grant_required() {
        let mut local = descriptor("pure.local", "PURE", "LOCAL");
        local["authority_policy"]["grant_required"] = serde_json::Value::Bool(true);
        let payload = canonical_payload(&serde_json::json!([local]));
        let envelope = envelope_for(&payload);
        let error = load_catalog_from_snapshot(&envelope).unwrap_err();
        assert!(
            error
                .message()
                .contains("LOCAL route cannot require a grant")
        );
    }

    #[test]
    fn refuses_an_unknown_execution_class() {
        let payload = canonical_payload(&serde_json::json!([descriptor(
            "weird.capability",
            "SIDEWAYS",
            "LOCAL"
        ),]));
        let envelope = envelope_for(&payload);
        let error = load_catalog_from_snapshot(&envelope).unwrap_err();
        assert!(
            error.message().contains("invalid execution_class"),
            "{error}"
        );
    }

    #[test]
    fn refuses_a_descriptor_without_an_adapter() {
        let mut bare = descriptor("no.adapter", "READ", "DIRECT");
        bare["adapter_id"] = serde_json::Value::String(String::new());
        let payload = canonical_payload(&serde_json::json!([bare]));
        let envelope = envelope_for(&payload);
        let error = load_catalog_from_snapshot(&envelope).unwrap_err();
        assert!(
            error.message().contains("adapter_id is required"),
            "{error}"
        );
    }

    #[test]
    fn base64_shape_rules() {
        assert!(is_standard_base64("AAAA"));
        assert!(is_standard_base64("AAA="));
        assert!(is_standard_base64("AA=="));
        assert!(!is_standard_base64("AAA"));
        assert!(!is_standard_base64("A==="));
        assert!(!is_standard_base64(""));
        assert!(!is_standard_base64("A*AA"));
    }

    #[test]
    fn constant_time_comparison_matches_equality() {
        assert!(constant_time_equal_hex("abcd", "abcd"));
        assert!(!constant_time_equal_hex("abcd", "abce"));
        assert!(!constant_time_equal_hex("abcd", "abcde"));
    }
}
