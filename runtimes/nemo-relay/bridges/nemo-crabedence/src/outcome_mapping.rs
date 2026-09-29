// SPDX-License-Identifier: Apache-2.0

//! Crabedence wire outcomes mapped onto NeMo Relay's execution contracts.
//!
//! The durable execution contract's certainty model is preserved exactly. The
//! mapping is driven by the *dispatch boundary*, never by a status string
//! alone:
//!
//! | Crabedence outcome | NeMo Relay result |
//! | --- | --- |
//! | `SUCCEEDED` with valid evidence | confirmed success |
//! | `SUCCEEDED` for a CRITICAL capability without valid evidence | `UNKNOWN` |
//! | `FAILED` with `definitive_failure: true` | definitive failure, safe to retry |
//! | `FAILED` without `definitive_failure` | `UNKNOWN` — never retried |
//! | `DENIED` | definitive failure, not retryable |
//! | `UNKNOWN`, `IN_FLIGHT` | `UNKNOWN` — never retried |
//! | transport failure before the frame is transmitted | definitive failure, safe to retry |
//! | transport failure after transmission | `UNKNOWN` — never retried |
//!
//! # Why `FAILED` is not always a failure
//!
//! The kernel's own post-dispatch decision table
//! (`classifyPostDispatch` in `internal/execution/dispatch.go`) maps
//! `FAILED + DefinitiveFailure` to a durable `FAILED` and bare `FAILED` to
//! `UNKNOWN`. A planner that reads only the status string would claim more
//! certainty than the kernel itself does — the exact failure mode the contract
//! exists to prevent — so the bridge requires the flag before it reports a
//! definitive failure.
//!
//! The NEMO TypeScript compatibility layer predates this rule and maps bare
//! `FAILED` to `FAILED`. The bridge deliberately does not mirror that
//! behavior; the divergence is recorded here so the two are not reconciled in
//! the wrong direction.
//!
//! # Why the class does not drive the mapping
//!
//! The TypeScript adapter converts an ambiguous transport failure into
//! `UNKNOWN` only for `MUTATION`/`CRITICAL`, because its outcome type has no
//! way to say "transmitted, outcome unknown" for a read. NeMo Relay's
//! [`EffectExecutionError`] carries [`DispatchState`] and
//! [`OutcomeCertainty`] explicitly, so the bridge reports the honest
//! classification for every class and lets the kernel make the
//! class-appropriate call. That is strictly more information, not a weaker
//! guarantee.

use nemo_relay_executor::unstable::{
    DispatchState, EffectExecutionError, ExecutionResult, OutcomeCertainty,
};
use serde_json::Value as Json;

use crate::transport::{TransportError, TransportErrorKind};

/// The wire status of one execution response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireStatus {
    /// The effect committed.
    Succeeded,
    /// The invocation failed.
    Failed,
    /// Admission refused the invocation.
    Denied,
    /// The outcome cannot be proven.
    Unknown,
    /// The invocation is still in progress at the kernel.
    InFlight,
}

impl WireStatus {
    /// Parses a wire status, returning `None` for an unknown value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "SUCCEEDED" => Some(Self::Succeeded),
            "FAILED" => Some(Self::Failed),
            "DENIED" => Some(Self::Denied),
            "UNKNOWN" => Some(Self::Unknown),
            "IN_FLIGHT" => Some(Self::InFlight),
            _ => None,
        }
    }

    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Denied => "DENIED",
            Self::Unknown => "UNKNOWN",
            Self::InFlight => "IN_FLIGHT",
        }
    }
}

/// One classified execution response.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionOutcome {
    /// The wire status.
    pub status: WireStatus,
    /// Structured result payload, when the service returned one.
    pub result: Option<Json>,
    /// Human-readable error detail.
    pub error: Option<String>,
    /// Machine-readable failure code.
    pub failure_code: Option<String>,
    /// Evidence digest (`SHA-256` hex) when evidence exists.
    pub evidence_digest: Option<String>,
    /// Evidence receipt version.
    pub receipt_version: Option<u64>,
    /// Provider identity, when the service reported one.
    pub provider: Option<String>,
    /// Provider run identifier, when the service reported one.
    pub run_id: Option<String>,
    /// Whether a `FAILED` response asserts that no effect occurred.
    pub definitive_failure: bool,
}

/// Parses and validates one execution response.
///
/// The response shape is validated here rather than trusted, mirroring the
/// TypeScript adapter's wire validation: a malformed peer cannot inject an
/// arbitrary status, a non-string error, or an evidence digest that is not a
/// digest. A violation is a protocol failure, and because the request was
/// transmitted the resulting classification is ambiguous.
pub fn parse_outcome(response: &Json) -> Result<ExecutionOutcome, EffectExecutionError> {
    let object = response
        .as_object()
        .ok_or_else(|| protocol_violation("response is not an object"))?;
    let status = object
        .get("status")
        .and_then(Json::as_str)
        .and_then(WireStatus::parse)
        .ok_or_else(|| {
            protocol_violation(&format!(
                "invalid wire status {}",
                object
                    .get("status")
                    .map_or_else(|| "null".to_string(), Json::to_string)
            ))
        })?;

    let error = optional_string(object, "error")?;
    let failure_code = optional_string(object, "failure_code")?;
    let definitive_failure = match object.get("definitive_failure") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| protocol_violation("response.definitive_failure must be a boolean"))?,
    };

    let (evidence_digest, receipt_version) = match object.get("evidence") {
        None => (None, None),
        Some(value) => {
            let evidence = value
                .as_object()
                .ok_or_else(|| protocol_violation("response.evidence must be an object"))?;
            let digest = evidence
                .get("digest")
                .and_then(Json::as_str)
                .filter(|digest| is_valid_evidence_digest(digest))
                .ok_or_else(|| {
                    protocol_violation("response.evidence.digest must be a 64-character hex string")
                })?
                .to_string();
            let receipt_version = match evidence.get("receipt_version") {
                None => None,
                Some(value) => Some(value.as_u64().ok_or_else(|| {
                    protocol_violation("response.evidence.receipt_version must be an integer")
                })?),
            };
            (Some(digest), receipt_version)
        }
    };

    let (provider, run_id) = match object.get("execution") {
        None => (None, None),
        Some(value) => {
            let execution = value
                .as_object()
                .ok_or_else(|| protocol_violation("response.execution must be an object"))?;
            let provider = execution
                .get("provider")
                .and_then(Json::as_str)
                .ok_or_else(|| {
                    protocol_violation("response.execution must have provider and run_id strings")
                })?
                .to_string();
            let run_id = execution
                .get("run_id")
                .and_then(Json::as_str)
                .ok_or_else(|| {
                    protocol_violation("response.execution must have provider and run_id strings")
                })?
                .to_string();
            (Some(provider), Some(run_id))
        }
    };

    Ok(ExecutionOutcome {
        status,
        result: object.get("result").cloned(),
        error,
        failure_code,
        evidence_digest,
        receipt_version,
        provider,
        run_id,
        definitive_failure,
    })
}

/// Maps a classified outcome onto NeMo Relay's execution contracts.
///
/// `requires_evidence` is true for CRITICAL capabilities, which must not be
/// reported as committed without valid completion evidence. The kernel already
/// enforces this before it answers, so the check here is defense in depth
/// against a response that was rewritten in transit.
pub fn map_outcome(
    outcome: &ExecutionOutcome,
    requires_evidence: bool,
) -> Result<ExecutionResult, EffectExecutionError> {
    match outcome.status {
        WireStatus::Succeeded => {
            if requires_evidence && let Some(reason) = missing_evidence_reason(outcome) {
                return Err(unknown(&reason, outcome, DispatchState::DispatchConfirmed));
            }
            Ok(ExecutionResult {
                output: outcome.result.clone().unwrap_or(Json::Null),
                outcome_certainty: OutcomeCertainty::ConfirmedSuccess,
                receipt_digest: outcome.evidence_digest.clone(),
                receipt: None,
            })
        }
        WireStatus::Failed => {
            if outcome.definitive_failure {
                Err(EffectExecutionError {
                    code: outcome
                        .failure_code
                        .clone()
                        .unwrap_or_else(|| "EXECUTION_FAILED".to_string()),
                    dispatch_state: DispatchState::NotDispatched,
                    outcome_certainty: OutcomeCertainty::ConfirmedFailure,
                    provider_request_id: outcome.run_id.clone(),
                    retryable: true,
                    reconciliation_required: false,
                    message: outcome
                        .error
                        .clone()
                        .unwrap_or_else(|| "execution failed definitively".to_string()),
                })
            } else {
                Err(unknown(
                    "FAILED without definitive_failure is a post-dispatch ambiguity — the kernel cannot prove no effect occurred",
                    outcome,
                    DispatchState::DispatchAttempted,
                ))
            }
        }
        WireStatus::Denied => Err(EffectExecutionError {
            code: outcome
                .failure_code
                .clone()
                .unwrap_or_else(|| "ADMISSION_DENIED".to_string()),
            dispatch_state: DispatchState::NotDispatched,
            outcome_certainty: OutcomeCertainty::ConfirmedFailure,
            provider_request_id: outcome.run_id.clone(),
            retryable: false,
            reconciliation_required: false,
            message: outcome
                .error
                .clone()
                .unwrap_or_else(|| "admission denied".to_string()),
        }),
        WireStatus::Unknown | WireStatus::InFlight => Err(unknown(
            if outcome.status == WireStatus::InFlight {
                "the invocation is still in progress at the execution kernel; IN_FLIGHT is not a terminal outcome for the caller"
            } else {
                "the execution outcome cannot be proven; reconcile before retrying"
            },
            outcome,
            DispatchState::DispatchAttempted,
        )),
    }
}

/// Builds a locally refused request: nothing was dispatched and nothing can
/// have occurred, so the refusal is definitive and not retryable.
///
/// Shared by every component that refuses before the socket, so a refusal
/// reads the same way wherever it originates.
pub fn refused_request(code: &str, message: String) -> EffectExecutionError {
    EffectExecutionError {
        code: code.to_string(),
        dispatch_state: DispatchState::NotDispatched,
        outcome_certainty: OutcomeCertainty::ConfirmedFailure,
        provider_request_id: None,
        retryable: false,
        reconciliation_required: false,
        message,
    }
}

/// Maps a transport failure onto NeMo Relay's execution error contract.
///
/// The classification is the dispatch boundary: a pre-dispatch failure is a
/// definitive failure that is safe to retry, and anything after transmission is
/// ambiguous.
pub fn map_transport_failure(error: &TransportError) -> EffectExecutionError {
    match error.kind() {
        TransportErrorKind::PreDispatch => EffectExecutionError {
            code: "TRANSPORT_PRE_DISPATCH".to_string(),
            dispatch_state: DispatchState::NotDispatched,
            outcome_certainty: OutcomeCertainty::ConfirmedFailure,
            provider_request_id: None,
            retryable: true,
            reconciliation_required: false,
            message: error.message().to_string(),
        },
        TransportErrorKind::PostDispatch | TransportErrorKind::Protocol => EffectExecutionError {
            code: "EXECUTION_UNKNOWN".to_string(),
            dispatch_state: DispatchState::DispatchAttempted,
            outcome_certainty: OutcomeCertainty::Unknown,
            provider_request_id: None,
            retryable: false,
            reconciliation_required: true,
            message: error.message().to_string(),
        },
    }
}

/// Reports why a CRITICAL success cannot be trusted, mirroring the kernel's
/// post-dispatch evidence contract.
fn missing_evidence_reason(outcome: &ExecutionOutcome) -> Option<String> {
    if outcome.evidence_digest.is_none() {
        return Some(
            "CRITICAL capability returned SUCCEEDED without evidence digest (post-dispatch uncertainty)"
                .to_string(),
        );
    }
    if outcome.receipt_version != Some(3) {
        return Some(format!(
            "CRITICAL capability returned receipt_version {} (must be 3, post-dispatch uncertainty)",
            outcome
                .receipt_version
                .map_or_else(|| "absent".to_string(), |version| version.to_string())
        ));
    }
    if outcome.run_id.is_none() {
        return Some(
            "CRITICAL capability returned SUCCEEDED without run_id (post-dispatch uncertainty)"
                .to_string(),
        );
    }
    None
}

fn unknown(
    reason: &str,
    outcome: &ExecutionOutcome,
    dispatch_state: DispatchState,
) -> EffectExecutionError {
    let detail = outcome
        .error
        .as_deref()
        .map_or_else(|| reason.to_string(), |error| format!("{reason}: {error}"));
    EffectExecutionError {
        code: "EXECUTION_UNKNOWN".to_string(),
        dispatch_state,
        outcome_certainty: OutcomeCertainty::Unknown,
        provider_request_id: outcome.run_id.clone(),
        retryable: false,
        reconciliation_required: true,
        message: detail,
    }
}

/// A response-shape violation. The request was transmitted, so the outcome is
/// as ambiguous as any other post-dispatch failure.
fn protocol_violation(reason: &str) -> EffectExecutionError {
    EffectExecutionError {
        code: "EXECUTION_UNKNOWN".to_string(),
        dispatch_state: DispatchState::DispatchAttempted,
        outcome_certainty: OutcomeCertainty::Unknown,
        provider_request_id: None,
        retryable: false,
        reconciliation_required: true,
        message: format!("response violated the capability invocation ABI: {reason}"),
    }
}

fn optional_string(
    object: &serde_json::Map<String, Json>,
    field: &str,
) -> Result<Option<String>, EffectExecutionError> {
    match object.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_string()))
            .ok_or_else(|| protocol_violation(&format!("response.{field} must be a string"))),
    }
}

fn is_valid_evidence_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemo_relay_executor::unstable::state_for_error;
    use nemo_relay_ledger::unstable::ExecutionState;

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn outcome(status: WireStatus) -> ExecutionOutcome {
        ExecutionOutcome {
            status,
            result: None,
            error: None,
            failure_code: None,
            evidence_digest: None,
            receipt_version: None,
            provider: None,
            run_id: None,
            definitive_failure: false,
        }
    }

    #[test]
    fn succeeded_maps_to_confirmed_success() {
        let mut outcome = outcome(WireStatus::Succeeded);
        outcome.result = Some(serde_json::json!({ "echoed": true }));
        let result = map_outcome(&outcome, false).expect("success");
        assert_eq!(result.outcome_certainty, OutcomeCertainty::ConfirmedSuccess);
        assert_eq!(result.output["echoed"], true);
    }

    #[test]
    fn critical_success_without_evidence_is_unknown() {
        let outcome = outcome(WireStatus::Succeeded);
        let error = map_outcome(&outcome, true).unwrap_err();
        assert_eq!(error.outcome_certainty, OutcomeCertainty::Unknown);
        assert_eq!(state_for_error(&error), ExecutionState::Unknown);
    }

    #[test]
    fn critical_success_with_evidence_is_committed() {
        let mut outcome = outcome(WireStatus::Succeeded);
        outcome.evidence_digest = Some(DIGEST.to_string());
        outcome.receipt_version = Some(3);
        outcome.run_id = Some("run-1".to_string());
        let result = map_outcome(&outcome, true).expect("success");
        assert_eq!(result.receipt_digest.as_deref(), Some(DIGEST));
    }

    #[test]
    fn definitive_failure_is_failed_and_retryable() {
        let mut outcome = outcome(WireStatus::Failed);
        outcome.definitive_failure = true;
        outcome.failure_code = Some("EXECUTION_FAILED".to_string());
        let error = map_outcome(&outcome, false).unwrap_err();
        assert_eq!(error.code, "EXECUTION_FAILED");
        assert!(error.retryable);
        assert!(!error.reconciliation_required);
        assert_eq!(state_for_error(&error), ExecutionState::Failed);
    }

    #[test]
    fn bare_failure_is_unknown_and_never_retried() {
        let outcome = outcome(WireStatus::Failed);
        let error = map_outcome(&outcome, false).unwrap_err();
        assert_eq!(error.code, "EXECUTION_UNKNOWN");
        assert!(!error.retryable);
        assert!(error.reconciliation_required);
        assert_eq!(state_for_error(&error), ExecutionState::Unknown);
    }

    #[test]
    fn denied_is_definitive_and_not_retryable() {
        let mut outcome = outcome(WireStatus::Denied);
        outcome.failure_code = Some("UNAUTHORIZED".to_string());
        let error = map_outcome(&outcome, false).unwrap_err();
        assert_eq!(error.code, "UNAUTHORIZED");
        assert!(!error.retryable);
        assert!(!error.reconciliation_required);
        assert_eq!(state_for_error(&error), ExecutionState::Failed);
    }

    #[test]
    fn in_flight_is_unknown_at_the_client_boundary() {
        let error = map_outcome(&outcome(WireStatus::InFlight), false).unwrap_err();
        assert_eq!(error.code, "EXECUTION_UNKNOWN");
        assert_eq!(state_for_error(&error), ExecutionState::Unknown);
    }

    #[test]
    fn pre_dispatch_transport_failure_is_retryable() {
        let transport = TransportError::new(TransportErrorKind::PreDispatch, "connection refused");
        let error = map_transport_failure(&transport);
        assert!(error.retryable);
        assert!(!error.reconciliation_required);
        assert_eq!(state_for_error(&error), ExecutionState::Failed);
    }

    #[test]
    fn post_dispatch_transport_failure_is_unknown() {
        for kind in [
            TransportErrorKind::PostDispatch,
            TransportErrorKind::Protocol,
        ] {
            let transport = TransportError::new(kind, "no response received");
            let error = map_transport_failure(&transport);
            assert!(!error.retryable, "{kind}");
            assert!(error.reconciliation_required, "{kind}");
            assert_eq!(state_for_error(&error), ExecutionState::Unknown, "{kind}");
        }
    }

    #[test]
    fn parses_a_full_response() {
        let response = serde_json::json!({
            "status": "SUCCEEDED",
            "result": { "ok": true },
            "evidence": { "digest": DIGEST, "receipt_version": 3 },
            "execution": { "provider": "counter", "run_id": "run-9" }
        });
        let outcome = parse_outcome(&response).expect("parsed");
        assert_eq!(outcome.status, WireStatus::Succeeded);
        assert_eq!(outcome.evidence_digest.as_deref(), Some(DIGEST));
        assert_eq!(outcome.receipt_version, Some(3));
        assert_eq!(outcome.run_id.as_deref(), Some("run-9"));
    }

    #[test]
    fn refuses_a_malformed_evidence_digest() {
        let response = serde_json::json!({
            "status": "SUCCEEDED",
            "evidence": { "digest": "not-a-digest" }
        });
        let error = parse_outcome(&response).unwrap_err();
        assert_eq!(state_for_error(&error), ExecutionState::Unknown);
    }

    #[test]
    fn refuses_an_unknown_status() {
        let response = serde_json::json!({ "status": "MAYBE" });
        let error = parse_outcome(&response).unwrap_err();
        assert!(error.message.contains("invalid wire status"), "{error}");
    }

    #[test]
    fn refuses_a_non_string_error_field() {
        let response = serde_json::json!({ "status": "FAILED", "error": 7 });
        let error = parse_outcome(&response).unwrap_err();
        assert!(error.message.contains("must be a string"), "{error}");
    }
}
