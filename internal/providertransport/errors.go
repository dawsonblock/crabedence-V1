package providertransport

import (
	"errors"
	"fmt"
)

// ErrUntrustedOrigin marks every destination-policy refusal — the
// request wanted to go somewhere the trusted origin does not name.
var ErrUntrustedOrigin = errors.New("providertransport: untrusted origin")

// PolicyError is a refusal made before any network I/O: destination
// policy, request limits, DLP, or request shape. It is a definite
// no-effect — the milestone is MilestonePolicyRefused and no byte
// reached the provider — so the caller may classify it FAILED, never
// UNKNOWN.
type PolicyError struct {
	Reason string
	Cause  AmbiguityCause
	// DLP marks the refusal as an outbound-DLP decision.
	DLP bool
	// ApprovalNeeded marks a DLP REQUIRE_APPROVAL decision — refused,
	// but because approval is pending rather than because the payload
	// violated policy.
	ApprovalNeeded bool
}

// Error implements error.
func (e *PolicyError) Error() string { return "providertransport: " + e.Reason }

// DispatchError is a transport failure after policy passed. Trace
// carries the furthest dispatch milestone — below
// MilestoneRequestWritten the failure is still a definite no-effect
// (connection refused, DNS failure, TLS failure all happen before the
// request exists on the wire); at or above it the outcome is
// ambiguous and must be reconciled as UNKNOWN.
type DispatchError struct {
	Cause AmbiguityCause
	Err   error
	Trace DispatchTrace
}

// Error implements error.
func (e *DispatchError) Error() string {
	return fmt.Sprintf("providertransport: %s (milestone=%s): %v", e.Cause, e.Trace.Milestone, e.Err)
}

// Unwrap exposes the underlying failure.
func (e *DispatchError) Unwrap() error { return e.Err }

// NoEffectProof reports whether err proves the provider never saw the
// request. The proof is cause-based, not milestone-based: only error
// classes that are inherently pre-request — DNS failure, connection
// refused, TLS handshake failure — can claim no request existed.
// Anything else stays ambiguous even when the trace shows no write
// milestone, because a write can partially succeed without firing the
// milestone and an injected failure can arrive with no milestones at
// all. True means the caller may record a definite no-effect; false
// means the outcome is ambiguous and must go UNKNOWN.
func NoEffectProof(err error) bool {
	var pe *PolicyError
	if errors.As(err, &pe) {
		return true
	}
	var de *DispatchError
	if errors.As(err, &de) {
		return de.Cause == CauseProviderTransportFailure
	}
	return false
}

// AmbiguityOf extracts the classified cause from a dispatch failure
// for the ambiguity-provenance contract; empty for non-dispatch
// errors.
func AmbiguityOf(err error) AmbiguityCause {
	var de *DispatchError
	if errors.As(err, &de) {
		return de.Cause
	}
	var pe *PolicyError
	if errors.As(err, &pe) {
		return pe.Cause
	}
	return ""
}

// TraceOf extracts the dispatch trace from any transport error.
func TraceOf(err error) DispatchTrace {
	var de *DispatchError
	if errors.As(err, &de) {
		return de.Trace
	}
	var pe *PolicyError
	if errors.As(err, &pe) {
		return DispatchTrace{Milestone: MilestonePolicyRefused, Cause: pe.Cause}
	}
	return DispatchTrace{}
}
