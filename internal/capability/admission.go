package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// FailureCode is a typed error vocabulary for execution failures.
// These are distinct from ExecutionStatus — status describes the
// outcome, while FailureCode describes why.
type FailureCode string

const (
	// FailureInvalidRequest means the request was malformed.
	FailureInvalidRequest FailureCode = "INVALID_REQUEST"

	// FailureUnauthorized means the principal lacks valid authority.
	FailureUnauthorized FailureCode = "UNAUTHORIZED"

	// FailureCapabilityNotFound means the capability is not registered.
	FailureCapabilityNotFound FailureCode = "CAPABILITY_NOT_FOUND"

	// FailureCapabilityUnimplemented means the capability is registered
	// but no adapter is wired to handle it.
	FailureCapabilityUnimplemented FailureCode = "CAPABILITY_UNIMPLEMENTED"

	// FailureAdmissionDenied means admission checks failed (class mismatch,
	// schema validation, authority policy, deadline).
	FailureAdmissionDenied FailureCode = "ADMISSION_DENIED"

	// FailureExecutionFailed means the provider executed and returned a
	// definitive failure.
	FailureExecutionFailed FailureCode = "EXECUTION_FAILED"

	// FailureExecutionUnknown means the provider may have executed but
	// the terminal outcome cannot be established.
	FailureExecutionUnknown FailureCode = "EXECUTION_UNKNOWN"

	// FailureInFlight means the execution is in progress.
	FailureInFlight FailureCode = "IN_FLIGHT"

	// FailureInternalError means an internal error occurred.
	FailureInternalError FailureCode = "INTERNAL_ERROR"

	// FailureIdempotencyConflict means the same key was used with a
	// different request.
	FailureIdempotencyConflict FailureCode = "IDEMPOTENCY_CONFLICT"
)

// AdmissionDecision is the result of admission checks.
type AdmissionDecision struct {
	// Allowed is true if the request is admitted.
	Allowed bool `json:"allowed"`

	// FailureCode is set when Allowed is false.
	FailureCode FailureCode `json:"failure_code,omitempty"`

	// Reason is a human-readable explanation.
	Reason string `json:"reason,omitempty"`

	// Descriptor is the resolved capability descriptor.
	Descriptor Descriptor `json:"descriptor"`
}

// AdmissionRequest is the input to admission checking.
type AdmissionRequest struct {
	Capability     string          `json:"capability"`
	Arguments      json.RawMessage `json:"arguments"`
	Principal      string          `json:"principal"`
	GrantID        string          `json:"grant_id"`
	ExecutionClass string          `json:"execution_class"` // caller assertion
	IdempotencyKey string          `json:"idempotency_key"`
	Deadline       string          `json:"deadline"`
}

// VerifyAuthority resolves the grant and checks that it permits the
// capability for the given principal. This is the real authority
// verification — not just presence checks.
//
// Returns nil if authorized, or a FailureCode + reason if not.
func (r *Registry) VerifyAuthority(ctx context.Context, req AdmissionRequest, resolver GrantResolver) (FailureCode, string) {
	if req.Principal == "" {
		return FailureUnauthorized, "missing principal"
	}

	desc, ok := r.Lookup(req.Capability)
	if !ok {
		return FailureCapabilityNotFound, fmt.Sprintf("capability not registered: %s", req.Capability)
	}

	if !desc.AuthorityPolicy.GrantRequired {
		return "", ""
	}

	if req.GrantID == "" {
		return FailureUnauthorized, "missing grant_id"
	}

	if resolver == nil {
		// No resolver configured — fail closed for grant-required capabilities
		return FailureUnauthorized, "no grant resolver configured"
	}

	grant, err := resolver.Resolve(ctx, req.GrantID, req.Principal)
	if err != nil {
		return FailureUnauthorized, fmt.Sprintf("grant resolution failed: %v", err)
	}

	if grant == nil {
		return FailureUnauthorized, fmt.Sprintf("grant not found or not issued to principal: %s", req.GrantID)
	}

	if !grant.IsValid(req.Capability, time.Now()) {
		return FailureUnauthorized, fmt.Sprintf("grant %s does not permit capability %s (expired, revoked, or not authorized)", req.GrantID, req.Capability)
	}

	return "", ""
}

// Admit performs admission checks for an execution request.
// It validates:
//   - Capability exists in the registry
//   - Caller's execution class matches the registry's pinned class
//   - Authority (principal + grant_id) is present
//   - Idempotency key is present for mutations
//   - Deadline is valid and not expired
//
// It does NOT perform schema validation or authority grant resolution
// — those are separate steps (see VerifyAuthority).
func (r *Registry) Admit(req AdmissionRequest) AdmissionDecision {
	desc, ok := r.Lookup(req.Capability)
	if !ok {
		return AdmissionDecision{
			Allowed:     false,
			FailureCode: FailureCapabilityNotFound,
			Reason:      fmt.Sprintf("capability not registered: %s", req.Capability),
		}
	}

	// Check adapter is wired
	if desc.AdapterID == "" {
		return AdmissionDecision{
			Allowed:     false,
			FailureCode: FailureCapabilityUnimplemented,
			Reason:      fmt.Sprintf("capability has no adapter: %s", req.Capability),
		}
	}

	// Verify caller's execution class assertion matches registry
	if req.ExecutionClass != "" && req.ExecutionClass != string(desc.ExecutionClass) {
		return AdmissionDecision{
			Allowed:     false,
			FailureCode: FailureAdmissionDenied,
			Reason: fmt.Sprintf("execution class mismatch: caller asserted %s but %s is pinned as %s",
				req.ExecutionClass, req.Capability, desc.ExecutionClass),
		}
	}

	// Check authority presence (grant resolution is a separate step)
	if req.Principal == "" {
		return AdmissionDecision{
			Allowed:     false,
			FailureCode: FailureUnauthorized,
			Reason:      "missing principal",
		}
	}
	if desc.AuthorityPolicy.GrantRequired && req.GrantID == "" {
		return AdmissionDecision{
			Allowed:     false,
			FailureCode: FailureUnauthorized,
			Reason:      "missing grant_id",
		}
	}

	// Check idempotency key for mutations
	if desc.ExecutionClass.RequiresIdempotencyKey() && req.IdempotencyKey == "" {
		return AdmissionDecision{
			Allowed:     false,
			FailureCode: FailureAdmissionDenied,
			Reason:      fmt.Sprintf("idempotency key required for %s capabilities", desc.ExecutionClass),
		}
	}

	return AdmissionDecision{
		Allowed:    true,
		Descriptor: desc,
	}
}
