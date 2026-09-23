package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
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

	// FailureCapabilityUnavailable means the capability is registered
	// but no adapter is wired to handle it.
	FailureCapabilityUnavailable FailureCode = "CAPABILITY_UNAVAILABLE"

	// FailureReasonAdapterNotConfigured is the machine-readable reason
	// carried in the error text when a known, registered capability's
	// adapter is not configured in this deployment. The failure code
	// stays CAPABILITY_UNAVAILABLE — the capability exists, this runtime
	// simply cannot currently execute it. It must never be reported as
	// CAPABILITY_NOT_FOUND, which means the software/policy definition
	// does not recognize the capability at all.
	FailureReasonAdapterNotConfigured = "ADAPTER_NOT_CONFIGURED"

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
	Descriptor ResolvedDescriptor `json:"descriptor"`
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
// On success it returns the resolved grant so the caller can bind the
// exact immutable authority material (generation + digest) into the
// execution identity. A nil grant is returned when no grant is
// required or when authorization fails.
func (r *Registry) VerifyAuthority(ctx context.Context, req AdmissionRequest, resolver GrantResolver) (*Grant, FailureCode, string) {
	if req.Principal == "" {
		return nil, FailureUnauthorized, "missing principal"
	}

	desc, ok := r.Lookup(req.Capability)
	if !ok {
		return nil, FailureCapabilityNotFound, fmt.Sprintf("capability not registered: %s", req.Capability)
	}

	if !desc.AuthorityPolicy.GrantRequired {
		return nil, "", ""
	}

	if req.GrantID == "" {
		return nil, FailureUnauthorized, "missing grant_id"
	}

	if resolver == nil {
		// No resolver configured — fail closed for grant-required capabilities
		return nil, FailureUnauthorized, "no grant resolver configured"
	}

	grant, err := resolver.Resolve(ctx, req.GrantID, req.Principal)
	if err != nil {
		return nil, FailureUnauthorized, fmt.Sprintf("grant resolution failed: %v", err)
	}

	if grant == nil {
		return nil, FailureUnauthorized, fmt.Sprintf("grant not found or not issued to principal: %s", req.GrantID)
	}

	// Expiry is evaluated by the resolver's own clock when it declares
	// ExpiryIsAuthoritative (the PostgreSQL/SQLite authority stores
	// filter on the database clock inside Resolve) — the application
	// clock must not veto a grant the authority store's clock considers
	// valid. Resolvers without a database clock keep the app-time
	// expiry check here.
	dbOwnedExpiry := false
	if ar, ok := resolver.(interface{ ExpiryIsAuthoritative() bool }); ok {
		dbOwnedExpiry = ar.ExpiryIsAuthoritative()
	}
	if grant.Revoked || !grant.HasCapability(req.Capability) || (!dbOwnedExpiry && grant.Expired(time.Now())) {
		return nil, FailureUnauthorized, fmt.Sprintf("grant %s does not permit capability %s (expired, revoked, or not authorized)", req.GrantID, req.Capability)
	}

	// Resource scope: for every constraint dimension the capability
	// binds to an argument, the grant must admit the argument's value.
	// A grant without that dimension is unconstrained (admits any
	// value) — capability scope alone is deliberately not least
	// privilege, so least-privilege deployments issue constrained
	// grants.
	if len(desc.AuthorityPolicy.ResourceArguments) > 0 {
		if fc, reason := checkResourceConstraints(desc, req.Arguments, grant); fc != "" {
			return nil, fc, reason
		}
	}

	return grant, "", ""
}

// checkResourceConstraints evaluates the grant's resource constraints
// against the request arguments. Every dimension the descriptor binds
// must extract to a string argument the grant admits; anything else —
// missing argument, non-string value, disallowed value — denies.
func checkResourceConstraints(desc ResolvedDescriptor, raw json.RawMessage, grant *Grant) (FailureCode, string) {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return FailureInvalidRequest, fmt.Sprintf("cannot evaluate resource constraints: arguments are not a JSON object: %v", err)
	}
	dimensions := make([]string, 0, len(desc.AuthorityPolicy.ResourceArguments))
	for dimension := range desc.AuthorityPolicy.ResourceArguments {
		dimensions = append(dimensions, dimension)
	}
	sort.Strings(dimensions)
	for _, dimension := range dimensions {
		argName := desc.AuthorityPolicy.ResourceArguments[dimension]
		field, ok := args[argName]
		if !ok {
			return FailureUnauthorized, fmt.Sprintf("grant %s cannot be evaluated: resource argument %q (dimension %q) is missing", grant.ID, argName, dimension)
		}
		var value string
		if err := json.Unmarshal(field, &value); err != nil {
			return FailureUnauthorized, fmt.Sprintf("grant %s cannot be evaluated: resource argument %q (dimension %q) is not a string", grant.ID, argName, dimension)
		}
		if !grant.AllowsResource(dimension, value) {
			return FailureUnauthorized, fmt.Sprintf("grant %s does not permit %s %q", grant.ID, dimension, value)
		}
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
			FailureCode: FailureCapabilityUnavailable,
			Reason:      fmt.Sprintf("capability has no adapter: %s", req.Capability),
		}
	}

	// Verify caller's execution class assertion (optional, advisory).
	// If present, it must match the registry's pinned class.
	// If absent, the registry's pinned class is used (planner-agnostic).
	// This is a defense-in-depth check — the registry is authoritative.
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
