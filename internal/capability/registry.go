// Package capability defines the authoritative capability registry for
// the Crabedence execution service.
//
// The registry is the single source of truth for three orthogonal
// dimensions pinned per capability:
//   - Execution class: side-effect semantics (PURE, READ, MUTATION, CRITICAL)
//   - Assurance profile: admission/durability/evidence (NONE, STANDARD, DURABLE, HIGH_ASSURANCE)
//   - Execution route: dispatch mechanism (LOCAL, DIRECT, CRABEDENCE)
//
// Plus:
//   - Argument schema (JSON Schema)
//   - Authority policy
//   - Adapter/provider binding (fixed or server-controlled policy)
//
// Dimensions are resolved and frozen at registration time. The active
// registry contains only ResolvedDescriptors — no runtime inference.
// Invalid combinations (e.g. CRITICAL/HIGH_ASSURANCE/LOCAL) are rejected
// at registration, not discovered at execution.
//
// Callers (including any planner — Hermes, NEMO, OpenAI SDK, custom)
// cannot override these values. The caller's execution_class field is
// treated as an assertion at most — the registry's pinned values are
// authoritative. The dispatch layer (Function Hooks or equivalent)
// reads the execution_route from the descriptor to decide routing.
package capability

import (
	"encoding/json"
	"fmt"
	"sync"
)

// ExecutionClass represents the risk classification of a capability.
type ExecutionClass string

const (
	ClassPure     ExecutionClass = "PURE"
	ClassRead     ExecutionClass = "READ"
	ClassMutation ExecutionClass = "MUTATION"
	ClassCritical ExecutionClass = "CRITICAL"
)

// Valid returns true if the execution class is a known value.
func (c ExecutionClass) Valid() bool {
	switch c {
	case ClassPure, ClassRead, ClassMutation, ClassCritical:
		return true
	}
	return false
}

// RequiresIdempotencyKey returns true if the class requires an idempotency key.
func (c ExecutionClass) RequiresIdempotencyKey() bool {
	return c == ClassMutation || c == ClassCritical
}

// RequiresEvidence returns true if the class requires evidence on success.
func (c ExecutionClass) RequiresEvidence() bool {
	return c == ClassCritical
}

// AssuranceProfile determines admission, durability, and evidence
// requirements. This is orthogonal to effect class — a public READ
// and a medical-records READ are both READ, but may have different
// assurance profiles.
type AssuranceProfile string

const (
	// AssuranceNone: no durability, no evidence, no idempotency.
	// Used for PURE capabilities that never cross the execution boundary.
	AssuranceNone AssuranceProfile = "NONE"

	// AssuranceStandard: admission and authority verified, but no
	// durable idempotency or evidence. Used for typical READ operations.
	AssuranceStandard AssuranceProfile = "STANDARD"

	// AssuranceDurable: PostgreSQL-backed idempotency, exactly-once
	// semantics. Used for MUTATION operations.
	AssuranceDurable AssuranceProfile = "DURABLE"

	// AssuranceHighAssurance: durable idempotency plus V3 evidence,
	// receipt signing, and reconciliation. Used for CRITICAL operations.
	AssuranceHighAssurance AssuranceProfile = "HIGH_ASSURANCE"
)

// Valid returns true if the assurance profile is a known value.
func (a AssuranceProfile) Valid() bool {
	switch a {
	case AssuranceNone, AssuranceStandard, AssuranceDurable, AssuranceHighAssurance:
		return true
	}
	return false
}

// RequiresDurableStore returns true if the profile requires PostgreSQL.
func (a AssuranceProfile) RequiresDurableStore() bool {
	return a == AssuranceDurable || a == AssuranceHighAssurance
}

// RequiresEvidence returns true if the profile requires V3 evidence.
func (a AssuranceProfile) RequiresEvidence() bool {
	return a == AssuranceHighAssurance
}

// DefaultAssuranceProfile returns the default assurance profile for
// an execution class. This is a registration-time convenience; the
// capability definition explicitly pins the resolved value.
func DefaultAssuranceProfile(c ExecutionClass) AssuranceProfile {
	switch c {
	case ClassPure:
		return AssuranceNone
	case ClassRead:
		return AssuranceStandard
	case ClassMutation:
		return AssuranceDurable
	case ClassCritical:
		return AssuranceHighAssurance
	}
	return AssuranceStandard
}

// ExecutionRoute determines which execution mechanism handles a
// capability. This is the third orthogonal dimension, independent
// of effect class and assurance profile.
//
// The route is pinned in the capability descriptor — the planner
// does not decide what is "safe." Function Hooks (or any dispatch
// layer) looks up the route and dispatches accordingly.
type ExecutionRoute string

const (
	// RouteLocal: execute in the calling process. No socket hop,
	// no durability, no admission. Used for PURE capabilities.
	RouteLocal ExecutionRoute = "LOCAL"

	// RouteDirect: execute via a direct adapter with admission but
	// without the full durable execution kernel. Used for low-risk
	// READs where the descriptor explicitly permits it.
	RouteDirect ExecutionRoute = "DIRECT"

	// RouteCrabedence: execute through the Crabedence trusted
	// execution kernel with authority, idempotency, dispatch,
	// evidence, and reconciliation. Used for sensitive READs,
	// MUTATIONs, and CRITICALs.
	RouteCrabedence ExecutionRoute = "CRABEDENCE"
)

// Valid returns true if the execution route is a known value.
func (r ExecutionRoute) Valid() bool {
	switch r {
	case RouteLocal, RouteDirect, RouteCrabedence:
		return true
	}
	return false
}

// DefaultExecutionRoute returns the default route for an assurance
// profile. This is a registration-time convenience; the capability
// definition explicitly pins the resolved value.
func DefaultExecutionRoute(p AssuranceProfile) ExecutionRoute {
	switch p {
	case AssuranceNone:
		return RouteLocal
	case AssuranceStandard:
		return RouteDirect
	case AssuranceDurable, AssuranceHighAssurance:
		return RouteCrabedence
	}
	return RouteCrabedence
}

// AuthorityPolicy defines how authority is verified for a capability.
type AuthorityPolicy struct {
	// ID is the policy identifier (e.g. "gmail.send").
	ID string `json:"id"`

	// GrantRequired is true if a grant_id is required.
	GrantRequired bool `json:"grant_required"`
}

// CapabilityDescriptor is the raw, pre-resolution capability definition.
// AssuranceProfile and ExecutionRoute may be unspecified — they are
// resolved from defaults during registration. This type is used by
// the registry's trusted catalog builder, never by the execution path.
type CapabilityDescriptor struct {
	// ID is the unique capability identifier (e.g. "email.send").
	ID string `json:"id"`

	// ExecutionClass is the effect classification.
	ExecutionClass ExecutionClass `json:"execution_class"`

	// AssuranceProfile is the admission/durability/evidence profile.
	// If empty, defaults to DefaultAssuranceProfile(ExecutionClass).
	AssuranceProfile AssuranceProfile `json:"assurance_profile,omitempty"`

	// ExecutionRoute is the dispatch route.
	// If empty, defaults to DefaultExecutionRoute(resolved AssuranceProfile).
	ExecutionRoute ExecutionRoute `json:"execution_route,omitempty"`

	// Schema is the JSON Schema for argument validation.
	Schema json.RawMessage `json:"schema,omitempty"`

	// AuthorityPolicy defines how authority is verified.
	AuthorityPolicy AuthorityPolicy `json:"authority_policy"`

	// AdapterID identifies the provider adapter that handles this capability.
	// May be a fixed adapter ID or a server-controlled adapter policy.
	AdapterID string `json:"adapter_id"`
}

// ResolvedDescriptor is the frozen, fully-resolved capability definition.
// All three dimensions are concrete. This is the only descriptor type
// that exists in the active registry or reaches the execution path.
//
// If a capability exists in the active registry, its execution
// semantics have already been completely resolved and validated.
type ResolvedDescriptor struct {
	// ID is the unique capability identifier (e.g. "email.send").
	ID string `json:"id"`

	// ExecutionClass is the pinned effect classification.
	ExecutionClass ExecutionClass `json:"execution_class"`

	// AssuranceProfile is the pinned, concrete assurance profile.
	AssuranceProfile AssuranceProfile `json:"assurance_profile"`

	// ExecutionRoute is the pinned, concrete dispatch route.
	ExecutionRoute ExecutionRoute `json:"execution_route"`

	// Schema is the JSON Schema for argument validation.
	Schema json.RawMessage `json:"schema,omitempty"`

	// AuthorityPolicy defines how authority is verified.
	AuthorityPolicy AuthorityPolicy `json:"authority_policy"`

	// AdapterID identifies the provider adapter that handles this capability.
	AdapterID string `json:"adapter_id"`
}

// Descriptor is an alias for backward compatibility with existing code.
// New code should use CapabilityDescriptor for raw definitions and
// ResolvedDescriptor for the active registry.
//
// Deprecated: Use CapabilityDescriptor for registration input and
// ResolvedDescriptor for registry lookups.
type Descriptor = CapabilityDescriptor

// ValidateDescriptorCompatibility checks that the execution route can
// satisfy the stated assurance contract. This prevents the bypass
// problem at descriptor configuration time — e.g. registering
// CRITICAL/HIGH_ASSURANCE/DIRECT is rejected because a DIRECT adapter
// cannot provide HIGH_ASSURANCE guarantees.
func ValidateDescriptorCompatibility(effect ExecutionClass, assurance AssuranceProfile, route ExecutionRoute) error {
	switch route {
	case RouteLocal:
		// LOCAL can only satisfy NONE assurance and only for PURE effects.
		if effect != ClassPure {
			return fmt.Errorf("route LOCAL requires effect PURE, got %s", effect)
		}
		if assurance != AssuranceNone {
			return fmt.Errorf("route LOCAL cannot satisfy assurance %s (requires NONE)", assurance)
		}

	case RouteDirect:
		// DIRECT can satisfy STANDARD for READ effects.
		// It cannot handle MUTATION/CRITICAL effects or DURABLE/HIGH_ASSURANCE.
		if effect == ClassMutation || effect == ClassCritical {
			return fmt.Errorf("route DIRECT cannot handle effect %s (requires CRABEDENCE)", effect)
		}
		if assurance == AssuranceDurable || assurance == AssuranceHighAssurance {
			return fmt.Errorf("route DIRECT cannot satisfy assurance %s (requires CRABEDENCE)", assurance)
		}

	case RouteCrabedence:
		// CRABEDENCE can satisfy STANDARD, DURABLE, and HIGH_ASSURANCE.
		// It can handle all effect classes.

	default:
		return fmt.Errorf("unknown execution route: %s", route)
	}
	return nil
}

// Resolve takes a raw CapabilityDescriptor, applies defaults to
// unspecified dimensions, validates compatibility, and returns a
// frozen ResolvedDescriptor. Returns an error if the combination
// is invalid.
func Resolve(d CapabilityDescriptor) (ResolvedDescriptor, error) {
	if d.ID == "" {
		return ResolvedDescriptor{}, fmt.Errorf("capability ID is required")
	}
	if !d.ExecutionClass.Valid() {
		return ResolvedDescriptor{}, fmt.Errorf("invalid execution class: %s", d.ExecutionClass)
	}

	// Resolve assurance profile from default if unspecified.
	assurance := d.AssuranceProfile
	if assurance == "" {
		assurance = DefaultAssuranceProfile(d.ExecutionClass)
	}
	if !assurance.Valid() {
		return ResolvedDescriptor{}, fmt.Errorf("invalid assurance profile: %s", assurance)
	}

	// Resolve execution route from default if unspecified.
	route := d.ExecutionRoute
	if route == "" {
		route = DefaultExecutionRoute(assurance)
	}
	if !route.Valid() {
		return ResolvedDescriptor{}, fmt.Errorf("invalid execution route: %s", route)
	}

	// Validate that the route can satisfy the assurance contract.
	if err := ValidateDescriptorCompatibility(d.ExecutionClass, assurance, route); err != nil {
		return ResolvedDescriptor{}, fmt.Errorf("capability %s: %w", d.ID, err)
	}

	return ResolvedDescriptor{
		ID:               d.ID,
		ExecutionClass:   d.ExecutionClass,
		AssuranceProfile: assurance,
		ExecutionRoute:   route,
		Schema:           d.Schema,
		AuthorityPolicy:  d.AuthorityPolicy,
		AdapterID:        d.AdapterID,
	}, nil
}

// EffectiveAssuranceProfile returns the assurance profile, defaulting
// to the standard mapping for the execution class if not set.
//
// Deprecated: Use Resolve() to get a ResolvedDescriptor with concrete values.
func (d CapabilityDescriptor) EffectiveAssuranceProfile() AssuranceProfile {
	if d.AssuranceProfile != "" && d.AssuranceProfile.Valid() {
		return d.AssuranceProfile
	}
	return DefaultAssuranceProfile(d.ExecutionClass)
}

// EffectiveExecutionRoute returns the execution route, defaulting
// to the standard mapping for the assurance profile if not set.
//
// Deprecated: Use Resolve() to get a ResolvedDescriptor with concrete values.
func (d CapabilityDescriptor) EffectiveExecutionRoute() ExecutionRoute {
	if d.ExecutionRoute != "" && d.ExecutionRoute.Valid() {
		return d.ExecutionRoute
	}
	return DefaultExecutionRoute(d.EffectiveAssuranceProfile())
}

// Registry is the server-controlled, trusted admitted capability catalog.
// It stores only ResolvedDescriptors — all dimensions are concrete and
// validated at registration time. The planner cannot register or modify
// capabilities; it can only discover them via the planner-visible catalog.
//
// Thread-safe and immutable after registration.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]ResolvedDescriptor
}

// NewRegistry creates an empty capability registry.
func NewRegistry() *Registry {
	return &Registry{
		entries: make(map[string]ResolvedDescriptor),
	}
}

// Register resolves and validates a capability descriptor, then adds
// it to the registry. Returns an error if the capability is already
// registered or if the descriptor is invalid or incompatible.
func (r *Registry) Register(d CapabilityDescriptor) error {
	resolved, err := Resolve(d)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[resolved.ID]; exists {
		return fmt.Errorf("capability already registered: %s", resolved.ID)
	}

	r.entries[resolved.ID] = resolved
	return nil
}

// RegisterResolved adds an already-resolved descriptor to the registry.
// This is for trusted catalog builders that have already validated.
func (r *Registry) RegisterResolved(d ResolvedDescriptor) error {
	if d.ID == "" {
		return fmt.Errorf("capability ID is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[d.ID]; exists {
		return fmt.Errorf("capability already registered: %s", d.ID)
	}

	r.entries[d.ID] = d
	return nil
}

// Lookup retrieves a resolved capability descriptor by ID.
// Returns the descriptor and true if found, or zero value and false.
func (r *Registry) Lookup(id string) (ResolvedDescriptor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	d, ok := r.entries[id]
	return d, ok
}

// List returns all registered capability IDs.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of registered capabilities.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}
