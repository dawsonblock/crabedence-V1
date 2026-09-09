// Package capability defines the authoritative capability registry for
// the Crabedence execution service.
//
// The registry is the single source of truth for:
//   - Execution class (PURE, READ, MUTATION, CRITICAL)
//   - Argument schema (JSON Schema)
//   - Authority policy
//   - Adapter/provider binding
//
// Callers (including NeMo) cannot override these values. The caller's
// execution_class field is treated as an assertion at most — the
// registry's pinned class is authoritative.
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

// AuthorityPolicy defines how authority is verified for a capability.
type AuthorityPolicy struct {
	// ID is the policy identifier (e.g. "gmail.send").
	ID string `json:"id"`

	// GrantRequired is true if a grant_id is required.
	GrantRequired bool `json:"grant_required"`
}

// Descriptor describes a registered capability. This is the server-side
// authoritative definition — callers cannot override these values.
type Descriptor struct {
	// ID is the unique capability identifier (e.g. "email.send").
	ID string `json:"id"`

	// ExecutionClass is the pinned risk classification.
	ExecutionClass ExecutionClass `json:"execution_class"`

	// Schema is the JSON Schema for argument validation.
	Schema json.RawMessage `json:"schema,omitempty"`

	// AuthorityPolicy defines how authority is verified.
	AuthorityPolicy AuthorityPolicy `json:"authority_policy"`

	// AdapterID identifies the provider adapter that handles this capability.
	AdapterID string `json:"adapter_id"`
}

// Registry is the server-controlled capability catalog.
// It is thread-safe and immutable after registration.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]Descriptor
}

// NewRegistry creates an empty capability registry.
func NewRegistry() *Registry {
	return &Registry{
		entries: make(map[string]Descriptor),
	}
}

// Register adds a capability to the registry.
// Returns an error if the capability is already registered or if the
// descriptor is invalid.
func (r *Registry) Register(d Descriptor) error {
	if d.ID == "" {
		return fmt.Errorf("capability ID is required")
	}
	if !d.ExecutionClass.Valid() {
		return fmt.Errorf("invalid execution class: %s", d.ExecutionClass)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[d.ID]; exists {
		return fmt.Errorf("capability already registered: %s", d.ID)
	}

	r.entries[d.ID] = d
	return nil
}

// Lookup retrieves a capability descriptor by ID.
// Returns the descriptor and true if found, or zero value and false.
func (r *Registry) Lookup(id string) (Descriptor, bool) {
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
