package capability

import (
	"sort"
)

// Runtime availability.
//
// The registry describes policy: the complete capability surface a
// release ships and recognizes. Availability describes deployment
// state: whether this runtime can currently execute a known capability.
// The two are deliberately separate (see
// docs/architecture/capability-registry-semantics.md).
//
// INV-014: provider availability cannot modify capability security
// classification. Availability is never written into a descriptor and
// never changes execution class, route, assurance, schemas, authority
// policy, descriptor digests, or the registry digest. An unavailable
// adapter fails closed at dispatch — it never becomes a routing change
// or a class downgrade.

// AvailabilityStatus is the trusted runtime availability of one
// capability's adapter.
type AvailabilityStatus string

const (
	// AvailabilityAvailable: the adapter is wired and usable.
	AvailabilityAvailable AvailabilityStatus = "AVAILABLE"

	// AvailabilityAdapterNotConfigured: the capability is known, but
	// this deployment has no adapter for it. The capability exists; it
	// is simply not executable here.
	AvailabilityAdapterNotConfigured AvailabilityStatus = "ADAPTER_NOT_CONFIGURED"

	// AvailabilityAdapterUnhealthy: the adapter is wired but not
	// currently usable (provider unreachable, health check failing).
	AvailabilityAdapterUnhealthy AvailabilityStatus = "ADAPTER_UNHEALTHY"

	// AvailabilityFeatureDisabled: the adapter is wired but disabled
	// by deployment policy.
	AvailabilityFeatureDisabled AvailabilityStatus = "FEATURE_DISABLED"
)

// Valid reports whether the status is a known value.
func (s AvailabilityStatus) Valid() bool {
	switch s {
	case AvailabilityAvailable, AvailabilityAdapterNotConfigured, AvailabilityAdapterUnhealthy, AvailabilityFeatureDisabled:
		return true
	}
	return false
}

// AdapterState is the deployment's availability view of one adapter.
type AdapterState struct {
	Status AvailabilityStatus `json:"status"`
	Reason string             `json:"reason,omitempty"`
}

// AdapterAvailability maps adapter IDs to their deployment state. An
// adapter absent from the map is ADAPTER_NOT_CONFIGURED: the deployment
// did not wire it.
type AdapterAvailability map[string]AdapterState

// CapabilityAvailability is the runtime availability of one registered
// capability. It is a derived view — never persisted into the registry
// and never part of any digest.
type CapabilityAvailability struct {
	CapabilityID string             `json:"capability_id"`
	AdapterID    string             `json:"adapter_id"`
	Status       AvailabilityStatus `json:"status"`
	Reason       string             `json:"reason,omitempty"`
}

// Available reports whether the capability is currently executable in
// this deployment.
func (a CapabilityAvailability) Available() bool {
	return a.Status == AvailabilityAvailable
}

// Availability resolves the runtime availability of every registered
// capability against this deployment's adapters, sorted by capability
// ID. It reads the registry; it never mutates it (INV-014).
func (r *Registry) Availability(adapters AdapterAvailability) []CapabilityAvailability {
	r.mu.RLock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	descriptors := make([]ResolvedDescriptor, 0, len(ids))
	for _, id := range ids {
		descriptors = append(descriptors, r.entries[id])
	}
	r.mu.RUnlock()

	entries := make([]CapabilityAvailability, 0, len(descriptors))
	for _, descriptor := range descriptors {
		entry := CapabilityAvailability{
			CapabilityID: descriptor.ID,
			AdapterID:    descriptor.AdapterID,
		}
		state, ok := adapters[descriptor.AdapterID]
		switch {
		case descriptor.AdapterID == "":
			// A missing binding is a registry defect the whole-registry
			// scan reports; availability simply cannot be positive.
			entry.Status = AvailabilityAdapterNotConfigured
			entry.Reason = "capability has no adapter binding"
		case !ok:
			entry.Status = AvailabilityAdapterNotConfigured
			entry.Reason = "adapter is not wired in this deployment"
		case !state.Status.Valid():
			entry.Status = AvailabilityAdapterUnhealthy
			entry.Reason = "adapter reported an unknown availability status"
		default:
			entry.Status = state.Status
			entry.Reason = state.Reason
		}
		entries = append(entries, entry)
	}
	return entries
}

// Unavailable returns the registered capabilities this deployment
// cannot currently execute, in ID order.
func (r *Registry) Unavailable(adapters AdapterAvailability) []CapabilityAvailability {
	var unavailable []CapabilityAvailability
	for _, entry := range r.Availability(adapters) {
		if !entry.Available() {
			unavailable = append(unavailable, entry)
		}
	}
	return unavailable
}
