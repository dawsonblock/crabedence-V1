package execution

import (
	"fmt"

	"github.com/openclaw/crabbox/internal/capability"
)

// ProviderCapabilities declares the evidence and reconciliation
// support a provider adapter offers. The dispatch executor reads the
// declaration at admission: a CRITICAL execution is denied when the
// provider cannot supply both completion and non-effect proof,
// because a post-dispatch ambiguity through such a provider could
// never be resolved — the record would strand UNKNOWN forever.
type ProviderCapabilities struct {
	// SupportsProviderIdempotency — the provider accepts a
	// deterministic idempotency key and deduplicates retries
	// server-side.
	SupportsProviderIdempotency bool
	// SupportsStatusLookup — the provider exposes a strongly
	// consistent operation-status lookup keyed by provider_run_id.
	SupportsStatusLookup bool
	// SupportsCompletionProof — the provider can supply evidence
	// proving an operation ran (required for COMPLETED receipts).
	SupportsCompletionProof bool
	// SupportsNonexecutionProof — the provider can supply evidence
	// proving an operation did NOT run (required for NO_EFFECT
	// receipts).
	SupportsNonexecutionProof bool
	// RecoveryLocatorType names the locator scheme the adapter's
	// PrepareRecovery produces; empty means the generic
	// metadata-only locator.
	RecoveryLocatorType string
}

// CapabilityDeclarer is the optional contract a Handler implements to
// advertise per-adapter ProviderCapabilities. A CRITICAL execution
// routed to an adapter with no declaration is denied: an undeclared
// provider cannot be assumed capable of producing the evidence a
// CRITICAL terminal transition requires in either direction.
type CapabilityDeclarer interface {
	ProviderCapabilities(adapterID string) ProviderCapabilities
}

// providerCapsFor resolves the capability declaration for adapterID.
// declared=false when the handler does not implement
// CapabilityDeclarer at all.
func providerCapsFor(h Handler, adapterID string) (caps ProviderCapabilities, declared bool) {
	d, ok := h.(CapabilityDeclarer)
	if !ok {
		return ProviderCapabilities{}, false
	}
	return d.ProviderCapabilities(adapterID), true
}

// checkCriticalProviderCapability enforces the CRITICAL admission
// gate — see ProviderCapabilities.
func checkCriticalProviderCapability(h Handler, desc capability.ResolvedDescriptor) *Response {
	if desc.ExecutionClass != capability.ClassCritical {
		return nil
	}
	caps, declared := providerCapsFor(h, desc.AdapterID)
	if declared && caps.SupportsCompletionProof && caps.SupportsNonexecutionProof {
		return nil
	}
	reason := "does not declare provider capabilities"
	if declared {
		reason = fmt.Sprintf("lacks required evidence support (completion_proof=%v nonexecution_proof=%v)",
			caps.SupportsCompletionProof, caps.SupportsNonexecutionProof)
	}
	return &Response{
		Status:      StatusDenied,
		FailureCode: string(capability.FailureAdmissionDenied),
		Error: fmt.Sprintf("CRITICAL admission denied: provider %q %s — "+
			"a CRITICAL effect requires a provider able to prove both completion and non-effect",
			desc.AdapterID, reason),
	}
}
