package execution

import (
	"github.com/openclaw/crabbox/internal/capability"
)

// IssuanceCatalog returns the resolved-descriptor catalog that grant issuance
// validates scope declarations against: the release registry plus the explicit
// qualification extensions.
//
// Issuance needs the union, not just the release half: the qualification
// harness issues grants for qualification.critical.commit through the same
// CLI, and a capability the catalog cannot resolve is a capability whose
// declared resource dimensions the issuer never saw — which the issuance
// policy refuses. The extension's descriptor is the authoritative answer for
// its dimensions, exactly as the deployed qualification registry computes it.
func IssuanceCatalog() (*capability.Registry, error) {
	registry := capability.NewRegistry()
	if err := RegisterBuiltinCapabilities(registry); err != nil {
		return nil, err
	}
	if err := RegisterQualificationCapabilities(registry); err != nil {
		return nil, err
	}
	return registry, nil
}
