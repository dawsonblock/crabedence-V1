package execution

import (
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
)

// TestBuiltInRegistryPassesStartupScan pins the service's own
// capability registry against the startup invariant scan: every
// built-in descriptor must use supported schema keywords, carry an
// adapter binding, and be wired to a handler the service dispatches.
func TestBuiltInRegistryPassesStartupScan(t *testing.T) {
	registry := capability.NewRegistry()
	if err := RegisterBuiltinCapabilities(registry); err != nil {
		t.Fatalf("register built-ins: %v", err)
	}

	if err := registry.Validate(); err != nil {
		t.Fatalf("built-in registry must pass the invariant scan: %v", err)
	}
	availability := capability.AdapterAvailability{
		"system":       {Status: capability.AvailabilityAvailable},
		"test-counter": {Status: capability.AvailabilityAvailable},
		"system-info":  {Status: capability.AvailabilityAvailable},
		"github":       {Status: capability.AvailabilityAvailable},
	}
	if report := registry.CheckAdapterAvailability(availability); len(report.Unavailable) != 0 {
		t.Fatalf("built-in adapters must be wired: %+v", report.Unavailable)
	}

	report, err := registry.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Total != 5 {
		t.Fatalf("built-in registry total = %d, want 5", report.Total)
	}
	if report.Digest == "" {
		t.Fatal("registry digest must be non-empty")
	}
}
