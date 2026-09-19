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
	for name, register := range map[string]func(*capability.Registry) error{
		"system.echo":            RegisterEchoCapability,
		"test.counter.increment": RegisterCounterCapability,
		"system.info":            RegisterSystemInfoCapability,
		"github.issue.create":    RegisterGitHubIssueCapability,
	} {
		if err := register(registry); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}

	if err := registry.Validate(); err != nil {
		t.Fatalf("built-in registry must pass the invariant scan: %v", err)
	}
	if err := registry.ValidateAdapters(map[string]bool{
		"system": true, "test-counter": true, "system-info": true, "github": true,
	}); err != nil {
		t.Fatalf("built-in adapters must be wired: %v", err)
	}

	report, err := registry.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Total != 4 {
		t.Fatalf("built-in registry total = %d, want 4", report.Total)
	}
	if report.Digest == "" {
		t.Fatal("registry digest must be non-empty")
	}
}
