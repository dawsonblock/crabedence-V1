package execution

import (
	"fmt"

	"github.com/openclaw/crabbox/internal/capability"
)

// RegisterBuiltinCapabilities registers the complete built-in
// capability surface this build ships.
//
// It is the single source of truth for release registry membership: the
// service, cmd/registry-digest, and the qualification harness all build
// the release registry through it, so a release can never advertise a
// different catalog than the service serves.
//
// Registration is unconditional — deployment configuration never decides
// registry membership. Adapter availability is a runtime property
// (see capability.AdapterAvailability).
func RegisterBuiltinCapabilities(registry *capability.Registry) error {
	registrations := []struct {
		name     string
		register func(*capability.Registry) error
	}{
		{"system.echo", RegisterEchoCapability},
		{"test.counter.increment", RegisterCounterCapability},
		{"system.info", RegisterSystemInfoCapability},
		{"github.issue.create", RegisterGitHubIssueCapability},
		{"github.issue.get", RegisterGitHubReadCapabilities},
	}
	for _, registration := range registrations {
		if err := registration.register(registry); err != nil {
			return fmt.Errorf("failed to register %s: %w", registration.name, err)
		}
	}
	return nil
}
