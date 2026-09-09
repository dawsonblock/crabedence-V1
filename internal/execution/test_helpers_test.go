package execution

import (
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// testGrantResolver creates an InMemoryGrantResolver with a test grant
// that permits all capabilities for alice@example.com.
func testGrantResolver() *capability.InMemoryGrantResolver {
	r := capability.NewInMemoryGrantResolver()
	r.AddGrant(&capability.Grant{
		ID:           "grant_123",
		Principal:    "alice@example.com",
		Capabilities: []string{"*"}, // wildcard — all capabilities
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	return r
}

// setupServiceWithGrants creates a service with a grant resolver
// that permits alice@example.com for all capabilities.
func setupServiceWithGrants(registry *capability.Registry, handler Handler, socketPath string) *Service {
	s := NewService(registry, handler, socketPath)
	s.SetGrantResolver(testGrantResolver())
	return s
}
