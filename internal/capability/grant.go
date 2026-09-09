package capability

import (
	"context"
	"time"
)

// Grant represents an authorization grant issued to a principal.
type Grant struct {
	ID            string
	Principal     string
	Capabilities   []string // capabilities this grant permits
	ExpiresAt     time.Time
	Revoked       bool
}

// IsValid checks whether the grant is valid for the given capability at the given time.
func (g *Grant) IsValid(capabilityID string, now time.Time) bool {
	if g == nil {
		return false
	}
	if g.Revoked {
		return false
	}
	if !g.ExpiresAt.IsZero() && now.After(g.ExpiresAt) {
		return false
	}
	if len(g.Capabilities) == 0 {
		// Empty capabilities means all capabilities (wildcard)
		return true
	}
	for _, c := range g.Capabilities {
		if c == capabilityID || c == "*" {
			return true
		}
	}
	return false
}

// GrantResolver resolves grant IDs to grants.
// Implementations may use PostgreSQL, an in-memory store, or an external
// authorization service.
type GrantResolver interface {
	// Resolve looks up a grant by ID and returns it if valid.
	// Returns nil if the grant does not exist or is invalid.
	Resolve(ctx context.Context, grantID string, principal string) (*Grant, error)
}

// NoopGrantResolver always returns nil (no grant found).
// This is the default when no real resolver is configured.
// It causes all grant-required capabilities to be denied.
type NoopGrantResolver struct{}

func (NoopGrantResolver) Resolve(ctx context.Context, grantID string, principal string) (*Grant, error) {
	return nil, nil
}

// InMemoryGrantResolver is a simple in-memory grant resolver for testing.
type InMemoryGrantResolver struct {
	grants map[string]*Grant
}

// NewInMemoryGrantResolver creates a resolver backed by a map.
func NewInMemoryGrantResolver() *InMemoryGrantResolver {
	return &InMemoryGrantResolver{grants: make(map[string]*Grant)}
}

// AddGrant adds a grant to the resolver.
func (r *InMemoryGrantResolver) AddGrant(g *Grant) {
	r.grants[g.ID] = g
}

// Resolve looks up a grant by ID.
func (r *InMemoryGrantResolver) Resolve(ctx context.Context, grantID string, principal string) (*Grant, error) {
	g, ok := r.grants[grantID]
	if !ok {
		return nil, nil
	}
	if g.Principal != principal {
		return nil, nil
	}
	return g, nil
}
