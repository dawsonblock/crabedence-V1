package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Grant represents an authorization grant issued to a principal.
type Grant struct {
	ID           string
	Principal    string
	Capabilities []string // capabilities this grant permits
	ExpiresAt    time.Time
	Revoked      bool
	// Generation is the immutable version of this grant's material.
	// Reissuing a grant_id produces a new generation row rather than
	// mutating the already-issued grant, so a durable execution can
	// prove exactly which authority material admitted it. Zero means
	// generation tracking is absent (in-memory resolvers).
	Generation int64
	// Digest is ComputeGrantDigest's output over this generation's
	// material, stored at issue time. Empty when generation tracking
	// is absent.
	Digest string
}

// ComputeGrantDigest returns the SHA-256 of the grant's canonical
// material — grant_id, generation, principal, sorted capabilities, and
// expiry — hex-encoded. It is deterministic: the same grant material
// always produces the same digest, and any mutation produces a
// different one. Execution request digests bind it so that the same
// grant_id at a different generation is a different authority.
func ComputeGrantDigest(g *Grant) string {
	caps := append([]string(nil), g.Capabilities...)
	sort.Strings(caps)
	expires := ""
	if !g.ExpiresAt.IsZero() {
		expires = g.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	canonical, err := json.Marshal(struct {
		GrantID      string   `json:"grant_id"`
		Generation   int64    `json:"generation"`
		Principal    string   `json:"principal"`
		Capabilities []string `json:"capabilities"`
		ExpiresAt    string   `json:"expires_at"`
	}{
		GrantID:      g.ID,
		Generation:   g.Generation,
		Principal:    g.Principal,
		Capabilities: caps,
		ExpiresAt:    expires,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// IsValid checks whether the grant is valid for the given capability at the given time.
func (g *Grant) IsValid(capabilityID string, now time.Time) bool {
	if g == nil {
		return false
	}
	return !g.Revoked && !g.Expired(now) && g.HasCapability(capabilityID)
}

// Expired reports whether the grant is expired at `now`. Resolvers that
// evaluate expiry against their own database clock inside Resolve
// already filter expired grants; VerifyAuthority skips this check for
// them (see ExpiryIsAuthoritative) so the application clock can never
// veto a grant the authority store's clock considers valid.
func (g *Grant) Expired(now time.Time) bool {
	return !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt)
}

// HasCapability reports whether the grant's capability list permits the
// requested capability. An empty list permits all capabilities.
func (g *Grant) HasCapability(capabilityID string) bool {
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
	mu     sync.RWMutex
	grants map[string]*Grant
}

// NewInMemoryGrantResolver creates a resolver backed by a map.
func NewInMemoryGrantResolver() *InMemoryGrantResolver {
	return &InMemoryGrantResolver{grants: make(map[string]*Grant)}
}

// AddGrant adds a grant to the resolver.
func (r *InMemoryGrantResolver) AddGrant(g *Grant) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grants[g.ID] = g
}

// Resolve looks up a grant by ID.
func (r *InMemoryGrantResolver) Resolve(ctx context.Context, grantID string, principal string) (*Grant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.grants[grantID]
	if !ok {
		return nil, nil
	}
	if g.Principal != principal {
		return nil, nil
	}
	return g, nil
}
