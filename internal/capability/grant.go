package capability

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
	// Constraints bind the grant to specific resource values per
	// dimension (e.g. "repo": ["openclaw/crabbox"]). A capability's
	// authority policy maps each constraint dimension to a request
	// argument; admission requires the argument's value to be listed
	// for every bound dimension ("*" admits any value). A dimension
	// absent from Constraints is unconstrained, so a grant issued
	// without constraints covers every resource the capability can
	// name — issue constrained grants for least privilege.
	// Constraints are immutable grant material, bound into Digest.
	Constraints map[string][]string
	ExpiresAt   time.Time
	Revoked     bool
	// IssuedAt is the issuance instant, part of the immutable grant
	// material bound into Digest. Stores normalize it to Unix
	// milliseconds before persisting.
	IssuedAt time.Time
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
// material — grant_id, generation, principal, sorted capabilities,
// issuance time, and expiry — hex-encoded. It is deterministic: the
// same grant material always produces the same digest, and any
// mutation produces a different one. Execution request digests bind it
// so that the same grant_id at a different generation is a different
// authority.
//
// Time is bound as Unix-millisecond integers, never a formatted
// timestamp string: SQLite stores expiry/issue as INTEGER ms and
// PostgreSQL TIMESTAMPTZ round-trips ms-exact, so a resolved grant
// always reproduces its stored digest identically on either backend.
func ComputeGrantDigest(g *Grant) string {
	caps := append([]string(nil), g.Capabilities...)
	sort.Strings(caps)
	var issuedAtMs, expiresAtMs int64
	if !g.IssuedAt.IsZero() {
		issuedAtMs = g.IssuedAt.UTC().UnixMilli()
	}
	if !g.ExpiresAt.IsZero() {
		expiresAtMs = g.ExpiresAt.UTC().UnixMilli()
	}
	canonical, err := json.Marshal(struct {
		GrantID      string              `json:"grant_id"`
		Generation   int64               `json:"generation"`
		Principal    string              `json:"principal"`
		Capabilities []string            `json:"capabilities"`
		Constraints  map[string][]string `json:"constraints,omitempty"`
		IssuedAtMs   int64               `json:"issued_at_ms"`
		ExpiresAtMs  int64               `json:"expires_at_ms"`
	}{
		GrantID:      g.ID,
		Generation:   g.Generation,
		Principal:    g.Principal,
		Capabilities: caps,
		Constraints:  normalizeConstraints(g.Constraints),
		IssuedAtMs:   issuedAtMs,
		ExpiresAtMs:  expiresAtMs,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// normalizeConstraints returns a canonical copy of constraints: each
// dimension's value list deduplicated and sorted so logically
// identical constraints always produce identical digests. Returns nil
// for empty input so unconstrained grants keep their pre-constraints
// digest (omitempty drops the field from the canonical material).
func normalizeConstraints(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for dimension, values := range in {
		seen := make(map[string]bool, len(values))
		list := make([]string, 0, len(values))
		for _, v := range values {
			if !seen[v] {
				seen[v] = true
				list = append(list, v)
			}
		}
		sort.Strings(list)
		out[dimension] = list
	}
	return out
}

// VerifyGrantDigest reports whether the grant's stored digest matches
// the digest recomputed from its material, compared in constant time.
//
// Authority material must PROVE its identity, not merely carry one: a
// grant whose stored digest is absent or disagrees with the material it
// covers is unverified, and callers must refuse it rather than resolve
// the (possibly degraded) material it decoded.
func VerifyGrantDigest(g *Grant) bool {
	if g == nil || g.Digest == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(ComputeGrantDigest(g)), []byte(g.Digest)) == 1
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

// AllowsResource reports whether the grant admits the given value for
// a resource-constraint dimension. A dimension absent from
// Constraints is unconstrained (allowed); a present dimension admits
// only listed values or the "*" wildcard. An explicitly empty list
// admits nothing.
func (g *Grant) AllowsResource(dimension, value string) bool {
	allowed, ok := g.Constraints[dimension]
	if !ok {
		return true
	}
	for _, v := range allowed {
		if v == value || v == "*" {
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
