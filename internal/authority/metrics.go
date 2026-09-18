package authority

import (
	"sync/atomic"
)

// Metrics exposes the authority-store semantic counters — the
// grant-lifecycle signals an operator must see: issuance, per-
// generation and whole-grant revocation, reference closure, and
// resolve denials (revoked, expired, wrong-principal, or missing
// material consulted at admission). Counters are monotonic per store
// instance; Snapshot flattens them to stable names for export, the
// same contract as idempotency.StoreMetrics.
type Metrics struct {
	issued             atomic.Int64
	generationsRevoked atomic.Int64
	grantsRevoked      atomic.Int64
	refsClosed         atomic.Int64
	resolves           atomic.Int64
	resolveDenied      atomic.Int64
}

// Metrics returns the store's live counter set. Both engine
// implementations expose the same counters — a backend-neutral
// semantic contract.
func (s *Store) Metrics() *Metrics       { return &s.metrics }
func (s *SQLiteStore) Metrics() *Metrics { return &s.metrics }

// Snapshot flattens the counters to a stable-name map for export.
func (m *Metrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"authority_grants_issued_total":       m.issued.Load(),
		"authority_generations_revoked_total": m.generationsRevoked.Load(),
		"authority_grants_revoked_total":      m.grantsRevoked.Load(),
		"authority_refs_closed_total":         m.refsClosed.Load(),
		"authority_resolves_total":            m.resolves.Load(),
		"authority_resolve_denials_total":     m.resolveDenied.Load(),
	}
}
