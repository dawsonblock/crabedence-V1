package idempotency

import (
	"sync/atomic"
)

// StoreMetrics exposes the semantic invariant counters item-level
// qualification requires — not HTTP-flavored request counts but the
// durable-execution signals an operator must alert on:
//
//   - state totals (committed/failed/unknown entered)
//   - lease/fence violations (stale-fence mutation attempts, lease loss)
//   - observation monotonicity violations (conflicting provider reports)
//   - reconciliation activity and CRITICAL evidence rejections
//
// Counters are monotonic per store instance. A snapshot is a plain
// map so it can be exported to any metrics backend without coupling
// the store to one.
type StoreMetrics struct {
	acquires               atomic.Int64
	executing              atomic.Int64
	inFlight               atomic.Int64
	committed              atomic.Int64
	failed                 atomic.Int64
	unknownEntered         atomic.Int64
	leaseRenewals          atomic.Int64
	fenceRejections        atomic.Int64
	observationWrites      atomic.Int64
	observationConflicts   atomic.Int64
	reconcileClaims        atomic.Int64
	reconcileResolutions   atomic.Int64
	criticalEvidenceDenied atomic.Int64
	epochRejections        atomic.Int64
	recoveryRejections     atomic.Int64
}

// Metrics returns the store's live counter set. Both store
// implementations expose the same counters — a backend-neutral
// semantic contract.
func (s *Store) Metrics() *StoreMetrics       { return &s.metrics }
func (s *SQLiteStore) Metrics() *StoreMetrics { return &s.metrics }

// Snapshot flattens the counters to a stable-name map for export.
func (m *StoreMetrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"effect_acquires_total":                m.acquires.Load(),
		"effect_executing_total":               m.executing.Load(),
		"effect_in_flight_total":               m.inFlight.Load(),
		"effect_committed_total":               m.committed.Load(),
		"effect_failed_total":                  m.failed.Load(),
		"effect_unknown_entered_total":         m.unknownEntered.Load(),
		"effect_lease_renewals_total":          m.leaseRenewals.Load(),
		"effect_fence_rejections_total":        m.fenceRejections.Load(),
		"effect_observation_writes_total":      m.observationWrites.Load(),
		"provider_observation_conflicts_total": m.observationConflicts.Load(),
		"reconciliation_claims_total":          m.reconcileClaims.Load(),
		"reconciliation_resolutions_total":     m.reconcileResolutions.Load(),
		"critical_evidence_rejected_total":     m.criticalEvidenceDenied.Load(),
		"cluster_epoch_rejections_total":       m.epochRejections.Load(),
		"cluster_recovery_rejections_total":    m.recoveryRejections.Load(),
	}
}
