package idempotency

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestStoreMetricsLifecycle drives a record through the full durable
// lifecycle and verifies the semantic counters move at each boundary.
func TestStoreMetricsLifecycle(t *testing.T) {
	db, err := OpenSQLiteDB(filepath.Join(t.TempDir(), "db", "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	acq, err := s.Acquire(ctx, "k", "p", "cap", "d", "g", "MUTATION", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginExecution(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkInFlight(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, "prov", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordProviderObservation(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, ProviderObservation{
		ProviderID: "prov", ProviderStatus: "SUCCEEDED", Result: []byte(`{"ok":1}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Finalize(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, TerminalReceipt{
		ExecutionID: acq.Record.ExecutionID, Capability: "cap", Principal: "p",
		RequestDigest: "d", TerminalStatus: StateCommitted, CanonicalResult: []byte(`{"ok":1}`),
	}); err != nil {
		t.Fatal(err)
	}

	// A stale-fence mutation attempt on the sealed record counts a
	// fence rejection.
	if err := s.RecordProviderObservation(ctx, acq.Record.ExecutionID, "stale", 99, ProviderObservation{
		ProviderID: "prov", ProviderStatus: "FAILED",
	}); err == nil {
		t.Fatal("stale-fence observation must be rejected")
	}

	// UNKNOWN path on a second record.
	acq2, err := s.Acquire(ctx, "k2", "p", "cap", "d2", "g", "MUTATION", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginExecution(ctx, acq2.Record.ExecutionID, acq2.LeaseToken, acq2.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkInFlight(ctx, acq2.Record.ExecutionID, acq2.LeaseToken, acq2.Generation, "prov", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	rec2, _ := s.Lookup(ctx, acq2.Record.ExecutionID)
	if err := s.EnterRecovery(ctx, acq2.Record.ExecutionID, StateInFlight, rec2.Version); err != nil {
		t.Fatal(err)
	}
	rec2, _ = s.Lookup(ctx, acq2.Record.ExecutionID)
	if err := s.ResolveRecovery(ctx, acq2.Record.ExecutionID, rec2.Version, RecoveryResult{
		Decision: RecoveryFailed, Result: []byte(`{"no_effect":true}`),
	}); err != nil {
		t.Fatal(err)
	}

	got := s.Metrics().Snapshot()
	want := map[string]int64{
		"effect_acquires_total":            2,
		"effect_executing_total":           2,
		"effect_in_flight_total":           2,
		"effect_committed_total":           1,
		"effect_failed_total":              1,
		"effect_unknown_entered_total":     1,
		"effect_observation_writes_total":  1,
		"effect_fence_rejections_total":    1,
		"reconciliation_resolutions_total": 1,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %d, want %d", k, got[k], w)
		}
	}
	for k, v := range got {
		t.Logf("%s = %d", k, v)
	}
}

// TestStoreMetricsSnapshotKeys pins the exported counter names — an
// alerting/qualification surface other components may depend on.
func TestStoreMetricsSnapshotKeys(t *testing.T) {
	m := &StoreMetrics{}
	want := []string{
		"effect_acquires_total", "effect_executing_total", "effect_in_flight_total",
		"effect_committed_total", "effect_failed_total", "effect_unknown_entered_total",
		"effect_lease_renewals_total", "effect_fence_rejections_total",
		"effect_observation_writes_total", "provider_observation_conflicts_total",
		"reconciliation_claims_total", "reconciliation_resolutions_total",
		"critical_evidence_rejected_total", "cluster_epoch_rejections_total",
		"cluster_recovery_rejections_total", "effect_lease_lost_total",
		"reconciliation_suspended_total",
	}
	got := m.Snapshot()
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing metric key %s", k)
		}
	}
	if len(got) != len(want) {
		t.Errorf("snapshot has %d keys, want %d — undocumented counter added", len(got), len(want))
	}
}
