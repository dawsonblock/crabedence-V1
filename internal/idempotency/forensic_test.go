package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// forensicDriveToInFlight acquires, begins, and marks a record
// IN_FLIGHT — the shared setup for forensic tests that need a
// post-dispatch record.
func forensicDriveToInFlight(t *testing.T, ctx context.Context, s *SQLiteStore, key, digest string) (*AcquireResult, string) {
	t.Helper()
	acq, err := s.Acquire(ctx, key, "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq.Kind != LeaseAcquired {
		t.Fatalf("acquire: %v kind=%v", err, acq.Kind)
	}
	execID := acq.Record.ExecutionID
	if err := s.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "prov",
		json.RawMessage(`{"external_token":"tok"}`)); err != nil {
		t.Fatalf("mark in flight: %v", err)
	}
	return acq, execID
}

func eventTypes(events []EffectEvent) []string {
	types := make([]string, len(events))
	for i, e := range events {
		types[i] = e.EventType
	}
	return types
}

// TestForensicEventHistoryLifecycle verifies that a full dispatch
// lifecycle produces an ordered, complete forensic event history.
func TestForensicEventHistoryLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("lifecycle")

	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-life", digest)

	obs := ProviderObservation{
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		ProviderStatus: "SUCCEEDED",
		Result:         json.RawMessage(`{"ok":1}`),
	}
	if err := s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}
	receipt := sqliteReceipt(execID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
	if err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	events, err := s.ListEffectEvents(ctx, execID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	want := []string{
		EventAcquired,
		EventExecutionBegun,
		EventDispatchStarted,
		EventProviderObserved,
		EventTerminalResolved,
	}
	got := eventTypes(events)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("event history = %v, want %v", got, want)
	}
	// Sequences are strictly ordered and record versions non-decreasing.
	for i, e := range events {
		if e.Sequence != i+1 {
			t.Fatalf("event %d sequence = %d", i, e.Sequence)
		}
		if i > 0 && e.RecordVersion < events[i-1].RecordVersion {
			t.Fatalf("event %d record_version %d < previous %d",
				i, e.RecordVersion, events[i-1].RecordVersion)
		}
	}
	// Transition events carry correct prev/new states.
	if events[1].PreviousState != "PREPARED" || events[1].NewState != "EXECUTING" {
		t.Errorf("EXECUTION_BEGUN states: %s→%s", events[1].PreviousState, events[1].NewState)
	}
	if events[2].PreviousState != "EXECUTING" || events[2].NewState != "IN_FLIGHT" {
		t.Errorf("DISPATCH_STARTED states: %s→%s", events[2].PreviousState, events[2].NewState)
	}
	if events[4].PreviousState != "IN_FLIGHT" || events[4].NewState != "COMMITTED" {
		t.Errorf("TERMINAL_RESOLVED states: %s→%s", events[4].PreviousState, events[4].NewState)
	}
	if events[0].Actor == "" {
		t.Error("ACQUIRED event must record the acquiring actor")
	}
}

// TestForensicObservationLedgerBytes verifies the observation ledger
// preserves the exact asserted result bytes and is self-verifying.
func TestForensicObservationLedgerBytes(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("obsbytes")

	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-obs", digest)

	// Non-canonical input: spaced keys — the ledger must keep the
	// exact asserted bytes while the row stores the canonical form.
	raw := json.RawMessage(`{  "b": 2, "a": 1 }`)
	obs := ProviderObservation{
		ProviderID:     "prov",
		ProviderRunID:  "run-9",
		ProviderStatus: "SUCCEEDED",
		Result:         raw,
		EvidenceDigest: "ev-provider",
	}
	if err := s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}

	recs, err := s.ListProviderObservations(ctx, execID)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("observation rows = %d, want 1", len(recs))
	}
	row := recs[0]
	if row.Kind != ObservationDispatch {
		t.Errorf("kind = %q, want %q", row.Kind, ObservationDispatch)
	}
	if row.ProviderID != "prov" || row.ProviderRunID != "run-9" {
		t.Errorf("provider identity: %q/%q", row.ProviderID, row.ProviderRunID)
	}
	// Exact bytes preserved — not the canonicalized form.
	if string(row.ResultBytes) != string(raw) {
		t.Errorf("result_bytes = %q, want exact asserted bytes %q", row.ResultBytes, raw)
	}
	sum := sha256.Sum256(raw)
	if row.ResultSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("result_sha256 = %q, want sha256(asserted bytes) %q",
			row.ResultSHA256, hex.EncodeToString(sum[:]))
	}
	if row.EvidenceSHA256 != "ev-provider" {
		t.Errorf("evidence_sha256 = %q", row.EvidenceSHA256)
	}
	// Canonical digest correlates with the materialized row.
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if row.ResultCanonicalDigest == "" || row.ResultCanonicalDigest != rec.ProviderResultDigest {
		t.Errorf("canonical digest %q != row provider_result_digest %q",
			row.ResultCanonicalDigest, rec.ProviderResultDigest)
	}
	if rec.ProviderEvidenceDigest != "ev-provider" {
		t.Errorf("provider_evidence_digest = %q, want ev-provider", rec.ProviderEvidenceDigest)
	}
}

// TestForensicEvidenceSplit verifies provider-time evidence and
// terminal-time evidence are persisted separately on the row.
func TestForensicEvidenceSplit(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("split")

	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-split", digest)

	obs := ProviderObservation{
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		ProviderStatus: "SUCCEEDED",
		EvidenceDigest: "ev-provider",
	}
	if err := s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}

	receipt := sqliteReceipt(execID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
	receipt.EvidenceDigest = "ev-terminal"
	if err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	// Provider-time evidence is preserved separately — the terminal
	// write did not erase it.
	if rec.ProviderEvidenceDigest != "ev-provider" {
		t.Errorf("provider_evidence_digest = %q, want ev-provider", rec.ProviderEvidenceDigest)
	}
	if rec.TerminalEvidenceDigest != "ev-terminal" {
		t.Errorf("terminal_evidence_digest = %q, want ev-terminal", rec.TerminalEvidenceDigest)
	}
	// Terminal result is cryptographically bound.
	sum := sha256.Sum256(receipt.CanonicalResult)
	if rec.TerminalResultDigest != hex.EncodeToString(sum[:]) {
		t.Errorf("terminal_result_digest = %q, want sha256(canonical result) %q",
			rec.TerminalResultDigest, hex.EncodeToString(sum[:]))
	}
	// The projection still reports the latest evidence.
	if rec.EvidenceDigest != "ev-terminal" {
		t.Errorf("evidence_digest projection = %q, want ev-terminal", rec.EvidenceDigest)
	}
}

// TestForensicRecoveryObservationKinds verifies observation kind
// classification across the recovery boundary.
func TestForensicRecoveryObservationKinds(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("kinds")

	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-kind", digest)
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	// Recovery entry carries the first observation.
	obs := ProviderObservation{
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		ProviderStatus: "UNKNOWN",
		Result:         json.RawMessage(`{"status":"pending"}`),
	}
	if err := s.EnterRecoveryWithObservation(ctx, execID, StateInFlight, rec.Version, obs); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}

	// A late observation on the UNKNOWN record is reconciliation-side.
	// Provider identity/status must agree with the stored observation —
	// only the evidence digest is new information here.
	obs2 := ProviderObservation{
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		EvidenceDigest: "ev-reconcile",
	}
	if err := s.RecordProviderObservation(ctx, execID, "", 0, obs2); err != nil {
		t.Fatalf("late observe: %v", err)
	}

	rec, err = s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	res := RecoveryResult{
		Decision:       RecoveryCommitted,
		Result:         json.RawMessage(`{"done":true}`),
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		EvidenceDigest: "ev-terminal",
		ReceiptVersion: 4,
	}
	if err := s.ResolveRecovery(ctx, execID, rec.Version, res); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	recs, err := s.ListProviderObservations(ctx, execID)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("observation rows = %d, want 3", len(recs))
	}
	wantKinds := []string{ObservationRecovery, ObservationReconciliation, ObservationReconciliation}
	for i, k := range wantKinds {
		if recs[i].Kind != k {
			t.Errorf("observation %d kind = %q, want %q", i, recs[i].Kind, k)
		}
		if recs[i].Sequence != i+1 {
			t.Errorf("observation %d sequence = %d", i, recs[i].Sequence)
		}
	}

	events, err := s.ListEffectEvents(ctx, execID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	got := eventTypes(events)
	wantTail := []string{EventEnteredUnknown, EventReconciliationObserved, EventTerminalResolved}
	if len(got) < len(wantTail) {
		t.Fatalf("events = %v", got)
	}
	tail := got[len(got)-len(wantTail):]
	if fmt.Sprint(tail) != fmt.Sprint(wantTail) {
		t.Errorf("event tail = %v, want %v", tail, wantTail)
	}

	// Terminal columns were written by the recovery resolution.
	final, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if final.TerminalEvidenceDigest != "ev-terminal" {
		t.Errorf("terminal_evidence_digest = %q", final.TerminalEvidenceDigest)
	}
	sum := sha256.Sum256(res.Result)
	if final.TerminalResultDigest != hex.EncodeToString(sum[:]) {
		t.Errorf("terminal_result_digest = %q", final.TerminalResultDigest)
	}
	_ = acq
}

// TestForensicLeaseLostEvent verifies a fenced-out writer leaves a
// LEASE_LOST forensic annotation.
func TestForensicLeaseLostEvent(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("lost")

	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-lost", digest)

	// A stale token loses the fence — the loss must be annotated.
	err := s.RecordProviderObservation(ctx, execID, "stale-token", 99,
		ProviderObservation{ProviderID: "prov", ProviderStatus: "X"})
	if err == nil {
		t.Fatal("expected observation rejection")
	}
	events, err := s.ListEffectEvents(ctx, execID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.EventType == EventLeaseLost {
			found = true
		}
	}
	if !found {
		t.Fatalf("no LEASE_LOST event in %v", eventTypes(events))
	}
	_ = acq
}

// TestForensicClaimEvents verifies reconciliation claim lifecycle
// events are recorded.
func TestForensicClaimEvents(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("claims")

	_, execID := forensicDriveToInFlight(t, ctx, s, "k-claim", digest)
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if err := s.EnterRecovery(ctx, execID, StateInFlight, rec.Version); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}

	claimed, err := s.ClaimUnknownBatch(ctx, "worker-1", 10, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed %d records", len(claimed))
	}
	if err := s.ReleaseReconcileClaim(ctx, execID, claimed[0].Version, 0, "retry later"); err != nil {
		t.Fatalf("release: %v", err)
	}

	events, err := s.ListEffectEvents(ctx, execID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	got := eventTypes(events)
	for _, want := range []string{EventReconciliationClaimed, EventClaimReleased} {
		var found bool
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	// The claim event records the claiming worker and claim epoch.
	for _, e := range events {
		if e.EventType == EventReconciliationClaimed {
			if e.Actor != "worker-1" {
				t.Errorf("claim actor = %q", e.Actor)
			}
			if e.ClaimGeneration != 1 {
				t.Errorf("claim generation = %d, want 1", e.ClaimGeneration)
			}
		}
	}
}

// TestForensicEventRollbackOnFailure proves the transactional coupling:
// when the event row cannot be written, the state mutation it describes
// must roll back — a forensic entry can never be silently missing.
func TestForensicEventRollbackOnFailure(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("rollback")

	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-rb", digest)

	// Breaking the event ledger makes every forensic write fail.
	if _, err := s.db.ExecContext(ctx, `DROP TABLE effect_events`); err != nil {
		t.Fatalf("drop: %v", err)
	}

	receipt := sqliteReceipt(execID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
	err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt)
	if err == nil {
		t.Fatal("finalize must fail when the event insert fails")
	}

	// The state mutation rolled back with the event — still IN_FLIGHT.
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != StateInFlight {
		t.Fatalf("state = %s after rolled-back finalize, want IN_FLIGHT", rec.State)
	}
}
