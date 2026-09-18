package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Live PostgreSQL conformance tests for the forensic record —
// CRABBOX_TEST_DATABASE_URL required (scripts/test-live-postgres.sh).

func liveForensicStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store, context.Background()
}

func liveForensicInFlight(t *testing.T, ctx context.Context, s *Store, key, digest string) (*AcquireResult, string) {
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

// TestLiveForensicEventHistory asserts the same ordered event history
// on PostgreSQL as the SQLite conformance test.
func TestLiveForensicEventHistory(t *testing.T) {
	s, ctx := liveForensicStore(t)
	key := fmt.Sprintf("forensic-life-%d", time.Now().UnixNano())
	acq, execID := liveForensicInFlight(t, ctx, s, key, "digest-life")

	obs := ProviderObservation{
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		ProviderStatus: "SUCCEEDED",
		Result:         json.RawMessage(`{"ok":1}`),
	}
	if err := s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	receipt := TerminalReceipt{
		ExecutionID:     execID,
		Capability:      rec.CapabilityID,
		Principal:       rec.PrincipalID,
		RequestDigest:   rec.RequestDigest,
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"ok":true}`),
		ProviderID:      "prov",
		ProviderRunID:   "run-1",
		ReceiptVersion:  3,
	}
	if err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	events, err := s.ListEffectEvents(ctx, execID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	want := []string{
		EventAcquired, EventExecutionBegun, EventDispatchStarted,
		EventProviderObserved, EventTerminalResolved,
	}
	got := eventTypes(events)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("event history = %v, want %v", got, want)
	}
	for i, e := range events {
		if e.Sequence != i+1 {
			t.Fatalf("event %d sequence = %d", i, e.Sequence)
		}
	}
}

// TestLiveForensicObservationLedger asserts the ledger preserves the
// exact asserted result bytes and is self-verifying on PostgreSQL.
func TestLiveForensicObservationLedger(t *testing.T) {
	s, ctx := liveForensicStore(t)
	key := fmt.Sprintf("forensic-obs-%d", time.Now().UnixNano())
	acq, execID := liveForensicInFlight(t, ctx, s, key, "digest-obs")

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
	if string(row.ResultBytes) != string(raw) {
		t.Errorf("result_bytes = %q, want exact bytes %q", row.ResultBytes, raw)
	}
	sum := sha256.Sum256(raw)
	if row.ResultSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("result_sha256 = %q", row.ResultSHA256)
	}
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if row.ResultCanonicalDigest != rec.ProviderResultDigest {
		t.Errorf("canonical digest %q != row %q", row.ResultCanonicalDigest, rec.ProviderResultDigest)
	}
	if rec.ProviderEvidenceDigest != "ev-provider" {
		t.Errorf("provider_evidence_digest = %q", rec.ProviderEvidenceDigest)
	}
}

// TestLiveForensicRecoveryObservationRace exercises the IN_FLIGHT →
// UNKNOWN CAS race on real PostgreSQL: exactly one recovery entrant
// wins; the loser persists its observation as a reconciliation row.
func TestLiveForensicRecoveryObservationRace(t *testing.T) {
	s, ctx := liveForensicStore(t)
	key := fmt.Sprintf("forensic-race-%d", time.Now().UnixNano())
	_, execID := liveForensicInFlight(t, ctx, s, key, "digest-race")

	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	obs := ProviderObservation{
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		ProviderStatus: "UNKNOWN",
		Result:         json.RawMessage(`{"status":"pending"}`),
	}

	const racers = 8
	var won, conflict, other int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := s.EnterRecoveryWithObservation(ctx, execID, StateInFlight, rec.Version, obs)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case err != nil && errors.Is(err, LeaseStateConflict):
				conflict++
				// The dispatcher's recovery path falls back to a
				// direct observation write on the UNKNOWN record —
				// the observation is never lost to the CAS race.
				if oerr := s.RecordProviderObservation(ctx, execID, "", 0, obs); oerr != nil {
					t.Errorf("fallback observation: %v", oerr)
				}
			default:
				other++
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if won != 1 || conflict != racers-1 || other != 0 {
		t.Fatalf("won=%d conflict=%d other=%d", won, conflict, other)
	}
	recs, err := s.ListProviderObservations(ctx, execID)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(recs) != racers {
		t.Fatalf("observation rows = %d, want %d (winner + all fallbacks)", len(recs), racers)
	}
	var recoveryKind, reconKind int
	for _, r := range recs {
		switch r.Kind {
		case ObservationRecovery:
			recoveryKind++
		case ObservationReconciliation:
			reconKind++
		}
	}
	if recoveryKind != 1 || reconKind != racers-1 {
		t.Fatalf("kinds: recovery=%d reconciliation=%d", recoveryKind, reconKind)
	}
	// Every loser event is recorded too.
	events, err := s.ListEffectEvents(ctx, execID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var enteredUnknown, reconObserved int
	for _, e := range events {
		switch e.EventType {
		case EventEnteredUnknown:
			enteredUnknown++
		case EventReconciliationObserved:
			reconObserved++
		}
	}
	if enteredUnknown != 1 || reconObserved != racers-1 {
		t.Fatalf("events: entered_unknown=%d recon_observed=%d", enteredUnknown, reconObserved)
	}
}
