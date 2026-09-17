package idempotency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// openSQLiteStore opens an embedded store on a temp file. No daemon,
// no CRABBOX_TEST_DATABASE_URL — the SQLite suite always runs.
func openSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crabedence-test.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store
}

// sqliteDigest is a deterministic request digest for tests.
func sqliteDigest(s string) string {
	d, err := ComputeDigestFromRaw(1, "alice", "cap.mut",
		json.RawMessage(fmt.Sprintf(`{"q":%q}`, s)), "", "MUTATION")
	if err != nil {
		panic(err)
	}
	return d
}

func sqliteReceipt(execID, capID, principal, digest, providerID, runID string, status State) TerminalReceipt {
	return TerminalReceipt{
		ExecutionID:     execID,
		Capability:      capID,
		Principal:       principal,
		RequestDigest:   digest,
		CanonicalResult: json.RawMessage(`{"ok":true}`),
		ReceiptVersion:  3,
		ProviderID:      providerID,
		ProviderRunID:   runID,
		TerminalStatus:  status,
	}
}

func TestSQLiteStoreHappyPath(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq.Kind != LeaseAcquired {
		t.Fatalf("acquire: %v kind=%v", err, acq.Kind)
	}
	rec := acq.Record

	// Same key + digest while lease held → held by other.
	acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq2.Kind != LeaseHeldByOther {
		t.Fatalf("re-acquire: %v kind=%v", err, acq2.Kind)
	}
	// Different digest → idempotency conflict.
	acq3, err := s.Acquire(ctx, "k1", "alice", "cap.mut", sqliteDigest("b"), "", "MUTATION", 5*time.Minute)
	if err != nil || acq3.Kind != IdempotencyConflict {
		t.Fatalf("conflict acquire: %v kind=%v", err, acq3.Kind)
	}

	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	locator := json.RawMessage(`{"external_token":"tok-1"}`)
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", locator); err != nil {
		t.Fatalf("mark in flight: %v", err)
	}

	// Status-only observation must persist (regression: no skip).
	obs := ProviderObservation{ProviderID: "prov", ProviderStatus: "SUCCEEDED"}
	if err := s.RecordProviderObservation(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}

	receipt := sqliteReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
	if err := s.Finalize(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	final, err := s.Lookup(ctx, rec.ExecutionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if final.State != StateCommitted || final.ProviderRunID != "run-1" {
		t.Fatalf("final: %s run=%q", final.State, final.ProviderRunID)
	}

	// Idempotent replay returns the stored terminal record.
	acq4, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq4.Kind != TerminalReplay || acq4.Record.State != StateCommitted {
		t.Fatalf("replay: %v kind=%v state=%v", err, acq4.Kind, acq4.Record.State)
	}
}

func TestSQLiteStoreStaleFencing(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Wrong token → LeaseTokenMismatch.
	if err := s.MarkInFlight(ctx, rec.ExecutionID, "bad-token", acq.Generation, "", nil); !errors.Is(err, LeaseTokenMismatch) {
		t.Fatalf("want LeaseTokenMismatch, got %v", err)
	}
	// Wrong generation → LeaseGenerationMismatch.
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation+99, "", nil); !errors.Is(err, LeaseGenerationMismatch) {
		t.Fatalf("want LeaseGenerationMismatch, got %v", err)
	}
}

func TestSQLiteStoreExpiredInFlightBecomesUnknown(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 60*time.Millisecond)
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil); err != nil {
		t.Fatalf("in flight: %v", err)
	}
	time.Sleep(80 * time.Millisecond)

	// Expired IN_FLIGHT must NOT be reclaimed — it becomes UNKNOWN.
	acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", time.Minute)
	if err != nil || acq2.Kind != RecoveryRequired {
		t.Fatalf("want RecoveryRequired, got %v err=%v", acq2.Kind, err)
	}
	rec2, _ := s.Lookup(ctx, rec.ExecutionID)
	if rec2.State != StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN", rec2.State)
	}
	if rec2.EnteredUnknownAt == nil {
		t.Fatal("entered_unknown_at not set")
	}
}

func TestSQLiteStoreAbandonAndReclaim(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.AbandonPreDispatch(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	// Lease-less PREPARED reacquires immediately.
	acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq2.Kind != LeaseAcquired {
		t.Fatalf("reacquire: %v kind=%v", err, acq2.Kind)
	}
}

func TestSQLiteStoreReconcileClaimLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation)
	s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil)
	if err := s.EnterRecovery(ctx, rec.ExecutionID, StateInFlight, rec.Version+2); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}
	// ^ EnterRecovery bumps version twice from acquire? No — BeginExecution
	// and MarkInFlight each bump once. Recompute from the record.
	cur, _ := s.Lookup(ctx, rec.ExecutionID)
	if cur.State != StateUnknown {
		t.Fatalf("state=%s want UNKNOWN", cur.State)
	}

	claimed, err := s.ClaimUnknownBatch(ctx, "w1", 10, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v n=%d", err, len(claimed))
	}
	if claimed[0].ReconcileOwner != "w1" {
		t.Fatalf("owner=%q", claimed[0].ReconcileOwner)
	}
	// Second worker cannot claim while the first holds it.
	claimed2, err := s.ClaimUnknownBatch(ctx, "w2", 10, time.Minute)
	if err != nil || len(claimed2) != 0 {
		t.Fatalf("double claim: %v n=%d", err, len(claimed2))
	}
	// Renewal extends the live claim.
	if err := s.RenewReconcileClaim(ctx, rec.ExecutionID, claimed[0].Version, time.Minute); err != nil {
		t.Fatalf("renew: %v", err)
	}
	// Resolve to FAILED (recovery) with proof fields.
	res := RecoveryResult{
		Decision:       RecoveryFailed,
		EvidenceDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ReceiptVersion: 3,
		ProviderID:     "prov",
		Result:         json.RawMessage(`{"no_effect":true}`),
	}
	if err := s.ResolveRecovery(ctx, rec.ExecutionID, claimed[0].Version, res); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	final, _ := s.Lookup(ctx, rec.ExecutionID)
	if final.State != StateFailed {
		t.Fatalf("state=%s want FAILED", final.State)
	}
}

func TestSQLiteStoreProviderIdentityMonotonic(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation)
	s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov-A", nil)

	// Observation establishes provider identity.
	obs := ProviderObservation{ProviderID: "prov-A", ProviderRunID: "run-1", ProviderStatus: "SUCCEEDED"}
	if err := s.RecordProviderObservation(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, obs); err != nil {
		t.Fatalf("observe: %v", err)
	}
	// Contradictory observation → typed conflict.
	bad := ProviderObservation{ProviderID: "prov-B"}
	if err := s.RecordProviderObservation(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, bad); !errors.Is(err, ProviderObservationConflict) {
		t.Fatalf("want ProviderObservationConflict, got %v", err)
	}
	// Terminal receipt with a different provider → conflict, not overwrite.
	receipt := sqliteReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov-B", "run-9", StateCommitted)
	if err := s.Finalize(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); !errors.Is(err, ProviderObservationConflict) {
		t.Fatalf("finalize want ProviderObservationConflict, got %v", err)
	}
	// Confirming receipt finalizes.
	ok := sqliteReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov-A", "run-1", StateCommitted)
	if err := s.Finalize(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight, ok); err != nil {
		t.Fatalf("finalize: %v", err)
	}
}

func TestSQLiteStoreLocatorDenylist(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	rec := acq.Record
	s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation)
	locator := json.RawMessage(`{"client_secret":"abc"}`)
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", locator); !errors.Is(err, LocatorContainsSecret) {
		t.Fatalf("want LocatorContainsSecret, got %v", err)
	}
}

// TestSQLiteStoreConcurrentAcquire hammers the single-writer path:
// N goroutines racing on one idempotency identity must produce
// exactly one lease holder — busy_timeout plus CAS fencing, not
// application locks.
func TestSQLiteStoreConcurrentAcquire(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("a")

	const n = 32
	type outcome struct {
		kind AcquireResultKind
		err  error
	}
	results := make(chan outcome, n)
	for i := 0; i < n; i++ {
		go func() {
			acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			results <- outcome{kind: acq.Kind}
		}()
	}
	acquired := 0
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			// Any error — e.g. a SQLITE_BUSY that outlasted busy_timeout —
			// means the serialized-writer path is failing, not fencing.
			t.Fatalf("concurrent acquire errored: %v", r.err)
		}
		switch r.kind {
		case LeaseAcquired:
			acquired++
		case LeaseHeldByOther:
		default:
			t.Fatalf("concurrent acquire: unexpected kind %s", r.kind)
		}
	}
	if acquired != 1 {
		t.Fatalf("concurrent acquire: %d winners, want exactly 1", acquired)
	}
}

func TestSQLiteStoreSchemaVersion(t *testing.T) {
	s := openSQLiteStore(t)
	v, err := s.SchemaVersion(context.Background())
	if err != nil || v < RequiredSchemaVersion {
		t.Fatalf("schema version %v err=%v", v, err)
	}
}

// A path containing DSN metacharacters must be rejected — otherwise it
// could silently truncate the filename or override durability pragmas.
func TestOpenSQLiteDBRejectsDSNMetachars(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a?b.db", "a#b.db"} {
		if _, err := OpenSQLiteDB(filepath.Join(dir, name)); err == nil {
			t.Fatalf("path %q: want rejection, got nil", name)
		}
	}
}
