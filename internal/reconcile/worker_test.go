package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/testutil"
)

// TestNoopResolverReturnsUnknown verifies that the NoopResolver
// returns RecoveryUnknown, ensuring fail-closed reconciliation.
func TestNoopResolverReturnsUnknown(t *testing.T) {
	r := NoopResolver{}
	result, err := r.Resolve(context.Background(), &idempotency.Record{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryUnknown {
		t.Errorf("expected RecoveryUnknown, got %s", result.Decision)
	}
}

// TestWorkerRegisterResolver verifies that capability-specific
// resolvers are selected over the default.
func TestWorkerRegisterResolver(t *testing.T) {
	defaultResolver := NoopResolver{}
	w := NewWorker(nil, defaultResolver, 0)

	custom := &mockResolver{decision: idempotency.RecoveryCommitted}
	w.RegisterResolver("test.capability", custom)

	// Default should be NoopResolver (UNKNOWN)
	result, err := w.resolve(context.Background(), &idempotency.Record{CapabilityID: "other.capability"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryUnknown {
		t.Errorf("expected RecoveryUnknown for unregistered capability, got %s", result.Decision)
	}

	// Registered capability should use custom resolver
	result, err = w.resolve(context.Background(), &idempotency.Record{CapabilityID: "test.capability"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryCommitted {
		t.Errorf("expected RecoveryCommitted for registered capability, got %s", result.Decision)
	}
}

// TestWorkerNilDefaultResolver verifies that a nil default resolver
// returns UNKNOWN (fail-closed).
func TestWorkerNilDefaultResolver(t *testing.T) {
	w := NewWorker(nil, nil, 0)
	result, err := w.resolve(context.Background(), &idempotency.Record{CapabilityID: "any.capability"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryUnknown {
		t.Errorf("expected RecoveryUnknown with nil default resolver, got %s", result.Decision)
	}
}

// TestReconcileBackoff verifies the exponential backoff function
// produces the correct sequence and saturates at the maximum without
// integer-shift overflow.
func TestReconcileBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 30 * time.Second},
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 16 * time.Minute},
		{6, 30 * time.Minute},  // 32m > 30m cap → saturated
		{7, 30 * time.Minute},  // beyond cap → saturated
		{10, 30 * time.Minute}, // far beyond → saturated
		{50, 30 * time.Minute}, // extreme overflow → saturated (not 0)
		{-1, 30 * time.Second}, // negative → clamped to base
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			got := reconcileBackoff(tt.attempt)
			if got != tt.want {
				t.Errorf("reconcileBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
			}
		})
	}
}

// TestReconcileBackoffNeverZero verifies that backoff never returns
// zero or negative — a permanently unresolved record must not enter
// a hot retry loop.
func TestReconcileBackoffNeverZero(t *testing.T) {
	for i := 0; i < 200; i++ {
		d := reconcileBackoff(i)
		if d <= 0 {
			t.Fatalf("reconcileBackoff(%d) = %v, must be positive", i, d)
		}
		if d > 30*time.Minute {
			t.Fatalf("reconcileBackoff(%d) = %v, exceeds 30m cap", i, d)
		}
	}
}

// mockResolver is a test RecoveryResolver that returns a fixed decision.
// For tests that need the full RecoveryResult, use fullResultResolver.
type mockResolver struct {
	decision idempotency.RecoveryDecision
}

func (m *mockResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.RecoveryResult, error) {
	return idempotency.RecoveryResult{Decision: m.decision}, nil
}

// TestLiveWorkerReconciliation tests the full recovery pipeline:
// UNKNOWN record → resolver returns COMMITTED + proof → worker
// resolves → record is durably COMMITTED with receipt preserved.
func TestLiveWorkerReconciliation(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	// Create a MUTATION record in UNKNOWN state.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = 'test-worker-reconcile'`)
	acq, err := store.Acquire(ctx, "test-worker-reconcile", "alice@example.com", "test.counter.increment",
		"digest-worker", "grant_w", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected lease acquired, got %s", acq.Kind)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Lookup(ctx, execID)
	if err := store.EnterRecovery(ctx, execID, idempotency.StateInFlight, rec.Version); err != nil {
		t.Fatal(err)
	}

	// Create a resolver that returns COMMITTED + proof. The artifact
	// carries the provider's raw observation; the resolver-supplied
	// digest is deliberately wrong to prove the worker recomputes the
	// evidence digest from artifact bytes rather than trusting it.
	artifact := []byte(`{"counter":"test","value":1,"provider":"test-counter"}`)
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(artifact))
	proofResolver := &fullResultResolver{
		result: idempotency.RecoveryResult{
			Decision:         idempotency.RecoveryCommitted,
			Result:           []byte(`{"counter":"test","value":1}`),
			EvidenceArtifact: artifact,
			EvidenceDigest:   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			ReceiptVersion:   3,
			ProviderID:       "test-counter",
			ProviderRunID:    "run_worker_reconcile",
		},
	}

	w := NewWorker(store, NoopResolver{}, 0)
	w.RegisterResolver("test.counter.increment", proofResolver)

	// Run one reconciliation cycle.
	rec2, _ := store.Lookup(ctx, execID)
	w.reconcileOne(ctx, rec2)

	// Verify the record is now COMMITTED.
	rec, _ = store.Lookup(ctx, execID)
	if rec.State != idempotency.StateCommitted {
		t.Errorf("expected COMMITTED after reconciliation, got %s", rec.State)
	}
	if rec.ProviderID != "test-counter" {
		t.Errorf("expected provider_id=test-counter, got %q", rec.ProviderID)
	}
	if rec.ProviderRunID != "run_worker_reconcile" {
		t.Errorf("expected provider_run_id=run_worker_reconcile, got %q", rec.ProviderRunID)
	}
	if rec.EvidenceDigest != wantDigest {
		t.Errorf("expected evidence digest recomputed from artifact (%s), got %q", wantDigest, rec.EvidenceDigest)
	}
}

// TestLiveWorkerDeadLettersAfterAttemptCeiling verifies the reconcile
// dead-letter path: a record that exhausts the attempt ceiling is
// parked (next_reconcile_at far future), stays UNKNOWN, and is never
// claimed again — it must not churn through the reconcile loop forever.
func TestLiveWorkerDeadLettersAfterAttemptCeiling(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-deadletter-%d", time.Now().UnixNano())
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, prefix)

	acq, err := store.Acquire(ctx, prefix, "alice@example.com", "test.counter.increment",
		"digest-deadletter", "grant_dl", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected lease acquired, got %s", acq.Kind)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Lookup(ctx, execID)
	if err := store.EnterRecovery(ctx, execID, idempotency.StateInFlight, rec.Version); err != nil {
		t.Fatal(err)
	}

	// Simulate a record that has already been claimed many times.
	if _, err := db.ExecContext(ctx,
		`UPDATE execution_requests SET reconcile_attempt = 10 WHERE execution_id = $1`, execID); err != nil {
		t.Fatal(err)
	}

	w := NewWorker(store, NoopResolver{}, 0)
	w.SetMaxAttempts(5) // effectiveAttempt (10-1) already exceeds the ceiling

	rec, _ = store.Lookup(ctx, execID)
	if err := w.reconcileOne(ctx, rec); err != nil {
		t.Fatalf("dead-letter release should not error, got %v", err)
	}

	rec, _ = store.Lookup(ctx, execID)
	if rec.State != idempotency.StateUnknown {
		t.Errorf("dead-lettered record must stay UNKNOWN, got %s", rec.State)
	}
	if rec.NextReconcileAt == nil || rec.NextReconcileAt.Before(time.Now().Add(50*365*24*time.Hour)) {
		t.Errorf("dead-lettered record must be parked ~100 years out, got %v", rec.NextReconcileAt)
	}
	if rec.ReconcileOwner != "" {
		t.Error("dead-lettered record must not hold a reconcile claim")
	}

	// It is never claimed again.
	claimed, err := store.ClaimUnknownBatch(ctx, "worker-x", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range claimed {
		if c.ExecutionID == execID {
			t.Fatal("dead-lettered record was claimed again")
		}
	}
}

// TestLiveWorkerReconcileCriticalFailedWithoutProof verifies that
// CRITICAL executions cannot be resolved to FAILED without evidence.
func TestLiveWorkerReconcileCriticalFailedWithoutProof(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	// Create a CRITICAL record in UNKNOWN state.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = 'test-worker-crit'`)
	acq, err := store.Acquire(ctx, "test-worker-crit", "alice@example.com", "test.critical.deploy",
		"digest-crit", "grant_c", "CRITICAL", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected lease acquired, got %s", acq.Kind)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "deploy-adapter", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Lookup(ctx, execID)
	if err := store.EnterRecovery(ctx, execID, idempotency.StateInFlight, rec.Version); err != nil {
		t.Fatal(err)
	}

	// Resolver claims FAILED but provides no proof.
	badResolver := &fullResultResolver{
		result: idempotency.RecoveryResult{
			Decision: idempotency.RecoveryFailed,
		},
	}

	w := NewWorker(store, NoopResolver{}, 0)
	w.RegisterResolver("test.critical.deploy", badResolver)
	rec2, _ := store.Lookup(ctx, execID)
	w.reconcileOne(ctx, rec2)

	// The record must remain UNKNOWN — the CRITICAL FAILED claim was rejected.
	rec, _ = store.Lookup(ctx, execID)
	if rec.State != idempotency.StateUnknown {
		t.Errorf("expected UNKNOWN (FAILED without proof rejected), got %s", rec.State)
	}
}

// fullResultResolver returns a complete RecoveryResult (unlike mockResolver
// which only returns Decision). This exercises the full evidence pipeline.
type fullResultResolver struct {
	result idempotency.RecoveryResult
}

func (r *fullResultResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.RecoveryResult, error) {
	return r.result, nil
}

// slowResolver sleeps for delay (honoring context cancellation) before
// returning a fixed result — simulates a provider lookup slower than
// one claim TTL.
type slowResolver struct {
	delay  time.Duration
	result idempotency.RecoveryResult
}

func (r *slowResolver) Resolve(ctx context.Context, _ *idempotency.Record) (idempotency.RecoveryResult, error) {
	select {
	case <-ctx.Done():
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, ctx.Err()
	case <-time.After(r.delay):
	}
	return r.result, nil
}

// makeUnknownRecord creates an UNKNOWN execution record for testing:
// acquire → begin → in-flight → enter recovery.
func makeUnknownRecord(t *testing.T, db *sql.DB, store *idempotency.Store, ctx context.Context, key, capability, class string) string {
	t.Helper()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
	acq, err := store.Acquire(ctx, key, "alice@example.com", capability,
		"digest-"+key, "grant_t", class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected lease acquired, got %s", acq.Kind)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-provider", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Lookup(ctx, execID)
	if err := store.EnterRecovery(ctx, execID, idempotency.StateInFlight, rec.Version); err != nil {
		t.Fatal(err)
	}
	return execID
}

// TestLiveClaimHeartbeatBlocksSecondWorker proves a resolver that runs
// LONGER than one claim TTL keeps its claim: the claim heartbeat renews
// reconcile_lease_expires_at, so a second worker's ClaimUnknownBatch
// must not be able to steal the record mid-resolution.
//
// Timing: claim TTL = 400ms, resolver = 900ms (> 2× initial TTL).
// At t=600ms — past the initial TTL — the record must be unclaimable.
func TestLiveClaimHeartbeatBlocksSecondWorker(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := fmt.Sprintf("test-claim-hb-%d", time.Now().UnixNano())
	execID := makeUnknownRecord(t, db, store, ctx, key, "test.counter.increment", "MUTATION")
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	w := NewWorker(store, NoopResolver{}, 0)
	w.SetWorkerID("worker-hb-1")
	w.SetClaimDuration(400 * time.Millisecond)
	w.RegisterResolver("test.counter.increment", &slowResolver{
		delay:  900 * time.Millisecond,
		result: idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown},
	})

	claimed, err := store.ClaimUnknownBatch(ctx, "worker-hb-1", 50, 400*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	var rec *idempotency.Record
	for _, r := range claimed {
		if r.ExecutionID == execID {
			rec = r
		}
	}
	if rec == nil {
		t.Fatal("test record was not claimed by worker-hb-1")
	}

	done := make(chan error, 1)
	go func() { done <- w.reconcileOne(ctx, rec) }()

	// At t=600ms the initial 400ms claim TTL has elapsed — but the
	// heartbeat must have renewed it, so worker-hb-2 cannot claim.
	time.Sleep(600 * time.Millisecond)
	other, err := store.ClaimUnknownBatch(ctx, "worker-hb-2", 50, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range other {
		if r.ExecutionID == execID {
			t.Error("second worker claimed the record while the claim heartbeat held it")
		}
	}
	// Release any other records the probe claim grabbed so they are not
	// stranded.
	for _, r := range other {
		_ = store.ReleaseReconcileClaim(ctx, r.ExecutionID, r.Version, 0, "")
	}

	if err := <-done; err != nil {
		t.Fatalf("reconcileOne failed: %v", err)
	}
	rec2, _ := store.Lookup(ctx, execID)
	if rec2.State != idempotency.StateUnknown {
		t.Errorf("expected UNKNOWN after unresolved reconciliation, got %s", rec2.State)
	}
	if rec2.ReconcileOwner != "" {
		t.Errorf("claim should be released after reconcileOne, got owner %q", rec2.ReconcileOwner)
	}
}

// TestLiveClaimExpiryRecovery proves a crashed claim owner does not hold
// a record forever: once the claim TTL elapses without renewal, another
// worker recovers the record.
func TestLiveClaimExpiryRecovery(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := fmt.Sprintf("test-claim-expiry-%d", time.Now().UnixNano())
	execID := makeUnknownRecord(t, db, store, ctx, key, "test.counter.increment", "MUTATION")
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	// Worker 1 claims with a 150ms claim TTL, then "crashes" — no
	// renewal, no release.
	claimed, err := store.ClaimUnknownBatch(ctx, "worker-crash-1", 50, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	held := false
	for _, r := range claimed {
		if r.ExecutionID == execID {
			held = true
		}
	}
	if !held {
		t.Fatal("worker-crash-1 did not claim the record")
	}

	// Immediately after the claim, a second worker must not get it.
	other, err := store.ClaimUnknownBatch(ctx, "worker-crash-2", 50, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range other {
		if r.ExecutionID == execID {
			t.Fatal("record claimable while claim still valid")
		}
	}
	for _, r := range other {
		_ = store.ReleaseReconcileClaim(ctx, r.ExecutionID, r.Version, 0, "")
	}

	// After the claim TTL elapses without renewal, worker 2 recovers it.
	time.Sleep(300 * time.Millisecond)
	other, err = store.ClaimUnknownBatch(ctx, "worker-crash-2", 50, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	recovered := false
	for _, r := range other {
		if r.ExecutionID == execID {
			recovered = true
			_ = store.ReleaseReconcileClaim(ctx, r.ExecutionID, r.Version, 0, "")
		}
	}
	if !recovered {
		t.Error("expired claim was not recoverable by a second worker")
	}
}

// openTestDB opens a test database connection scoped to a package-private
// schema so parallel package test binaries cannot interfere.
func openTestDB(dbURL string) (*sql.DB, error) {
	return testutil.OpenLiveDB(dbURL, "crabbox_test_reconcile")
}

// countingResolver counts resolver invocations and returns a fixed
// result — used to prove the attempt ceiling bounds provider lookups.
type countingResolver struct {
	calls  int32
	result idempotency.RecoveryResult
}

func (r *countingResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.RecoveryResult, error) {
	r.calls++
	return r.result, nil
}

// TestLiveWorkerSuspendsPastClaimCeiling verifies the attempt ceiling is
// enforced BEFORE the resolver runs: reconcile_attempt counts claims
// (ClaimUnknownBatch increments it), so a record claimed beyond the
// ceiling must be suspended without spending another provider lookup.
func TestLiveWorkerSuspendsPastClaimCeiling(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := fmt.Sprintf("test-ceiling-%d", time.Now().UnixNano())
	execID := makeUnknownRecord(t, db, store, ctx, key, "test.counter.increment", "MUTATION")
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	resolver := &countingResolver{result: idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}}
	w := NewWorker(store, NoopResolver{}, 0)
	w.SetWorkerID("worker-ceiling")
	w.SetMaxAttempts(5)
	w.RegisterResolver("test.counter.increment", resolver)

	// Seed at the ceiling: five claims have already run their lookups.
	if _, err := db.ExecContext(ctx,
		`UPDATE execution_requests SET reconcile_attempt = 5 WHERE execution_id = $1`, execID); err != nil {
		t.Fatal(err)
	}

	// The sixth claim must NOT invoke the resolver.
	claimed, err := store.ClaimUnknownBatch(ctx, "worker-ceiling", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var rec *idempotency.Record
	for _, r := range claimed {
		if r.ExecutionID == execID {
			rec = r
		}
	}
	if rec == nil {
		t.Fatal("record was not claimed")
	}
	if rec.ReconcileAttempt != 6 {
		t.Fatalf("expected reconcile_attempt=6 after claim, got %d", rec.ReconcileAttempt)
	}
	if err := w.reconcileOne(ctx, rec); err != nil {
		t.Fatalf("ceiling suspend must not error, got %v", err)
	}
	if resolver.calls != 0 {
		t.Errorf("resolver invoked %d times past the ceiling — must be 0", resolver.calls)
	}
	rec2, _ := store.Lookup(ctx, execID)
	if rec2.State != idempotency.StateUnknown {
		t.Errorf("suspended record must stay UNKNOWN, got %s", rec2.State)
	}
	if rec2.NextReconcileAt == nil || rec2.NextReconcileAt.Before(time.Now().Add(50*365*24*time.Hour)) {
		t.Errorf("suspended record must be parked ~100 years out, got %v", rec2.NextReconcileAt)
	}
}

// TestLiveWorkerResolverRunsAtLastAllowedClaim verifies the ceiling is
// exact: the maxAttempts-th claim still runs its resolver (it is the
// last permitted lookup), and the record is suspended afterwards —
// the ceiling bounds resolver calls, not just claims.
func TestLiveWorkerResolverRunsAtLastAllowedClaim(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := fmt.Sprintf("test-ceiling-exact-%d", time.Now().UnixNano())
	execID := makeUnknownRecord(t, db, store, ctx, key, "test.counter.increment", "MUTATION")
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	resolver := &countingResolver{result: idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}}
	w := NewWorker(store, NoopResolver{}, 0)
	w.SetWorkerID("worker-ceiling-exact")
	w.SetMaxAttempts(5)
	w.RegisterResolver("test.counter.increment", resolver)

	// Four claims already ran; the fifth (last allowed) claim runs the
	// resolver, then the record suspends — no sixth lookup is possible.
	if _, err := db.ExecContext(ctx,
		`UPDATE execution_requests SET reconcile_attempt = 4 WHERE execution_id = $1`, execID); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimUnknownBatch(ctx, "worker-ceiling-exact", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var rec *idempotency.Record
	for _, r := range claimed {
		if r.ExecutionID == execID {
			rec = r
		}
	}
	if rec == nil {
		t.Fatal("record was not claimed")
	}
	if rec.ReconcileAttempt != 5 {
		t.Fatalf("expected reconcile_attempt=5 after claim, got %d", rec.ReconcileAttempt)
	}
	if err := w.reconcileOne(ctx, rec); err != nil {
		t.Fatalf("last allowed claim must not error, got %v", err)
	}
	if resolver.calls != 1 {
		t.Errorf("fifth claim must invoke the resolver exactly once, got %d", resolver.calls)
	}
	rec2, _ := store.Lookup(ctx, execID)
	if rec2.State != idempotency.StateUnknown {
		t.Errorf("record must stay UNKNOWN after exhausting the ceiling, got %s", rec2.State)
	}
	if rec2.NextReconcileAt == nil || rec2.NextReconcileAt.Before(time.Now().Add(50*365*24*time.Hour)) {
		t.Errorf("record that exhausted the ceiling must be parked, got %v", rec2.NextReconcileAt)
	}
}

// TestLiveBatchClaimHeartbeatProtectsQueuedRecords verifies the batch-
// wide claim heartbeat: while a slow resolver processes the first
// claimed record, later records' claims must keep being renewed — a
// second worker must not steal a queued record whose initial claim TTL
// elapsed mid-batch.
//
// Timing: claim TTL = 400ms, slow resolver = 900ms. At t=600ms — past
// the queued record's initial TTL — it must still be unclaimable.
func TestLiveBatchClaimHeartbeatProtectsQueuedRecords(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-batch-hb-%d", time.Now().UnixNano())
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")
	// Claim scans all UNKNOWN rows — isolate exact assertions.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE state = 'UNKNOWN'`)

	slowID := makeUnknownRecord(t, db, store, ctx, prefix+"-slow", "test.slow", "MUTATION")
	queuedID := makeUnknownRecord(t, db, store, ctx, prefix+"-queued", "test.fast", "MUTATION")

	fastResolver := &countingResolver{result: idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}}
	w := NewWorker(store, NoopResolver{}, 0)
	w.SetWorkerID("worker-batch-1")
	w.SetClaimDuration(400 * time.Millisecond)
	w.RegisterResolver("test.slow", &slowResolver{
		delay:  900 * time.Millisecond,
		result: idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown},
	})
	w.RegisterResolver("test.fast", fastResolver)

	done := make(chan error, 1)
	go func() { done <- w.reconcileAll(ctx) }()

	// At t=600ms the queued record's initial 400ms claim TTL has
	// elapsed — but the batch heartbeat must have renewed it, so
	// worker-batch-2 cannot claim it while the slow resolver runs.
	time.Sleep(600 * time.Millisecond)
	other, err := store.ClaimUnknownBatch(ctx, "worker-batch-2", 50, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range other {
		if r.ExecutionID == queuedID {
			t.Error("second worker stole a queued record whose claim the batch heartbeat should hold")
		}
	}
	for _, r := range other {
		_ = store.ReleaseReconcileClaim(ctx, r.ExecutionID, r.Version, 0, "")
	}

	if err := <-done; err != nil {
		t.Fatalf("reconcileAll failed: %v", err)
	}
	if fastResolver.calls == 0 {
		t.Error("queued record was never processed by its claiming worker")
	}
	for _, id := range []string{slowID, queuedID} {
		rec, _ := store.Lookup(ctx, id)
		if rec.ReconcileOwner != "" {
			t.Errorf("record %s still claimed after batch drained (owner %q)", id, rec.ReconcileOwner)
		}
	}
}

// claimRecord claims a single UNKNOWN record for the given worker and
// returns the claimed record (carrying the post-claim version that
// reconcileOne's claim revalidation requires).
func claimRecord(t *testing.T, store *idempotency.Store, ctx context.Context, workerID, execID string) *idempotency.Record {
	t.Helper()
	claimed, err := store.ClaimUnknownBatch(ctx, workerID, 50, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range claimed {
		if r.ExecutionID == execID {
			return r
		}
	}
	t.Fatalf("record %s was not claimed by %s", execID, workerID)
	return nil
}

// TestLiveReconcileSkipsResolverOnStaleClaim verifies that a worker
// which lost its claim before reaching a queued record never invokes
// the resolver: reconcileOne synchronously revalidates the claim, and
// the version CAS fails because the reclaiming worker bumped it.
// Without this check a stale worker could spend a provider lookup on a
// record another worker owns, so maxAttempts would no longer bound the
// number of provider resolution calls.
func TestLiveReconcileSkipsResolverOnStaleClaim(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := fmt.Sprintf("test-stale-claim-%d", time.Now().UnixNano())
	execID := makeUnknownRecord(t, db, store, ctx, key, "test.counter.increment", "MUTATION")
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	resolver := &countingResolver{result: idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}}
	w := NewWorker(store, resolver, 0)
	w.SetWorkerID("worker-stale")
	w.SetClaimDuration(200 * time.Millisecond)

	// Worker A claims the record with a short TTL.
	claimed, err := store.ClaimUnknownBatch(ctx, "worker-stale", 50, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	var stale *idempotency.Record
	for _, r := range claimed {
		if r.ExecutionID == execID {
			stale = r
		}
	}
	if stale == nil {
		t.Fatal("worker-stale did not claim the record")
	}

	// The claim expires and worker B reclaims (bumping version) — the
	// situation a queued record is in when a slow batch member delayed
	// reconcileOne past the claim TTL.
	time.Sleep(300 * time.Millisecond)
	recB := claimRecord(t, store, ctx, "worker-fresh", execID)

	// Worker A's stale record must not reach the resolver.
	if err := w.reconcileOne(ctx, stale); err == nil {
		t.Error("reconcileOne on a stale claim must fail")
	}
	if resolver.calls != 0 {
		t.Errorf("resolver invoked %d times on a stale claim, want 0", resolver.calls)
	}

	// Worker B's fresh claim resolves normally.
	if err := w.reconcileOne(ctx, recB); err != nil {
		t.Fatalf("reconcileOne on a valid claim failed: %v", err)
	}
	if resolver.calls != 1 {
		t.Errorf("resolver invoked %d times on a valid claim, want 1", resolver.calls)
	}
}
