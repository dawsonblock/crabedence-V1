package reconcile

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/idempotency"
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

	// Create a resolver that returns COMMITTED + proof.
	proofResolver := &fullResultResolver{
		result: idempotency.RecoveryResult{
			Decision:       idempotency.RecoveryCommitted,
			Result:         []byte(`{"counter":"test","value":1}`),
			EvidenceDigest: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			ReceiptVersion: 3,
			ProviderID:     "test-counter",
			ProviderRunID:  "run_worker_reconcile",
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

// openTestDB opens a test database connection.
func openTestDB(dbURL string) (*sql.DB, error) {
	return sql.Open("pgx", dbURL)
}
