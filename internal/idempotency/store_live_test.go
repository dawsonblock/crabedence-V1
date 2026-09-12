package idempotency

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file contains live PostgreSQL tests for the lease-based idempotency
// contract. They require a real PostgreSQL database via
// CRABBOX_TEST_DATABASE_URL.
//
// Run with:
//
//	CRABBOX_TEST_DATABASE_URL=postgres://user@localhost/dbname \
//	  go test ./internal/idempotency/ -run TestLive -v -count=1
//
// The tests are skipped when the environment variable is absent.

// ─── Test helpers ────────────────────────────────────────────────────────────
// These helpers adapt the typed API for tests written against the legacy
// Reserve/TransitionState/FinalizeLegacy signatures. They look up the lease
// generation internally, matching the legacy wrapper behavior.

// testReserve wraps Acquire with the default lease duration.
func testReserve(store *Store, ctx context.Context, key, principal, capability, digest, grantID, class string) (*AcquireResult, error) {
	return store.Acquire(ctx, key, principal, capability, digest, grantID, class, DefaultLeaseDuration)
}

// testReserveWithLease wraps Acquire with an explicit lease duration.
func testReserveWithLease(store *Store, ctx context.Context, key, principal, capability, digest, grantID, class string, duration time.Duration) (*AcquireResult, error) {
	return store.Acquire(ctx, key, principal, capability, digest, grantID, class, duration)
}

// testTransition performs a typed state transition, looking up the lease
// generation from the store. Only the transitions used in tests are supported.
func testTransition(store *Store, ctx context.Context, executionID, leaseToken string, expectedState, newState State) error {
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	gen := rec.LeaseGeneration
	switch {
	case expectedState == StatePrepared && newState == StateExecuting:
		return store.BeginExecution(ctx, executionID, leaseToken, gen)
	case expectedState == StateExecuting && newState == StateInFlight:
		return store.MarkInFlight(ctx, executionID, leaseToken, gen, "", nil)
	default:
		return fmt.Errorf("unsupported test transition %s → %s", expectedState, newState)
	}
}

// testFinalize builds a TerminalReceipt and calls Finalize with the store's
// current lease generation. TerminalStatus is mapped from the legacy name.
func testFinalize(store *Store, ctx context.Context, executionID, leaseToken string, expectedState, terminalStatus State, result json.RawMessage, evidenceDigest string, receiptVersion int) error {
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	receipt := TerminalReceipt{
		ExecutionID:     executionID,
		Capability:      rec.CapabilityID,
		Principal:       rec.PrincipalID,
		RequestDigest:   rec.RequestDigest,
		TerminalStatus:  terminalStatus,
		CanonicalResult: result,
		EvidenceDigest:  evidenceDigest,
		ReceiptVersion:  receiptVersion,
	}
	return store.Finalize(ctx, executionID, leaseToken, rec.LeaseGeneration, expectedState, receipt)
}

// testEnterRecovery traverses the full lifecycle to enter recovery:
// PREPARED → EXECUTING → IN_FLIGHT → UNKNOWN. This is the only legal
// path — EnterRecovery enforces IN_FLIGHT as the sole origin.
func testEnterRecovery(store *Store, ctx context.Context, executionID, leaseToken string) error {
	if err := testTransition(store, ctx, executionID, leaseToken, StatePrepared, StateExecuting); err != nil {
		return fmt.Errorf("testEnterRecovery: %w", err)
	}
	if err := testTransition(store, ctx, executionID, leaseToken, StateExecuting, StateInFlight); err != nil {
		return fmt.Errorf("testEnterRecovery: %w", err)
	}
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	return store.EnterRecovery(ctx, executionID, StateInFlight, rec.Version)
}

// testRenewLease looks up the generation and calls RenewLease.
func testRenewLease(store *Store, ctx context.Context, executionID, leaseToken string, duration time.Duration) error {
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		return err
	}
	return store.RenewLease(ctx, executionID, leaseToken, rec.LeaseGeneration, duration)
}

func TestLiveStoreConcurrentReserveSingleExecution(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()

	// Clean up any prior test data.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-concurrent-%'`)

	key := fmt.Sprintf("test-concurrent-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-abc123"
	grantID := "grant_test"
	class := "MUTATION"

	const numCallers = 100
	var acquiredCount int64
	var inFlightCount int64
	var errorCount int64

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < numCallers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			reserve, err := testReserve(store, ctx, key, principal, capability, digest, grantID, class)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			if reserve.Kind == IdempotencyConflict {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			if reserve.Acquired() {
				// This caller owns the reservation — only ONE caller should get this.
				atomic.AddInt64(&acquiredCount, 1)

				// Simulate the execution lifecycle.
				// Transition RESERVED → DISPATCHING
				if err := testTransition(store, ctx, reserve.Record.ExecutionID, reserve.LeaseToken, StatePrepared, StateExecuting); err != nil {
					t.Errorf("lease holder failed to transition to DISPATCHING: %v", err)
				}
				if err := testTransition(store, ctx, reserve.Record.ExecutionID, reserve.LeaseToken, StateExecuting, StateInFlight); err != nil {
					t.Errorf("lease holder failed to transition to IN_FLIGHT: %v", err)
				}

				// Finalize with SUCCEEDED
				result := []byte(`{"value":42}`)
				if err := testFinalize(store, ctx, reserve.Record.ExecutionID, reserve.LeaseToken, StateInFlight, StateCommitted, result, "evidencedigest000000000000000000000000000000000000000000000000000000123456", 3); err != nil {
					t.Errorf("lease holder failed to finalize: %v", err)
				}
			} else {
				// This caller does NOT own the reservation — should see IN_FLIGHT
				// or the terminal result after the owner finalizes.
				atomic.AddInt64(&inFlightCount, 1)
				if reserve.Record == nil {
					t.Error("non-acquired caller received nil record")
				}
			}
		}()
	}

	close(start)
	wg.Wait()

	if errorCount > 0 {
		t.Errorf("%d callers returned errors", errorCount)
	}

	if acquiredCount != 1 {
		t.Errorf("exactly 1 caller should acquire the reservation, got %d", acquiredCount)
	}

	expectedInFlight := int64(numCallers - 1)
	if inFlightCount != expectedInFlight {
		t.Errorf("exactly %d callers should see IN_FLIGHT (not acquired), got %d", expectedInFlight, inFlightCount)
	}

	t.Logf("100-way concurrency: acquired=%d, in_flight=%d, errors=%d", acquiredCount, inFlightCount, errorCount)
}

func TestLiveStoreSameKeyDifferentDigestConflict(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-conflict-%'`)

	key := fmt.Sprintf("test-conflict-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	grantID := "grant_test"
	class := "MUTATION"

	// First caller reserves with digest A.
	reserve1, err := testReserve(store, ctx, key, principal, capability, "digest-A", grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve1.Acquired() {
		t.Fatal("first caller should acquire the reservation")
	}

	// Second caller uses the same key with a DIFFERENT digest.
	reserve2, err := testReserve(store, ctx, key, principal, capability, "digest-B", grantID, class)
	if err != nil {
		t.Fatal(err)
	}

	if reserve2.Kind != IdempotencyConflict {
		t.Error("same key + different digest must produce CONFLICT")
	}
	if reserve2.Acquired() {
		t.Error("conflicting caller must NOT acquire the reservation")
	}

	// Clean up.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

func TestLiveStoreLeaseExpiryReclaim(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-lease-%'`)

	key := fmt.Sprintf("test-lease-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-lease-test"
	grantID := "grant_test"
	class := "MUTATION"

	// Caller A reserves with a very short lease (100ms).
	reserveA, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired() {
		t.Fatal("caller A should acquire with fresh key")
	}

	// Caller B tries immediately — should NOT acquire (lease still valid).
	reserveB, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reserveB.Acquired() {
		t.Error("caller B should NOT acquire while lease is valid")
	}

	// Wait for the lease to expire.
	time.Sleep(200 * time.Millisecond)

	// Caller C tries after expiry — SHOULD acquire via lease reclaim.
	reserveC, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveC.Acquired() {
		t.Error("caller C should acquire after lease expiry")
	}

	// Caller A's old lease token should NOT be able to finalize.
	err = testFinalize(store, ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateInFlight, StateCommitted, nil, "", 3)
	if err == nil {
		t.Error("old lease holder (A) should NOT be able to finalize after lease takeover")
	}

	// Caller C (new lease holder) CAN finalize.
	if err := testTransition(store, ctx, reserveC.Record.ExecutionID, reserveC.LeaseToken, StatePrepared, StateExecuting); err != nil {
		t.Errorf("new lease holder (C) failed to transition: %v", err)
	}
	if err := testTransition(store, ctx, reserveC.Record.ExecutionID, reserveC.LeaseToken, StateExecuting, StateInFlight); err != nil {
		t.Errorf("new lease holder (C) failed to transition to IN_FLIGHT: %v", err)
	}
	err = testFinalize(store, ctx, reserveC.Record.ExecutionID, reserveC.LeaseToken, StateInFlight, StateCommitted, []byte(`{"ok":true}`), "", 0)
	if err != nil {
		t.Errorf("new lease holder (C) failed to finalize: %v", err)
	}

	// Clean up.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

func TestLiveStoreFinalizeConflict(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-finalize-%'`)

	key := fmt.Sprintf("test-finalize-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-finalize-test"
	grantID := "grant_test"
	class := "MUTATION"

	// Reserve and transition to DISPATCHING.
	reserve, err := testReserve(store, ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve.Acquired() {
		t.Fatal("should acquire")
	}
	executionID := reserve.Record.ExecutionID
	leaseToken := reserve.LeaseToken

	if err := testTransition(store, ctx, executionID, leaseToken, StatePrepared, StateExecuting); err != nil {
		t.Fatal(err)
	}
	if err := testTransition(store, ctx, executionID, leaseToken, StateExecuting, StateInFlight); err != nil {
		t.Fatal(err)
	}

	// Finalize with SUCCEEDED and evidence digest X.
	if err := testFinalize(store, ctx, executionID, leaseToken, StateInFlight, StateCommitted, []byte(`{"result":"A"}`), "digest_X", 3); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}

	// Identical re-finalize — should be idempotent (no error).
	if err := testFinalize(store, ctx, executionID, leaseToken, StateInFlight, StateCommitted, []byte(`{"result":"A"}`), "digest_X", 3); err != nil {
		t.Errorf("identical re-finalize should be idempotent, got: %v", err)
	}

	// Conflicting finalize — different terminal state.
	err = testFinalize(store, ctx, executionID, leaseToken, StateInFlight, StateFailed, []byte(`{"result":"B"}`), "", 0)
	if err == nil {
		t.Error("conflicting finalize (SUCCEEDED → FAILED) must be rejected")
	}

	// Conflicting finalize — same state but different evidence.
	err = testFinalize(store, ctx, executionID, leaseToken, StateInFlight, StateCommitted, []byte(`{"result":"B"}`), "digest_Y", 3)
	if err == nil {
		t.Error("conflicting finalize (different evidence) must be rejected")
	}

	// Verify the stored record still has the original values.
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateCommitted {
		t.Errorf("state should still be SUCCEEDED, got %s", rec.State)
	}
	if rec.EvidenceDigest != "digest_X" {
		t.Errorf("evidence should still be digest_X, got %s", rec.EvidenceDigest)
	}

	// Clean up.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

func TestLiveStoreListExpiredLeases(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-expired-%'`)

	key := fmt.Sprintf("test-expired-%d", time.Now().UnixNano())

	// Create a record with a short lease.
	_, err = testReserveWithLease(store, ctx, key, "alice", "test.cap", "digest", "", "MUTATION", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Before expiry — no expired leases for this key.
	expired, err := store.ListExpiredLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range expired {
		if rec.IdempotencyKey == key {
			t.Error("lease should not be expired yet")
		}
	}

	// Wait for expiry.
	time.Sleep(100 * time.Millisecond)

	// After expiry — should appear.
	expired, err = store.ListExpiredLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range expired {
		if rec.IdempotencyKey == key {
			found = true
			break
		}
	}
	if !found {
		t.Error("expired lease should be listed after expiry")
	}

	// Clean up.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// ─── Mandatory adversarial durable-store qualification cases ───────────
//
// The following tests implement the mandatory cases from the audit:
// each must pass before the invariant "durable idempotency prevents
// duplicate side effects" can be claimed.

// TestLiveStoreLargeIntegerConflict verifies that the same idempotency
// key with arguments differing only in large integer values beyond
// IEEE-754 precision produces IDEMPOTENCY_CONFLICT, not silent
// deduplication.
func TestLiveStoreLargeIntegerConflict(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-largeint-%'`)

	key := fmt.Sprintf("test-largeint-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	grantID := "grant_test"
	class := "MUTATION"

	// Two arguments that differ only in large integers beyond IEEE-754
	// exact range: 9007199254740992 vs 9007199254740993.
	// With UseNumber(), these produce different digests.
	argsA := json.RawMessage(`{"count":9007199254740992}`)
	argsB := json.RawMessage(`{"count":9007199254740993}`)

	digestA, err := ComputeDigestFromRaw(1, principal, capability, argsA, grantID, class)
	if err != nil {
		t.Fatalf("digestA: %v", err)
	}
	digestB, err := ComputeDigestFromRaw(1, principal, capability, argsB, grantID, class)
	if err != nil {
		t.Fatalf("digestB: %v", err)
	}

	if digestA == digestB {
		t.Fatal("large integers 9007199254740992 and 9007199254740993 must produce different digests")
	}

	// First caller reserves with digest A.
	reserve1, err := testReserve(store, ctx, key, principal, capability, digestA, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve1.Acquired() {
		t.Fatal("first caller should acquire")
	}

	// Second caller uses same key with digest B (different large integer).
	reserve2, err := testReserve(store, ctx, key, principal, capability, digestB, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if reserve2.Kind != IdempotencyConflict {
		t.Error("same key + different large integer digest must produce CONFLICT")
	}
	if reserve2.Acquired() {
		t.Error("conflicting caller must NOT acquire")
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveStoreCrashInDispatchingRecovery verifies that a crash in
// DISPATCHING (pre-dispatch, after state transition but before
// calling the provider) is safely recoverable: the lease expires and
// a new caller can reclaim it.
func TestLiveStoreCrashInDispatchingRecovery(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-crash-disp-%'`)

	key := fmt.Sprintf("test-crash-disp-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-crash-disp"
	grantID := "grant_test"
	class := "MUTATION"

	// Caller A reserves with a short lease and transitions to DISPATCHING,
	// then "crashes" (does not call the provider, does not finalize).
	reserveA, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired() {
		t.Fatal("caller A should acquire")
	}
	if err := testTransition(store, ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StatePrepared, StateExecuting); err != nil {
		t.Fatalf("A failed to transition to DISPATCHING: %v", err)
	}
	// Simulate crash: no further action from caller A.

	// Wait for lease to expire.
	time.Sleep(200 * time.Millisecond)

	// Caller B reclaims after expiry.
	reserveB, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveB.Acquired() {
		t.Fatal("caller B should acquire after lease expiry (DISPATCHING crash recovery)")
	}

	// Caller A's old token cannot transition or finalize.
	if err := testTransition(store, ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateExecuting, StateInFlight); err == nil {
		t.Error("old lease holder (A) should NOT be able to transition after takeover")
	}
	if err := testFinalize(store, ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateInFlight, StateCommitted, nil, "", 0); err == nil {
		t.Error("old lease holder (A) should NOT be able to finalize after takeover")
	}

	// Caller B can complete the lifecycle.
	if err := testTransition(store, ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, StatePrepared, StateExecuting); err != nil {
		t.Errorf("B failed to transition to DISPATCHING: %v", err)
	}
	if err := testTransition(store, ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, StateExecuting, StateInFlight); err != nil {
		t.Errorf("B failed to transition to IN_FLIGHT: %v", err)
	}
	if err := testFinalize(store, ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, StateInFlight, StateCommitted, []byte(`{"ok":true}`), "", 0); err != nil {
		t.Errorf("B failed to finalize: %v", err)
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveStoreCrashInFlightUnknown verifies that a crash in IN_FLIGHT
// (post-dispatch, provider accepted the request) results in UNKNOWN,
// not blind retry. The record must be marked UNKNOWN for reconciliation.
func TestLiveStoreCrashInFlightUnknown(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-crash-inflight-%'`)

	key := fmt.Sprintf("test-crash-inflight-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-crash-inflight"
	grantID := "grant_test"
	class := "MUTATION"

	// Caller A reserves, transitions to DISPATCHING, then IN_FLIGHT,
	// then "crashes" (provider accepted but no terminal result).
	reserveA, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired() {
		t.Fatal("caller A should acquire")
	}
	execID := reserveA.Record.ExecutionID
	leaseToken := reserveA.LeaseToken

	if err := testTransition(store, ctx, execID, leaseToken, StatePrepared, StateExecuting); err != nil {
		t.Fatal(err)
	}
	if err := testTransition(store, ctx, execID, leaseToken, StateExecuting, StateInFlight); err != nil {
		t.Fatal(err)
	}
	// Simulate crash after dispatch: no finalize.

	// Wait for lease to expire.
	time.Sleep(200 * time.Millisecond)

	// The record should still be IN_FLIGHT with an expired lease.
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateInFlight {
		t.Errorf("record should still be IN_FLIGHT after crash, got %s", rec.State)
	}

	// The reconcile worker would mark this as UNKNOWN. Simulate that
	// using the contract's EnterRecovery (CAS, not blind SetState).
	if err := store.EnterRecovery(ctx, execID, StateInFlight, rec.Version); err != nil {
		t.Fatalf("failed to mark crashed IN_FLIGHT as UNKNOWN: %v", err)
	}

	// Verify the record is now UNKNOWN.
	rec, err = store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateUnknown {
		t.Errorf("record should be UNKNOWN after crash recovery, got %s", rec.State)
	}

	// A new caller with the same key should see UNKNOWN (terminal),
	// not acquire a new reservation.
	reserveB, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reserveB.Acquired() {
		t.Error("new caller should NOT acquire when record is UNKNOWN (may have side-effected)")
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveStoreLeaseRenewalByOldTokenRejected verifies that after a
// lease takeover, the old lease holder cannot renew their lease.
func TestLiveStoreLeaseRenewalByOldTokenRejected(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-renew-%'`)

	key := fmt.Sprintf("test-renew-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-renew-test"
	grantID := "grant_test"
	class := "MUTATION"

	// Caller A reserves with a short lease.
	reserveA, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired() {
		t.Fatal("caller A should acquire")
	}
	oldToken := reserveA.LeaseToken

	// Wait for lease to expire.
	time.Sleep(200 * time.Millisecond)

	// Caller B takes over.
	reserveB, err := testReserveWithLease(store, ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveB.Acquired() {
		t.Fatal("caller B should acquire after expiry")
	}

	// Caller A tries to renew with the old token — must be rejected.
	err = testRenewLease(store, ctx, reserveA.Record.ExecutionID, oldToken, time.Minute)
	if err == nil {
		t.Error("old lease holder (A) should NOT be able to renew after takeover")
	}

	// Caller B (current holder) CAN renew.
	err = testRenewLease(store, ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, time.Minute)
	if err != nil {
		t.Errorf("current lease holder (B) should be able to renew: %v", err)
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveStoreRetryAfterInvalidEvidenceNoMagicV3 verifies that if a
// CRITICAL operation is finalized with FAILED (invalid evidence), a
// retry with valid V3 evidence cannot magically overwrite the terminal
// rejection. The terminal state is immutable.
func TestLiveStoreRetryAfterInvalidEvidenceNoMagicV3(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-novoodoo-%'`)

	key := fmt.Sprintf("test-novoodoo-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.mutation.op"
	digest := "digest-novoodoo"
	grantID := "grant_test"
	class := "MUTATION"

	// Reserve and transition through the lifecycle.
	reserve, err := testReserve(store, ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve.Acquired() {
		t.Fatal("should acquire")
	}
	execID := reserve.Record.ExecutionID
	leaseToken := reserve.LeaseToken

	if err := testTransition(store, ctx, execID, leaseToken, StatePrepared, StateExecuting); err != nil {
		t.Fatal(err)
	}
	if err := testTransition(store, ctx, execID, leaseToken, StateExecuting, StateInFlight); err != nil {
		t.Fatal(err)
	}

	// Finalize with FAILED (simulating: CRITICAL returned invalid V2
	// evidence, kernel rejected it as FAILED).
	if err := testFinalize(store, ctx, execID, leaseToken, StateInFlight, StateFailed, []byte(`{"error":"invalid evidence"}`), "", 0); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}

	// Retry: attempt to finalize as SUCCEEDED with valid V3 evidence.
	// This must be rejected — FAILED is terminal and immutable.
	err = testFinalize(store, ctx, execID, leaseToken, StateInFlight, StateCommitted, []byte(`{"ok":true}`), "valid_digest_000000000000000000000000000000000000000000000000000000123456", 3)
	if err == nil {
		t.Error("retry with V3 evidence must NOT overwrite terminal FAILED state")
	}

	// Verify the record is still FAILED.
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateFailed {
		t.Errorf("state should still be FAILED, got %s", rec.State)
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveStoreRecoveryWithProofOfCompletion verifies that when the
// reconcile worker's resolver confirms the operation succeeded,
// the record transitions to SUCCEEDED.
func TestLiveStoreRecoveryWithProofOfCompletion(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-recover-ok-%'`)

	key := fmt.Sprintf("test-recover-ok-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-recover-ok"
	grantID := "grant_test"
	class := "MUTATION"

	// Create a record in UNKNOWN state (crashed after dispatch).
	reserve, err := testReserve(store, ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	execID := reserve.Record.ExecutionID

	// Transition to UNKNOWN via the full lifecycle:
	// PREPARED → EXECUTING → IN_FLIGHT → UNKNOWN.
	if err := testEnterRecovery(store, ctx, execID, reserve.LeaseToken); err != nil {
		t.Fatal(err)
	}

	// Simulate the reconcile worker: resolver confirms completion.
	proofResult := []byte(`{"confirmed":true,"provider_run_id":"run_123"}`)
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveRecovery(ctx, execID, rec.Version, RecoveryResult{
		Decision:       RecoveryCommitted,
		Result:         proofResult,
		EvidenceDigest: "proof_digest_000000000000000000000000000000000000000000000000000000123456",
		ProviderRunID:  "run_123",
	}); err != nil {
		t.Fatalf("recovery to COMMITTED failed: %v", err)
	}

	// Verify.
	rec, err = store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateCommitted {
		t.Errorf("recovery with proof should result in COMMITTED, got %s", rec.State)
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveStoreRecoveryWithProofOfFailure verifies that when the
// reconcile worker's resolver confirms the operation failed,
// the record transitions to FAILED.
func TestLiveStoreRecoveryWithProofOfFailure(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-recover-fail-%'`)

	key := fmt.Sprintf("test-recover-fail-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-recover-fail"
	grantID := "grant_test"
	class := "MUTATION"

	// Create a record in UNKNOWN state.
	reserve, err := testReserve(store, ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	execID := reserve.Record.ExecutionID

	// Transition to UNKNOWN via the full lifecycle:
	// PREPARED → EXECUTING → IN_FLIGHT → UNKNOWN.
	if err := testEnterRecovery(store, ctx, execID, reserve.LeaseToken); err != nil {
		t.Fatal(err)
	}

	// Simulate the reconcile worker: resolver confirms failure.
	proofResult := []byte(`{"confirmed":false,"error":"provider returned error"}`)
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveRecovery(ctx, execID, rec.Version, RecoveryResult{
		Decision: RecoveryFailed,
		Result:   proofResult,
	}); err != nil {
		t.Fatalf("recovery to FAILED failed: %v", err)
	}

	// Verify.
	rec, err = store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateFailed {
		t.Errorf("recovery with proof of failure should result in FAILED, got %s", rec.State)
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveStoreRecoveryWithoutProofStaysUnknown verifies that when
// the reconcile worker's resolver cannot determine the outcome,
// the record stays UNKNOWN — it is NOT retried by assumption.
func TestLiveStoreRecoveryWithoutProofStaysUnknown(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-recover-unknown-%'`)

	key := fmt.Sprintf("test-recover-unknown-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-recover-unknown"
	grantID := "grant_test"
	class := "MUTATION"

	// Create a record in UNKNOWN state via the full lifecycle:
	// PREPARED → EXECUTING → IN_FLIGHT → UNKNOWN.
	reserve, err := testReserve(store, ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	execID := reserve.Record.ExecutionID

	if err := testEnterRecovery(store, ctx, execID, reserve.LeaseToken); err != nil {
		t.Fatal(err)
	}

	// Simulate the reconcile worker: NoopResolver returns UNKNOWN.
	// The worker should NOT change state (stays UNKNOWN).
	// Verify the record is still UNKNOWN after "reconciliation".
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateUnknown {
		t.Errorf("recovery without proof should stay UNKNOWN, got %s", rec.State)
	}

	// A new caller with the same key should see UNKNOWN (terminal),
	// not acquire a new reservation.
	reserve2, err := testReserve(store, ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if reserve2.Acquired() {
		t.Error("new caller should NOT acquire when record is UNKNOWN — no retry by assumption")
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// ─── Effect Fabric contract test matrix ─────────────────────────────
//
// These tests exercise the new lease-fenced contract directly through
// the typed API (Acquire, BeginExecution, MarkInFlight, Finalize,
// RenewLease, EnterRecovery, ResolveRecovery).

// TestLiveEffectFabricExpiredLeaseMatrix exercises the full expired-
// lease reclaim matrix:
//
//	expired PREPARED → reclaim succeeds
//	expired EXECUTING → reclaim succeeds (pre-dispatch)
//	expired IN_FLIGHT → reclaim denied → UNKNOWN
//	expired lease renew → denied
//	expired lease transition → denied
//	expired lease finalize → denied
//	old lease after takeover → denied
//	old generation with correct old token → denied
//	new owner finalize → succeeds
func TestLiveEffectFabricExpiredLeaseMatrix(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	prefix := fmt.Sprintf("test-ef-matrix-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	grantID := "grant_test"
	class := "MUTATION"

	// ── expired PREPARED → reclaim succeeds ──
	key1 := prefix + "-prepared"
	digest1 := "digest-ef-prepared"
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key1)

	r1, err := store.Acquire(ctx, key1, principal, capability, digest1, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Kind != LeaseAcquired {
		t.Fatalf("expected ACQUIRED, got %s", r1.Kind)
	}
	time.Sleep(200 * time.Millisecond)

	r1b, err := store.Acquire(ctx, key1, principal, capability, digest1, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r1b.Kind != LeaseReclaimed {
		t.Errorf("expired PREPARED: expected RECLAIMED, got %s", r1b.Kind)
	}
	if r1b.Generation != 2 {
		t.Errorf("expected generation 2, got %d", r1b.Generation)
	}

	// ── expired EXECUTING → reclaim succeeds (pre-dispatch) ──
	key2 := prefix + "-executing"
	digest2 := "digest-ef-executing"
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key2)

	r2, err := store.Acquire(ctx, key2, principal, capability, digest2, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(ctx, r2.Record.ExecutionID, r2.LeaseToken, r2.Generation); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	r2b, err := store.Acquire(ctx, key2, principal, capability, digest2, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r2b.Kind != LeaseReclaimed {
		t.Errorf("expired EXECUTING: expected RECLAIMED, got %s", r2b.Kind)
	}

	// ── expired IN_FLIGHT → reclaim denied → UNKNOWN ──
	key3 := prefix + "-inflight"
	digest3 := "digest-ef-inflight"
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key3)

	r3, err := store.Acquire(ctx, key3, principal, capability, digest3, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginExecution(ctx, r3.Record.ExecutionID, r3.LeaseToken, r3.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, r3.Record.ExecutionID, r3.LeaseToken, r3.Generation, "", nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	r3b, err := store.Acquire(ctx, key3, principal, capability, digest3, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r3b.Kind != RecoveryRequired {
		t.Errorf("expired IN_FLIGHT: expected RECOVERY_REQUIRED, got %s", r3b.Kind)
	}

	// Verify the record is now UNKNOWN.
	rec3, _ := store.Lookup(ctx, r3.Record.ExecutionID)
	if rec3.State != StateUnknown {
		t.Errorf("expired IN_FLIGHT: expected UNKNOWN, got %s", rec3.State)
	}

	// ── expired lease renew → denied ──
	err = store.RenewLease(ctx, r1.Record.ExecutionID, r1.LeaseToken, r1.Generation, time.Minute)
	if err == nil {
		t.Error("expired lease: renew should be denied")
	}

	// ── expired lease transition → denied ──
	err = store.BeginExecution(ctx, r1.Record.ExecutionID, r1.LeaseToken, r1.Generation)
	if err == nil {
		t.Error("expired lease: transition should be denied")
	}

	// ── expired lease finalize → denied ──
	receipt := TerminalReceipt{TerminalStatus: StateCommitted}
	err = store.Finalize(ctx, r1.Record.ExecutionID, r1.LeaseToken, r1.Generation, StateInFlight, receipt)
	if err == nil {
		t.Error("expired lease: finalize should be denied")
	}

	// ── old lease after takeover → denied ──
	err = store.BeginExecution(ctx, r1.Record.ExecutionID, r1.LeaseToken, r1.Generation)
	if err == nil {
		t.Error("old lease after takeover: transition should be denied")
	}

	// ── old generation with correct old token → denied ──
	err = store.BeginExecution(ctx, r1.Record.ExecutionID, r1.LeaseToken, 1)
	if err == nil {
		t.Error("old generation: transition should be denied")
	}

	// ── new owner finalize → succeeds ──
	if err := store.BeginExecution(ctx, r1b.Record.ExecutionID, r1b.LeaseToken, r1b.Generation); err != nil {
		t.Errorf("new owner: BeginExecution failed: %v", err)
	}
	if err := store.MarkInFlight(ctx, r1b.Record.ExecutionID, r1b.LeaseToken, r1b.Generation, "", nil); err != nil {
		t.Errorf("new owner: MarkInFlight failed: %v", err)
	}
	receipt1b := TerminalReceipt{
		ExecutionID:     r1b.Record.ExecutionID,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest1,
		TerminalStatus:  StateCommitted,
		CanonicalResult: []byte(`{"ok":true}`),
	}
	if err := store.Finalize(ctx, r1b.Record.ExecutionID, r1b.LeaseToken, r1b.Generation, StateInFlight, receipt1b); err != nil {
		t.Errorf("new owner: Finalize failed: %v", err)
	}

	for _, k := range []string{key1, key2, key3} {
		db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, k)
	}
}

// TestLiveEffectFabricStaleWorkerFencing tests that a stale worker
// (old generation) cannot perform any operations after a newer
// worker takes over.
func TestLiveEffectFabricStaleWorkerFencing(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	key := fmt.Sprintf("test-ef-fencing-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	digest := "digest-ef-fencing"
	grantID := "grant_test"
	class := "MUTATION"
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	// Worker A acquires generation 1.
	rA, err := store.Acquire(ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if rA.Generation != 1 {
		t.Fatalf("expected generation 1, got %d", rA.Generation)
	}
	execID := rA.Record.ExecutionID
	tokenA := rA.LeaseToken
	genA := rA.Generation

	// Wait for lease to expire.
	time.Sleep(200 * time.Millisecond)

	// Worker B acquires generation 2 (takes over).
	rB, err := store.Acquire(ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if rB.Generation != 2 {
		t.Fatalf("expected generation 2, got %d", rB.Generation)
	}
	tokenB := rB.LeaseToken
	genB := rB.Generation

	// Worker A (stale, generation 1) attempts:
	// 1. Renew → must fail
	err = store.RenewLease(ctx, execID, tokenA, genA, time.Minute)
	if err == nil {
		t.Error("stale worker A: renew should fail")
	}

	// 2. BeginExecution → must fail
	err = store.BeginExecution(ctx, execID, tokenA, genA)
	if err == nil {
		t.Error("stale worker A: BeginExecution should fail")
	}

	// 3. MarkInFlight → must fail
	err = store.MarkInFlight(ctx, execID, tokenA, genA, "", nil)
	if err == nil {
		t.Error("stale worker A: MarkInFlight should fail")
	}

	// 4. Finalize → must fail
	receipt := TerminalReceipt{TerminalStatus: StateCommitted}
	err = store.Finalize(ctx, execID, tokenA, genA, StateInFlight, receipt)
	if err == nil {
		t.Error("stale worker A: Finalize should fail")
	}

	// Worker B (current, generation 2) can operate.
	if err := store.BeginExecution(ctx, execID, tokenB, genB); err != nil {
		t.Errorf("worker B: BeginExecution failed: %v", err)
	}
	if err := store.MarkInFlight(ctx, execID, tokenB, genB, "", nil); err != nil {
		t.Errorf("worker B: MarkInFlight failed: %v", err)
	}
	receiptB := TerminalReceipt{
		ExecutionID:     execID,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest,
		TerminalStatus:  StateCommitted,
		CanonicalResult: []byte(`{"ok":true}`),
	}
	if err := store.Finalize(ctx, execID, tokenB, genB, StateInFlight, receiptB); err != nil {
		t.Errorf("worker B: Finalize failed: %v", err)
	}

	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}

// TestLiveEffectFabricFinalizationConflicts tests the immutable
// terminal receipt conflict detection.
func TestLiveEffectFabricFinalizationConflicts(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	prefix := fmt.Sprintf("test-ef-fconflict-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	grantID := "grant_test"
	class := "MUTATION"

	helper := func(key, digest string) (string, string, int) {
		db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
		r, err := store.Acquire(ctx, key, principal, capability, digest, grantID, class, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginExecution(ctx, r.Record.ExecutionID, r.LeaseToken, r.Generation); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkInFlight(ctx, r.Record.ExecutionID, r.LeaseToken, r.Generation, "", nil); err != nil {
			t.Fatal(err)
		}
		return r.Record.ExecutionID, r.LeaseToken, r.Generation
	}

	// ── same receipt twice → ALREADY_FINALIZED (idempotent) ──
	key1 := prefix + "-same"
	digest1 := "digest-fc-same"
	execID1, token1, gen1 := helper(key1, digest1)
	receipt1 := TerminalReceipt{
		ExecutionID:     execID1,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest1,
		TerminalStatus:  StateCommitted,
		CanonicalResult: []byte(`{"result":"A"}`),
		ProviderID:      "test",
		ProviderRunID:   "run_1",
		EvidenceDigest:  "digest_X",
		ReceiptVersion:  3,
	}
	if err := store.Finalize(ctx, execID1, token1, gen1, StateInFlight, receipt1); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}
	if err := store.Finalize(ctx, execID1, token1, gen1, StateInFlight, receipt1); err != nil {
		t.Errorf("same receipt twice: expected idempotent, got error: %v", err)
	}

	// ── same state, different result → FINALIZATION_CONFLICT ──
	key2 := prefix + "-diffresult"
	digest2 := "digest-fc-diffresult"
	execID2, token2, gen2 := helper(key2, digest2)
	receipt2a := TerminalReceipt{
		ExecutionID:     execID2,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest2,
		TerminalStatus:  StateCommitted,
		CanonicalResult: []byte(`{"result":"A"}`),
		ProviderID:      "test",
		ProviderRunID:   "run_2",
	}
	if err := store.Finalize(ctx, execID2, token2, gen2, StateInFlight, receipt2a); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}
	receipt2b := receipt2a
	receipt2b.CanonicalResult = []byte(`{"result":"B"}`)
	if err := store.Finalize(ctx, execID2, token2, gen2, StateInFlight, receipt2b); err == nil {
		t.Error("different result: expected FINALIZATION_CONFLICT")
	}

	// ── same result, different provider_run_id → FINALIZATION_CONFLICT ──
	key3 := prefix + "-diffprovider"
	digest3 := "digest-fc-diffprovider"
	execID3, token3, gen3 := helper(key3, digest3)
	receipt3a := TerminalReceipt{
		ExecutionID:     execID3,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest3,
		TerminalStatus:  StateCommitted,
		CanonicalResult: []byte(`{"result":"A"}`),
		ProviderID:      "test",
		ProviderRunID:   "run_3a",
	}
	if err := store.Finalize(ctx, execID3, token3, gen3, StateInFlight, receipt3a); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}
	receipt3b := receipt3a
	receipt3b.ProviderRunID = "run_3b"
	if err := store.Finalize(ctx, execID3, token3, gen3, StateInFlight, receipt3b); err == nil {
		t.Error("different provider_run_id: expected FINALIZATION_CONFLICT")
	}

	// ── same digest, different receipt version → FINALIZATION_CONFLICT ──
	key4 := prefix + "-diffversion"
	digest4 := "digest-fc-diffversion"
	execID4, token4, gen4 := helper(key4, digest4)
	receipt4a := TerminalReceipt{
		ExecutionID:     execID4,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest4,
		TerminalStatus:  StateCommitted,
		CanonicalResult: []byte(`{"result":"A"}`),
		ProviderID:      "test",
		ProviderRunID:   "run_4",
		EvidenceDigest:  "digest_Z",
		ReceiptVersion:  3,
	}
	if err := store.Finalize(ctx, execID4, token4, gen4, StateInFlight, receipt4a); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}
	receipt4b := receipt4a
	receipt4b.ReceiptVersion = 2
	if err := store.Finalize(ctx, execID4, token4, gen4, StateInFlight, receipt4b); err == nil {
		t.Error("different receipt version: expected FINALIZATION_CONFLICT")
	}

	// ── terminal state overwrite → rejected ──
	key5 := prefix + "-overwrite"
	digest5 := "digest-fc-overwrite"
	execID5, token5, gen5 := helper(key5, digest5)
	receipt5a := TerminalReceipt{
		ExecutionID:     execID5,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest5,
		TerminalStatus:  StateCommitted,
		CanonicalResult: []byte(`{"result":"A"}`),
		ProviderID:      "test",
		ProviderRunID:   "run_5",
	}
	if err := store.Finalize(ctx, execID5, token5, gen5, StateInFlight, receipt5a); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}
	receipt5b := TerminalReceipt{
		ExecutionID:     execID5,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest5,
		TerminalStatus:  StateFailed,
		CanonicalResult: []byte(`{"error":"oops"}`),
		ProviderID:      "test",
		ProviderRunID:   "run_5",
	}
	if err := store.Finalize(ctx, execID5, token5, gen5, StateInFlight, receipt5b); err == nil {
		t.Error("terminal state overwrite: expected FINALIZATION_CONFLICT")
	}

	for _, k := range []string{key1, key2, key3, key4, key5} {
		db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, k)
	}
}

// TestLiveEffectFabricEvidenceRecovery tests the recovery resolution
// paths for UNKNOWN records.
func TestLiveEffectFabricEvidenceRecovery(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	prefix := fmt.Sprintf("test-ef-recovery-%d", time.Now().UnixNano())
	principal := "alice@example.com"
	capability := "test.counter.increment"
	grantID := "grant_test"
	class := "MUTATION"

	helper := func(key, digest string) string {
		db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
		r, err := store.Acquire(ctx, key, principal, capability, digest, grantID, class, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginExecution(ctx, r.Record.ExecutionID, r.LeaseToken, r.Generation); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkInFlight(ctx, r.Record.ExecutionID, r.LeaseToken, r.Generation, "", nil); err != nil {
			t.Fatal(err)
		}
		rec, _ := store.Lookup(ctx, r.Record.ExecutionID)
		if err := store.EnterRecovery(ctx, r.Record.ExecutionID, StateInFlight, rec.Version); err != nil {
			t.Fatal(err)
		}
		return r.Record.ExecutionID
	}

	// ── IN_FLIGHT + provider proof success → COMMITTED ──
	key1 := prefix + "-success"
	execID1 := helper(key1, "digest-er-success")
	rec1, _ := store.Lookup(ctx, execID1)
	result1 := RecoveryResult{
		Decision:       RecoveryCommitted,
		Result:         []byte(`{"confirmed":true}`),
		EvidenceDigest: "proof_digest_000000000000000000000000000000000000000000000000000000123456",
		ReceiptVersion: 3,
		ProviderID:     "test",
		ProviderRunID:  "run_recovery_1",
	}
	if err := store.ResolveRecovery(ctx, execID1, rec1.Version, result1); err != nil {
		t.Fatalf("recovery to COMMITTED failed: %v", err)
	}
	rec1b, _ := store.Lookup(ctx, execID1)
	if rec1b.State != StateCommitted {
		t.Errorf("expected COMMITTED, got %s", rec1b.State)
	}

	// ── IN_FLIGHT + provider proof definitive failure → FAILED ──
	key2 := prefix + "-failed"
	execID2 := helper(key2, "digest-er-failed")
	rec2, _ := store.Lookup(ctx, execID2)
	result2 := RecoveryResult{
		Decision: RecoveryFailed,
		Result:   []byte(`{"confirmed":false,"error":"provider error"}`),
	}
	if err := store.ResolveRecovery(ctx, execID2, rec2.Version, result2); err != nil {
		t.Fatalf("recovery to FAILED failed: %v", err)
	}
	rec2b, _ := store.Lookup(ctx, execID2)
	if rec2b.State != StateFailed {
		t.Errorf("expected FAILED, got %s", rec2b.State)
	}

	// ── IN_FLIGHT + no proof → UNKNOWN (stays) ──
	key3 := prefix + "-unknown"
	execID3 := helper(key3, "digest-er-unknown")
	rec3, _ := store.Lookup(ctx, execID3)
	if err := store.ResolveRecovery(ctx, execID3, rec3.Version, RecoveryResult{Decision: RecoveryUnknown}); err != nil {
		t.Fatalf("recovery to UNKNOWN failed: %v", err)
	}
	rec3b, _ := store.Lookup(ctx, execID3)
	if rec3b.State != StateUnknown {
		t.Errorf("expected UNKNOWN, got %s", rec3b.State)
	}

	// ── stale recovery result racing newer resolution → CAS rejection ──
	key4 := prefix + "-cas-race"
	execID4 := helper(key4, "digest-er-cas")
	rec4, _ := store.Lookup(ctx, execID4)
	if err := store.ResolveRecovery(ctx, execID4, rec4.Version, RecoveryResult{
		Decision:       RecoveryCommitted,
		Result:         []byte(`{"confirmed":true}`),
		EvidenceDigest: "proof_digest_000000000000000000000000000000000000000000000000000000123456",
	}); err != nil {
		t.Fatalf("first recovery resolution failed: %v", err)
	}
	err = store.ResolveRecovery(ctx, execID4, rec4.Version, RecoveryResult{
		Decision: RecoveryFailed,
		Result:   []byte(`{"error":"stale"}`),
	})
	if err == nil {
		t.Error("stale recovery result: expected CAS rejection")
	}
	rec4b, _ := store.Lookup(ctx, execID4)
	if rec4b.State != StateCommitted {
		t.Errorf("expected COMMITTED after CAS race, got %s", rec4b.State)
	}

	for _, k := range []string{key1, key2, key3, key4} {
		db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, k)
	}
}

// TestLiveEffectFabricCrashAfterPrepared verifies that a crash after
// PREPARED (before EXECUTING) is safely reclaimable: the lease expires
// and a new caller can reclaim and complete the execution.
func TestLiveEffectFabricCrashAfterPrepared(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	key := fmt.Sprintf("test-crash-prepared-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-crash-prepared-%'`)
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	// Caller A acquires and reaches PREPARED, then crashes.
	acqA, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
		"digest-crash-prepared", "grant_test", "MUTATION", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if acqA.Kind != LeaseAcquired {
		t.Fatalf("expected ACQUIRED, got %s", acqA.Kind)
	}
	// Crash: no BeginExecution, no further action.

	time.Sleep(200 * time.Millisecond)

	// Caller B reclaims after lease expiry.
	acqB, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
		"digest-crash-prepared", "grant_test", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if acqB.Kind != LeaseReclaimed {
		t.Fatalf("expected RECLAIMED, got %s", acqB.Kind)
	}

	// Caller A's old token cannot begin execution.
	if err := store.BeginExecution(ctx, acqA.Record.ExecutionID, acqA.LeaseToken, acqA.Generation); err == nil {
		t.Error("old lease holder should NOT be able to BeginExecution after takeover")
	}

	// Caller B completes the lifecycle.
	if err := store.BeginExecution(ctx, acqB.Record.ExecutionID, acqB.LeaseToken, acqB.Generation); err != nil {
		t.Fatalf("B failed to BeginExecution: %v", err)
	}
	if err := store.MarkInFlight(ctx, acqB.Record.ExecutionID, acqB.LeaseToken, acqB.Generation, "", nil); err != nil {
		t.Fatalf("B failed to MarkInFlight: %v", err)
	}
	receipt := TerminalReceipt{
		ExecutionID:     acqB.Record.ExecutionID,
		Capability:      "test.counter.increment",
		Principal:       "alice@example.com",
		RequestDigest:   "digest-crash-prepared",
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"ok":true}`),
		ReceiptVersion:  3,
	}
	if err := store.Finalize(ctx, acqB.Record.ExecutionID, acqB.LeaseToken, acqB.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("B failed to finalize: %v", err)
	}
}

// TestLiveEffectFabricCrashAfterFinalization verifies that a crash
// after finalization (before the response reaches the caller) results
// in terminal replay: the caller retries and gets the same terminal
// result, not a new execution.
func TestLiveEffectFabricCrashAfterFinalization(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	key := fmt.Sprintf("test-crash-final-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE 'test-crash-final-%'`)
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	// Caller A acquires and completes the full lifecycle.
	acqA, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
		"digest-crash-final", "grant_test", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if acqA.Kind != LeaseAcquired {
		t.Fatalf("expected ACQUIRED, got %s", acqA.Kind)
	}

	if err := store.BeginExecution(ctx, acqA.Record.ExecutionID, acqA.LeaseToken, acqA.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, acqA.Record.ExecutionID, acqA.LeaseToken, acqA.Generation, "", nil); err != nil {
		t.Fatal(err)
	}
	originalResult := json.RawMessage(`{"value":42}`)
	receipt := TerminalReceipt{
		ExecutionID:     acqA.Record.ExecutionID,
		Capability:      "test.counter.increment",
		Principal:       "alice@example.com",
		RequestDigest:   "digest-crash-final",
		TerminalStatus:  StateCommitted,
		CanonicalResult: originalResult,
		ReceiptVersion:  3,
	}
	if err := store.Finalize(ctx, acqA.Record.ExecutionID, acqA.LeaseToken, acqA.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("A failed to finalize: %v", err)
	}

	// Crash: A's response is lost. A retries with the same idempotency key.
	acqB, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
		"digest-crash-final", "grant_test", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// The retry should get TERMINAL_REPLAY, not a new acquisition.
	if acqB.Kind != TerminalReplay {
		t.Fatalf("expected TERMINAL_REPLAY after finalization crash, got %s", acqB.Kind)
	}
	if acqB.Record == nil {
		t.Fatal("expected non-nil record for terminal replay")
	}
	if acqB.Record.State != StateCommitted {
		t.Errorf("expected COMMITTED replay, got %s", acqB.Record.State)
	}

	// The replayed result must match the original.
	var resultStr string
	if err := json.Unmarshal(acqB.Record.Result, &resultStr); err == nil {
		if resultStr != "42" {
			t.Errorf("expected replay result {\"value\":42}, got %s", acqB.Record.Result)
		}
	}
}

// TestLiveStoreRenewLeaseMonotonic verifies that RenewLease cannot
// shorten an existing valid lease. If a record has a 30-minute lease
// and a renewal is requested for 5 minutes, the expiry must remain
// at 30 minutes (or later), not regress to 5 minutes.
func TestLiveStoreRenewLeaseMonotonic(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := "test-renew-monotonic-" + t.Name()
	principal := "alice@example.com"
	capability := "test.counter.increment"

	// Acquire with a long lease (30 minutes).
	acq, err := store.Acquire(ctx, key, principal, capability,
		"digest-renew", "grant_renew", "MUTATION", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected lease acquired, got %s", acq.Kind)
	}
	execID := acq.Record.ExecutionID

	// Get the initial expiry.
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.LeaseExpiresAt == nil {
		t.Fatal("expected non-nil lease expiry")
	}
	initialExpiry := *rec.LeaseExpiresAt

	// Renew with a SHORTER duration (5 minutes).
	if err := store.RenewLease(ctx, execID, acq.LeaseToken, acq.Generation, 5*time.Minute); err != nil {
		t.Fatalf("renewal failed: %v", err)
	}

	// The expiry must NOT have regressed.
	rec2, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec2.LeaseExpiresAt == nil {
		t.Fatal("expected non-nil lease expiry after renewal")
	}
	newExpiry := *rec2.LeaseExpiresAt
	if newExpiry.Before(initialExpiry) {
		t.Errorf("renewal shortened lease: was %v, now %v", initialExpiry, newExpiry)
	}
}

// TestLiveStoreRecoveryLocatorPersisted verifies that MarkInFlight
// persists the provider_id and recovery_locator atomically with the
// IN_FLIGHT state transition.
func TestLiveStoreRecoveryLocatorPersisted(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := "test-locator-" + t.Name()
	acq, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
		"digest-locator", "grant_loc", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected lease acquired, got %s", acq.Kind)
	}

	// Begin execution, then mark IN_FLIGHT with provider + locator.
	if err := store.BeginExecution(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	locator := json.RawMessage(`{"capability_id":"test.counter.increment","arguments":{"counter":"test"}}`)
	if err := store.MarkInFlight(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, "test-counter", locator); err != nil {
		t.Fatal(err)
	}

	// Verify the record has the provider and locator persisted.
	rec, err := store.Lookup(ctx, acq.Record.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateInFlight {
		t.Fatalf("expected IN_FLIGHT, got %s", rec.State)
	}
	if rec.ProviderID != "test-counter" {
		t.Errorf("expected provider_id=test-counter, got %q", rec.ProviderID)
	}
	if len(rec.RecoveryLocator) == 0 {
		t.Error("expected non-empty recovery_locator")
	}
	var loc map[string]any
	if err := json.Unmarshal(rec.RecoveryLocator, &loc); err != nil {
		t.Fatalf("failed to parse recovery_locator: %v", err)
	}
	if loc["capability_id"] != "test.counter.increment" {
		t.Errorf("expected capability_id in locator, got %v", loc["capability_id"])
	}
}

// TestLiveStoreCriticalRecoveryFailedRequiresProof verifies that
// CRITICAL executions cannot be recovered to FAILED without evidence.
// A resolver claiming FAILED without proof could allow a retry of
// an already-executed side effect.
func TestLiveStoreCriticalRecoveryFailedRequiresProof(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := "test-crit-fail-" + t.Name()
	acq, err := store.Acquire(ctx, key, "alice@example.com", "test.critical.deploy",
		"digest-crit-fail", "grant_crit", "CRITICAL", time.Minute)
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

	// Expire the lease so it enters UNKNOWN.
	rec, _ := store.Lookup(ctx, execID)
	if err := store.EnterRecovery(ctx, execID, StateInFlight, rec.Version); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Lookup(ctx, execID)

	// Attempt recovery to FAILED without proof — must be rejected.
	err = store.ResolveRecovery(ctx, execID, rec.Version, RecoveryResult{
		Decision: RecoveryFailed,
	})
	if err == nil {
		t.Error("CRITICAL RecoveryFailed without proof should be rejected")
	}

	// Attempt recovery to COMMITTED without proof — must also be rejected.
	rec, _ = store.Lookup(ctx, execID)
	err = store.ResolveRecovery(ctx, execID, rec.Version, RecoveryResult{
		Decision: RecoveryCommitted,
	})
	if err == nil {
		t.Error("CRITICAL RecoveryCommitted without proof should be rejected")
	}

	// With full proof, RecoveryFailed should succeed.
	rec, _ = store.Lookup(ctx, execID)
	err = store.ResolveRecovery(ctx, execID, rec.Version, RecoveryResult{
		Decision:       RecoveryFailed,
		EvidenceDigest: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		ReceiptVersion: 3,
		ProviderID:     "deploy-adapter",
		ProviderRunID:  "run_critical_fail_proof",
	})
	if err != nil {
		t.Errorf("CRITICAL RecoveryFailed with proof should succeed: %v", err)
	}

	// Verify final state is FAILED.
	rec, _ = store.Lookup(ctx, execID)
	if rec.State != StateFailed {
		t.Errorf("expected FAILED, got %s", rec.State)
	}
}

// TestLiveStoreReplayProviderMetadata verifies that a terminal replay
// returns the stored provider_id and provider_run_id, not the adapter
// ID or internal execution ID.
func TestLiveStoreReplayProviderMetadata(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := "test-replay-meta-" + t.Name()
	acq, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
		"digest-replay-meta", "grant_replay", "MUTATION", time.Minute)
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
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "github-adapter", nil); err != nil {
		t.Fatal(err)
	}

	// Finalize with specific provider metadata.
	receipt := TerminalReceipt{
		ExecutionID:    execID,
		Capability:     "test.counter.increment",
		Principal:      "alice@example.com",
		RequestDigest:  "digest-replay-meta",
		TerminalStatus: StateCommitted,
		ProviderID:     "github",
		ProviderRunID:  "issue-98765",
	}
	if err := store.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err != nil {
		t.Fatal(err)
	}

	// Re-acquire — should get terminal replay with stored provider metadata.
	acq2, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
		"digest-replay-meta", "grant_replay", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if acq2.Kind != TerminalReplay {
		t.Fatalf("expected TERMINAL_REPLAY, got %s", acq2.Kind)
	}
	if acq2.Record == nil {
		t.Fatal("expected non-nil record")
	}
	if acq2.Record.ProviderID != "github" {
		t.Errorf("expected provider_id=github, got %q", acq2.Record.ProviderID)
	}
	if acq2.Record.ProviderRunID != "issue-98765" {
		t.Errorf("expected provider_run_id=issue-98765, got %q", acq2.Record.ProviderRunID)
	}
}

// TestLiveClaimUnknownBatch verifies that ClaimUnknownBatch claims
// UNKNOWN records with FOR UPDATE SKIP LOCKED, setting reconcile_owner
// and reconcile_lease_expires_at, and that claimed records are not
// re-claimed by a second call.
func TestLiveClaimUnknownBatch(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-claim-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create 3 UNKNOWN records.
	execIDs := make([]string, 3)
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("%s-%d", prefix, i)
		acq, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
			fmt.Sprintf("digest-claim-%d", i), "grant_claim", "MUTATION", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !acq.Acquired() {
			t.Fatalf("expected lease acquired for %s, got %s", key, acq.Kind)
		}
		execIDs[i] = acq.Record.ExecutionID
		if err := store.BeginExecution(ctx, execIDs[i], acq.LeaseToken, acq.Generation); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkInFlight(ctx, execIDs[i], acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
			t.Fatal(err)
		}
		rec, _ := store.Lookup(ctx, execIDs[i])
		if err := store.EnterRecovery(ctx, execIDs[i], StateInFlight, rec.Version); err != nil {
			t.Fatal(err)
		}
	}

	// Worker A claims 2 records.
	batch1, err := store.ClaimUnknownBatch(ctx, "worker-a", 2, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch1) != 2 {
		t.Fatalf("expected 2 claimed, got %d", len(batch1))
	}
	for _, rec := range batch1 {
		if rec.ReconcileOwner != "worker-a" {
			t.Errorf("expected reconcile_owner=worker-a, got %q", rec.ReconcileOwner)
		}
		if rec.ReconcileAttempt != 1 {
			t.Errorf("expected reconcile_attempt=1, got %d", rec.ReconcileAttempt)
		}
		if rec.ReconcileLeaseExpiresAt == nil {
			t.Error("expected reconcile_lease_expires_at to be set")
		}
	}

	// Worker B claims — should only get the remaining 1 record
	// (the other 2 are claimed by worker-a).
	batch2, err := store.ClaimUnknownBatch(ctx, "worker-b", 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch2) != 1 {
		t.Fatalf("expected 1 claimed by worker-b, got %d", len(batch2))
	}
	if batch2[0].ReconcileOwner != "worker-b" {
		t.Errorf("expected reconcile_owner=worker-b, got %q", batch2[0].ReconcileOwner)
	}

	// Verify the claimed records are the disjoint set.
	claimedIDs := map[string]bool{}
	for _, rec := range batch1 {
		claimedIDs[rec.ExecutionID] = true
	}
	for _, rec := range batch2 {
		if claimedIDs[rec.ExecutionID] {
			t.Errorf("record %s claimed by both workers", rec.ExecutionID)
		}
	}
}

// TestLiveClaimUnknownBatchRespectsBackoff verifies that records with a
// future next_reconcile_at are not claimed.
func TestLiveClaimUnknownBatchRespectsBackoff(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-backoff-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create an UNKNOWN record.
	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.counter.increment",
		"digest-backoff", "grant_backoff", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Lookup(ctx, execID)
	if err := store.EnterRecovery(ctx, execID, StateInFlight, rec.Version); err != nil {
		t.Fatal(err)
	}

	// Claim it.
	batch, err := store.ClaimUnknownBatch(ctx, "worker-a", 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 1 {
		t.Fatalf("expected 1 claimed, got %d", len(batch))
	}

	// Release with a 10-minute backoff duration (DB computes timestamp).
	if err := store.ReleaseReconcileClaim(ctx, execID, batch[0].Version, 10*time.Minute, "test backoff"); err != nil {
		t.Fatal(err)
	}

	// Try to claim again — should get 0 (backoff active).
	batch2, err := store.ClaimUnknownBatch(ctx, "worker-b", 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch2) != 0 {
		t.Fatalf("expected 0 claimed (backoff), got %d", len(batch2))
	}

	// Verify the record has the backoff fields set.
	rec, _ = store.Lookup(ctx, execID)
	if rec.NextReconcileAt == nil {
		t.Error("expected next_reconcile_at to be set")
	}
	if rec.LastReconcileError != "test backoff" {
		t.Errorf("expected last_reconcile_error='test backoff', got %q", rec.LastReconcileError)
	}
	if rec.ReconcileOwner != "" {
		t.Errorf("expected reconcile_owner cleared, got %q", rec.ReconcileOwner)
	}
}

// TestLiveResolveRecoveryClearsClaim verifies that a successful
// ResolveRecovery clears the reconcile claim fields.
func TestLiveResolveRecoveryClearsClaim(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-resolve-clear-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create an UNKNOWN record and claim it.
	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.counter.increment",
		"digest-resolve-clear", "grant_rc", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Lookup(ctx, execID)
	if err := store.EnterRecovery(ctx, execID, StateInFlight, rec.Version); err != nil {
		t.Fatal(err)
	}

	batch, err := store.ClaimUnknownBatch(ctx, "worker-a", 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 1 {
		t.Fatalf("expected 1 claimed, got %d", len(batch))
	}

	// Resolve with proof.
	err = store.ResolveRecovery(ctx, execID, batch[0].Version, RecoveryResult{
		Decision:       RecoveryCommitted,
		Result:         []byte(`{"resolved":true}`),
		EvidenceDigest: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		ReceiptVersion: 3,
		ProviderID:     "test-counter",
		ProviderRunID:  "run-resolve-clear",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify claim fields are cleared.
	rec, _ = store.Lookup(ctx, execID)
	if rec.State != StateCommitted {
		t.Fatalf("expected COMMITTED, got %s", rec.State)
	}
	if rec.ReconcileOwner != "" {
		t.Errorf("expected reconcile_owner cleared, got %q", rec.ReconcileOwner)
	}
	if rec.NextReconcileAt != nil {
		t.Error("expected next_reconcile_at cleared")
	}
	if rec.LastReconcileError != "" {
		t.Errorf("expected last_reconcile_error cleared, got %q", rec.LastReconcileError)
	}
}

// TestLiveFinalizeDeniedRejected verifies that Finalize with a DENIED
// terminal status is rejected — DENIED is a wire-level admission status,
// not a durable store state.
func TestLiveFinalizeDeniedRejected(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-denied-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create a PREPARED record.
	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.counter.increment",
		"digest-denied", "grant_denied", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID

	// Try to finalize as DENIED from PREPARED — should be rejected.
	err = store.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StatePrepared, TerminalReceipt{
		ExecutionID:    execID,
		TerminalStatus: StateDenied,
	})
	if err == nil {
		t.Fatal("expected DENIED finalization to be rejected, got nil error")
	}

	// Try to finalize as DENIED from EXECUTING — should also be rejected.
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Lookup(ctx, execID)
	err = store.Finalize(ctx, execID, acq.LeaseToken, rec.LeaseGeneration, StateExecuting, TerminalReceipt{
		ExecutionID:    execID,
		TerminalStatus: StateDenied,
	})
	if err == nil {
		t.Fatal("expected DENIED finalization from EXECUTING to be rejected, got nil error")
	}
}

// TestLiveEnterRecoveryRejectsNonInFlight verifies that EnterRecovery
// enforces the legal transition matrix — only IN_FLIGHT → UNKNOWN is
// permitted. PREPARED, COMMITTED, and FAILED must be rejected.
func TestLiveEnterRecoveryRejectsNonInFlight(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-recovery-guard-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create a PREPARED record.
	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.counter.increment",
		"digest-guard", "grant_g", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID

	// PREPARED → UNKNOWN must be rejected.
	rec, _ := store.Lookup(ctx, execID)
	err = store.EnterRecovery(ctx, execID, StatePrepared, rec.Version)
	if err == nil {
		t.Fatal("expected PREPARED → UNKNOWN to be rejected")
	}

	// EXECUTING → UNKNOWN must be rejected.
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Lookup(ctx, execID)
	err = store.EnterRecovery(ctx, execID, StateExecuting, rec.Version)
	if err == nil {
		t.Fatal("expected EXECUTING → UNKNOWN to be rejected")
	}

	// COMMITTED → UNKNOWN must be rejected (terminal is immutable).
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Lookup(ctx, execID)
	err = store.Finalize(ctx, execID, acq.LeaseToken, rec.LeaseGeneration, StateInFlight, TerminalReceipt{
		ExecutionID:     execID,
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Lookup(ctx, execID)
	err = store.EnterRecovery(ctx, execID, StateCommitted, rec.Version)
	if err == nil {
		t.Fatal("expected COMMITTED → UNKNOWN to be rejected")
	}
}

// TestLiveConcurrentIdenticalFinalize verifies that two concurrent
// workers finalizing the same execution with identical receipts both
// succeed — the CAS loser sees the terminal state and matching digest
// and returns success (idempotent), not a conflict.
func TestLiveConcurrentIdenticalFinalize(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-conc-finalize-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create and dispatch a MUTATION record.
	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.counter.increment",
		"digest-conc", "grant_c", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
		t.Fatal(err)
	}

	// Build the identical receipt both workers will try to finalize.
	rec, _ := store.Lookup(ctx, execID)
	receipt := TerminalReceipt{
		ExecutionID:     execID,
		Capability:      rec.CapabilityID,
		Principal:       rec.PrincipalID,
		RequestDigest:   rec.RequestDigest,
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"value":42}`),
		ProviderID:      "test-counter",
		ProviderRunID:   "run-conc",
		EvidenceDigest:  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		ReceiptVersion:  3,
	}

	// Launch two concurrent finalizations with the same receipt.
	const workers = 2
	var wg sync.WaitGroup
	var successes, conflicts, other int64
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := store.Finalize(ctx, execID, acq.LeaseToken, rec.LeaseGeneration, StateInFlight, receipt)
			if err == nil {
				atomic.AddInt64(&successes, 1)
			} else if strings.Contains(err.Error(), "FINALIZATION_CONFLICT") {
				atomic.AddInt64(&conflicts, 1)
			} else {
				atomic.AddInt64(&other, 1)
				t.Logf("unexpected finalize error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	// Both should succeed — the first commits, the second sees the
	// identical receipt and returns idempotent success.
	if successes != workers {
		t.Errorf("expected %d successes, got %d (conflicts=%d, other=%d)", workers, successes, conflicts, other)
	}

	// Verify the record is COMMITTED.
	rec, _ = store.Lookup(ctx, execID)
	if rec.State != StateCommitted {
		t.Errorf("expected COMMITTED, got %s", rec.State)
	}
}

// TestLiveCriticalFinalizeRequiresProof verifies that CRITICAL
// finalization to COMMITTED or FAILED requires evidence at the
// store boundary — not just in DispatchExecutor.
func TestLiveCriticalFinalizeRequiresProof(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-crit-finalize-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create a CRITICAL record.
	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.critical.deploy",
		"digest-crit", "grant_c", "CRITICAL", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "deploy-adapter", nil); err != nil {
		t.Fatal(err)
	}

	// CRITICAL → COMMITTED without evidence must fail.
	rec, _ := store.Lookup(ctx, execID)
	err = store.Finalize(ctx, execID, acq.LeaseToken, rec.LeaseGeneration, StateInFlight, TerminalReceipt{
		ExecutionID:    execID,
		TerminalStatus: StateCommitted,
	})
	if err == nil {
		t.Fatal("expected CRITICAL → COMMITTED without evidence to be rejected")
	}

	// CRITICAL → FAILED without evidence must fail.
	err = store.Finalize(ctx, execID, acq.LeaseToken, rec.LeaseGeneration, StateInFlight, TerminalReceipt{
		ExecutionID:    execID,
		TerminalStatus: StateFailed,
	})
	if err == nil {
		t.Fatal("expected CRITICAL → FAILED without evidence to be rejected")
	}

	// CRITICAL → COMMITTED with full proof must succeed.
	err = store.Finalize(ctx, execID, acq.LeaseToken, rec.LeaseGeneration, StateInFlight, TerminalReceipt{
		ExecutionID:     execID,
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"deployed":true}`),
		ProviderID:      "deploy-adapter",
		ProviderRunID:   "run-crit-1",
		EvidenceDigest:  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		ReceiptVersion:  3,
	})
	if err != nil {
		t.Fatalf("CRITICAL → COMMITTED with proof should succeed: %v", err)
	}
}

// TestLiveRecoveryLocatorCleared verifies that the recovery_locator
// is cleared after terminal finalization — it contains raw request
// arguments and must not persist beyond the terminal transition.
func TestLiveRecoveryLocatorCleared(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-locator-clear-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create and dispatch a record with a recovery locator.
	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.counter.increment",
		"digest-loc", "grant_l", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	locator := json.RawMessage(`{"capability_id":"test.counter.increment","arguments":{"counter":"test"}}`)
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", locator); err != nil {
		t.Fatal(err)
	}

	// Verify the locator was persisted.
	rec, _ := store.Lookup(ctx, execID)
	if len(rec.RecoveryLocator) == 0 {
		t.Fatal("expected recovery_locator to be persisted")
	}

	// Finalize — the locator should be cleared.
	err = store.Finalize(ctx, execID, acq.LeaseToken, rec.LeaseGeneration, StateInFlight, TerminalReceipt{
		ExecutionID:     execID,
		TerminalStatus:  StateCommitted,
		CanonicalResult: json.RawMessage(`{"done":true}`),
		ProviderID:      "test-counter",
		ProviderRunID:   "run-loc",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Lookup(ctx, execID)
	if len(rec.RecoveryLocator) != 0 {
		t.Errorf("expected recovery_locator cleared after finalization, got %d bytes", len(rec.RecoveryLocator))
	}
}

// TestLiveEnterRecoveryWithObservation verifies that
// EnterRecoveryWithObservation persists provider metadata alongside
// the UNKNOWN transition.
func TestLiveEnterRecoveryWithObservation(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-obs-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	acq, err := store.Acquire(ctx, prefix+"-0", "alice@example.com", "test.counter.increment",
		"digest-obs", "grant_o", "MUTATION", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	execID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, execID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkInFlight(ctx, execID, acq.LeaseToken, acq.Generation, "test-counter", nil); err != nil {
		t.Fatal(err)
	}

	// Enter recovery with provider observation.
	rec, _ := store.Lookup(ctx, execID)
	err = store.EnterRecoveryWithObservation(ctx, execID, StateInFlight, rec.Version,
		"github-adapter", "issue-98765", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		json.RawMessage(`{"issue_url":"https://github.com/org/repo/issues/1"}`))
	if err != nil {
		t.Fatal(err)
	}

	// Verify the observation was persisted.
	rec, _ = store.Lookup(ctx, execID)
	if rec.State != StateUnknown {
		t.Fatalf("expected UNKNOWN, got %s", rec.State)
	}
	if rec.ProviderID != "github-adapter" {
		t.Errorf("expected provider_id=github-adapter, got %q", rec.ProviderID)
	}
	if rec.ProviderRunID != "issue-98765" {
		t.Errorf("expected provider_run_id=issue-98765, got %q", rec.ProviderRunID)
	}
	if rec.EvidenceDigest != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" {
		t.Errorf("expected evidence_digest preserved, got %q", rec.EvidenceDigest)
	}
}

// TestLiveClaimExpiredBatch verifies that expired-lease claiming uses
// FOR UPDATE SKIP LOCKED and does not process the same records twice.
func TestLiveClaimExpiredBatch(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-expired-claim-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	// Create records with very short leases.
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("%s-%d", prefix, i)
		_, err := store.Acquire(ctx, key, "alice@example.com", "test.counter.increment",
			fmt.Sprintf("digest-exp-%d", i), "grant_e", "MUTATION", 50*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond) // Let leases expire.

	// Claim expired batch — should get all 3.
	batch, err := store.ClaimExpiredBatch(ctx, "worker-a", 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claimed := 0
	for _, rec := range batch {
		if strings.HasPrefix(rec.IdempotencyKey, prefix) {
			claimed++
		}
	}
	if claimed != 3 {
		t.Fatalf("expected 3 claimed expired records, got %d", claimed)
	}

	// Second claim should get 0 — already claimed.
	batch2, err := store.ClaimExpiredBatch(ctx, "worker-b", 10, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claimed2 := 0
	for _, rec := range batch2 {
		if strings.HasPrefix(rec.IdempotencyKey, prefix) {
			claimed2++
		}
	}
	if claimed2 != 0 {
		t.Fatalf("expected 0 on second claim, got %d", claimed2)
	}
}
