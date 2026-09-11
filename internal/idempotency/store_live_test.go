package idempotency

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

			reserve, err := store.Reserve(ctx, key, principal, capability, digest, grantID, class)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			if reserve.Conflict {
				atomic.AddInt64(&errorCount, 1)
				return
			}

			if reserve.Acquired {
				// This caller owns the reservation — only ONE caller should get this.
				atomic.AddInt64(&acquiredCount, 1)

				// Simulate the execution lifecycle.
				// Transition RESERVED → DISPATCHING
				if err := store.TransitionState(ctx, reserve.Record.ExecutionID, reserve.LeaseToken, StateReserved, StateDispatching); err != nil {
					t.Errorf("lease holder failed to transition to DISPATCHING: %v", err)
				}
				if err := store.TransitionState(ctx, reserve.Record.ExecutionID, reserve.LeaseToken, StateDispatching, StateInFlight); err != nil {
					t.Errorf("lease holder failed to transition to IN_FLIGHT: %v", err)
				}

				// Finalize with SUCCEEDED
				result := []byte(`{"value":42}`)
				if err := store.FinalizeLegacy(ctx, reserve.Record.ExecutionID, reserve.LeaseToken, StateInFlight, StateSucceeded, result, "evidencedigest000000000000000000000000000000000000000000000000000000123456", 3); err != nil {
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
	reserve1, err := store.Reserve(ctx, key, principal, capability, "digest-A", grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve1.Acquired {
		t.Fatal("first caller should acquire the reservation")
	}

	// Second caller uses the same key with a DIFFERENT digest.
	reserve2, err := store.Reserve(ctx, key, principal, capability, "digest-B", grantID, class)
	if err != nil {
		t.Fatal(err)
	}

	if !reserve2.Conflict {
		t.Error("same key + different digest must produce CONFLICT")
	}
	if reserve2.Acquired {
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
	reserveA, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired {
		t.Fatal("caller A should acquire with fresh key")
	}

	// Caller B tries immediately — should NOT acquire (lease still valid).
	reserveB, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reserveB.Acquired {
		t.Error("caller B should NOT acquire while lease is valid")
	}

	// Wait for the lease to expire.
	time.Sleep(200 * time.Millisecond)

	// Caller C tries after expiry — SHOULD acquire via lease reclaim.
	reserveC, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveC.Acquired {
		t.Error("caller C should acquire after lease expiry")
	}

	// Caller A's old lease token should NOT be able to finalize.
	err = store.FinalizeLegacy(ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateInFlight, StateSucceeded, nil, "", 3)
	if err == nil {
		t.Error("old lease holder (A) should NOT be able to finalize after lease takeover")
	}

	// Caller C (new lease holder) CAN finalize.
	if err := store.TransitionState(ctx, reserveC.Record.ExecutionID, reserveC.LeaseToken, StateReserved, StateDispatching); err != nil {
		t.Errorf("new lease holder (C) failed to transition: %v", err)
	}
	if err := store.TransitionState(ctx, reserveC.Record.ExecutionID, reserveC.LeaseToken, StateDispatching, StateInFlight); err != nil {
		t.Errorf("new lease holder (C) failed to transition to IN_FLIGHT: %v", err)
	}
	err = store.FinalizeLegacy(ctx, reserveC.Record.ExecutionID, reserveC.LeaseToken, StateInFlight, StateSucceeded, []byte(`{"ok":true}`), "", 0)
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
	reserve, err := store.Reserve(ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve.Acquired {
		t.Fatal("should acquire")
	}
	executionID := reserve.Record.ExecutionID
	leaseToken := reserve.LeaseToken

	if err := store.TransitionState(ctx, executionID, leaseToken, StateReserved, StateDispatching); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionState(ctx, executionID, leaseToken, StateDispatching, StateInFlight); err != nil {
		t.Fatal(err)
	}

	// Finalize with SUCCEEDED and evidence digest X.
	if err := store.FinalizeLegacy(ctx, executionID, leaseToken, StateInFlight, StateSucceeded, []byte(`{"result":"A"}`), "digest_X", 3); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}

	// Identical re-finalize — should be idempotent (no error).
	if err := store.FinalizeLegacy(ctx, executionID, leaseToken, StateInFlight, StateSucceeded, []byte(`{"result":"A"}`), "digest_X", 3); err != nil {
		t.Errorf("identical re-finalize should be idempotent, got: %v", err)
	}

	// Conflicting finalize — different terminal state.
	err = store.FinalizeLegacy(ctx, executionID, leaseToken, StateInFlight, StateFailed, []byte(`{"result":"B"}`), "", 0)
	if err == nil {
		t.Error("conflicting finalize (SUCCEEDED → FAILED) must be rejected")
	}

	// Conflicting finalize — same state but different evidence.
	err = store.FinalizeLegacy(ctx, executionID, leaseToken, StateInFlight, StateSucceeded, []byte(`{"result":"B"}`), "digest_Y", 3)
	if err == nil {
		t.Error("conflicting finalize (different evidence) must be rejected")
	}

	// Verify the stored record still has the original values.
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateSucceeded {
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
	_, err = store.ReserveWithLease(ctx, key, "alice", "test.cap", "digest", "", "MUTATION", 50*time.Millisecond)
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
	reserve1, err := store.Reserve(ctx, key, principal, capability, digestA, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve1.Acquired {
		t.Fatal("first caller should acquire")
	}

	// Second caller uses same key with digest B (different large integer).
	reserve2, err := store.Reserve(ctx, key, principal, capability, digestB, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve2.Conflict {
		t.Error("same key + different large integer digest must produce CONFLICT")
	}
	if reserve2.Acquired {
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
	reserveA, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired {
		t.Fatal("caller A should acquire")
	}
	if err := store.TransitionState(ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateReserved, StateDispatching); err != nil {
		t.Fatalf("A failed to transition to DISPATCHING: %v", err)
	}
	// Simulate crash: no further action from caller A.

	// Wait for lease to expire.
	time.Sleep(200 * time.Millisecond)

	// Caller B reclaims after expiry.
	reserveB, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveB.Acquired {
		t.Fatal("caller B should acquire after lease expiry (DISPATCHING crash recovery)")
	}

	// Caller A's old token cannot transition or finalize.
	if err := store.TransitionState(ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateDispatching, StateInFlight); err == nil {
		t.Error("old lease holder (A) should NOT be able to transition after takeover")
	}
	if err := store.FinalizeLegacy(ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateInFlight, StateSucceeded, nil, "", 0); err == nil {
		t.Error("old lease holder (A) should NOT be able to finalize after takeover")
	}

	// Caller B can complete the lifecycle.
	if err := store.TransitionState(ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, StateReserved, StateDispatching); err != nil {
		t.Errorf("B failed to transition to DISPATCHING: %v", err)
	}
	if err := store.TransitionState(ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, StateDispatching, StateInFlight); err != nil {
		t.Errorf("B failed to transition to IN_FLIGHT: %v", err)
	}
	if err := store.FinalizeLegacy(ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, StateInFlight, StateSucceeded, []byte(`{"ok":true}`), "", 0); err != nil {
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
	reserveA, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired {
		t.Fatal("caller A should acquire")
	}
	execID := reserveA.Record.ExecutionID
	leaseToken := reserveA.LeaseToken

	if err := store.TransitionState(ctx, execID, leaseToken, StateReserved, StateDispatching); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionState(ctx, execID, leaseToken, StateDispatching, StateInFlight); err != nil {
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

	// The reconcile worker would mark this as UNKNOWN. Simulate that.
	if err := store.SetState(ctx, execID, StateUnknown, nil, ""); err != nil {
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
	reserveB, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reserveB.Acquired {
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
	reserveA, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveA.Acquired {
		t.Fatal("caller A should acquire")
	}
	oldToken := reserveA.LeaseToken

	// Wait for lease to expire.
	time.Sleep(200 * time.Millisecond)

	// Caller B takes over.
	reserveB, err := store.ReserveWithLease(ctx, key, principal, capability, digest, grantID, class, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !reserveB.Acquired {
		t.Fatal("caller B should acquire after expiry")
	}

	// Caller A tries to renew with the old token — must be rejected.
	err = store.RenewLeaseLegacy(ctx, reserveA.Record.ExecutionID, oldToken, time.Minute)
	if err == nil {
		t.Error("old lease holder (A) should NOT be able to renew after takeover")
	}

	// Caller B (current holder) CAN renew.
	err = store.RenewLeaseLegacy(ctx, reserveB.Record.ExecutionID, reserveB.LeaseToken, time.Minute)
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
	capability := "test.critical.op"
	digest := "digest-novoodoo"
	grantID := "grant_test"
	class := "CRITICAL"

	// Reserve and transition through the lifecycle.
	reserve, err := store.Reserve(ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if !reserve.Acquired {
		t.Fatal("should acquire")
	}
	execID := reserve.Record.ExecutionID
	leaseToken := reserve.LeaseToken

	if err := store.TransitionState(ctx, execID, leaseToken, StateReserved, StateDispatching); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionState(ctx, execID, leaseToken, StateDispatching, StateInFlight); err != nil {
		t.Fatal(err)
	}

	// Finalize with FAILED (simulating: CRITICAL returned invalid V2
	// evidence, kernel rejected it as FAILED).
	if err := store.FinalizeLegacy(ctx, execID, leaseToken, StateInFlight, StateFailed, []byte(`{"error":"invalid evidence"}`), "", 0); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}

	// Retry: attempt to finalize as SUCCEEDED with valid V3 evidence.
	// This must be rejected — FAILED is terminal and immutable.
	err = store.FinalizeLegacy(ctx, execID, leaseToken, StateInFlight, StateSucceeded, []byte(`{"ok":true}`), "valid_digest_000000000000000000000000000000000000000000000000000000123456", 3)
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
	reserve, err := store.Reserve(ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	execID := reserve.Record.ExecutionID

	if err := store.SetState(ctx, execID, StateUnknown, nil, ""); err != nil {
		t.Fatal(err)
	}

	// Simulate the reconcile worker: resolver confirms completion.
	proofResult := []byte(`{"confirmed":true,"provider_run_id":"run_123"}`)
	if err := store.SetState(ctx, execID, StateSucceeded, proofResult, "proof_digest_000000000000000000000000000000000000000000000000000000123456"); err != nil {
		t.Fatalf("recovery to SUCCEEDED failed: %v", err)
	}

	// Verify.
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateSucceeded {
		t.Errorf("recovery with proof should result in SUCCEEDED, got %s", rec.State)
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
	reserve, err := store.Reserve(ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	execID := reserve.Record.ExecutionID

	if err := store.SetState(ctx, execID, StateUnknown, nil, ""); err != nil {
		t.Fatal(err)
	}

	// Simulate the reconcile worker: resolver confirms failure.
	proofResult := []byte(`{"confirmed":false,"error":"provider returned error"}`)
	if err := store.SetState(ctx, execID, StateFailed, proofResult, ""); err != nil {
		t.Fatalf("recovery to FAILED failed: %v", err)
	}

	// Verify.
	rec, err := store.Lookup(ctx, execID)
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

	// Create a record in UNKNOWN state.
	reserve, err := store.Reserve(ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	execID := reserve.Record.ExecutionID

	if err := store.SetState(ctx, execID, StateUnknown, nil, ""); err != nil {
		t.Fatal(err)
	}

	// Simulate the reconcile worker: NoopResolver returns UNKNOWN.
	// The worker should NOT call SetState (state stays UNKNOWN).
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
	reserve2, err := store.Reserve(ctx, key, principal, capability, digest, grantID, class)
	if err != nil {
		t.Fatal(err)
	}
	if reserve2.Acquired {
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
	if err := store.MarkInFlight(ctx, r3.Record.ExecutionID, r3.LeaseToken, r3.Generation); err != nil {
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
	if err := store.MarkInFlight(ctx, r1b.Record.ExecutionID, r1b.LeaseToken, r1b.Generation); err != nil {
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
	err = store.MarkInFlight(ctx, execID, tokenA, genA)
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
	if err := store.MarkInFlight(ctx, execID, tokenB, genB); err != nil {
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
		if err := store.MarkInFlight(ctx, r.Record.ExecutionID, r.LeaseToken, r.Generation); err != nil {
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
		if err := store.MarkInFlight(ctx, r.Record.ExecutionID, r.LeaseToken, r.Generation); err != nil {
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
	if err := store.ResolveRecovery(ctx, execID1, rec1.Version, RecoveryCommitted, result1); err != nil {
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
	if err := store.ResolveRecovery(ctx, execID2, rec2.Version, RecoveryFailed, result2); err != nil {
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
	if err := store.ResolveRecovery(ctx, execID3, rec3.Version, RecoveryUnknown, RecoveryResult{Decision: RecoveryUnknown}); err != nil {
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
	if err := store.ResolveRecovery(ctx, execID4, rec4.Version, RecoveryCommitted, RecoveryResult{
		Decision:       RecoveryCommitted,
		Result:         []byte(`{"confirmed":true}`),
		EvidenceDigest: "proof_digest_000000000000000000000000000000000000000000000000000000123456",
	}); err != nil {
		t.Fatalf("first recovery resolution failed: %v", err)
	}
	err = store.ResolveRecovery(ctx, execID4, rec4.Version, RecoveryFailed, RecoveryResult{
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
