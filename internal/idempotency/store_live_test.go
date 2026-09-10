package idempotency

import (
	"context"
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
				if err := store.Finalize(ctx, reserve.Record.ExecutionID, reserve.LeaseToken, StateInFlight, StateSucceeded, result, "evidencedigest000000000000000000000000000000000000000000000000000000123456", 3); err != nil {
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
	err = store.Finalize(ctx, reserveA.Record.ExecutionID, reserveA.LeaseToken, StateInFlight, StateSucceeded, nil, "", 3)
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
	err = store.Finalize(ctx, reserveC.Record.ExecutionID, reserveC.LeaseToken, StateInFlight, StateSucceeded, []byte(`{"ok":true}`), "", 0)
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
	if err := store.Finalize(ctx, executionID, leaseToken, StateInFlight, StateSucceeded, []byte(`{"result":"A"}`), "digest_X", 3); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}

	// Identical re-finalize — should be idempotent (no error).
	if err := store.Finalize(ctx, executionID, leaseToken, StateInFlight, StateSucceeded, []byte(`{"result":"A"}`), "digest_X", 3); err != nil {
		t.Errorf("identical re-finalize should be idempotent, got: %v", err)
	}

	// Conflicting finalize — different terminal state.
	err = store.Finalize(ctx, executionID, leaseToken, StateInFlight, StateFailed, []byte(`{"result":"B"}`), "", 0)
	if err == nil {
		t.Error("conflicting finalize (SUCCEEDED → FAILED) must be rejected")
	}

	// Conflicting finalize — same state but different evidence.
	err = store.Finalize(ctx, executionID, leaseToken, StateInFlight, StateSucceeded, []byte(`{"result":"B"}`), "digest_Y", 3)
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
