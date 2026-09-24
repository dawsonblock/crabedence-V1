package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// failObservationStore wraps a real EffectStore and fails
// RecordProviderObservation — simulating a transient store error in
// the post-dispatch observation window.
type failObservationStore struct {
	idempotency.EffectStore
	err error
}

func (s failObservationStore) RecordProviderObservation(ctx context.Context, executionID, leaseToken string, leaseGen int, obs idempotency.ProviderObservation) error {
	return s.err
}

// succeedHandler returns a fixed successful response after a delay.
type succeedHandler struct {
	delay time.Duration
}

func (h succeedHandler) Execute(_ context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	time.Sleep(h.delay)
	return Response{
		Status: StatusSucceeded,
		Result: json.RawMessage(`{"ok":true}`),
		Execution: &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    fmt.Sprintf("run-%d", time.Now().UnixNano()),
		},
	}
}

func openExecutorSQLiteStore(t *testing.T, cfg idempotency.LeaseConfig) *idempotency.SQLiteStore {
	t.Helper()
	// A generous busy timeout: concurrency torture tests here run many
	// writers against one ledger, and a slow CI disk can push write-lock
	// waits past the production 5s. The property under test is
	// correctness under concurrency, not throughput on a given runner.
	db, err := idempotency.OpenSQLiteDBForTest(filepath.Join(t.TempDir(), "db", "exec-test.db"), 30000)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := idempotency.NewSQLiteStoreWithConfig(db, cfg)
	if err != nil {
		t.Fatalf("NewSQLiteStoreWithConfig: %v", err)
	}
	return store
}

// TestObservationFailureRecoverySurvivesCallerCancel is the regression
// for the post-dispatch durability-context defect: after the provider
// returns, mandatory persistence must run on a context detached from
// the caller's cancellation.
//
// Sequence: provider succeeds → caller cancels → the durable
// observation write fails → the executor must still persist
// UNKNOWN/recovery under the detached context. The buggy code passed
// the cancelled caller ctx to enterRecoveryWithObservation, so the
// recovery write failed instantly and the record stranded IN_FLIGHT.
//
// The assertion is on the DURABLE state, not the wire response —
// both versions report UNKNOWN to the caller; only the fixed version
// actually persists it.
func TestObservationFailureRecoverySurvivesCallerCancel(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)

	wrapped := failObservationStore{
		EffectStore: store,
		err:         errors.New("injected observation write failure"),
	}
	exec := NewDispatchExecutor(succeedHandler{delay: 10 * time.Millisecond}, wrapped)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel the instant the provider has returned — the dispatch
	// boundary is crossed, so cancellation must not erase the
	// mandatory persistence path.
	exec.postDispatchHook = cancel

	key := fmt.Sprintf("obs-fail-cancel-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "test-adapter",
	})

	if resp.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN wire status, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("expected durable state UNKNOWN after cancelled-caller recovery, got %s — "+
			"recovery persistence ran under the cancelled caller context", rec.State)
	}
}

// TestHeartbeatSurvivesCallerCancelThroughFinalize proves the lease
// heartbeat is not owned by the caller's context: once IN_FLIGHT is
// persisted, a caller disconnect must not stop lease renewal while
// mandatory post-dispatch persistence is still running.
//
// Timing: lease = 300ms, provider = 100ms, cancel at provider return,
// slow finalization (preFinalizeHook) = 400ms. The record commits at
// ~500ms — past the original 300ms lease expiry. With the heartbeat
// derived from the caller ctx, renewal stops at ~100ms, the lease
// expires at 300ms, and Finalize's fenced CAS fails → UNKNOWN.
// With a durability-owned heartbeat, the lease renews through
// finalization → COMMITTED.
func TestHeartbeatSurvivesCallerCancelThroughFinalize(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.LeaseConfig{
		DefaultDuration: 300 * time.Millisecond,
		MaxDuration:     10 * time.Second,
		RenewalWindow:   100 * time.Millisecond,
	})

	exec := NewDispatchExecutor(succeedHandler{delay: 100 * time.Millisecond}, store)
	// Slow evidence verification / receipt construction after the
	// provider returns — the lease must remain valid through it.
	exec.preFinalizeHook = func() { time.Sleep(400 * time.Millisecond) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exec.postDispatchHook = cancel

	key := fmt.Sprintf("hb-cancel-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "test-adapter",
	})

	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED — heartbeat must survive caller cancel through finalization, got %s: %s",
			resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s — heartbeat did not survive caller cancellation", rec.State)
	}
}
