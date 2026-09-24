package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// Per-stage durability budget tests. Each post-dispatch stage derives
// its own bounded context: exhausting one stage's budget must never
// consume the next stage's — emergency recovery in particular must
// still persist the provider observation after the observation or
// terminalization stage timed out.

// slowObservationStore delays the durable observation write, letting a
// test exhaust the observation-persistence budget deterministically.
// An expired context fails the write the way database/sql does —
// mirroring the real store rather than relying on driver internals.
type slowObservationStore struct {
	idempotency.EffectStore
	delay time.Duration
}

func (s slowObservationStore) RecordProviderObservation(ctx context.Context, executionID, leaseToken string, leaseGen int, obs idempotency.ProviderObservation) error {
	time.Sleep(s.delay)
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.EffectStore.RecordProviderObservation(ctx, executionID, leaseToken, leaseGen, obs)
}

// ctxHonoringStore fails Finalize on an already-expired context, the
// way database/sql refuses to run a statement on a done context.
type ctxHonoringStore struct {
	idempotency.EffectStore
}

func (s ctxHonoringStore) Finalize(ctx context.Context, executionID, leaseToken string, leaseGen int, expected idempotency.State, receipt idempotency.TerminalReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.EffectStore.Finalize(ctx, executionID, leaseToken, leaseGen, expected, receipt)
}

// deadlineRecordingStore records whether lease renewals ran under a
// bounded (deadline-bearing) context.
type deadlineRecordingStore struct {
	idempotency.EffectStore
	mu          sync.Mutex
	sawDeadline bool
}

func (s *deadlineRecordingStore) RenewLease(ctx context.Context, executionID, leaseToken string, leaseGeneration int, duration time.Duration) error {
	if _, ok := ctx.Deadline(); ok {
		s.mu.Lock()
		s.sawDeadline = true
		s.mu.Unlock()
	}
	return s.EffectStore.RenewLease(ctx, executionID, leaseToken, leaseGeneration, duration)
}

func mutationRequest(key string) Request {
	return Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}
}

func mutationDescriptor() capability.ResolvedDescriptor {
	return capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "test-adapter",
	}
}

// TestExhaustedObservationBudgetStillRecovers proves the observation
// stage's exhausted budget does not starve emergency recovery: the
// observation write times out, and recovery — on a FRESH budget — must
// still drive the record to UNKNOWN with the provider observation
// persisted.
func TestExhaustedObservationBudgetStillRecovers(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(succeedHandler{delay: 10 * time.Millisecond},
		slowObservationStore{EffectStore: store, delay: 250 * time.Millisecond})
	exec.SetTimeouts(ExecutorTimeouts{
		ObservationPersistence: 100 * time.Millisecond,
		Terminalization:        2 * time.Second,
		EmergencyRecovery:      2 * time.Second,
	})

	key := fmt.Sprintf("budget-obs-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), mutationRequest(key), mutationDescriptor())
	if resp.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN after observation timeout, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("expected durable UNKNOWN, got %s — recovery inherited the exhausted observation context", rec.State)
	}

	obs, err := store.ListProviderObservations(context.Background(), rec.ExecutionID)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("provider observation was not persisted — recovery must run on a fresh budget")
	}
}

// TestExhaustedTerminalizationBudgetStillRecovers proves the
// terminalization stage's exhausted budget does not starve emergency
// recovery: the fenced Finalize fails on the expired terminal context,
// and recovery — on a fresh budget — persists UNKNOWN plus the
// provider observation.
func TestExhaustedTerminalizationBudgetStillRecovers(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(succeedHandler{delay: 10 * time.Millisecond},
		ctxHonoringStore{EffectStore: store})
	exec.SetTimeouts(ExecutorTimeouts{
		ObservationPersistence: 2 * time.Second,
		Terminalization:        100 * time.Millisecond,
		EmergencyRecovery:      2 * time.Second,
	})
	// Slow evidence verification / receipt construction that exhausts
	// the terminalization budget before Finalize runs.
	exec.preFinalizeHook = func() { time.Sleep(150 * time.Millisecond) }

	key := fmt.Sprintf("budget-term-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), mutationRequest(key), mutationDescriptor())
	if resp.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN after terminalization timeout, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("expected durable UNKNOWN, got %s — recovery inherited the exhausted terminalization context", rec.State)
	}

	obs, err := store.ListProviderObservations(context.Background(), rec.ExecutionID)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("provider observation was not persisted — recovery must run on a fresh budget")
	}
}

// TestSufficientTerminalizationBudgetCommits is the control for the
// test above: the same slow verification with an adequate budget
// commits normally, so the UNKNOWN above is caused by the budget
// boundary, not the delay itself.
func TestSufficientTerminalizationBudgetCommits(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(succeedHandler{delay: 10 * time.Millisecond},
		ctxHonoringStore{EffectStore: store})
	exec.SetTimeouts(ExecutorTimeouts{
		ObservationPersistence: 2 * time.Second,
		Terminalization:        2 * time.Second,
		EmergencyRecovery:      2 * time.Second,
	})
	exec.preFinalizeHook = func() { time.Sleep(150 * time.Millisecond) }

	key := fmt.Sprintf("budget-term-ok-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), mutationRequest(key), mutationDescriptor())
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED with an adequate terminalization budget, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s", rec.State)
	}
}

// slowRenewalStore stalls every lease renewal, simulating a storage
// stall (an fsync under load) on the renewal path.
type slowRenewalStore struct {
	idempotency.EffectStore
	delay time.Duration
}

func (s slowRenewalStore) RenewLease(ctx context.Context, executionID, leaseToken string, leaseGeneration int, duration time.Duration) error {
	time.Sleep(s.delay)
	return s.EffectStore.RenewLease(ctx, executionID, leaseToken, leaseGeneration, duration)
}

// TestLeaseRenewalToleratesStorageLatency proves a storage stall on
// the renewal path changes latency, not semantics: the dispatch
// outlives the original lease, a 500ms renewal stall lands well
// inside the settle window, and the record still reaches COMMITTED.
// Success is only possible if the stalled renewal actually extended
// the lease — the handler runs longer than the original lease.
func TestLeaseRenewalToleratesStorageLatency(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.LeaseConfig{
		DefaultDuration: 5 * time.Second,
		MaxDuration:     10 * time.Second,
		RenewalWindow:   2 * time.Second,
	})
	exec := NewDispatchExecutor(succeedHandler{delay: 6 * time.Second},
		slowRenewalStore{EffectStore: store, delay: 500 * time.Millisecond})

	key := fmt.Sprintf("budget-latency-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), mutationRequest(key), mutationDescriptor())
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED with a stalled renewal inside the lease window, got %s: %s", resp.Status, resp.Error)
	}
	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("expected COMMITTED after a stalled renewal, got %s", rec.State)
	}
}

// TestHeartbeatRenewalsAreBounded proves lease renewals run under the
// LeaseOperation budget rather than the unbounded heartbeat lifetime —
// a hung store call must not stall the renewal loop until the lease
// expires.
func TestHeartbeatRenewalsAreBounded(t *testing.T) {
	// The dispatch must outlast the lease with renewals keeping it
	// alive. Budgets carry real headroom: a 300ms lease leaves only
	// 100ms of slack per renewal cycle, and a single fsync stall under
	// a loaded machine expires the lease before finalization — a
	// failure about the test machine, not the renewal path.
	store := openExecutorSQLiteStore(t, idempotency.LeaseConfig{
		DefaultDuration: 1 * time.Second,
		MaxDuration:     10 * time.Second,
		RenewalWindow:   250 * time.Millisecond,
	})
	rec := &deadlineRecordingStore{EffectStore: store}
	exec := NewDispatchExecutor(succeedHandler{delay: 2 * time.Second}, rec)

	key := fmt.Sprintf("budget-hb-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), mutationRequest(key), mutationDescriptor())
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}

	rec.mu.Lock()
	saw := rec.sawDeadline
	rec.mu.Unlock()
	if !saw {
		t.Fatal("lease renewals must run under a bounded LeaseOperation context")
	}
}

func TestSetTimeoutsFillsZeroFields(t *testing.T) {
	exec := NewDispatchExecutor(succeedHandler{}, nil)
	exec.SetTimeouts(ExecutorTimeouts{Terminalization: time.Second})

	want := DefaultExecutorTimeouts()
	want.Terminalization = time.Second
	if exec.timeouts != want {
		t.Fatalf("timeouts = %+v, want %+v", exec.timeouts, want)
	}
}

// wedgedHandler never returns and never observes context cancellation
// — the hung-provider case the executor-owned ceiling exists for.
type wedgedHandler struct{}

func (wedgedHandler) Execute(context.Context, Request, capability.ResolvedDescriptor) Response {
	select {}
}

// handlerFunc adapts a function to Handler for tests.
type handlerFunc func(context.Context, Request, capability.ResolvedDescriptor) Response

func (f handlerFunc) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	return f(ctx, req, desc)
}

// TestProviderCeilingBoundsHungHandler proves a provider that ignores
// cancellation entirely cannot pin a lease forever: the executor's own
// ProviderExecution budget ends the dispatch and converges the record
// to UNKNOWN + recovery — never FAILED, never an indefinite hold.
func TestProviderCeilingBoundsHungHandler(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(wedgedHandler{}, store)
	exec.SetTimeouts(ExecutorTimeouts{
		ProviderExecution:      100 * time.Millisecond,
		ProviderExecutionGrace: 20 * time.Millisecond,
	})

	key := fmt.Sprintf("ceiling-hang-%d", time.Now().UnixNano())
	start := time.Now()
	resp := exec.ExecuteWithIdempotency(context.Background(), mutationRequest(key), mutationDescriptor())
	elapsed := time.Since(start)

	if resp.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN after provider ceiling, got %s: %s", resp.Status, resp.Error)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("dispatch held %s for a hung handler — ceiling did not bound it", elapsed)
	}

	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("expected durable UNKNOWN for reconciliation, got %s", rec.State)
	}
}

// TestProviderCeilingKeepsCooperativeAnswer proves the grace window:
// a handler that observes the ceiling cancellation and returns within
// the grace has its own answer used — including any provider evidence
// the durable observation must persist.
func TestProviderCeilingKeepsCooperativeAnswer(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(handlerFunc(func(ctx context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
		<-ctx.Done() // observe cancellation, then answer promptly
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureExecutionFailed),
			Error:             "provider aborted on cancellation",
			DefinitiveFailure: true,
			Execution:         &ExecutionMeta{Provider: desc.AdapterID, RunID: "run-grace"},
		}
	}), store)
	exec.SetTimeouts(ExecutorTimeouts{
		ProviderExecution:      50 * time.Millisecond,
		ProviderExecutionGrace: 2 * time.Second,
	})

	key := fmt.Sprintf("ceiling-grace-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), mutationRequest(key), mutationDescriptor())
	if resp.Status != StatusFailed {
		t.Fatalf("cooperative handler's own answer must win, got %s: %s", resp.Status, resp.Error)
	}
	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateFailed {
		t.Fatalf("expected durable FAILED for a definitive no-effect, got %s", rec.State)
	}
}

// TestProviderCeilingPureReadFailsSafely proves the ceiling's other
// half: a no-side-effect route converges to FAILED, not UNKNOWN.
func TestProviderCeilingPureReadFailsSafely(t *testing.T) {
	exec := NewDispatchExecutor(wedgedHandler{}, nil)
	exec.SetTimeouts(ExecutorTimeouts{
		ProviderExecution:      50 * time.Millisecond,
		ProviderExecutionGrace: 10 * time.Millisecond,
	})
	desc := capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassRead,
		AdapterID:      "test-adapter",
	}
	resp := exec.ExecuteWithIdempotency(context.Background(), Request{
		Capability: "test.read",
		Arguments:  json.RawMessage(`{}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}, desc)
	if resp.Status != StatusFailed {
		t.Fatalf("READ ceiling must be a safe FAILED, got %s: %s", resp.Status, resp.Error)
	}
}
