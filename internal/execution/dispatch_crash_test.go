package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// countingHandler wraps succeedHandler and counts provider invocations
// so crash tests can assert dispatch-count invariants.
type countingHandler struct {
	delay   time.Duration
	handler func() Response
	calls   *atomic.Int32
}

func (h *countingHandler) Execute(_ context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	h.calls.Add(1)
	time.Sleep(h.delay)
	if h.handler != nil {
		return h.handler()
	}
	return Response{
		Status: StatusSucceeded,
		Result: json.RawMessage(`{"ok":true}`),
		Execution: &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    fmt.Sprintf("run-%d", time.Now().UnixNano()),
		},
	}
}

// ambiguousHandler returns a response the classifier maps to UNKNOWN —
// driving the executor down the recovery path so recovery crash points
// are reachable.
type ambiguousHandler struct{ calls *atomic.Int32 }

func (h ambiguousHandler) Execute(_ context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	h.calls.Add(1)
	return Response{
		Status: StatusFailed,
		Error:  "provider timeout: outcome ambiguous",
		Execution: &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    "run-ambiguous",
		},
	}
}

// runCrashExecute invokes the executor and swallows the injected crash
// panic, returning nothing — the assertion is on the durable record.
func runCrashExecute(exec *DispatchExecutor, req Request, desc capability.ResolvedDescriptor) {
	defer func() { _ = recover() }()
	exec.ExecuteWithIdempotency(context.Background(), req, desc)
}

func crashRequest(principal, key string) Request {
	return Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: principal, AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}
}

var crashDesc = capability.ResolvedDescriptor{
	ExecutionClass: capability.ClassMutation,
	AdapterID:      "test-adapter",
}

// TestCrashPointMatrix exercises every failure-injection point: the
// crash hook panics at the named boundary and the durable record must
// reflect exactly the state the boundary implies — never a fabricated
// terminal outcome, never a skipped observation.
func TestCrashPointMatrix(t *testing.T) {
	tests := []struct {
		point          CrashPoint
		ambiguous      bool
		wantState      idempotency.State
		wantCalls      int32
		wantObsPersist bool
	}{
		{CrashAfterAcquire, false, idempotency.StatePrepared, 0, false},
		{CrashAfterBeginExecution, false, idempotency.StateExecuting, 0, false},
		{CrashAfterMarkInFlight, false, idempotency.StateInFlight, 0, false},
		{CrashBeforeProvider, false, idempotency.StateInFlight, 0, false},
		{CrashAfterProvider, false, idempotency.StateInFlight, 1, false},
		{CrashBeforeObservation, false, idempotency.StateInFlight, 1, false},
		{CrashAfterObservation, false, idempotency.StateInFlight, 1, true},
		{CrashBeforeFinalize, false, idempotency.StateInFlight, 1, true},
		{CrashAfterFinalize, false, idempotency.StateCommitted, 1, true},
		// Recovery path — ambiguous provider outcome.
		{CrashBeforeRecovery, true, idempotency.StateInFlight, 1, true},
		{CrashAfterRecovery, true, idempotency.StateUnknown, 1, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.point), func(t *testing.T) {
			store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)

			var calls atomic.Int32
			var handler Handler
			if tt.ambiguous {
				handler = ambiguousHandler{calls: &calls}
			} else {
				handler = &countingHandler{calls: &calls}
			}
			exec := NewDispatchExecutor(handler, store)
			exec.SetCrashHook(func(p CrashPoint) {
				if p == tt.point {
					panic(fmt.Sprintf("injected crash at %s", p))
				}
			})

			principal := "alice@example.com"
			key := fmt.Sprintf("crash-%s-%d", tt.point, time.Now().UnixNano())
			runCrashExecute(exec, crashRequest(principal, key), crashDesc)

			if got := calls.Load(); got != tt.wantCalls {
				t.Errorf("provider dispatch count = %d, want %d", got, tt.wantCalls)
			}

			rec, err := store.LookupByKey(context.Background(), principal, "test.mut", key)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if rec.State != tt.wantState {
				t.Errorf("durable state = %s, want %s", rec.State, tt.wantState)
			}
			obsPersisted := rec.ProviderStatus != "" || rec.ProviderObservedAt != nil
			if obsPersisted != tt.wantObsPersist {
				t.Errorf("provider observation persisted = %v, want %v", obsPersisted, tt.wantObsPersist)
			}
		})
	}
}

// TestCrashPointsAreOrdered pins the intended firing order for a
// successful execution so a refactoring that reorders or drops a
// boundary fails loudly.
func TestCrashPointsAreOrdered(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&countingHandler{calls: &atomic.Int32{}}, store)

	var fired []CrashPoint
	exec.SetCrashHook(func(p CrashPoint) { fired = append(fired, p) })

	resp := exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", fmt.Sprintf("order-%d", time.Now().UnixNano())),
		crashDesc)
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected success, got %s: %s", resp.Status, resp.Error)
	}

	want := []CrashPoint{
		CrashAfterAcquire,
		CrashAfterBeginExecution,
		CrashAfterMarkInFlight,
		CrashBeforeProvider,
		CrashAfterProvider,
		CrashBeforeObservation,
		CrashAfterObservation,
		CrashBeforeFinalize,
		CrashAfterFinalize,
	}
	if len(fired) != len(want) {
		t.Fatalf("fired %v, want %v", fired, want)
	}
	for i := range want {
		if fired[i] != want[i] {
			t.Fatalf("fired %v, want %v", fired, want)
		}
	}
}

// TestCrashPointsRecoveryOrder pins the firing order on the recovery
// path: an ambiguous provider outcome routes through the observation
// write into EnterRecovery, never through Finalize.
func TestCrashPointsRecoveryOrder(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	var calls atomic.Int32
	exec := NewDispatchExecutor(ambiguousHandler{calls: &calls}, store)

	var fired []CrashPoint
	exec.SetCrashHook(func(p CrashPoint) { fired = append(fired, p) })

	resp := exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", fmt.Sprintf("order-rec-%d", time.Now().UnixNano())),
		crashDesc)
	if resp.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN, got %s: %s", resp.Status, resp.Error)
	}

	want := []CrashPoint{
		CrashAfterAcquire,
		CrashAfterBeginExecution,
		CrashAfterMarkInFlight,
		CrashBeforeProvider,
		CrashAfterProvider,
		CrashBeforeObservation,
		CrashAfterObservation,
		CrashBeforeRecovery,
		CrashAfterRecovery,
	}
	if len(fired) != len(want) {
		t.Fatalf("fired %v, want %v", fired, want)
	}
	for i := range want {
		if fired[i] != want[i] {
			t.Fatalf("fired %v, want %v", fired, want)
		}
	}
}

// ctxAwareProvider honors caller cancellation during the provider call
// — the realistic case for a cancellation suite. A cancelled call
// returns an ambiguous failure (the request may have been sent).
type ctxAwareProvider struct {
	delay time.Duration
}

func (p ctxAwareProvider) Execute(ctx context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return Response{
			Status: StatusFailed,
			Error:  "context cancelled during provider call — request may have been sent",
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    "run-cancelled",
			},
		}
	}
	return Response{
		Status: StatusSucceeded,
		Result: json.RawMessage(`{"ok":true}`),
		Execution: &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    "run-ok",
		},
	}
}

// TestAdversarialCancellation cancels the caller at every durable
// boundary and asserts the cancellation contract:
//
//   - before the dispatch boundary: cancellation may abort; the record
//     stays pre-dispatch claimable — never a fabricated effect claim.
//   - after the dispatch boundary: cancellation cannot erase
//     mandatory persistence — the record reaches UNKNOWN (ambiguous
//     provider outcome) or COMMITTED (provider answered), never
//     stranded mid-transition by the caller's lifecycle.
func TestAdversarialCancellation(t *testing.T) {
	tests := []struct {
		point        CrashPoint
		wantStates   []idempotency.State
		wantTerminal bool // durable final state required
	}{
		{CrashAfterAcquire, []idempotency.State{idempotency.StatePrepared, idempotency.StateExecuting}, false},
		{CrashAfterBeginExecution, []idempotency.State{idempotency.StatePrepared, idempotency.StateExecuting, idempotency.StateInFlight}, false},
		// IN_FLIGHT is already durable — a cancelled provider call is
		// post-dispatch ambiguity → UNKNOWN.
		{CrashAfterMarkInFlight, []idempotency.State{idempotency.StateUnknown, idempotency.StateInFlight}, false},
		{CrashBeforeProvider, []idempotency.State{idempotency.StateUnknown, idempotency.StateInFlight}, false},
		// Provider already answered — mandatory persistence runs on the
		// detached context regardless of caller cancellation.
		{CrashAfterProvider, []idempotency.State{idempotency.StateCommitted, idempotency.StateUnknown}, true},
		{CrashBeforeObservation, []idempotency.State{idempotency.StateCommitted, idempotency.StateUnknown}, true},
		{CrashAfterObservation, []idempotency.State{idempotency.StateCommitted, idempotency.StateUnknown}, true},
		{CrashBeforeFinalize, []idempotency.State{idempotency.StateCommitted, idempotency.StateUnknown}, true},
		{CrashAfterFinalize, []idempotency.State{idempotency.StateCommitted}, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.point), func(t *testing.T) {
			store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
			exec := NewDispatchExecutor(ctxAwareProvider{delay: 30 * time.Millisecond}, store)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exec.SetCrashHook(func(p CrashPoint) {
				if p == tt.point {
					cancel()
				}
			})

			key := fmt.Sprintf("cancel-%s-%d", tt.point, time.Now().UnixNano())
			resp := exec.ExecuteWithIdempotency(ctx, crashRequest("alice@example.com", key), crashDesc)

			rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			ok := false
			for _, ws := range tt.wantStates {
				if rec.State == ws {
					ok = true
				}
			}
			if !ok {
				t.Errorf("durable state = %s, want one of %v (wire=%s)", rec.State, tt.wantStates, resp.Status)
			}
			if tt.wantTerminal && !rec.State.IsDurablyFinal() && rec.State != idempotency.StateUnknown {
				t.Errorf("post-provider cancel left non-final state %s — persistence was not caller-independent", rec.State)
			}
			t.Logf("cancel@%s → wire=%s durable=%s", tt.point, resp.Status, rec.State)
		})
	}
}
