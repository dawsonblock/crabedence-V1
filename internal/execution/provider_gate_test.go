package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// TestProviderGateBoundsConcurrency pins the containment property: the
// number of simultaneously executing provider calls is bounded, and a
// saturated provider is refused instead of accumulating goroutines.
func TestProviderGateBoundsConcurrency(t *testing.T) {
	gate := NewProviderGate(ProviderGateConfig{MaxConcurrent: 2})
	l1, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	l2, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if _, err := gate.Acquire("prov"); !errors.Is(err, ErrProviderSaturated) {
		t.Fatalf("third acquire = %v, want ErrProviderSaturated", err)
	}
	l1.Release()
	l3, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	l2.Release()
	l3.Release()

	// Capacity is per provider: another adapter has its own budget.
	l4, err := gate.Acquire("other")
	if err != nil {
		t.Fatalf("independent provider acquire: %v", err)
	}
	l4.Release()
}

// TestProviderGateHealthTransitions pins the circuit: consecutive
// ambiguous outcomes degrade the provider, then open the circuit; the
// cooldown admits exactly one probe, and a successful probe heals it.
func TestProviderGateHealthTransitions(t *testing.T) {
	now := time.Unix(0, 0)
	gate := NewProviderGate(ProviderGateConfig{DegradedAfter: 2, OpenAfter: 3, OpenCooldown: time.Minute})
	gate.setClock(func() time.Time { return now })

	if got := gate.Health("prov"); got != ProviderHealthy {
		t.Fatalf("fresh provider health = %s, want healthy", got)
	}
	gate.RecordAmbiguous("prov", "ambiguous outcome")
	if got := gate.Health("prov"); got != ProviderHealthy {
		t.Fatalf("one failure = %s, want healthy", got)
	}
	gate.RecordAmbiguous("prov", "ambiguous outcome")
	if got := gate.Health("prov"); got != ProviderDegraded {
		t.Fatalf("two failures = %s, want degraded", got)
	}
	gate.RecordAmbiguous("prov", "ambiguous outcome")
	if got := gate.Health("prov"); got != ProviderOpen {
		t.Fatalf("three failures = %s, want open", got)
	}
	if _, err := gate.Acquire("prov"); !errors.Is(err, ErrProviderCircuitOpen) {
		t.Fatalf("open circuit acquire = %v, want ErrProviderCircuitOpen", err)
	}

	// The cooldown admits exactly one probe; a second concurrent
	// acquisition is refused while the probe is unresolved.
	now = now.Add(time.Minute)
	probe, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("probe acquire: %v", err)
	}
	if _, err := gate.Acquire("prov"); !errors.Is(err, ErrProviderCircuitOpen) {
		t.Fatalf("second concurrent probe = %v, want ErrProviderCircuitOpen", err)
	}

	// A successful probe heals the provider and restores capacity.
	gate.RecordSuccess("prov")
	probe.Release()
	if got := gate.Health("prov"); got != ProviderHealthy {
		t.Fatalf("after successful probe health = %s, want healthy", got)
	}
	l, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("healthy acquire: %v", err)
	}
	l.Release()
}

// TestProviderGateFailingProbeReopensCircuit proves a probe that fails
// re-opens the circuit for another full cooldown instead of admitting
// traffic again.
func TestProviderGateFailingProbeReopensCircuit(t *testing.T) {
	now := time.Unix(0, 0)
	gate := NewProviderGate(ProviderGateConfig{DegradedAfter: 1, OpenAfter: 1, OpenCooldown: time.Minute})
	gate.setClock(func() time.Time { return now })

	gate.RecordAmbiguous("prov", "ambiguous outcome")
	now = now.Add(time.Minute)
	probe, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("probe acquire: %v", err)
	}
	gate.RecordAmbiguous("prov", "ambiguous outcome")
	probe.Release()
	if _, err := gate.Acquire("prov"); !errors.Is(err, ErrProviderCircuitOpen) {
		t.Fatalf("acquire after failing probe = %v, want ErrProviderCircuitOpen", err)
	}
	now = now.Add(time.Minute)
	next, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("probe after second cooldown: %v", err)
	}
	next.Release()
}

// TestProviderGateSnapshotAccountsWedgedAndTimeouts pins the
// observability surface: a call that outlived the ceiling stays
// counted as wedged (and keeps its slot) until its goroutine returns.
func TestProviderGateSnapshotAccountsWedgedAndTimeouts(t *testing.T) {
	gate := NewProviderGate(ProviderGateConfig{MaxConcurrent: 1})
	lease, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	lease.MarkTimeout()
	lease.MarkWedged()

	snap := gate.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot has %d providers, want 1", len(snap))
	}
	s := snap[0]
	if s.ProviderID != "prov" || s.InFlight != 1 || s.Wedged != 1 || s.Timeouts != 1 {
		t.Fatalf("snapshot = %+v, want provider prov in_flight=1 wedged=1 timeouts=1", s)
	}
	// The wedged call still holds its only slot: capacity is not
	// silently freed while the goroutine runs.
	if _, err := gate.Acquire("prov"); !errors.Is(err, ErrProviderSaturated) {
		t.Fatalf("acquire while wedged = %v, want ErrProviderSaturated", err)
	}

	lease.Release()
	snap = gate.Snapshot()
	if s := snap[0]; s.InFlight != 0 || s.Wedged != 0 || s.Timeouts != 1 {
		t.Fatalf("after release snapshot = %+v, want in_flight=0 wedged=0 timeouts=1", s)
	}
}

// blockingHandler blocks its first call until released, so a test can
// hold the provider gate's only slot open.
type blockingHandler struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func newBlockingHandler() *blockingHandler {
	return &blockingHandler{started: make(chan struct{}, 1), release: make(chan struct{})}
}

func (h *blockingHandler) Execute(_ context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	h.calls.Add(1)
	select {
	case h.started <- struct{}{}:
	default:
	}
	<-h.release
	return Response{
		Status:    StatusSucceeded,
		Result:    json.RawMessage(`{"ok":true}`),
		Execution: &ExecutionMeta{Provider: desc.AdapterID, RunID: "run-1"},
	}
}

// TestExecutorRefusesSaturatedProviderBeforeDispatch proves the
// dispatch-boundary semantics of a refusal: nothing reached the
// provider (provable no effect, FAILED), and the reservation was
// abandoned rather than consumed — the record returns to claimable
// PREPARED, so the same idempotency key dispatches for real once
// capacity exists.
func TestExecutorRefusesSaturatedProviderBeforeDispatch(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	handler := newBlockingHandler()
	exec := NewDispatchExecutor(handler, store)
	exec.SetProviderGate(NewProviderGate(ProviderGateConfig{MaxConcurrent: 1}))

	// First request occupies the only slot.
	firstDone := make(chan Response, 1)
	go func() {
		firstDone <- exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", "gate-key-1"), crashDesc)
	}()
	select {
	case <-handler.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first dispatch never reached the provider")
	}

	// Second request is refused before dispatch.
	resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", "gate-key-2"), crashDesc)
	if resp.Status != StatusFailed {
		t.Fatalf("saturated dispatch status = %s, want FAILED (%s)", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureCapabilityUnavailable) {
		t.Fatalf("saturated failure code = %s, want CAPABILITY_UNAVAILABLE", resp.FailureCode)
	}
	if !resp.DefinitiveFailure {
		t.Fatal("a refusal before dispatch must be a definitive no-effect failure")
	}
	if got := handler.calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (the refused request must not dispatch)", got)
	}

	// The refused request left a claimable record, not a terminal one.
	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", "gate-key-2")
	if err != nil {
		t.Fatalf("lookup refused request: %v", err)
	}
	if rec.State != idempotency.StatePrepared {
		t.Fatalf("refused request state = %s, want PREPARED (claimable)", rec.State)
	}

	// Capacity restored: the same key dispatches for real.
	close(handler.release)
	select {
	case first := <-firstDone:
		if first.Status != StatusSucceeded {
			t.Fatalf("first dispatch = %s, want SUCCEEDED (%s)", first.Status, first.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first dispatch never completed")
	}
	retry := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", "gate-key-2"), crashDesc)
	if retry.Status != StatusSucceeded {
		t.Fatalf("retry after capacity restored = %s, want SUCCEEDED (%s)", retry.Status, retry.Error)
	}
	if got := handler.calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
}

// TestExecutorOpensCircuitAfterRepeatedAmbiguity proves the health
// path: repeated post-dispatch ambiguity opens the circuit, and an
// open provider is refused before the provider is invoked.
func TestExecutorOpensCircuitAfterRepeatedAmbiguity(t *testing.T) {
	p := &simProvider{
		effect: true,
		respond: func(int32) Response {
			// Ignore cancellation entirely: every call outlives the
			// executor ceiling and converges to UNKNOWN.
			time.Sleep(250 * time.Millisecond)
			return Response{Status: StatusSucceeded}
		},
	}
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(p, store)
	exec.SetTimeouts(ExecutorTimeouts{ProviderExecution: 20 * time.Millisecond, ProviderExecutionGrace: 10 * time.Millisecond})
	exec.SetProviderGate(NewProviderGate(ProviderGateConfig{DegradedAfter: 1, OpenAfter: 2}))

	for i := 0; i < 2; i++ {
		resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", fmt.Sprintf("open-key-%d", i)), crashDesc)
		if resp.Status != StatusUnknown {
			t.Fatalf("dispatch %d = %s, want UNKNOWN (%s)", i, resp.Status, resp.Error)
		}
	}
	if got := exec.ProviderGate().Health(crashDesc.AdapterID); got != ProviderOpen {
		t.Fatalf("provider health = %s, want open", got)
	}

	before := p.calls.Load()
	resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", "open-key-refused"), crashDesc)
	if resp.Status != StatusFailed || resp.FailureCode != string(capability.FailureCapabilityUnavailable) {
		t.Fatalf("open-circuit dispatch = %s/%s, want FAILED/CAPABILITY_UNAVAILABLE (%s)", resp.Status, resp.FailureCode, resp.Error)
	}
	if !strings.Contains(resp.Error, "circuit is open") {
		t.Fatalf("open-circuit error = %q, want the circuit reason", resp.Error)
	}
	if got := p.calls.Load(); got != before {
		t.Fatalf("provider calls = %d, want %d (an open circuit must not dispatch)", got, before)
	}
}

// countingResolver is a recovery resolver that records its calls.
type countingResolver struct {
	mu     sync.Mutex
	calls  int
	result idempotency.RecoveryResult
	err    error
}

func (r *countingResolver) Resolve(context.Context, *idempotency.Record) (idempotency.RecoveryResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.result, r.err
}

// TestReconciliationIgnoresDispatchCapacity proves recovery queries
// are independent of dispatch capacity and health: the provider gate
// is saturated AND open, yet the resolver still runs and its outcome
// is counted without changing dispatch health.
func TestReconciliationIgnoresDispatchCapacity(t *testing.T) {
	gate := NewProviderGate(ProviderGateConfig{MaxConcurrent: 1, DegradedAfter: 1, OpenAfter: 1})
	lease, err := gate.Acquire("prov")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	gate.RecordAmbiguous("prov", "ambiguous outcome")
	if got := gate.Health("prov"); got != ProviderOpen {
		t.Fatalf("provider health = %s, want open", got)
	}

	resolver := &countingResolver{result: idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}}
	observed := gate.ObserveResolver("prov", resolver)
	result, err := observed.Resolve(context.Background(), &idempotency.Record{})
	if err != nil {
		t.Fatalf("reconciliation resolve: %v", err)
	}
	if result.Decision != idempotency.RecoveryUnknown {
		t.Fatalf("recovery decision = %s, want UNKNOWN passthrough", result.Decision)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (reconciliation must not acquire dispatch capacity)", resolver.calls)
	}

	snap := gate.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot has %d providers, want 1", len(snap))
	}
	if snap[0].ReconciliationFailures != 1 {
		t.Fatalf("reconciliation failures = %d, want 1", snap[0].ReconciliationFailures)
	}
	if snap[0].Health != ProviderOpen {
		t.Fatalf("reconciliation changed dispatch health to %s, want open", snap[0].Health)
	}
	lease.Release()
}
