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

// simProvider is an adversarial fake provider for qualification tests.
// It separates what the provider DID (the external effect) from what
// the provider SAID (the response) — the exact ambiguity the durable
// executor exists to handle. effects counts external side effects
// applied; calls counts invocations; respond produces per-call
// responses so a scenario can return contradictory answers.
type simProvider struct {
	calls   atomic.Int32
	effects atomic.Int32
	delay   time.Duration
	// effect, when true, applies the external side effect on every
	// invocation before responding.
	effect bool
	// respond produces the response for invocation n (1-based).
	// nil responds SUCCEEDED with a per-call run ID.
	respond func(n int32) Response
}

func (p *simProvider) Execute(_ context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	n := p.calls.Add(1)
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	if p.effect {
		p.effects.Add(1)
	}
	if p.respond != nil {
		resp := p.respond(n)
		if resp.Execution == nil {
			resp.Execution = &ExecutionMeta{Provider: desc.AdapterID, RunID: fmt.Sprintf("run-%d", n)}
		}
		return resp
	}
	return Response{
		Status:    StatusSucceeded,
		Result:    json.RawMessage(`{"ok":true}`),
		Execution: &ExecutionMeta{Provider: desc.AdapterID, RunID: fmt.Sprintf("run-%d", n)},
	}
}

func simExec(t *testing.T, p *simProvider) (*DispatchExecutor, *idempotency.SQLiteStore) {
	t.Helper()
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	return NewDispatchExecutor(p, store), store
}

// successLostResponse: the provider applied the effect but the wire
// outcome is ambiguous (timeout-shaped failure without definitive
// provenance). The record must become UNKNOWN — never FAILED — and
// the provider observation must carry what the provider reported.
func TestSimSuccessLostResponse(t *testing.T) {
	p := &simProvider{
		effect: true,
		respond: func(n int32) Response {
			return Response{Status: StatusFailed, Error: "connection reset after request sent"}
		},
	}
	exec, store := simExec(t, p)

	key := fmt.Sprintf("sim-lost-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), crashDesc)
	if resp.Status != StatusUnknown {
		t.Fatalf("effect applied + ambiguous response must be UNKNOWN, got %s", resp.Status)
	}
	if p.effects.Load() != 1 {
		t.Fatalf("expected 1 external effect, got %d", p.effects.Load())
	}
	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("durable state = %s, want UNKNOWN", rec.State)
	}
	if rec.ProviderStatus == "" {
		t.Error("provider observation not persisted for ambiguous outcome")
	}
}

// failureBeforeExecution: a provably pre-transmission failure — no
// effect happened, the executor may record FAILED with the error
// payload as receipt.
func TestSimFailureBeforeExecution(t *testing.T) {
	p := &simProvider{
		effect: false,
		respond: func(n int32) Response {
			return Response{
				Status:            StatusFailed,
				Error:             "connection refused: request never sent",
				DefinitiveFailure: true,
			}
		},
	}
	exec, store := simExec(t, p)

	key := fmt.Sprintf("sim-nosend-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), crashDesc)
	if resp.Status != StatusFailed {
		t.Fatalf("definitive pre-transmission failure should be FAILED, got %s", resp.Status)
	}
	if p.effects.Load() != 0 {
		t.Fatal("no effect should have been applied")
	}
	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != idempotency.StateFailed {
		t.Fatalf("durable state = %s, want FAILED", rec.State)
	}
}

// executionPlusTimeout: effect applied, response reads as timeout —
// UNKNOWN. A retry of the same idempotency key must NOT redispatch:
// it replays the UNKNOWN record. Provider effects stay at 1.
func TestSimExecutionPlusTimeoutNoRedispatch(t *testing.T) {
	p := &simProvider{
		effect: true,
		respond: func(n int32) Response {
			return Response{Status: StatusFailed, Error: "timeout awaiting provider response"}
		},
	}
	exec, store := simExec(t, p)

	key := fmt.Sprintf("sim-timeout-%d", time.Now().UnixNano())
	req := crashRequest("alice@example.com", key)
	resp1 := exec.ExecuteWithIdempotency(context.Background(), req, crashDesc)
	if resp1.Status != StatusUnknown {
		t.Fatalf("first dispatch = %s, want UNKNOWN", resp1.Status)
	}
	resp2 := exec.ExecuteWithIdempotency(context.Background(), req, crashDesc)
	if resp2.Status != StatusUnknown {
		t.Fatalf("retry must replay UNKNOWN, got %s", resp2.Status)
	}
	if p.calls.Load() != 1 || p.effects.Load() != 1 {
		t.Fatalf("UNKNOWN retry redispatched: calls=%d effects=%d, want 1/1", p.calls.Load(), p.effects.Load())
	}
	rec, _ := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("durable state = %s, want UNKNOWN", rec.State)
	}
}

// duplicateProviderResponse: an idempotent replay of a committed
// execution must not invoke the provider again.
func TestSimDuplicateResponseReplay(t *testing.T) {
	p := &simProvider{effect: true}
	exec, store := simExec(t, p)

	key := fmt.Sprintf("sim-dup-%d", time.Now().UnixNano())
	req := crashRequest("alice@example.com", key)
	resp1 := exec.ExecuteWithIdempotency(context.Background(), req, crashDesc)
	if resp1.Status != StatusSucceeded {
		t.Fatalf("first = %s", resp1.Status)
	}
	resp2 := exec.ExecuteWithIdempotency(context.Background(), req, crashDesc)
	if resp2.Status != StatusSucceeded {
		t.Fatalf("replay = %s, want SUCCEEDED", resp2.Status)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("committed replay redispatched: calls=%d, want 1", p.calls.Load())
	}
	rec, _ := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("state = %s, want COMMITTED", rec.State)
	}
}

// contradictoryProviderResponses: the provider returns a different
// result each call. A MUTATION execution commits on first dispatch;
// a second caller with the SAME idempotency key gets the stored
// result — never the contradictory second response.
func TestSimContradictoryResponses(t *testing.T) {
	p := &simProvider{
		effect: true,
		respond: func(n int32) Response {
			return Response{
				Status: StatusSucceeded,
				Result: json.RawMessage(fmt.Sprintf(`{"value":%d}`, n)),
			}
		},
	}
	exec, store := simExec(t, p)

	key := fmt.Sprintf("sim-contra-%d", time.Now().UnixNano())
	req := crashRequest("alice@example.com", key)
	resp1 := exec.ExecuteWithIdempotency(context.Background(), req, crashDesc)
	resp2 := exec.ExecuteWithIdempotency(context.Background(), req, crashDesc)
	if p.calls.Load() != 1 {
		t.Fatalf("second call redispatched: calls=%d", p.calls.Load())
	}
	if string(resp1.Result) != string(resp2.Result) {
		t.Errorf("replay returned different result: %s vs %s — stored result must win", resp1.Result, resp2.Result)
	}
	rec, _ := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if string(rec.Result) != string(resp1.Result) {
		t.Errorf("stored result %s != first response %s", rec.Result, resp1.Result)
	}
}

// delayedObservation: a slow provider does not strand the record —
// the heartbeat keeps the lease and the result commits.
func TestSimDelayedObservation(t *testing.T) {
	p := &simProvider{effect: true, delay: 150 * time.Millisecond}
	exec, store := simExec(t, p)

	key := fmt.Sprintf("sim-slow-%d", time.Now().UnixNano())
	resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), crashDesc)
	if resp.Status != StatusSucceeded {
		t.Fatalf("slow provider must still commit, got %s: %s", resp.Status, resp.Error)
	}
	rec, _ := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("state = %s, want COMMITTED", rec.State)
	}
}

// declaringProvider wraps simProvider with a ProviderCapabilities
// declaration for the CRITICAL admission gate.
type declaringProvider struct {
	*simProvider
	caps ProviderCapabilities
}

func (p declaringProvider) ProviderCapabilities(string) ProviderCapabilities {
	return p.caps
}

func criticalDesc() capability.ResolvedDescriptor {
	return capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassCritical,
		AdapterID:      "test-adapter",
	}
}

// TestCriticalAdmissionGate proves the provider-capability contract:
// a CRITICAL execution is denied at admission — before Acquire, before
// dispatch — when the provider cannot declare both completion and
// non-effect evidence support. No durable record is created.
func TestCriticalAdmissionGate(t *testing.T) {
	fullCaps := ProviderCapabilities{
		SupportsProviderIdempotency: true,
		SupportsStatusLookup:        true,
		SupportsCompletionProof:     true,
		SupportsNonexecutionProof:   true,
		RecoveryLocatorType:         "provider_run_id",
	}

	t.Run("undeclared provider denied", func(t *testing.T) {
		store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
		// simProvider declares nothing.
		exec := NewDispatchExecutor(&simProvider{effect: true}, store)
		key := fmt.Sprintf("crit-undecl-%d", time.Now().UnixNano())
		resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), criticalDesc())
		if resp.Status != StatusDenied || resp.FailureCode != string(capability.FailureAdmissionDenied) {
			t.Fatalf("undeclared provider must be ADMISSION_DENIED, got %s/%s", resp.Status, resp.FailureCode)
		}
		if _, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key); err == nil {
			t.Error("denied admission must not create a durable record")
		}
	})

	t.Run("insufficient capabilities denied", func(t *testing.T) {
		store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
		// Completion proof without non-effect proof is not enough.
		p := declaringProvider{simProvider: &simProvider{effect: true}, caps: ProviderCapabilities{
			SupportsCompletionProof: true,
		}}
		exec := NewDispatchExecutor(p, store)
		key := fmt.Sprintf("crit-insuf-%d", time.Now().UnixNano())
		resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), criticalDesc())
		if resp.Status != StatusDenied {
			t.Fatalf("provider lacking nonexecution_proof must be denied, got %s", resp.Status)
		}
		if p.calls.Load() != 0 {
			t.Error("denied admission must not dispatch to provider")
		}
	})

	t.Run("fully declared provider admitted", func(t *testing.T) {
		store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
		p := declaringProvider{simProvider: &simProvider{effect: true}, caps: fullCaps}
		exec := NewDispatchExecutor(p, store)
		key := fmt.Sprintf("crit-ok-%d", time.Now().UnixNano())
		resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), criticalDesc())
		// A declared provider reaches dispatch; the outcome depends on
		// evidence handling, but admission itself must not be DENIED.
		if resp.Status == StatusDenied {
			t.Fatalf("fully declared provider must not be admission-denied: %s", resp.Error)
		}
	})

	t.Run("mutation unaffected by gate", func(t *testing.T) {
		store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
		exec := NewDispatchExecutor(&simProvider{effect: true}, store)
		key := fmt.Sprintf("mut-ok-%d", time.Now().UnixNano())
		resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), crashDesc)
		if resp.Status != StatusSucceeded {
			t.Fatalf("MUTATION through undeclared provider must dispatch, got %s", resp.Status)
		}
	})
}
