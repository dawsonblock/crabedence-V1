package execution

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// readDesc is a PURE/READ-class descriptor: those requests skip the
// durable store and dispatch directly, which is exactly the path where a
// gate refusal can be mistaken for a provider outcome.
var readDesc = capability.ResolvedDescriptor{
	ExecutionClass: capability.ClassRead,
	AdapterID:      "test-adapter",
}

func readRequest(key string) Request {
	req := crashRequest("alice@example.com", key)
	req.Capability = "test.read"
	return req
}

// TestProviderGateRefusalDoesNotHealOpenCircuit is the regression for
// the provider-health accounting defect: a refusal produced by the gate
// itself (circuit open) must never be recorded as a provider success.
func TestProviderGateRefusalDoesNotHealOpenCircuit(t *testing.T) {
	p := &simProvider{}
	exec := NewDispatchExecutor(p, nil)
	gate := NewProviderGate(ProviderGateConfig{DegradedAfter: 1, OpenAfter: 1})
	exec.SetProviderGate(gate)

	gate.RecordAmbiguous(readDesc.AdapterID, "ambiguous outcome")
	if got := gate.Health(readDesc.AdapterID); got != ProviderOpen {
		t.Fatalf("precondition: health = %s, want open", got)
	}

	resp := exec.ExecuteWithIdempotency(context.Background(), readRequest("read-open"), readDesc)
	if resp.Status != StatusFailed {
		t.Fatalf("open-circuit READ = %s, want FAILED (%s)", resp.Status, resp.Error)
	}
	if got := gate.Health(readDesc.AdapterID); got != ProviderOpen {
		t.Fatalf("a gate refusal healed the circuit: health = %s, want open", got)
	}
	if got := p.calls.Load(); got != 0 {
		t.Fatalf("provider calls = %d, want 0 (an open circuit must not dispatch)", got)
	}
}

// TestProviderGateSaturationDoesNotResetHealth proves a saturated
// provider refusal leaves the failure streak exactly as it was.
func TestProviderGateSaturationDoesNotResetHealth(t *testing.T) {
	p := &simProvider{}
	exec := NewDispatchExecutor(p, nil)
	gate := NewProviderGate(ProviderGateConfig{MaxConcurrent: 1, DegradedAfter: 2, OpenAfter: 5})
	exec.SetProviderGate(gate)

	gate.RecordAmbiguous(readDesc.AdapterID, "ambiguous outcome")
	slot, err := gate.Acquire(readDesc.AdapterID)
	if err != nil {
		t.Fatalf("occupy slot: %v", err)
	}
	defer slot.Release()

	resp := exec.ExecuteWithIdempotency(context.Background(), readRequest("read-saturated"), readDesc)
	if resp.Status != StatusFailed || resp.FailureCode != string(capability.FailureCapabilityUnavailable) {
		t.Fatalf("saturated READ = %s/%s, want FAILED/CAPABILITY_UNAVAILABLE", resp.Status, resp.FailureCode)
	}
	snap := gate.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot has %d providers, want 1", len(snap))
	}
	if snap[0].ConsecutiveFailures != 1 {
		t.Fatalf("saturation reset the failure streak: %+v", snap[0])
	}
	if got := p.calls.Load(); got != 0 {
		t.Fatalf("provider calls = %d, want 0 (a saturated gate must not dispatch)", got)
	}
}

// TestExpiredDeadlineDoesNotCountAsProviderSuccess proves an
// executor-proved no-effect failure (the deadline expired before the
// handler could run) leaves provider health untouched.
func TestExpiredDeadlineDoesNotCountAsProviderSuccess(t *testing.T) {
	p := &simProvider{}
	exec := NewDispatchExecutor(p, nil)
	gate := NewProviderGate(ProviderGateConfig{DegradedAfter: 1, OpenAfter: 3})
	exec.SetProviderGate(gate)

	gate.RecordAmbiguous(readDesc.AdapterID, "ambiguous outcome")
	if got := gate.Health(readDesc.AdapterID); got != ProviderDegraded {
		t.Fatalf("precondition: health = %s, want degraded", got)
	}

	req := readRequest("read-expired")
	req.Deadline = time.Now().Add(-time.Minute).Format(time.RFC3339)
	resp := exec.ExecuteWithIdempotency(context.Background(), req, readDesc)
	if resp.Status != StatusFailed {
		t.Fatalf("expired-deadline READ = %s, want FAILED (%s)", resp.Status, resp.Error)
	}
	if !strings.Contains(resp.Error, "deadline") {
		t.Fatalf("expired-deadline error = %q, want the deadline reason", resp.Error)
	}
	if got := gate.Health(readDesc.AdapterID); got != ProviderDegraded {
		t.Fatalf("an expired deadline reset provider health to %s, want degraded", got)
	}
	if got := p.calls.Load(); got != 0 {
		t.Fatalf("provider calls = %d, want 0", got)
	}
}

// TestProviderProbeSuccessResetsHealth proves the positive direction
// still works: a probe that actually reaches the provider and succeeds
// heals it.
func TestProviderProbeSuccessResetsHealth(t *testing.T) {
	now := time.Unix(0, 0)
	p := &simProvider{}
	exec := NewDispatchExecutor(p, nil)
	gate := NewProviderGate(ProviderGateConfig{
		DegradedAfter: 1,
		OpenAfter:     1,
		OpenCooldown:  time.Minute,
	})
	gate.setClock(func() time.Time { return now })
	exec.SetProviderGate(gate)

	gate.RecordAmbiguous(readDesc.AdapterID, "ambiguous outcome")
	if got := gate.Health(readDesc.AdapterID); got != ProviderOpen {
		t.Fatalf("precondition: health = %s, want open", got)
	}
	// Before the cooldown: refused, and the circuit stays open.
	if resp := exec.ExecuteWithIdempotency(context.Background(), readRequest("read-refused"), readDesc); resp.Status != StatusFailed {
		t.Fatalf("pre-cooldown READ = %s, want FAILED", resp.Status)
	}
	if got := gate.Health(readDesc.AdapterID); got != ProviderOpen {
		t.Fatalf("health after refusal = %s, want open", got)
	}

	// After the cooldown the probe runs: the provider is reached and
	// answers, which is the one thing that may reset the streak.
	now = now.Add(time.Minute)
	resp := exec.ExecuteWithIdempotency(context.Background(), readRequest("read-probe"), readDesc)
	if resp.Status != StatusSucceeded {
		t.Fatalf("probe READ = %s, want SUCCEEDED (%s)", resp.Status, resp.Error)
	}
	if got := gate.Health(readDesc.AdapterID); got != ProviderHealthy {
		t.Fatalf("health after a successful probe = %s, want healthy", got)
	}
	if got := p.calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (the probe must reach the provider)", got)
	}
}

// TestReadCeilingCountsAsAmbiguousNotSuccess proves a provider that was
// invoked but never answered is not counted as healthy, even though the
// effect class makes the outcome a safe FAILED for the caller.
func TestReadCeilingCountsAsAmbiguousNotSuccess(t *testing.T) {
	p := &simProvider{
		respond: func(int32) Response {
			time.Sleep(250 * time.Millisecond)
			return Response{Status: StatusSucceeded}
		},
	}
	exec := NewDispatchExecutor(p, nil)
	exec.SetTimeouts(ExecutorTimeouts{
		ProviderExecution:      20 * time.Millisecond,
		ProviderExecutionGrace: 10 * time.Millisecond,
	})
	gate := NewProviderGate(ProviderGateConfig{DegradedAfter: 1, OpenAfter: 5})
	exec.SetProviderGate(gate)

	resp := exec.ExecuteWithIdempotency(context.Background(), readRequest("read-ceiling"), readDesc)
	if resp.Status != StatusFailed {
		t.Fatalf("READ ceiling = %s, want a safe FAILED (%s)", resp.Status, resp.Error)
	}
	snap := gate.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot has %d providers, want 1", len(snap))
	}
	if snap[0].ConsecutiveFailures != 1 {
		t.Fatalf("READ ceiling did not degrade the provider: %+v", snap[0])
	}
	if snap[0].Timeouts != 1 {
		t.Fatalf("READ ceiling did not record a timeout: %+v", snap[0])
	}
}
