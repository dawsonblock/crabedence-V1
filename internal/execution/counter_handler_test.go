package execution

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

func testCounterDescriptor() capability.ResolvedDescriptor {
	return capability.ResolvedDescriptor{
		ID:             "test.counter.increment",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "test-counter",
	}
}

// TestCounterResolverCrossPrincipal verifies the audit's execution-
// correlation fix: two principals using the same idempotency key on the
// same counter are DISTINCT durable executions. Alice's execution must
// not resolve Bob's UNKNOWN record to COMMITTED.
func TestCounterResolverCrossPrincipal(t *testing.T) {
	h := NewCounterHandler()
	desc := testCounterDescriptor()
	ctx := context.Background()

	// Alice executes: shared counter, key "same-key".
	resp := h.Execute(ctx, Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"shared","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com"},
		IdempotencyKey: "same-key",
	}, desc)
	if resp.Status != StatusSucceeded {
		t.Fatalf("alice execute failed: %s", resp.Status)
	}
	aliceRunID := resp.Execution.RunID

	// Alice's UNKNOWN record resolves COMMITTED with the ORIGINAL run ID.
	aliceRec := &idempotency.Record{
		ExecutionID:    "exec-alice",
		PrincipalID:    "alice@example.com",
		CapabilityID:   "test.counter.increment",
		IdempotencyKey: "same-key",
		RecoveryLocator: json.RawMessage(
			`{"counter":"shared","by":1}`),
	}
	res, err := h.Resolve(ctx, aliceRec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("alice should resolve COMMITTED, got %s", res.Decision)
	}
	if res.ProviderRunID != aliceRunID {
		t.Errorf("resolver must return original run ID %q, got %q", aliceRunID, res.ProviderRunID)
	}

	// Bob's record: same key, same counter, different principal — Bob's
	// execution never ran. Resolving it COMMITTED would be a false
	// positive that hides a missing side effect.
	bobRec := &idempotency.Record{
		ExecutionID:    "exec-bob",
		PrincipalID:    "bob@example.com",
		CapabilityID:   "test.counter.increment",
		IdempotencyKey: "same-key",
		RecoveryLocator: json.RawMessage(
			`{"counter":"shared","by":1}`),
	}
	res, err = h.Resolve(ctx, bobRec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == idempotency.RecoveryCommitted {
		t.Errorf("FALSE POSITIVE: bob resolved COMMITTED from alice's execution (run=%s)", res.ProviderRunID)
	}
}

// TestCounterResolverAmountMismatch verifies that a recorded execution
// with a different amount does not resolve — the locator's normalized
// parameters must match the recorded effect.
func TestCounterResolverAmountMismatch(t *testing.T) {
	h := NewCounterHandler()
	desc := testCounterDescriptor()
	ctx := context.Background()

	h.Execute(ctx, Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"c","by":5}`),
		Authority:      RequestAuthority{Principal: "alice@example.com"},
		IdempotencyKey: "k1",
	}, desc)

	res, err := h.Resolve(ctx, &idempotency.Record{
		PrincipalID:    "alice@example.com",
		IdempotencyKey: "k1",
		RecoveryLocator: json.RawMessage(
			`{"counter":"c","by":2}`), // different amount than executed
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == idempotency.RecoveryCommitted {
		t.Error("amount mismatch must not resolve COMMITTED")
	}
}

// TestCounterPrepareRecovery verifies the provider-owned locator: it
// stores the NORMALIZED executed form (semantic defaults applied) and
// the durable execution identity — not the raw argument blob.
func TestCounterPrepareRecovery(t *testing.T) {
	h := NewCounterHandler()
	locator, err := h.PrepareRecovery(context.Background(), idempotency.RecoveryLocatorInput{
		ExecutionID:    "exec-1",
		AdapterID:      "test-counter",
		CapabilityID:   "test.counter.increment",
		Principal:      "alice@example.com",
		IdempotencyKey: "k1",
		RequestDigest:  "d1",
		Arguments:      json.RawMessage(`{"counter":"x","by":0}`), // by=0 means default 1
	})
	if err != nil {
		t.Fatal(err)
	}
	var loc map[string]any
	if err := json.Unmarshal(locator, &loc); err != nil {
		t.Fatal(err)
	}
	if loc["by"] != float64(1) {
		t.Errorf("expected normalized by=1 (default applied), got %v", loc["by"])
	}
	if loc["counter"] != "x" {
		t.Errorf("expected counter=x, got %v", loc["counter"])
	}
	if loc["execution_id"] != "exec-1" {
		t.Errorf("expected execution_id in locator, got %v", loc["execution_id"])
	}
	if loc["principal"] != "alice@example.com" {
		t.Errorf("expected principal in locator, got %v", loc["principal"])
	}
	if _, hasArgs := loc["arguments"]; hasArgs {
		t.Error("provider locator must not embed raw arguments")
	}
}

// TestCounterPrepareRecoveryEquivalence verifies that semantically
// equivalent inputs produce identical locators — {"by":0} and {}
// both normalize to by=1, and {} (missing counter) defaults.
func TestCounterPrepareRecoveryEquivalence(t *testing.T) {
	h := NewCounterHandler()
	in := idempotency.RecoveryLocatorInput{
		ExecutionID: "e", AdapterID: "test-counter",
		CapabilityID: "c", Principal: "p", IdempotencyKey: "k",
	}
	a, err := h.PrepareRecovery(context.Background(), withArgs(in, `{"counter":"x","by":0}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.PrepareRecovery(context.Background(), withArgs(in, `{"counter":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("semantically equivalent args produced different locators:\n%s\n%s", a, b)
	}
}

func withArgs(in idempotency.RecoveryLocatorInput, args string) idempotency.RecoveryLocatorInput {
	in.Arguments = json.RawMessage(args)
	return in
}

// TestGenericRecoveryLocatorMinimization verifies the fallback locator
// never embeds raw arguments — only metadata needed for correlation.
func TestGenericRecoveryLocatorMinimization(t *testing.T) {
	desc := testCounterDescriptor()
	locator := buildRecoveryLocator(Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"secret-data","secret":"sensitive"}`),
		Authority:      RequestAuthority{Principal: "alice@example.com"},
		IdempotencyKey: "k1",
	}, desc, "digest-1")

	var loc map[string]any
	if err := json.Unmarshal(locator, &loc); err != nil {
		t.Fatal(err)
	}
	if _, hasArgs := loc["arguments"]; hasArgs {
		t.Error("generic locator must not embed raw arguments")
	}
	if loc["request_digest"] != "digest-1" {
		t.Error("generic locator must carry request_digest")
	}
	if loc["idempotency_key"] != "k1" {
		t.Error("generic locator must carry idempotency_key")
	}
	if loc["principal"] != "alice@example.com" {
		t.Error("generic locator must carry principal")
	}
}
