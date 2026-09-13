package execution

import (
	"context"
	"encoding/json"
	"reflect"
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

// TestCounterResolverCrossCapability verifies that the same principal
// reusing the same idempotency key under a DIFFERENT capability is a
// distinct durable execution — the store's uniqueness scope includes
// capability_id.
func TestCounterResolverCrossCapability(t *testing.T) {
	h := NewCounterHandler()
	desc := testCounterDescriptor()
	ctx := context.Background()

	h.Execute(ctx, Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"shared","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com"},
		IdempotencyKey: "same-key",
	}, desc)

	// Same principal, same key, different capability: never ran.
	res, err := h.Resolve(ctx, &idempotency.Record{
		PrincipalID:    "alice@example.com",
		CapabilityID:   "test.counter.other",
		IdempotencyKey: "same-key",
		RecoveryLocator: json.RawMessage(
			`{"counter":"shared","by":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == idempotency.RecoveryCommitted {
		t.Error("FALSE POSITIVE: different capability resolved COMMITTED from another capability's execution")
	}
}

// TestCounterResolverTokenGraft verifies that a locator carrying
// another execution's external token cannot resolve this record — the
// token identifies a specific execution and its recorded identity must
// match the record's durable identity.
func TestCounterResolverTokenGraft(t *testing.T) {
	h := NewCounterHandler()
	desc := testCounterDescriptor()
	ctx := context.Background()

	// Execution A runs under its token (as DispatchExecutor injects).
	ctxA := context.WithValue(ctx, externalTokenKey{}, "ctr-op-exec-A")
	h.Execute(ctxA, Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"shared","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com"},
		IdempotencyKey: "k-exec-a",
	}, desc)

	// Record B (a different durable execution) carries A's token — the
	// token matches an execution but the identities contradict.
	res, err := h.Resolve(ctx, &idempotency.Record{
		ExecutionID:    "exec-B",
		PrincipalID:    "alice@example.com",
		CapabilityID:   "test.counter.increment",
		IdempotencyKey: "k-exec-b",
		RecoveryLocator: json.RawMessage(
			`{"external_token":"ctr-op-exec-A","extensions":{"counter":"shared","by":1}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == idempotency.RecoveryCommitted {
		t.Error("FALSE POSITIVE: grafted token resolved a different execution COMMITTED")
	}

	// The genuine record for A still resolves via its token.
	res, err = h.Resolve(ctx, &idempotency.Record{
		ExecutionID:    "exec-A",
		PrincipalID:    "alice@example.com",
		CapabilityID:   "test.counter.increment",
		IdempotencyKey: "k-exec-a",
		RecoveryLocator: json.RawMessage(
			`{"external_token":"ctr-op-exec-A","extensions":{"counter":"shared","by":1}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("genuine token record must resolve COMMITTED, got %s", res.Decision)
	}
	if res.ProviderRunID == "" {
		t.Error("resolver must return the original provider run ID")
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
	if locator.ProviderID != "test-counter" {
		t.Errorf("expected provider_id=test-counter, got %q", locator.ProviderID)
	}
	if locator.ExecutionID != "exec-1" {
		t.Errorf("expected execution_id in locator, got %q", locator.ExecutionID)
	}
	if locator.PrincipalID != "alice@example.com" {
		t.Errorf("expected principal in locator, got %q", locator.PrincipalID)
	}
	if locator.ExternalToken != "ctr-op-exec-1" {
		t.Errorf("expected external token derived from execution_id, got %q", locator.ExternalToken)
	}
	var ext struct {
		Counter string `json:"counter"`
		By      int64  `json:"by"`
	}
	if err := json.Unmarshal(locator.Extensions, &ext); err != nil {
		t.Fatal(err)
	}
	if ext.By != 1 {
		t.Errorf("expected normalized by=1 (default applied), got %v", ext.By)
	}
	if ext.Counter != "x" {
		t.Errorf("expected counter=x, got %v", ext.Counter)
	}
	raw, _ := json.Marshal(locator)
	var loc map[string]any
	if err := json.Unmarshal(raw, &loc); err != nil {
		t.Fatal(err)
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
	if !reflect.DeepEqual(a, b) {
		t.Errorf("semantically equivalent args produced different locators:\n%+v\n%+v", a, b)
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
	locator := genericRecoveryLocator(Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"secret-data","secret":"sensitive"}`),
		Authority:      RequestAuthority{Principal: "alice@example.com"},
		IdempotencyKey: "k1",
	}, desc, "digest-1", "exec-1")

	raw, _ := json.Marshal(locator)
	var loc map[string]any
	if err := json.Unmarshal(raw, &loc); err != nil {
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
	if loc["principal_id"] != "alice@example.com" {
		t.Error("generic locator must carry principal")
	}
}
