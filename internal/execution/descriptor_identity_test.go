package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

func mutationDescriptorV1() capability.ResolvedDescriptor {
	return capability.ResolvedDescriptor{
		ID:                "test.mut",
		DescriptorVersion: 1,
		ExecutionClass:    capability.ClassMutation,
		AssuranceProfile:  capability.AssuranceDurable,
		ExecutionRoute:    capability.RouteCrabedence,
		AdapterID:         "test-adapter",
	}
}

// TestLegacyDigestRecordsRemainReplayable proves the compatibility
// window: a record created before descriptor identity was bound (its
// stored digest is the legacy digest) still replays instead of
// conflicting, and new records store the descriptor-bound digest.
func TestLegacyDigestRecordsRemainReplayable(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("legacy-%d", time.Now().UnixNano())
	args := json.RawMessage(`{"x":1}`)

	legacyDigest, err := idempotency.ComputeDigestFromRawWithAuthority(1,
		"alice@example.com", "test.mut", args, "grant_x", "MUTATION", 0, "", "DURABLE", "CRABEDENCE")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a pre-upgrade record: acquired and finalized under the
	// legacy digest.
	acq, err := store.AcquireWithAuthority(ctx, key, "alice@example.com", "test.mut", legacyDigest,
		idempotency.AuthorityBinding{Ref: "grant_x"}, "MUTATION", idempotency.DefaultLeaseConfig.DefaultDuration)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected to acquire the record, got %s", acq.Kind)
	}
	executionID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, executionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin execution: %v", err)
	}
	locator := json.RawMessage(`{"v":1,"provider_id":"test-adapter","strategy":"metadata"}`)
	if err := store.MarkInFlight(ctx, executionID, acq.LeaseToken, acq.Generation, "test-adapter", locator); err != nil {
		t.Fatalf("mark in flight: %v", err)
	}
	receipt := idempotency.TerminalReceipt{
		ExecutionID:     executionID,
		Capability:      "test.mut",
		Principal:       "alice@example.com",
		RequestDigest:   legacyDigest,
		TerminalStatus:  idempotency.StateCommitted,
		CanonicalResult: json.RawMessage(`{"legacy":true}`),
		ProviderID:      "test-adapter",
		ProviderRunID:   "run-legacy",
	}
	if err := store.Finalize(ctx, executionID, acq.LeaseToken, acq.Generation, idempotency.StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// The executor now binds descriptor identity, so the first acquire
	// conflicts — the legacy retry must replay the stored result.
	exec := NewDispatchExecutor(succeedHandler{delay: time.Millisecond}, store)
	response := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      args,
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, mutationDescriptorV1())

	if response.Status != StatusSucceeded {
		t.Fatalf("legacy record must replay, got %s: %s", response.Status, response.Error)
	}
	if string(response.Result) != `{"legacy":true}` {
		t.Fatalf("replayed result = %s", response.Result)
	}
}

// TestDescriptorIdentityFailsClosedOnRealConflict proves the compat
// window does not weaken conflict detection: the same key with
// different arguments matches neither digest and still conflicts.
func TestDescriptorIdentityFailsClosedOnRealConflict(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("descriptor-conflict-%d", time.Now().UnixNano())
	exec := NewDispatchExecutor(succeedHandler{delay: time.Millisecond}, store)

	first := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, mutationDescriptorV1())
	if first.Status != StatusSucceeded {
		t.Fatalf("first execution failed: %s: %s", first.Status, first.Error)
	}

	second := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":2}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, mutationDescriptorV1())
	if second.Status != StatusDenied || second.FailureCode != string(capability.FailureIdempotencyConflict) {
		t.Fatalf("different arguments under the same key must conflict, got %s: %s", second.Status, second.Error)
	}
}

// TestDescriptorVersionBumpIsANewIdentity proves a policy version bump
// changes the execution identity for the same key and arguments.
func TestDescriptorVersionBumpIsANewIdentity(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("descriptor-version-%d", time.Now().UnixNano())
	exec := NewDispatchExecutor(succeedHandler{delay: time.Millisecond}, store)

	first := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, mutationDescriptorV1())
	if first.Status != StatusSucceeded {
		t.Fatalf("first execution failed: %s: %s", first.Status, first.Error)
	}

	bumped := mutationDescriptorV1()
	bumped.DescriptorVersion = 2
	second := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, bumped)
	if second.Status != StatusDenied || second.FailureCode != string(capability.FailureIdempotencyConflict) {
		t.Fatalf("a policy version bump must change the execution identity, got %s: %s", second.Status, second.Error)
	}
}
