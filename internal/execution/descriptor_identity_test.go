package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

	// The replay must have been a one-time migrate-on-touch: the stored
	// digest is now the descriptor-bound identity, stamped at the
	// descriptor-bound version, with the migration on the event ledger.
	desc := mutationDescriptorV1()
	descDigest, err := desc.DescriptorDigest()
	if err != nil {
		t.Fatalf("descriptor digest: %v", err)
	}
	wantDigest, err := idempotency.ComputeDigestFromRawWithMediation(1,
		"alice@example.com", "test.mut", args, "grant_x", "MUTATION",
		0, "", "DURABLE", "CRABEDENCE", desc.DescriptorVersion, descDigest, nil)
	if err != nil {
		t.Fatalf("bound digest: %v", err)
	}
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.RequestDigest != wantDigest {
		t.Fatalf("migrated record must store the descriptor-bound digest %s, has %s",
			wantDigest, rec.RequestDigest)
	}
	if rec.DigestVersion != idempotency.DigestVersionDescriptorBound {
		t.Fatalf("migrated record digest_version = %d, want %d",
			rec.DigestVersion, idempotency.DigestVersionDescriptorBound)
	}
	events, err := store.ListEffectEvents(ctx, executionID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	sawMigration := false
	for _, ev := range events {
		if ev.EventType == idempotency.EventDigestMigrated {
			sawMigration = true
		}
	}
	if !sawMigration {
		t.Fatal("DIGEST_MIGRATED event missing from the forensic ledger")
	}

	// The migrated record is now protected like a fresh one: a policy
	// change under the same key must conflict, never replay.
	bumped := mutationDescriptorV1()
	bumped.DescriptorVersion = 2
	blocked := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      args,
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, bumped)
	if blocked.Status != StatusDenied || blocked.FailureCode != string(capability.FailureIdempotencyConflict) {
		t.Fatalf("a policy change after migration must conflict, got %s: %s", blocked.Status, blocked.Error)
	}
}

// TestLegacyRecordHeldLeaseIsNotMigrated proves the migration never
// pulls an identity out from under an active dispatch: a legacy record
// with a live lease reports IN_FLIGHT under its stored identity and
// keeps its legacy digest for the owner to finalize against.
func TestLegacyRecordHeldLeaseIsNotMigrated(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("legacy-held-%d", time.Now().UnixNano())
	args := json.RawMessage(`{"x":1}`)

	legacyDigest, err := idempotency.ComputeDigestFromRawWithAuthority(1,
		"alice@example.com", "test.mut", args, "grant_x", "MUTATION", 0, "", "DURABLE", "CRABEDENCE")
	if err != nil {
		t.Fatal(err)
	}
	acq, err := store.AcquireWithAuthority(ctx, key, "alice@example.com", "test.mut", legacyDigest,
		idempotency.AuthorityBinding{Ref: "grant_x"}, "MUTATION", idempotency.DefaultLeaseConfig.DefaultDuration)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !acq.Acquired() {
		t.Fatalf("expected acquisition, got %s", acq.Kind)
	}
	executionID := acq.Record.ExecutionID

	// The lease is still live: migration is refused, and the caller is
	// classified under the stored legacy identity — IN_FLIGHT, not a
	// conflict and never a second dispatch.
	exec := NewDispatchExecutor(succeedHandler{delay: time.Millisecond}, store)
	response := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      args,
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, mutationDescriptorV1())
	if response.Status != StatusInFlight {
		t.Fatalf("live-lease legacy record must report IN_FLIGHT, got %s: %s", response.Status, response.Error)
	}
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.RequestDigest != legacyDigest {
		t.Fatalf("held record's digest must not migrate mid-lease: %s != %s", rec.RequestDigest, legacyDigest)
	}
}

// TestLegacyRecordExpiredLeaseMigratesThenDispatches proves the
// pre-dispatch path through migration: an expired-lease legacy record
// is upgraded first, then reclaimed and dispatched under the
// descriptor-bound identity — so the finalize receipt matches the row
// instead of stranding the execution on a digest identity mismatch.
func TestLegacyRecordExpiredLeaseMigratesThenDispatches(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("legacy-expired-%d", time.Now().UnixNano())
	args := json.RawMessage(`{"x":1}`)

	legacyDigest, err := idempotency.ComputeDigestFromRawWithAuthority(1,
		"alice@example.com", "test.mut", args, "grant_x", "MUTATION", 0, "", "DURABLE", "CRABEDENCE")
	if err != nil {
		t.Fatal(err)
	}
	acq, err := store.AcquireWithAuthority(ctx, key, "alice@example.com", "test.mut", legacyDigest,
		idempotency.AuthorityBinding{Ref: "grant_x"}, "MUTATION", idempotency.DefaultLeaseConfig.DefaultDuration)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	executionID := acq.Record.ExecutionID
	if err := store.ExpireLeaseForTest(ctx, executionID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	exec := NewDispatchExecutor(succeedHandler{delay: time.Millisecond}, store)
	response := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      args,
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
	}, mutationDescriptorV1())
	if response.Status != StatusSucceeded {
		t.Fatalf("expired-lease legacy record must migrate and dispatch, got %s: %s", response.Status, response.Error)
	}
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("record must be COMMITTED after migration+dispatch, got %s", rec.State)
	}
	if rec.DigestVersion != idempotency.DigestVersionDescriptorBound {
		t.Fatalf("dispatched record digest_version = %d, want %d",
			rec.DigestVersion, idempotency.DigestVersionDescriptorBound)
	}
}

// TestLegacyRecordMediationMismatchStaysConflict proves the migration
// path cannot launder identity through the legacy digest: a legacy record
// (which predates mediation evidence) replayed by a request that carries
// mediation is a different identity, and must stay a conflict rather than
// fall back to classifying under the stored digest.
func TestLegacyRecordMediationMismatchStaysConflict(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("legacy-mediation-%d", time.Now().UnixNano())
	args := json.RawMessage(`{"x":1}`)

	legacyDigest, err := idempotency.ComputeDigestFromRawWithAuthority(1,
		"alice@example.com", "test.mut", args, "grant_x", "MUTATION", 0, "", "DURABLE", "CRABEDENCE")
	if err != nil {
		t.Fatal(err)
	}
	acq, err := store.AcquireWithAuthority(ctx, key, "alice@example.com", "test.mut", legacyDigest,
		idempotency.AuthorityBinding{Ref: "grant_x"}, "MUTATION", idempotency.DefaultLeaseConfig.DefaultDuration)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Clear the live-lease guard so the store's own mediation comparison is
	// what refuses the migration — both layers must agree before a record
	// may be reclassified.
	if err := store.ExpireLeaseForTest(ctx, acq.Record.ExecutionID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	exec := NewDispatchExecutor(succeedHandler{delay: time.Millisecond}, store)
	response := exec.ExecuteWithIdempotency(ctx, Request{
		Capability:     "test.mut",
		Arguments:      args,
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: key,
		Mediation: &RequestMediation{
			MiddlewareSetDigest: strings.Repeat("a", 64),
			OriginalArgsDigest:  strings.Repeat("b", 64),
		},
	}, mutationDescriptorV1())
	if response.Status != StatusDenied ||
		response.FailureCode != string(capability.FailureIdempotencyConflict) {
		t.Fatalf("mediation-mismatched legacy record must stay a conflict, got %s: %s",
			response.Status, response.Error)
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
