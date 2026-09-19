package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// Architectural laws, as first-class named tests. Each test asserts one
// law from the trust-closure plan; the law ID is the test name, so a
// violation is unambiguous in CI output.

// INV-006: Once external dispatch may have occurred, automatic replay
// requires proof of non-execution — an ambiguous post-dispatch result is
// UNKNOWN, never FAILED.
func TestINV006PostDispatchAmbiguityIsNeverFailed(t *testing.T) {
	desc := mutationDurableDescriptor("inv.mut")

	ambiguous, _ := classifyPostDispatch(Response{Status: StatusFailed}, desc)
	if ambiguous != idempotency.StateUnknown {
		t.Fatalf("INV-006 violated: ambiguous post-dispatch failure classified as %s", ambiguous)
	}
	denied, _ := classifyPostDispatch(Response{Status: StatusDenied}, desc)
	if denied != idempotency.StateUnknown {
		t.Fatalf("INV-006 violated: post-dispatch DENIED classified as %s", denied)
	}
	// Only an executor-provable definitive failure is terminal.
	definitive, _ := classifyPostDispatch(Response{Status: StatusFailed, DefinitiveFailure: true}, desc)
	if definitive != idempotency.StateFailed {
		t.Fatalf("a provable definitive failure must be FAILED, got %s", definitive)
	}
}

// INV-007: A stale lease owner can never finalize a receipt.
func TestINV007StaleLeaseOwnerCannotFinalize(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("inv007-%d", time.Now().UnixNano())

	first, err := store.AcquireWithAuthority(ctx, key, "alice@example.com", "inv.mut", "digest",
		idempotency.AuthorityBinding{}, "MUTATION", idempotency.DefaultLeaseConfig.DefaultDuration)
	if err != nil || !first.Acquired() {
		t.Fatalf("acquire: %v (%v)", err, first)
	}
	if err := store.AbandonPreDispatch(ctx, first.Record.ExecutionID, first.LeaseToken, first.Generation); err != nil {
		t.Fatalf("abandon: %v", err)
	}

	second, err := store.AcquireWithAuthority(ctx, key, "alice@example.com", "inv.mut", "digest",
		idempotency.AuthorityBinding{}, "MUTATION", idempotency.DefaultLeaseConfig.DefaultDuration)
	if err != nil || !second.Acquired() {
		t.Fatalf("reacquire: %v (%v)", err, second)
	}
	if second.Generation <= first.Generation {
		t.Fatalf("INV-007 setup: generation did not advance (%d -> %d)", first.Generation, second.Generation)
	}

	receipt := idempotency.TerminalReceipt{
		ExecutionID: first.Record.ExecutionID, Capability: "inv.mut", Principal: "alice@example.com",
		RequestDigest: "digest", TerminalStatus: idempotency.StateCommitted,
		CanonicalResult: json.RawMessage(`{}`), ProviderID: "test-adapter", ProviderRunID: "run",
	}
	if err := store.Finalize(ctx, first.Record.ExecutionID, first.LeaseToken, first.Generation,
		idempotency.StateInFlight, receipt); err == nil {
		t.Fatal("INV-007 violated: a stale lease owner finalized a receipt")
	}
}

// INV-009: Terminal receipts are immutable.
func TestINV009TerminalReceiptsAreImmutable(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	ctx := context.Background()
	key := fmt.Sprintf("inv009-%d", time.Now().UnixNano())

	acq, err := store.AcquireWithAuthority(ctx, key, "alice@example.com", "inv.mut", "digest",
		idempotency.AuthorityBinding{}, "MUTATION", idempotency.DefaultLeaseConfig.DefaultDuration)
	if err != nil || !acq.Acquired() {
		t.Fatalf("acquire: %v (%v)", err, acq)
	}
	executionID := acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, executionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatal(err)
	}
	locator := json.RawMessage(`{"v":1,"provider_id":"test-adapter","strategy":"metadata"}`)
	if err := store.MarkInFlight(ctx, executionID, acq.LeaseToken, acq.Generation, "test-adapter", locator); err != nil {
		t.Fatal(err)
	}

	original := idempotency.TerminalReceipt{
		ExecutionID: executionID, Capability: "inv.mut", Principal: "alice@example.com",
		RequestDigest: "digest", TerminalStatus: idempotency.StateCommitted,
		CanonicalResult: json.RawMessage(`{"first":true}`), ProviderID: "test-adapter", ProviderRunID: "run-1",
	}
	if err := store.Finalize(ctx, executionID, acq.LeaseToken, acq.Generation, idempotency.StateInFlight, original); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// Identical replay is idempotent.
	if err := store.Finalize(ctx, executionID, acq.LeaseToken, acq.Generation, idempotency.StateInFlight, original); err != nil {
		t.Fatalf("identical replay must be idempotent: %v", err)
	}

	// A conflicting receipt is rejected and the original is preserved.
	conflicting := original
	conflicting.CanonicalResult = json.RawMessage(`{"second":true}`)
	if err := store.Finalize(ctx, executionID, acq.LeaseToken, acq.Generation, idempotency.StateInFlight, conflicting); err == nil {
		t.Fatal("INV-009 violated: a conflicting terminal receipt overwrote the original")
	}
	record, err := store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatal(err)
	}
	if string(record.Result) != `{"first":true}` {
		t.Fatalf("INV-009 violated: stored result = %s", record.Result)
	}
}

// INV-010: The evidence signature covers the trusted artifact digest.
func TestINV010EvidenceSignatureCoversArtifactDigest(t *testing.T) {
	signer, err := evidence.LoadOrCreateSigner(filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	base := evidence.Binding{
		ExecutionID: "exec", Capability: "cap", Principal: "alice@example.com",
		RequestDigest: "request", ProviderID: "provider", ProviderRunID: "run",
		Outcome: evidence.OutcomeCompleted, EvidenceSHA256: strings.Repeat("a", 64),
	}
	other := base
	other.EvidenceSHA256 = strings.Repeat("b", 64)

	first, err := signer.Sign(base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.Sign(other)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("INV-010 violated: the signature does not cover the evidence digest")
	}
}

// INV-011: A registry-policy change changes request identity.
func TestINV011PolicyChangeChangesRequestIdentity(t *testing.T) {
	args := json.RawMessage(`{"x":1}`)
	base, err := idempotency.ComputeDigestFromRawWithDescriptor(1,
		"alice@example.com", "inv.mut", args, "", "MUTATION", 0, "", "DURABLE", "CRABEDENCE", 1, "aaaa")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := idempotency.ComputeDigestFromRawWithDescriptor(1,
		"alice@example.com", "inv.mut", args, "", "MUTATION", 0, "", "DURABLE", "CRABEDENCE", 1, "bbbb")
	if err != nil {
		t.Fatal(err)
	}
	if base == changed {
		t.Fatal("INV-011 violated: a policy change did not change the request identity")
	}
}
