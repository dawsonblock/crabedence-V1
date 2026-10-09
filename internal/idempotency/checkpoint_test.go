package idempotency

import (
	"context"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// TestStoreConformanceTerminalEvidence runs on both engines (postgres
// under CRABBOX_TEST_DATABASE_URL): the canonical terminal enumeration a
// checkpoint commits to must contain every terminal record in stable
// execution_id order, bind the immutable terminal digests and provider
// identity, and exclude non-terminal records.
func TestStoreConformanceTerminalEvidence(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()

		refs, err := s.TerminalEvidence(ctx)
		if err != nil {
			t.Fatalf("terminal evidence (empty): %v", err)
		}
		if len(refs) != 0 {
			t.Fatalf("empty store enumerates %d records", len(refs))
		}

		// One COMMITTED and one FAILED terminal record, plus one record
		// left in flight — non-terminal state must not appear.
		rec1, token1, gen1, digest1 := acquireFor(t, s, ctx, "ck-a", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		if err := s.Finalize(ctx, rec1.ExecutionID, token1, gen1, StateInFlight,
			confReceipt(rec1.ExecutionID, "cap.mut", "alice", digest1, "prov", "run-1", StateCommitted)); err != nil {
			t.Fatalf("finalize committed: %v", err)
		}
		rec2, token2, gen2, digest2 := acquireFor(t, s, ctx, "ck-b", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		if err := s.Finalize(ctx, rec2.ExecutionID, token2, gen2, StateInFlight,
			confReceipt(rec2.ExecutionID, "cap.mut", "alice", digest2, "prov", "run-2", StateFailed)); err != nil {
			t.Fatalf("finalize failed: %v", err)
		}
		if _, _, _, err := func() (*Record, string, int, error) {
			acq, err := s.Acquire(ctx, "ck-c", "alice", "cap.mut",
				confDigest("alice", "cap.mut", `{"q":"x"}`), "", "MUTATION", 5*time.Minute)
			if err != nil {
				return nil, "", 0, err
			}
			return acq.Record, acq.LeaseToken, acq.Generation, nil
		}(); err != nil {
			t.Fatalf("acquire in-flight: %v", err)
		}

		refs, err = s.TerminalEvidence(ctx)
		if err != nil {
			t.Fatalf("terminal evidence: %v", err)
		}
		if len(refs) != 2 {
			t.Fatalf("enumerated %d terminal refs, want 2", len(refs))
		}
		// Canonical order: execution_id ascending.
		if !(refs[0].ExecutionID < refs[1].ExecutionID) {
			t.Fatalf("enumeration not ordered: %q then %q", refs[0].ExecutionID, refs[1].ExecutionID)
		}
		byID := map[string]evidence.TerminalRef{refs[0].ExecutionID: refs[0], refs[1].ExecutionID: refs[1]}
		if r := byID[rec1.ExecutionID]; r.State != "COMMITTED" || r.RequestDigest != digest1 || r.ProviderRunID != "run-1" || r.UpdatedAt == "" {
			t.Fatalf("committed record not bound correctly: %+v", r)
		}
		if r := byID[rec2.ExecutionID]; r.State != "FAILED" || r.RequestDigest != digest2 || r.ProviderRunID != "run-2" || r.UpdatedAt == "" {
			t.Fatalf("failed record not bound correctly: %+v", r)
		}

		// Checkpoint roundtrip against the live enumeration — and the
		// rollback detection the store cannot provide by itself.
		signer, err := evidence.GenerateSigner()
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		trusted := map[string]bool{signer.Fingerprint(): true}
		cp := signer.SignCheckpoint(1, refs)
		if err := evidence.VerifyCheckpoint(cp, refs, trusted); err != nil {
			t.Fatalf("checkpoint over live enumeration rejected: %v", err)
		}
		if err := evidence.VerifyCheckpoint(cp, refs[:1], trusted); err == nil {
			t.Fatal("checkpoint accepted against a store missing a covered record")
		}
	})
}
