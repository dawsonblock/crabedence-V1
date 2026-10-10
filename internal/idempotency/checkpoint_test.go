package idempotency

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// TestStoreConformanceTerminalEvidence runs on both engines (postgres
// under CRABBOX_TEST_DATABASE_URL): the canonical terminal enumeration a
// checkpoint commits to must contain every terminal record in
// terminalization-commit order, bind the immutable terminal digests and
// provider identity, and exclude non-terminal records.
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
		// Canonical order: terminalization-commit order — rec1
		// finalized before rec2, and ledger positions are strictly
		// increasing.
		if refs[0].ExecutionID != rec1.ExecutionID || refs[1].ExecutionID != rec2.ExecutionID {
			t.Fatalf("enumeration not in commit order: %q then %q, finalized %q then %q",
				refs[0].ExecutionID, refs[1].ExecutionID, rec1.ExecutionID, rec2.ExecutionID)
		}
		if !(refs[0].Seq < refs[1].Seq) {
			t.Fatalf("terminal_seq not increasing: %d then %d", refs[0].Seq, refs[1].Seq)
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

// TestStoreConformanceTerminalEvidenceCommitOrder reproduces audit
// finding F-001: an enumeration ordered by execution_id is not the
// order in which terminal states were durably committed — execution ids
// are random UUIDv4 — so a legitimate late terminalization inserts into
// the middle of a previously checkpointed prefix and silently
// invalidates it. The ledger must enumerate in terminalization-commit
// order — an append-only sequence — and a checkpoint issued over the
// earlier prefix must still verify after the late record lands.
func TestStoreConformanceTerminalEvidenceCommitOrder(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()

		type acquired struct {
			rec    *Record
			token  string
			gen    int
			digest string
			status State
		}
		a := acquired{}
		b := acquired{}
		a.rec, a.token, a.gen, a.digest = acquireFor(t, s, ctx, "ord-a", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		b.rec, b.token, b.gen, b.digest = acquireFor(t, s, ctx, "ord-b", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		a.status, b.status = StateCommitted, StateFailed

		// Terminalize the record with the LARGER execution_id first so
		// that enumeration-by-id necessarily diverges from commit order:
		// under the defective ordering the late-terminalizing record
		// (smaller id) lands first in the enumeration.
		first, last := a, b
		if a.rec.ExecutionID < b.rec.ExecutionID {
			first, last = b, a
		}

		if err := s.Finalize(ctx, first.rec.ExecutionID, first.token, first.gen, StateInFlight,
			confReceipt(first.rec.ExecutionID, "cap.mut", "alice", first.digest, "prov", "run-first", first.status)); err != nil {
			t.Fatalf("finalize first: %v", err)
		}
		refs1, err := s.TerminalEvidence(ctx)
		if err != nil {
			t.Fatalf("terminal evidence after first: %v", err)
		}
		if len(refs1) != 1 || refs1[0].ExecutionID != first.rec.ExecutionID {
			t.Fatalf("first enumeration = %+v, want [%s]", refs1, first.rec.ExecutionID)
		}
		signer, err := evidence.GenerateSigner()
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		trusted := map[string]bool{signer.Fingerprint(): true}
		cp1 := signer.SignCheckpoint(1, refs1)

		// The older execution terminalizes LATE — after the checkpoint.
		if err := s.Finalize(ctx, last.rec.ExecutionID, last.token, last.gen, StateInFlight,
			confReceipt(last.rec.ExecutionID, "cap.mut", "alice", last.digest, "prov", "run-last", last.status)); err != nil {
			t.Fatalf("finalize last: %v", err)
		}
		refs2, err := s.TerminalEvidence(ctx)
		if err != nil {
			t.Fatalf("terminal evidence after last: %v", err)
		}
		if len(refs2) != 2 {
			t.Fatalf("enumerated %d terminal refs, want 2", len(refs2))
		}
		// Append-only commit order: the first-terminalized record stays
		// the prefix; the late one appends — regardless of id ordering.
		if refs2[0].ExecutionID != first.rec.ExecutionID || refs2[1].ExecutionID != last.rec.ExecutionID {
			t.Fatalf("enumeration is not terminalization order: [%s, %s], committed [%s, %s]",
				refs2[0].ExecutionID, refs2[1].ExecutionID, first.rec.ExecutionID, last.rec.ExecutionID)
		}
		// The checkpoint issued before the late terminalization must
		// still verify — the covered prefix is unchanged.
		if err := evidence.VerifyCheckpoint(cp1, refs2, trusted); err != nil {
			t.Fatalf("checkpoint over a legitimate prefix rejected after late terminalization: %v", err)
		}
	})
}

// TestStoreConformanceTerminalSeqConcurrency: concurrent terminalizations
// on distinct records must each receive a unique ledger position, and the
// enumeration must list them strictly in assigned order — the counter row
// is the serialization point, so races cannot produce duplicate or
// reordered positions.
func TestStoreConformanceTerminalSeqConcurrency(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		const k = 16
		type pending struct {
			rec    *Record
			token  string
			gen    int
			digest string
		}
		jobs := make([]pending, k)
		for i := 0; i < k; i++ {
			rec, token, gen, digest := acquireFor(t, s, ctx,
				fmt.Sprintf("conc-%02d", i), "alice", "cap.mut", "MUTATION", 5*time.Minute)
			jobs[i] = pending{rec, token, gen, digest}
		}
		var wg sync.WaitGroup
		errs := make(chan error, k)
		for _, j := range jobs {
			wg.Add(1)
			go func(j pending) {
				defer wg.Done()
				errs <- s.Finalize(ctx, j.rec.ExecutionID, j.token, j.gen, StateInFlight,
					confReceipt(j.rec.ExecutionID, "cap.mut", "alice", j.digest, "prov", "run-"+j.rec.ExecutionID[:8], StateCommitted))
			}(j)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent finalize: %v", err)
			}
		}
		refs, err := s.TerminalEvidence(ctx)
		if err != nil {
			t.Fatalf("terminal evidence: %v", err)
		}
		seen := map[int64]bool{}
		var prev int64
		for i, ref := range refs {
			if ref.Seq <= prev && i > 0 {
				t.Fatalf("enumeration not strictly increasing: seq %d after %d", ref.Seq, prev)
			}
			if seen[ref.Seq] {
				t.Fatalf("duplicate ledger position %d", ref.Seq)
			}
			seen[ref.Seq] = true
			prev = ref.Seq
		}
		if len(refs) < k {
			t.Fatalf("enumerated %d terminal refs, want at least %d", len(refs), k)
		}
	})
}

// TestStoreConformanceTerminalSeqRecoveryPath: a record that reaches its
// terminal state through ResolveRecovery (UNKNOWN → COMMITTED) gets a
// ledger position like any Finalize path — appended after everything
// already terminal.
func TestStoreConformanceTerminalSeqRecoveryPath(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		recA, tokA, genA, digA := acquireFor(t, s, ctx, "rec-a", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		if err := s.Finalize(ctx, recA.ExecutionID, tokA, genA, StateInFlight,
			confReceipt(recA.ExecutionID, "cap.mut", "alice", digA, "prov", "run-a", StateCommitted)); err != nil {
			t.Fatalf("finalize a: %v", err)
		}
		recB, _, _, _ := acquireFor(t, s, ctx, "rec-b", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		cur, err := s.Lookup(ctx, recB.ExecutionID)
		if err != nil {
			t.Fatalf("lookup b: %v", err)
		}
		if err := s.EnterRecoveryWithObservation(ctx, recB.ExecutionID, StateInFlight, cur.Version,
			ProviderObservation{ProviderID: "prov", ProviderRunID: "run-b", ProviderStatus: "UNKNOWN",
				Result: json.RawMessage(`{"amb":true}`)}); err != nil {
			t.Fatalf("enter recovery b: %v", err)
		}
		cur, err = s.Lookup(ctx, recB.ExecutionID)
		if err != nil {
			t.Fatalf("lookup b (unknown): %v", err)
		}
		if cur.State != StateUnknown {
			t.Fatalf("b state = %s, want UNKNOWN", cur.State)
		}
		res := RecoveryResult{
			Decision:       RecoveryCommitted,
			EvidenceDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ReceiptVersion: 3,
			ProviderID:     "prov",
			ProviderRunID:  "run-b",
			Result:         json.RawMessage(`{"completed":true}`),
		}
		if err := s.ResolveRecovery(ctx, recB.ExecutionID, cur.Version, res); err != nil {
			t.Fatalf("resolve b: %v", err)
		}
		refs, err := s.TerminalEvidence(ctx)
		if err != nil {
			t.Fatalf("terminal evidence: %v", err)
		}
		if len(refs) != 2 || refs[0].ExecutionID != recA.ExecutionID || refs[1].ExecutionID != recB.ExecutionID {
			t.Fatalf("recovery-path terminalization did not append: %+v", refs)
		}
		if refs[1].Seq <= refs[0].Seq {
			t.Fatalf("recovery terminal_seq not appended: %d then %d", refs[0].Seq, refs[1].Seq)
		}
	})
}

// TestSQLiteTerminalSeqUpgradeBackfill simulates a pre-ledger database
// being opened by ledger-aware code: the migration must backfill
// terminal_seq for already-terminal rows in their durable commit order
// (updated_at, execution_id), rebuild the counter at the high-water
// mark, and let new terminalizations continue the sequence without
// colliding.
func TestSQLiteTerminalSeqUpgradeBackfill(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)

	rec1, tok1, gen1, dig1 := acquireFor(t, s, ctx, "upg-a", "alice", "cap.mut", "MUTATION", 5*time.Minute)
	if err := s.Finalize(ctx, rec1.ExecutionID, tok1, gen1, StateInFlight,
		confReceipt(rec1.ExecutionID, "cap.mut", "alice", dig1, "prov", "run-1", StateCommitted)); err != nil {
		t.Fatalf("finalize 1: %v", err)
	}
	rec2, tok2, gen2, dig2 := acquireFor(t, s, ctx, "upg-b", "alice", "cap.mut", "MUTATION", 5*time.Minute)
	if err := s.Finalize(ctx, rec2.ExecutionID, tok2, gen2, StateInFlight,
		confReceipt(rec2.ExecutionID, "cap.mut", "alice", dig2, "prov", "run-2", StateFailed)); err != nil {
		t.Fatalf("finalize 2: %v", err)
	}
	// Distinct terminalization instants so the backfill order is not
	// merely the id tiebreak.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE execution_requests SET updated_at = updated_at + 86400000 WHERE execution_id = ?`, rec2.ExecutionID); err != nil {
		t.Fatalf("age rec2: %v", err)
	}

	// Demolish the ledger schema back to a pre-17 shape: column, counter
	// table, index, and the migration marker.
	for _, ddl := range []string{
		`DROP INDEX IF EXISTS idx_execution_requests_terminal_seq`,
		`ALTER TABLE execution_requests DROP COLUMN terminal_seq`,
		`DROP TABLE terminal_counter`,
		`DELETE FROM schema_migrations WHERE version = 17`,
	} {
		if _, err := s.db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("demolish %q: %v", ddl, err)
		}
	}

	// Re-running schema setup must re-apply the ledger migration and
	// backfill in (updated_at, execution_id) order — rec1 terminalized
	// before rec2, so it takes the earlier position.
	fresh, err := NewSQLiteStore(s.db)
	if err != nil {
		t.Fatalf("reopen after demolition: %v", err)
	}
	refs, err := fresh.TerminalEvidence(ctx)
	if err != nil {
		t.Fatalf("terminal evidence after upgrade: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("enumerated %d refs after upgrade, want 2", len(refs))
	}
	if refs[0].ExecutionID != rec1.ExecutionID || refs[1].ExecutionID != rec2.ExecutionID {
		t.Fatalf("backfill order wrong: %s then %s", refs[0].ExecutionID, refs[1].ExecutionID)
	}
	if refs[0].Seq != 1 || refs[1].Seq != 2 {
		t.Fatalf("backfill seqs = %d, %d — want 1, 2", refs[0].Seq, refs[1].Seq)
	}

	// The counter was lifted past the backfill: a new terminalization
	// continues at 3, never colliding with a backfilled row.
	rec3, tok3, gen3, dig3 := acquireFor(t, fresh, ctx, "upg-c", "alice", "cap.mut", "MUTATION", 5*time.Minute)
	if err := fresh.Finalize(ctx, rec3.ExecutionID, tok3, gen3, StateInFlight,
		confReceipt(rec3.ExecutionID, "cap.mut", "alice", dig3, "prov", "run-3", StateCommitted)); err != nil {
		t.Fatalf("finalize 3: %v", err)
	}
	refs, err = fresh.TerminalEvidence(ctx)
	if err != nil {
		t.Fatalf("terminal evidence post-upgrade: %v", err)
	}
	if len(refs) != 3 || refs[2].Seq != 3 || refs[2].ExecutionID != rec3.ExecutionID {
		t.Fatalf("post-upgrade terminalization not appended at seq 3: %+v", refs)
	}
}

// TestSQLiteTerminalEvidenceMissingSeqFailsClosed: a terminal row whose
// ledger position is absent is a hard error — enumeration never silently
// skips it — and reopening the store repairs the gap at the ledger end.
func TestSQLiteTerminalEvidenceMissingSeqFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	rec1, tok1, gen1, dig1 := acquireFor(t, s, ctx, "seq-ok", "alice", "cap.mut", "MUTATION", 5*time.Minute)
	if err := s.Finalize(ctx, rec1.ExecutionID, tok1, gen1, StateInFlight,
		confReceipt(rec1.ExecutionID, "cap.mut", "alice", dig1, "prov", "run-1", StateCommitted)); err != nil {
		t.Fatalf("finalize 1: %v", err)
	}
	rec2, tok2, gen2, dig2 := acquireFor(t, s, ctx, "null-seq", "alice", "cap.mut", "MUTATION", 5*time.Minute)
	if err := s.Finalize(ctx, rec2.ExecutionID, tok2, gen2, StateInFlight,
		confReceipt(rec2.ExecutionID, "cap.mut", "alice", dig2, "prov", "run-2", StateCommitted)); err != nil {
		t.Fatalf("finalize 2: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE execution_requests SET terminal_seq = NULL WHERE execution_id = ?`, rec2.ExecutionID); err != nil {
		t.Fatalf("null seq: %v", err)
	}
	if _, err := s.TerminalEvidence(ctx); err == nil {
		t.Fatal("enumeration silently skipped a terminal row with no ledger position")
	}
	// Reopen: the convergence pass appends the straggler at the end.
	fresh, err := NewSQLiteStore(s.db)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	refs, err := fresh.TerminalEvidence(ctx)
	if err != nil {
		t.Fatalf("enumeration after repair: %v", err)
	}
	if len(refs) != 2 || refs[0].ExecutionID != rec1.ExecutionID || refs[1].ExecutionID != rec2.ExecutionID || refs[1].Seq != 2 {
		t.Fatalf("straggler not healed at ledger end: %+v", refs)
	}
}
