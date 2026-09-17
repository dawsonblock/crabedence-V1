package reconcile

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// sqliteStore opens an embedded store for worker-level tests — the
// same reconcileOne path must work on the EffectStore interface,
// independent of storage engine.
func sqliteStore(t *testing.T) *idempotency.SQLiteStore {
	t.Helper()
	db, err := idempotency.OpenSQLiteDB(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return s
}

type fixedResolver struct{ result idempotency.RecoveryResult }

func (r fixedResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.RecoveryResult, error) {
	return r.result, nil
}

// TestSQLiteWorkerReconcileCommitted drives a full UNKNOWN → COMMITTED
// resolution through reconcileOne on the embedded store: claim,
// revalidation, resolver invocation, proof-carrying resolution.
func TestSQLiteWorkerReconcileCommitted(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t)

	digest, err := idempotency.ComputeDigestFromRaw(1, "alice", "cap.mut",
		json.RawMessage(`{"q":"x"}`), "", "MUTATION")
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil); err != nil {
		t.Fatalf("in flight: %v", err)
	}
	cur, err := s.Lookup(ctx, rec.ExecutionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if err := s.EnterRecoveryWithObservation(ctx, rec.ExecutionID, idempotency.StateInFlight, cur.Version,
		idempotency.ProviderObservation{ProviderID: "prov", ProviderRunID: "run-1", ProviderStatus: "UNKNOWN"}); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}

	w := NewWorker(s, NoopResolver{}, time.Minute)
	w.RegisterResolver("cap.mut", fixedResolver{result: idempotency.RecoveryResult{
		Decision:       idempotency.RecoveryCommitted,
		EvidenceDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ReceiptVersion: 3,
		ProviderID:     "prov",
		ProviderRunID:  "run-1",
		Result:         json.RawMessage(`{"completed":true}`),
	}})

	claimed, err := s.ClaimUnknownBatch(ctx, w.workerID, 10, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v n=%d", err, len(claimed))
	}
	if err := w.reconcileOne(ctx, claimed[0]); err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}
	final, err := s.Lookup(ctx, rec.ExecutionID)
	if err != nil {
		t.Fatalf("final lookup: %v", err)
	}
	if final.State != idempotency.StateCommitted {
		t.Fatalf("state=%s want COMMITTED", final.State)
	}
}
