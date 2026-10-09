package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// End-to-end: a checkpoint emitted over a real store verifies through
// the CLI path; a tampered enumeration fails with exit 1; bad usage
// fails with exit 2.
func TestVerifyCLIEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "db", "store.db")
	db, err := idempotency.OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx := context.Background()

	// Terminalize one record so the checkpoint covers real bytes.
	digest, err := idempotency.ComputeDigestFromRaw(1, "alice", "cap.mut",
		json.RawMessage(`{"q":"x"}`), "", "MUTATION")
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	acq, err := store.Acquire(ctx, "e2e-k", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := store.BeginExecution(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.MarkInFlight(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil); err != nil {
		t.Fatalf("in-flight: %v", err)
	}
	receipt := idempotency.TerminalReceipt{
		ExecutionID:     acq.Record.ExecutionID,
		Capability:      "cap.mut",
		Principal:       "alice",
		RequestDigest:   digest,
		CanonicalResult: json.RawMessage(`{"ok":true}`),
		ReceiptVersion:  3,
		ProviderID:      "prov",
		ProviderRunID:   "run-1",
		TerminalStatus:  idempotency.StateCommitted,
	}
	if err := store.Finalize(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation,
		idempotency.StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	db.Close()

	// Emit the checkpoint with a signer (this is what the service does).
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	vdb, err := idempotency.OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	vstore, err := idempotency.NewSQLiteStore(vdb)
	if err != nil {
		t.Fatalf("verify store: %v", err)
	}
	refs, err := vstore.TerminalEvidence(ctx)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	vdb.Close()
	if len(refs) != 1 {
		t.Fatalf("enumerated %d refs, want 1", len(refs))
	}
	cp := signer.SignCheckpoint(1, refs)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	payload, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(cpPath, payload, 0o600); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	out := &discardWriter{}
	code := run([]string{"-store", dbPath, "-checkpoint", cpPath, "-trusted", signer.Fingerprint()}, out, out)
	if code != 0 {
		t.Fatalf("valid checkpoint: exit %d", code)
	}

	// Untrusted signer → 1.
	code = run([]string{"-store", dbPath, "-checkpoint", cpPath, "-trusted", "aaaa"}, out, out)
	if code != 1 {
		t.Fatalf("untrusted signer: exit %d, want 1", code)
	}

	// Rollback: a store that no longer holds the covered record → 1.
	// Simulate by verifying the checkpoint against an empty store.
	emptyPath := filepath.Join(t.TempDir(), "db", "empty.db")
	edb, err := idempotency.OpenSQLiteDB(emptyPath)
	if err != nil {
		t.Fatalf("open empty store: %v", err)
	}
	if _, err := idempotency.NewSQLiteStore(edb); err != nil {
		t.Fatalf("new empty store: %v", err)
	}
	edb.Close()
	code = run([]string{"-store", emptyPath, "-checkpoint", cpPath, "-trusted", signer.Fingerprint()}, out, out)
	if code != 1 {
		t.Fatalf("rolled-back store: exit %d, want 1", code)
	}

	// Missing required flags → 2.
	if code := run([]string{"-checkpoint", cpPath, "-trusted", "x"}, out, out); code != 2 {
		t.Fatalf("usage: exit %d, want 2", code)
	}
}

type discardWriter struct{ io.Writer }

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
