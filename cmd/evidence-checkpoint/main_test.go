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

// seededStore builds a SQLite effect store holding one committed
// terminal record and returns its path with the terminal enumeration a
// checkpoint would commit to.
func seededStore(t *testing.T) (string, []evidence.TerminalRef) {
	t.Helper()
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
	refs, err := store.TerminalEvidence(ctx)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	db.Close()
	if len(refs) != 1 {
		t.Fatalf("enumerated %d refs, want 1", len(refs))
	}
	return dbPath, refs
}

// End-to-end: a checkpoint emitted over a real store verifies through
// the CLI path; a tampered enumeration fails with exit 1; bad usage
// fails with exit 2.
func TestVerifyCLIEndToEnd(t *testing.T) {
	dbPath, refs := seededStore(t)

	// Emit the checkpoint with a signer (this is what the service does).
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
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

// The same CLI path verifies a whole retained journal: every entry's
// signature plus the stream's continuity invariants, and the head's
// chain against the live store — or every entry's with -chains. Any
// tampered entry fails with exit 1.
func TestVerifyCLIJournal(t *testing.T) {
	dbPath, refs := seededStore(t)
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	journalPath := filepath.Join(t.TempDir(), "cp.json.jsonl")
	writeJournal := func(lines [][]byte) {
		t.Helper()
		var buf []byte
		for _, line := range lines {
			buf = append(buf, line...)
			buf = append(buf, '\n')
		}
		if err := os.WriteFile(journalPath, buf, 0o600); err != nil {
			t.Fatalf("write journal: %v", err)
		}
	}
	var lines [][]byte
	for seq := int64(1); seq <= 3; seq++ {
		payload, err := json.Marshal(signer.SignCheckpoint(seq, refs))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		lines = append(lines, payload)
	}
	writeJournal(lines)
	out := &discardWriter{}

	code := run([]string{"-store", dbPath, "-checkpoint", journalPath, "-trusted", signer.Fingerprint()}, out, out)
	if code != 0 {
		t.Fatalf("valid journal: exit %d", code)
	}
	code = run([]string{"-store", dbPath, "-checkpoint", journalPath, "-trusted", signer.Fingerprint(), "-chains"}, out, out)
	if code != 0 {
		t.Fatalf("valid journal with chains: exit %d", code)
	}

	// A tampered mid-history entry invalidates the journal — custody
	// rests on the whole stream, not just the head.
	tampered := append([]byte{}, lines[1]...)
	tampered[len(tampered)/2] ^= 0x20
	writeJournal([][]byte{lines[0], tampered, lines[2]})
	code = run([]string{"-store", dbPath, "-checkpoint", journalPath, "-trusted", signer.Fingerprint()}, out, out)
	if code != 1 {
		t.Fatalf("tampered journal: exit %d, want 1", code)
	}

	// A missing entry breaks contiguity the same way.
	writeJournal([][]byte{lines[0], lines[2]})
	code = run([]string{"-store", dbPath, "-checkpoint", journalPath, "-trusted", signer.Fingerprint()}, out, out)
	if code != 1 {
		t.Fatalf("gapped journal: exit %d, want 1", code)
	}
}

type discardWriter struct{ io.Writer }

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
