package execution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// Emission writes a verifiable checkpoint over the store's terminal
// enumeration, and increments the sequence on each emission.
func TestEmitCheckpointWritesVerifiableFile(t *testing.T) {
	db, err := idempotency.OpenSQLiteDB(filepath.Join(t.TempDir(), "db", "cp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	path := filepath.Join(t.TempDir(), "evidence-checkpoint.json")

	emitCheckpoint(context.Background(), store, signer, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatalf("checkpoint not parseable: %v", err)
	}
	refs, err := store.TerminalEvidence(context.Background())
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if err := evidence.VerifyCheckpoint(&cp, refs, map[string]bool{signer.Fingerprint(): true}); err != nil {
		t.Fatalf("emitted checkpoint does not verify: %v", err)
	}
	if cp.Sequence != 1 {
		t.Fatalf("first checkpoint sequence = %d, want 1", cp.Sequence)
	}

	// A second emission increments the sequence.
	emitCheckpoint(context.Background(), store, signer, path)
	data, _ = os.ReadFile(path)
	var cp2 evidence.Checkpoint
	if err := json.Unmarshal(data, &cp2); err != nil {
		t.Fatalf("second checkpoint not parseable: %v", err)
	}
	if cp2.Sequence != 2 {
		t.Fatalf("second checkpoint sequence = %d, want 2", cp2.Sequence)
	}
	if err := evidence.VerifyCheckpoint(&cp2, refs, map[string]bool{signer.Fingerprint(): true}); err != nil {
		t.Fatalf("second checkpoint does not verify: %v", err)
	}
}

// An existing checkpoint file that is not parseable is never overwritten:
// it may be evidence an operator expects to keep.
func TestEmitCheckpointRefusesUnreadableExisting(t *testing.T) {
	db, err := idempotency.OpenSQLiteDB(filepath.Join(t.TempDir(), "db", "cp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	signer, _ := evidence.GenerateSigner()
	path := filepath.Join(t.TempDir(), "evidence-checkpoint.json")
	before := []byte("not json — possibly evidence")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}
	emitCheckpoint(context.Background(), store, signer, path)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("unreadable existing checkpoint was overwritten")
	}
}
