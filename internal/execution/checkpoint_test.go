package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

	emitCheckpoint(context.Background(), store, signer, path, "")

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
	emitCheckpoint(context.Background(), store, signer, path, "")
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
	emitCheckpoint(context.Background(), store, signer, path, "")
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("unreadable existing checkpoint was overwritten")
	}
}

// Every emission is retained in the append-only sequence log beside the
// latest file — custody depends on the sequence, not just the head.
func TestEmitCheckpointRetainsSequenceLog(t *testing.T) {
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

	emitCheckpoint(context.Background(), store, signer, path, "")
	emitCheckpoint(context.Background(), store, signer, path, "")

	data, err := os.ReadFile(path + ".jsonl")
	if err != nil {
		t.Fatalf("read retained log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("retained log holds %d lines, want 2", len(lines))
	}
	refs, err := store.TerminalEvidence(context.Background())
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	for i, line := range lines {
		var cp evidence.Checkpoint
		if err := json.Unmarshal([]byte(line), &cp); err != nil {
			t.Fatalf("retained line %d not parseable: %v", i+1, err)
		}
		if cp.Sequence != int64(i+1) {
			t.Fatalf("retained line %d sequence = %d", i+1, cp.Sequence)
		}
		if err := evidence.VerifyCheckpoint(&cp, refs, map[string]bool{signer.Fingerprint(): true}); err != nil {
			t.Fatalf("retained line %d does not verify: %v", i+1, err)
		}
	}
}

// A lost latest file cannot restart the sequence: the retained log is
// the numbering authority.
func TestEmitCheckpointSequenceSurvivesLatestLoss(t *testing.T) {
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

	emitCheckpoint(context.Background(), store, signer, path, "")
	emitCheckpoint(context.Background(), store, signer, path, "")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove latest: %v", err)
	}
	emitCheckpoint(context.Background(), store, signer, path, "")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatalf("latest not parseable: %v", err)
	}
	if cp.Sequence != 3 {
		t.Fatalf("sequence after latest loss = %d, want 3", cp.Sequence)
	}
}

// A corrupted retained log refuses further emission — extending it
// could quietly hide destroyed evidence.
func TestEmitCheckpointRefusesCorruptRetainedLog(t *testing.T) {
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

	emitCheckpoint(context.Background(), store, signer, path, "")
	if err := os.WriteFile(path+".jsonl", []byte("corrupted tail\n"), 0o600); err != nil {
		t.Fatalf("corrupt log: %v", err)
	}
	latestBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	emitCheckpoint(context.Background(), store, signer, path, "")
	latestAfter, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read latest after: %v", err)
	}
	if string(latestAfter) != string(latestBefore) {
		t.Fatal("emission proceeded over a corrupt retained log")
	}
}

// A configured custody path receives the same latest file and retained
// sequence — the deployment must place it outside this host's failure
// domain for the custody to be independent.
func TestEmitCheckpointMirrorsCustodyPath(t *testing.T) {
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
	localDir := t.TempDir()
	custodyDir := t.TempDir()
	path := filepath.Join(localDir, "evidence-checkpoint.json")
	custody := filepath.Join(custodyDir, "evidence-checkpoint.json")

	emitCheckpoint(context.Background(), store, signer, path, custody)

	local, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read local latest: %v", err)
	}
	held, err := os.ReadFile(custody)
	if err != nil {
		t.Fatalf("read custody latest: %v", err)
	}
	if !bytes.Equal(local, held) {
		t.Fatal("custody latest differs from local latest")
	}
	localLog, err := os.ReadFile(path + ".jsonl")
	if err != nil {
		t.Fatalf("read local log: %v", err)
	}
	custodyLog, err := os.ReadFile(custody + ".jsonl")
	if err != nil {
		t.Fatalf("read custody log: %v", err)
	}
	if !bytes.Equal(localLog, custodyLog) {
		t.Fatal("custody retained log differs from local retained log")
	}
}

func newCheckpointTestStore(t *testing.T) idempotency.EffectStore {
	t.Helper()
	db, err := idempotency.OpenSQLiteDB(filepath.Join(t.TempDir(), "db", "cp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

// A custody log whose middle entry is corrupt under an intact tail is
// refused: the mirror verifies the full retained history before
// extending, so tampering anywhere in custody surfaces loudly instead
// of the next append laundering it.
func TestEmitCheckpointCustodyRefusesCorruptHistory(t *testing.T) {
	store := newCheckpointTestStore(t)
	signer, _ := evidence.GenerateSigner()
	localDir := t.TempDir()
	custodyDir := t.TempDir()
	path := filepath.Join(localDir, "evidence-checkpoint.json")
	custody := filepath.Join(custodyDir, "evidence-checkpoint.json")

	emitCheckpoint(context.Background(), store, signer, path, custody)
	emitCheckpoint(context.Background(), store, signer, path, custody)
	emitCheckpoint(context.Background(), store, signer, path, custody)

	// Flip one byte inside the middle entry's signature: the tail stays
	// intact and parseable while the history no longer verifies.
	custodyLog := custody + ".jsonl"
	raw, err := os.ReadFile(custodyLog)
	if err != nil {
		t.Fatalf("read custody log: %v", err)
	}
	lines := bytes.Split(raw, []byte{'\n'})
	sigIdx := bytes.Index(lines[1], []byte(`"signature"`))
	if sigIdx < 0 {
		t.Fatal("custody entry carries no signature field")
	}
	pos := sigIdx + len(`"signature":"`)
	if lines[1][pos] != 'A' {
		lines[1][pos] = 'A'
	} else {
		lines[1][pos] = 'B'
	}
	corrupt := bytes.Join(lines, []byte{'\n'})
	if err := os.WriteFile(custodyLog, corrupt, 0o600); err != nil {
		t.Fatalf("plant corrupt custody log: %v", err)
	}

	emitCheckpoint(context.Background(), store, signer, path, custody)

	after, err := os.ReadFile(custodyLog)
	if err != nil {
		t.Fatalf("re-read custody log: %v", err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Fatal("custody log was extended over corrupt history")
	}
	var cp evidence.Checkpoint
	held, err := os.ReadFile(custody)
	if err != nil {
		t.Fatalf("read custody latest: %v", err)
	}
	if err := json.Unmarshal(held, &cp); err != nil {
		t.Fatalf("custody latest unparseable: %v", err)
	}
	if cp.Sequence != 3 {
		t.Fatalf("custody latest advanced to %d over corrupt history", cp.Sequence)
	}
	var local evidence.Checkpoint
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read local latest: %v", err)
	}
	if err := json.Unmarshal(data, &local); err != nil {
		t.Fatalf("local latest unparseable: %v", err)
	}
	if local.Sequence != 4 {
		t.Fatalf("local stream stalled at %d — custody refusal must not block local emission", local.Sequence)
	}
}

// A custody copy that fell behind is backfilled from the verified local
// journal rather than left with a sequence gap.
func TestEmitCheckpointCustodyBackfillsLag(t *testing.T) {
	store := newCheckpointTestStore(t)
	signer, _ := evidence.GenerateSigner()
	localDir := t.TempDir()
	custodyDir := t.TempDir()
	path := filepath.Join(localDir, "evidence-checkpoint.json")
	custody := filepath.Join(custodyDir, "evidence-checkpoint.json")

	emitCheckpoint(context.Background(), store, signer, path, custody)
	emitCheckpoint(context.Background(), store, signer, path, custody)

	// Lag custody to a verified prefix: keep the first retained entry,
	// drop the latest-file pointer so only the journal arbitrates.
	custodyLog := custody + ".jsonl"
	raw, err := os.ReadFile(custodyLog)
	if err != nil {
		t.Fatalf("read custody log: %v", err)
	}
	idx := bytes.IndexByte(raw, '\n')
	if idx < 0 {
		t.Fatal("custody log holds no complete entry")
	}
	if err := os.WriteFile(custodyLog, raw[:idx+1], 0o600); err != nil {
		t.Fatalf("truncate custody log: %v", err)
	}
	if err := os.Remove(custody); err != nil {
		t.Fatalf("remove custody latest: %v", err)
	}

	emitCheckpoint(context.Background(), store, signer, path, custody)

	localLog, err := os.ReadFile(path + ".jsonl")
	if err != nil {
		t.Fatalf("read local log: %v", err)
	}
	after, err := os.ReadFile(custodyLog)
	if err != nil {
		t.Fatalf("re-read custody log: %v", err)
	}
	if !bytes.Equal(after, localLog) {
		t.Fatal("custody did not backfill to the local stream")
	}
}

// A custody latest file with no retained log claims continuity nothing
// verifies — divergent custody an operator must arbitrate, never
// silently overwritten.
func TestEmitCheckpointCustodyRefusesOrphanLatest(t *testing.T) {
	store := newCheckpointTestStore(t)
	signer, _ := evidence.GenerateSigner()
	localDir := t.TempDir()
	custodyDir := t.TempDir()
	path := filepath.Join(localDir, "evidence-checkpoint.json")
	custody := filepath.Join(custodyDir, "evidence-checkpoint.json")

	emitCheckpoint(context.Background(), store, signer, path, custody)
	emitCheckpoint(context.Background(), store, signer, path, custody)

	if err := os.Remove(custody + ".jsonl"); err != nil {
		t.Fatalf("remove custody log: %v", err)
	}
	heldBefore, err := os.ReadFile(custody)
	if err != nil {
		t.Fatalf("read custody latest: %v", err)
	}

	emitCheckpoint(context.Background(), store, signer, path, custody)

	if _, err := os.Stat(custody + ".jsonl"); !os.IsNotExist(err) {
		t.Fatal("custody log recreated over orphan latest")
	}
	heldAfter, err := os.ReadFile(custody)
	if err != nil {
		t.Fatalf("re-read custody latest: %v", err)
	}
	if !bytes.Equal(heldAfter, heldBefore) {
		t.Fatal("custody latest overwritten while its retained log was missing")
	}
}
