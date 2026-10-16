package history

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
)

func testWitness(t *testing.T) *evidence.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := evidence.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func appendTestEvents(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := s.Append(&Event{
			DedupeKey: fmt.Sprintf("test:%d", i),
			Kind:      KindExperiment,
			Subject:   "subject",
			Source:    "test",
			Payload:   []byte(fmt.Sprintf(`{"i":%d}`, i)),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A store rolled back below the witnessed head fails verification —
// witnessed events cannot uncommit.
func TestCheckpointDetectsRollback(t *testing.T) {
	s := openStore(t)
	appendTestEvents(t, s, 5)
	dir := t.TempDir()
	witness := testWitness(t)
	cp, err := s.WriteCheckpoint(dir, witness)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Sequence != 5 {
		t.Fatalf("checkpoint seq %d, want 5", cp.Sequence)
	}
	// Roll back: delete the two newest events — the store's own
	// chain still verifies, which is exactly why the checkpoint exists.
	if _, err := s.db.Exec(`DELETE FROM events WHERE seq > 3`); err != nil {
		t.Fatal(err)
	}
	findings := s.VerifyAgainstCheckpoint(cp)
	if len(findings) == 0 || !strings.Contains(findings[0], "rollback") {
		t.Fatalf("rollback not reported: %v", findings)
	}
}

// A store replaced wholesale by a different valid chain fails on
// identity, not just on missing events.
func TestCheckpointDetectsStoreReplacement(t *testing.T) {
	dir := t.TempDir()
	witness := testWitness(t)
	dbPath := filepath.Join(t.TempDir(), "h.db")
	s1, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	appendTestEvents(t, s1, 4)
	cp, err := s1.WriteCheckpoint(dir, witness)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()
	// Replace the database wholesale with another internally valid
	// store: same events, same chain integrity, different identity.
	if err := os.Remove(dbPath); err != nil {
		t.Fatal(err)
	}
	for _, wal := range []string{dbPath + "-wal", dbPath + "-shm"} {
		_ = os.Remove(wal)
	}
	s2, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	appendTestEvents(t, s2, 4)
	if findings := s2.Verify(); len(findings) != 0 {
		t.Fatalf("replacement store should verify internally: %v", findings)
	}
	findings := s2.VerifyAgainstCheckpoint(cp)
	if len(findings) == 0 || !strings.Contains(findings[0], "does not inherit") {
		t.Fatalf("store replacement not reported: %v", findings)
	}
}

// Events appended after the checkpoint are progress: the witnessed
// prefix still verifies and the checkpoint merely reads as older.
func TestCheckpointOlderCheckpointStillValid(t *testing.T) {
	s := openStore(t)
	appendTestEvents(t, s, 3)
	dir := t.TempDir()
	cp, err := s.WriteCheckpoint(dir, testWitness(t))
	if err != nil {
		t.Fatal(err)
	}
	appendTestEvents(t, s, 2)
	if findings := s.VerifyAgainstCheckpoint(cp); len(findings) != 0 {
		t.Fatalf("newer store failed witnessed-prefix check: %v", findings)
	}
}

// Checkpoints chain to each other: editing the witnessed series
// breaks the link, and a rewritten head's file fails the link check.
func TestCheckpointSeriesIsLinked(t *testing.T) {
	s := openStore(t)
	appendTestEvents(t, s, 2)
	dir := t.TempDir()
	witness := testWitness(t)
	if _, err := s.WriteCheckpoint(dir, witness); err != nil {
		t.Fatal(err)
	}
	appendTestEvents(t, s, 2)
	second, err := s.WriteCheckpoint(dir, witness)
	if err != nil {
		t.Fatal(err)
	}
	if second.PrevCheckpointSHA256 == "" {
		t.Fatal("second checkpoint did not link to the first")
	}
	cps, err := LoadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 2 {
		t.Fatalf("loaded %d checkpoints, want 2", len(cps))
	}
	if findings := VerifyCheckpointChain(cps); len(findings) != 0 {
		t.Fatalf("linked checkpoint series reported: %v", findings)
	}
	// Removing the first checkpoint leaves the second claiming a
	// link nobody can produce.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "cp-00000000-") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	cps, err = LoadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	findings := VerifyCheckpointChain(cps)
	if len(findings) == 0 {
		t.Fatal("orphaned checkpoint link not reported")
	}
}

// An interrupted checkpoint write leaves a .tmp remnant that must
// never be taken for a committed checkpoint.
func TestCheckpointTmpRemnantIgnored(t *testing.T) {
	s := openStore(t)
	appendTestEvents(t, s, 2)
	dir := t.TempDir()
	cp, err := s.WriteCheckpoint(dir, testWitness(t))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a torn write: a .tmp sibling that never renamed.
	if err := os.WriteFile(filepath.Join(dir, "cp-00000009-deadbeef.tmp"),
		[]byte(`{"record_type":"history-checkpoint/v1"`), 0o600); err != nil {
		t.Fatal(err)
	}
	cps, err := LoadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 1 || cps[0].Checkpoint().Sequence != cp.Sequence {
		t.Fatalf("tmp remnant disturbed checkpoint loading: %d", len(cps))
	}
}

// The file-level verifier rejects forged checkpoints: bad signature,
// signer/key mismatch, untrusted witness, wrong record type.
func TestVerifyCheckpointFileRejectsForgery(t *testing.T) {
	s := openStore(t)
	appendTestEvents(t, s, 2)
	dir := t.TempDir()
	witness := testWitness(t)
	good, err := s.WriteCheckpoint(dir, witness)
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{witness.Fingerprint(): true}
	if err := VerifyCheckpointFile(good, trusted); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	if err := VerifyCheckpointFile(good, map[string]bool{}); err == nil {
		t.Fatal("empty trust set accepted a checkpoint — must fail closed")
	}
	if err := VerifyCheckpointFile(good, map[string]bool{"deadbeef": true}); err == nil {
		t.Fatal("untrusted witness accepted")
	}
	forged := *good
	forged.Sequence = 999
	if err := VerifyCheckpointFile(&forged, trusted); err == nil {
		t.Fatal("altered sequence passed signature verification")
	}
	forged = *good
	forged.ChainHead = strings.Repeat("0", 64)
	if err := VerifyCheckpointFile(&forged, trusted); err == nil {
		t.Fatal("altered chain head passed signature verification")
	}
	other := testWitness(t)
	forged = *good
	forged.PublicKey = base64.StdEncoding.EncodeToString(other.PublicKey())
	if err := VerifyCheckpointFile(&forged, trusted); err == nil {
		t.Fatal("substituted key under old signature accepted")
	}
}
