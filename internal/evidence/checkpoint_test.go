package evidence

import (
	"fmt"
	"strings"
	"testing"
)

// checkpointFixture returns n deterministic terminal refs in the
// canonical (execution_id ascending) order.
func checkpointFixture(n int) []TerminalRef {
	refs := make([]TerminalRef, n)
	for i := 0; i < n; i++ {
		refs[i] = TerminalRef{
			ExecutionID:            fmt.Sprintf("exec-%04d", i),
			State:                  "COMMITTED",
			RequestDigest:          fmt.Sprintf("sha256:req-%04d", i),
			TerminalResultDigest:   fmt.Sprintf("sha256:res-%04d", i),
			TerminalEvidenceDigest: fmt.Sprintf("sha256:evi-%04d", i),
			TerminalReceiptDigest:  fmt.Sprintf("sha256:rcp-%04d", i),
			ProviderID:             "prov",
			ProviderRunID:          fmt.Sprintf("run-%04d", i),
			UpdatedAt:              fmt.Sprintf("2026-10-09T03:00:%02d.000Z", i),
		}
	}
	return refs
}

func trustedFp(t *testing.T, s *Signer) map[string]bool {
	t.Helper()
	return map[string]bool{s.Fingerprint(): true}
}

func TestCheckpointSignVerifyRoundtrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	refs := checkpointFixture(3)
	cp := signer.SignCheckpoint(7, refs)
	if cp.Sequence != 7 || cp.RecordCount != 3 {
		t.Fatalf("checkpoint metadata wrong: seq=%d count=%d", cp.Sequence, cp.RecordCount)
	}
	if err := VerifyCheckpoint(cp, refs, trustedFp(t, signer)); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
}

// A checkpoint over an empty enumeration verifies.
func TestCheckpointEmptyEnumeration(t *testing.T) {
	signer, _ := GenerateSigner()
	cp := signer.SignCheckpoint(1, nil)
	if err := VerifyCheckpoint(cp, nil, trustedFp(t, signer)); err != nil {
		t.Fatalf("empty checkpoint rejected: %v", err)
	}
}

// Rewriting any committed field of a covered record is detected.
func TestCheckpointDetectsRewrittenRecord(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(3)
	cp := signer.SignCheckpoint(1, refs)
	mutated := checkpointFixture(3)
	mutated[1].State = "FAILED"        // covered state changed
	mutated[1].ProviderRunID = "run-x" // covered provider identity changed
	mutated[2].UpdatedAt = "2026-10-10T00:00:00.000Z"
	if err := VerifyCheckpoint(cp, mutated, trustedFp(t, signer)); err == nil {
		t.Fatal("rewritten covered record accepted")
	} else if !strings.Contains(err.Error(), "chain mismatch") {
		t.Fatalf("wrong failure: %v", err)
	}
}

// Deleting a covered record is detected by the record count.
func TestCheckpointDetectsTruncation(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(3)
	cp := signer.SignCheckpoint(1, refs)
	if err := VerifyCheckpoint(cp, refs[:2], trustedFp(t, signer)); err == nil {
		t.Fatal("truncated enumeration accepted")
	}
	if err := VerifyCheckpoint(cp, nil, trustedFp(t, signer)); err == nil {
		t.Fatal("rolled-back (empty) store accepted")
	}
}

// Reordering covered records breaks the canonical order — detected.
func TestCheckpointDetectsReordering(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(3)
	cp := signer.SignCheckpoint(1, refs)
	reordered := checkpointFixture(3)
	reordered[0], reordered[2] = reordered[2], reordered[0]
	if err := VerifyCheckpoint(cp, reordered, trustedFp(t, signer)); err == nil {
		t.Fatal("reordered enumeration accepted")
	}
}

// Records appended after the checkpoint do not disturb it: the prefix
// property is what a sequence of checkpoints proves over time.
func TestCheckpointToleratesGrowth(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(3)
	cp := signer.SignCheckpoint(1, refs)
	grown := append(append([]TerminalRef{}, refs...), checkpointFixture(5)[3:]...)
	if err := VerifyCheckpoint(cp, grown, trustedFp(t, signer)); err != nil {
		t.Fatalf("grown enumeration rejected: %v", err)
	}
}

func TestCheckpointRejectsUntrustedSigner(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(2)
	cp := signer.SignCheckpoint(1, refs)
	if err := VerifyCheckpoint(cp, refs, map[string]bool{"deadbeef": true}); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	if err := VerifyCheckpoint(cp, refs, nil); err == nil {
		t.Fatal("nil trusted set accepted")
	}
}

// Mutating any signed field after issuance invalidates the signature —
// the checkpoint binds its own metadata.
func TestCheckpointRejectsTamperedSignedFields(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(2)
	cp := signer.SignCheckpoint(1, refs)
	for name, mutate := range map[string]func(*Checkpoint){
		"count":    func(c *Checkpoint) { c.RecordCount++ },
		"sequence": func(c *Checkpoint) { c.Sequence++ },
		"chain":    func(c *Checkpoint) { c.ChainDigest = CheckpointChainDigest(checkpointFixture(9)) },
		"issued":   func(c *Checkpoint) { c.IssuedAt = "2030-01-01T00:00:00Z" },
	} {
		bad := *cp
		mutate(&bad)
		if err := VerifyCheckpoint(&bad, refs, trustedFp(t, signer)); err == nil {
			t.Fatalf("tampered %s accepted", name)
		}
	}
}

// A checkpoint that claims one signer but embeds another's key is
// refused at the fingerprint check.
func TestCheckpointRejectsMismatchedSignerField(t *testing.T) {
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	refs := checkpointFixture(1)
	cp := signer.SignCheckpoint(1, refs)
	bad := *cp
	bad.Signer = other.Fingerprint()
	if err := VerifyCheckpoint(&bad, refs, map[string]bool{other.Fingerprint(): true}); err == nil {
		t.Fatal("signer/public_key mismatch accepted")
	}
}

func TestCheckpointRejectsMalformed(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(1)
	good := signer.SignCheckpoint(1, refs)
	cases := map[string]func(*Checkpoint){
		"bad type":        func(c *Checkpoint) { c.CheckpointType = "other" },
		"bad schema":      func(c *Checkpoint) { c.SchemaVersion = 99 },
		"negative seq":    func(c *Checkpoint) { c.Sequence = -1 },
		"negative count":  func(c *Checkpoint) { c.RecordCount = -1 },
		"bad issued_at":   func(c *Checkpoint) { c.IssuedAt = "not-a-time" },
		"empty issued_at": func(c *Checkpoint) { c.IssuedAt = "" },
		"bad chain":       func(c *Checkpoint) { c.ChainDigest = "zz" },
		"bad pubkey":      func(c *Checkpoint) { c.PublicKey = "%%%" },
		"bad signature":   func(c *Checkpoint) { c.Signature = "%%%" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := *good
			mutate(&c)
			if err := VerifyCheckpoint(&c, refs, trustedFp(t, signer)); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
	if err := VerifyCheckpoint(nil, refs, trustedFp(t, signer)); err == nil {
		t.Fatal("nil checkpoint accepted")
	}
}
