package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"testing"
)

// goldenCheckpointVector is the frozen evidence-checkpoint-v2 signing
// ABI, in the same shape as the ReceiptV3 golden vector. The chain
// digest is a SHA-256 over big-endian length-prefixed canonical fields
// per terminal record — terminal_seq first, so ledger position itself
// is signed — in enumeration order; the signing payload is the
// checkpoint domain prefix followed by the same length-prefixed
// encoding of the checkpoint fields. These vectors pin field order,
// the domain strings, the length-prefix encoding, and the signature:
// any change to CheckpointChainDigest or checkpointSigningBytes is a
// deliberate ABI change that must regenerate them under review, never
// drift silently.
var goldenCheckpointVector = struct {
	chainDigestV2      string
	chainDigestV1      string
	signingBytesSHA256 string
	signatureB64       string
}{
	chainDigestV2:      "4b90c658ada3f8fe2fec6151ddaf9fd1fd140773ef171d23572e4dfb51ff9814",
	chainDigestV1:      "401c69b039d76ee311ac39bb55deda4ac9148e344c8d2785cf6544f73507d682",
	signingBytesSHA256: "d08262694c785ca077bef9b707aae2fad9fd40d0c737baec34cbb89edabfb657",
	signatureB64:       "K4sF5ETR+DWQGs4W1puWMmcadH2cHgMZIsOK38OZMsH1w82qtsylWv/3cVU0pCLxGvJIjCmi9SkV33w2VHj+BA==",
}

// goldenCheckpoint returns a fully populated v2 checkpoint over the
// shared three-record fixture, signed by the golden receipt key with a
// fixed issuance timestamp — every signed field deterministic.
func goldenCheckpoint(t *testing.T, refs []TerminalRef) (Checkpoint, ed25519.PrivateKey) {
	t.Helper()
	seed, err := hex.DecodeString(goldenVector.seedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	cp := Checkpoint{
		SchemaVersion:  CheckpointSchemaVersion,
		CheckpointType: CheckpointType,
		Sequence:       7,
		IssuedAt:       "2026-01-02T03:04:05.000000006Z",
		RecordCount:    len(refs),
		ChainDigest:    CheckpointChainDigest(refs),
		PublicKey:      base64.StdEncoding.EncodeToString(s.PublicKey()),
		Signer:         s.Fingerprint(),
	}
	cp.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(key, checkpointSigningBytes(cp)))
	return cp, key
}

// TestGoldenCheckpointChainDigestV2 pins the v2 chain canon — the
// signed meaning of the terminal ledger itself.
func TestGoldenCheckpointChainDigestV2(t *testing.T) {
	got := CheckpointChainDigest(checkpointFixture(3))
	if got != goldenCheckpointVector.chainDigestV2 {
		t.Fatalf("v2 chain digest changed: %s, want %s — the checkpoint v2 canonical enumeration is frozen",
			got, goldenCheckpointVector.chainDigestV2)
	}
}

// TestGoldenCheckpointChainDigestV1 pins the legacy canon the v1
// verifier still answers, so the migration boundary cannot silently
// redefine what an old checkpoint meant.
func TestGoldenCheckpointChainDigestV1(t *testing.T) {
	ordered := checkpointFixture(3)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].ExecutionID < ordered[j].ExecutionID
	})
	got := checkpointChainDigestV1(ordered)
	if got != goldenCheckpointVector.chainDigestV1 {
		t.Fatalf("v1 chain digest changed: %s, want %s — the legacy checkpoint canon is frozen",
			got, goldenCheckpointVector.chainDigestV1)
	}
}

// TestGoldenCheckpointSigningPayload pins the exact bytes a v2
// signature covers: domain prefix plus length-prefixed fields.
func TestGoldenCheckpointSigningPayload(t *testing.T) {
	cp, _ := goldenCheckpoint(t, checkpointFixture(3))
	sum := sha256.Sum256(checkpointSigningBytes(cp))
	if got := hex.EncodeToString(sum[:]); got != goldenCheckpointVector.signingBytesSHA256 {
		t.Fatalf("checkpoint signing payload changed: sha256=%s, want %s — the v2 checkpoint ABI is frozen",
			got, goldenCheckpointVector.signingBytesSHA256)
	}
}

// TestGoldenCheckpointSignature pins the exact signature over the
// frozen payload and proves the stored vector verifies.
func TestGoldenCheckpointSignature(t *testing.T) {
	cp, key := goldenCheckpoint(t, checkpointFixture(3))
	if cp.Signature != goldenCheckpointVector.signatureB64 {
		t.Fatalf("checkpoint signature changed: %s, want %s — regenerate the vector only for a deliberate ABI change",
			cp.Signature, goldenCheckpointVector.signatureB64)
	}
	sig, err := base64.StdEncoding.DecodeString(goldenCheckpointVector.signatureB64)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, checkpointSigningBytes(cp), sig) {
		t.Fatal("the golden checkpoint signature does not verify — the vector is inconsistent")
	}
}
