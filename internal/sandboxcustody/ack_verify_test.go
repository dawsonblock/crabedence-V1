package sandboxcustody

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// The acknowledgement gate: VerifyWitnessAck is the independent check
// the executor runs before releasing operational rows. Every
// acceptance-table adversarial case must fail closed, and a genuine
// witness ack must pass.

func signedAck(t *testing.T, signer *evidence.Signer, ack *AckRecord) *AckRecord {
	t.Helper()
	pub := signer.PublicKey()
	ack.PublicKey = base64.StdEncoding.EncodeToString(pub)
	ack.Signer = evidence.Fingerprint(pub)
	fields, err := ack.SigningFields()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignRecord(WitnessDomain, fields...)
	if err != nil {
		t.Fatal(err)
	}
	ack.Signature = sig
	return ack
}

func v2Ack() *AckRecord {
	return &AckRecord{
		RecordType:       AckRecordTypeV2,
		AckSeq:           1,
		SegmentSeq:       7,
		FirstTerminalSeq: 10,
		LastTerminalSeq:  12,
		RowCount:         3,
		PayloadSHA256:    "ab12cd",
		RequestCreatedAt: 1729000000000,
		PrevAckSHA256:    "",
		WitnessedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func bindingFor(ack *AckRecord) *AckBinding {
	return &AckBinding{
		SegmentSeq:       ack.SegmentSeq,
		FirstTerminalSeq: ack.FirstTerminalSeq,
		LastTerminalSeq:  ack.LastTerminalSeq,
		RowCount:         ack.RowCount,
		PayloadSHA256:    ack.PayloadSHA256,
		RequestCreatedAt: ack.RequestCreatedAt,
	}
}

func TestVerifyWitnessAckAcceptsValidV2(t *testing.T) {
	signer, _ := evidence.GenerateSigner()
	ack := signedAck(t, signer, v2Ack())
	trust := NewTrustRoot(signer.PublicKey())
	if err := VerifyWitnessAck(ack, bindingFor(ack), trust); err != nil {
		t.Fatalf("a genuine witness ack refused: %v", err)
	}
	// Fingerprint-pinned trust accepts the same key identity.
	fpTrust := NewFingerprintTrust(signer.Fingerprint())
	if err := VerifyWitnessAck(ack, bindingFor(ack), fpTrust); err != nil {
		t.Fatalf("fingerprint-pinned trust refused the witness's own key: %v", err)
	}
}

// Matching digest, invalid signature — the check a forged
// acknowledgement can never pass.
func TestVerifyWitnessAckRejectsInvalidSignature(t *testing.T) {
	signer, _ := evidence.GenerateSigner()
	ack := signedAck(t, signer, v2Ack())
	// Corrupt the signature while keeping it well-formed.
	raw, _ := base64.StdEncoding.DecodeString(ack.Signature)
	raw[0] ^= 0xff
	ack.Signature = base64.StdEncoding.EncodeToString(raw)
	trust := NewTrustRoot(signer.PublicKey())
	if err := VerifyWitnessAck(ack, bindingFor(ack), trust); err == nil {
		t.Fatal("a corrupted signature verified")
	}
}

// A signature minted for another record never verifies as this one —
// the versioned vector binds every field.
func TestVerifyWitnessAckRejectsFieldTamper(t *testing.T) {
	signer, _ := evidence.GenerateSigner()
	ack := signedAck(t, signer, v2Ack())
	trust := NewTrustRoot(signer.PublicKey())
	for _, mutate := range []func(*AckRecord){
		func(a *AckRecord) { a.SegmentSeq = 99 },
		func(a *AckRecord) { a.RowCount = 99 },
		func(a *AckRecord) { a.PayloadSHA256 = "deadbeef" },
		func(a *AckRecord) { a.RequestCreatedAt++ },
		func(a *AckRecord) { a.AckSeq = 44 },
	} {
		bad := *ack
		mutate(&bad)
		if err := VerifyWitnessAck(&bad, bindingFor(ack), trust); err == nil {
			t.Fatal("a tampered ack field went unnoticed")
		}
	}
}

// A substituted signer — a well-formed ack under a key the trust root
// never approved — is refused even though its signature is genuine.
func TestVerifyWitnessAckRejectsSubstitutedSigner(t *testing.T) {
	real, _ := evidence.GenerateSigner()
	rogue, _ := evidence.GenerateSigner()
	ack := signedAck(t, rogue, v2Ack())
	trust := NewTrustRoot(real.PublicKey())
	if err := VerifyWitnessAck(ack, bindingFor(ack), trust); err == nil {
		t.Fatal("an unapproved witness's signature was accepted")
	}
}

// A replayed acknowledgement — genuinely signed, correct witness,
// minted for a different segment — answers this request not at all.
func TestVerifyWitnessAckRejectsReplayedAck(t *testing.T) {
	signer, _ := evidence.GenerateSigner()
	trust := NewTrustRoot(signer.PublicKey())
	old := signedAck(t, signer, func() *AckRecord {
		a := v2Ack()
		a.SegmentSeq = 3
		return a
	}())
	// The requester asked about segment 7 — the response attests 3.
	want := bindingFor(v2Ack())
	if err := VerifyWitnessAck(old, want, trust); err == nil {
		t.Fatal("an ack for another segment satisfied this request")
	}
	// Same failure class with the segment matching but the request
	// instance differing — a replay of an earlier retry of the same
	// segment identity.
	replay := signedAck(t, signer, func() *AckRecord {
		a := v2Ack()
		a.RequestCreatedAt = a.RequestCreatedAt - 1
		return a
	}())
	if err := VerifyWitnessAck(replay, want, trust); err == nil {
		t.Fatal("an ack for an earlier request instance satisfied this one")
	}
}

// Legacy v1 acknowledgements still verify — under their own signing
// vector, so a v1 signature can never pass as v2.
func TestVerifyWitnessAckAcceptsV1(t *testing.T) {
	signer, _ := evidence.GenerateSigner()
	ack := signedAck(t, signer, &AckRecord{
		RecordType:       AckRecordTypeV1,
		AckSeq:           1,
		SegmentSeq:       7,
		FirstTerminalSeq: 10,
		LastTerminalSeq:  12,
		RowCount:         3,
		PayloadSHA256:    "ab12cd",
		WitnessedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	})
	trust := NewTrustRoot(signer.PublicKey())
	if err := VerifyWitnessAck(ack, bindingFor(v2Ack()), trust); err != nil {
		t.Fatalf("a legacy v1 ack refused: %v", err)
	}
}

// No configured trust is no trust — an otherwise-perfect ack fails
// closed because the witness's identity was never pinned.
func TestVerifyWitnessAckFailsClosedWithoutTrust(t *testing.T) {
	signer, _ := evidence.GenerateSigner()
	ack := signedAck(t, signer, v2Ack())
	for _, trust := range []*TrustRoot{nil, NewTrustRoot(), NewFingerprintTrust()} {
		if err := VerifyWitnessAck(ack, bindingFor(ack), trust); err == nil {
			t.Fatal("an acknowledgement verified with no witness trust configured")
		}
	}
}

// A self-declared signer — a fingerprint that does not match the
// embedded public key — is not identity.
func TestVerifyWitnessAckRejectsSelfDeclaredSigner(t *testing.T) {
	signer, _ := evidence.GenerateSigner()
	ack := signedAck(t, signer, v2Ack())
	// Claim a different fingerprint while keeping the real key —
	// signer's claim is inconsistent before trust is even consulted.
	other, _ := evidence.GenerateSigner()
	ack.Signer = other.Fingerprint()
	trust := NewTrustRoot(signer.PublicKey())
	if err := VerifyWitnessAck(ack, bindingFor(ack), trust); err == nil {
		t.Fatal("a self-declared signer identity was accepted")
	}
}

// The trust root's file format: the anchor needs no authorization,
// every rotation needs the incumbent's signed transition.
func TestTrustRootFileTransitions(t *testing.T) {
	dir := t.TempDir()
	k1, _ := evidence.GenerateSigner()
	k2, _ := evidence.GenerateSigner()
	b64 := func(k *evidence.Signer) string {
		return base64.StdEncoding.EncodeToString(k.PublicKey())
	}

	// A lone anchor loads.
	path := dir + "/trust.json"
	write := func(s string) {
		if err := writeTestFile(path, s); err != nil {
			t.Fatal(err)
		}
	}
	write(fmt.Sprintf(`{"version":1,"witnesses":[{"public_key":%q}]}`, b64(k1)))
	tr, err := LoadTrustRoot(path)
	if err != nil || !tr.Approve(k1.Fingerprint(), k1.PublicKey()) {
		t.Fatalf("anchor trust root: %v", err)
	}

	// A rotation with no transition signature refuses.
	write(fmt.Sprintf(`{"version":1,"witnesses":[{"public_key":%q},{"public_key":%q}]}`, b64(k1), b64(k2)))
	if _, err := LoadTrustRoot(path); err == nil {
		t.Fatal("an unauthorized key rotation was trusted")
	}

	// A rotation signed by the incumbent loads — and only then does
	// the successor vouch.
	sig, err := SignKeyTransition(k1, k2.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	write(fmt.Sprintf(`{"version":1,"witnesses":[{"public_key":%q},{"public_key":%q,"signature":%q}]}`,
		b64(k1), b64(k2), sig))
	tr, err = LoadTrustRoot(path)
	if err != nil {
		t.Fatalf("authorized rotation refused: %v", err)
	}
	if !tr.Approve(k2.Fingerprint(), k2.PublicKey()) {
		t.Fatal("the rotated successor did not inherit authority")
	}

	// A transition signed by the wrong key refuses.
	sig2, err := SignKeyTransition(k2, k1.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	write(fmt.Sprintf(`{"version":1,"witnesses":[{"public_key":%q},{"public_key":%q,"signature":%q}]}`,
		b64(k1), b64(k2), sig2))
	if _, err := LoadTrustRoot(path); err == nil {
		t.Fatal("a transition signed by the successor itself was trusted")
	}
}

// A trust file another user could read or write is not a trust root.
func TestTrustRootFilePermissions(t *testing.T) {
	dir := t.TempDir()
	k1, _ := evidence.GenerateSigner()
	path := dir + "/trust.json"
	content := fmt.Sprintf(`{"version":1,"witnesses":[{"public_key":%q}]}`,
		base64.StdEncoding.EncodeToString(k1.PublicKey()))
	if err := writeTestFile(path, content); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustRoot(path); err == nil {
		t.Fatal("a group-readable trust root was accepted")
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
