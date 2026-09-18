package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// goldenVector is the frozen ReceiptV3 signing ABI. The signing
// payload is a deterministic binary construction — a domain-
// separation prefix followed by big-endian length-prefixed fields —
// so these vectors pin the field order, the domain string, the
// length-prefix encoding, and the signature itself. Any change to
// signingBytes (field order, prefix, encoding) breaks this test,
// which is the point: the receipt ABI is a cross-component contract
// and must not drift silently.
//
// Regenerating (deliberate ABI change only): fix the fixture inputs,
// print signingBytes/signatures as in TestPrintGoldenVector's
// original form, and update the constants — then review every
// consumer of ReceiptV3 across languages.
var goldenVector = struct {
	seedHex            string
	publicKeyB64       string
	fingerprint        string
	signingBytesSHA256 string
	signatureB64       string
}{
	seedHex:            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	publicKeyB64:       "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
	fingerprint:        "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
	signingBytesSHA256: "4b05d7aae2e02a4a95908a84898c7e64ee644cbca1407e7065e1d9bd5d786f6f",
	signatureB64:       "f8wJvqXTFoQZsLW1+9pJZcM0OAly4AlOpsEAbu22gETXXXrc9xy/wXXSb7jP3VocS67LT/Bz37SJgqoyxtnHBg==",
}

func goldenReceipt(t *testing.T) (ReceiptV3, ed25519.PrivateKey) {
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
	r := ReceiptV3{
		SchemaVersion:  ReceiptV3SchemaVersion,
		ReceiptType:    ReceiptType,
		ExecutionID:    "exec-0001",
		Capability:     "example.send",
		Principal:      "alice@example.com",
		RequestDigest:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ProviderID:     "provider-a",
		ProviderRunID:  "run-42",
		Outcome:        OutcomeCompleted,
		EvidenceSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		IssuedAt:       "2026-01-02T03:04:05.000000006Z",
		PublicKey:      base64.StdEncoding.EncodeToString(s.PublicKey()),
		Signer:         s.Fingerprint(),
	}
	return r, key
}

// TestGoldenSigningPayload pins the canonical signing bytes: domain
// prefix + length-prefixed field encoding is frozen.
func TestGoldenSigningPayload(t *testing.T) {
	r, _ := goldenReceipt(t)
	sb := signingBytes(r)
	sum := sha256.Sum256(sb)
	if got := hex.EncodeToString(sum[:]); got != goldenVector.signingBytesSHA256 {
		t.Fatalf("signing payload changed: sha256=%s, want %s — the ReceiptV3 signing ABI is frozen",
			got, goldenVector.signingBytesSHA256)
	}
}

// TestGoldenSignature pins the exact Ed25519 signature over the frozen
// payload, and the derived public key/fingerprint for the fixed seed.
func TestGoldenSignature(t *testing.T) {
	r, key := goldenReceipt(t)
	pub := key.Public().(ed25519.PublicKey)
	if got := base64.StdEncoding.EncodeToString(pub); got != goldenVector.publicKeyB64 {
		t.Fatalf("public key = %s, want %s", got, goldenVector.publicKeyB64)
	}
	if got := Fingerprint(pub); got != goldenVector.fingerprint {
		t.Fatalf("fingerprint = %s, want %s", got, goldenVector.fingerprint)
	}
	sig := ed25519.Sign(key, signingBytes(r))
	if got := base64.StdEncoding.EncodeToString(sig); got != goldenVector.signatureB64 {
		t.Fatalf("signature = %s, want %s", got, goldenVector.signatureB64)
	}
	r.Signature = goldenVector.signatureB64
	if err := VerifySignature(r); err != nil {
		t.Fatalf("golden receipt fails signature verification: %v", err)
	}
}

// TestGoldenReceiptRoundTrip verifies the golden receipt end-to-end:
// serialize, strict-parse, verify signature, verify binding + trust.
func TestGoldenReceiptRoundTrip(t *testing.T) {
	r, _ := goldenReceipt(t)
	r.Signature = goldenVector.signatureB64
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{
		ExecutionID:    r.ExecutionID,
		Capability:     r.Capability,
		Principal:      r.Principal,
		RequestDigest:  r.RequestDigest,
		ProviderID:     r.ProviderID,
		ProviderRunID:  r.ProviderRunID,
		Outcome:        r.Outcome,
		EvidenceSHA256: r.EvidenceSHA256,
	}
	trusted := map[string]bool{goldenVector.fingerprint: true}
	if err := VerifyReceipt(raw, binding, trusted); err != nil {
		t.Fatalf("golden receipt fails full verification: %v", err)
	}
	// Trust boundary: the same receipt under an empty/other trust set
	// must fail closed.
	if err := VerifyReceipt(raw, binding, nil); err == nil {
		t.Fatal("verification succeeded with no trusted signers")
	}
	if err := VerifyReceipt(raw, binding, map[string]bool{"deadbeef": true}); err == nil {
		t.Fatal("verification succeeded under an untrusted signer set")
	}
	// Binding boundary: a different execution ID must be rejected.
	binding.ExecutionID = "exec-9999"
	if err := VerifyReceipt(raw, binding, trusted); err == nil {
		t.Fatal("verification succeeded with a mismatched binding")
	}
}
