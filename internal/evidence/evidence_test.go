package evidence

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func testBinding() Binding {
	return Binding{
		ExecutionID:    "exec-1",
		Capability:     "test.critical.deploy",
		Principal:      "alice@example.com",
		RequestDigest:  "digest-1",
		ProviderID:     "deploy-adapter",
		ProviderRunID:  "run-1",
		Outcome:        OutcomeCompleted,
		EvidenceSHA256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	b := testBinding()
	raw, err := signer.Sign(b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	trusted := map[string]bool{signer.Fingerprint(): true}
	if err := VerifyReceipt(raw, b, trusted); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	signer, _ := GenerateSigner()
	b := testBinding()
	raw, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the bound outcome — signature no longer matches.
	tampered := strings.Replace(string(raw), `"outcome":"COMPLETED"`, `"outcome":"NO_EFFECT"`, 1)
	trusted := map[string]bool{signer.Fingerprint(): true}
	if err := VerifyReceipt(json.RawMessage(tampered), b, trusted); err == nil {
		t.Error("tampered receipt must be rejected")
	}
}

func TestVerifyRejectsUntrustedSigner(t *testing.T) {
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	b := testBinding()
	raw, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	// Valid signature, but the signer is not trusted.
	if err := VerifyReceipt(raw, b, map[string]bool{other.Fingerprint(): true}); err == nil {
		t.Error("untrusted signer must be rejected")
	}
	// Empty trust set fails closed.
	if err := VerifyReceipt(raw, b, nil); err == nil {
		t.Error("empty trust set must fail closed")
	}
}

func TestVerifyRejectsBindingMismatch(t *testing.T) {
	signer, _ := GenerateSigner()
	b := testBinding()
	raw, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{signer.Fingerprint(): true}

	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.ExecutionID = "exec-2" },
		func(b *Binding) { b.Principal = "bob@example.com" },
		func(b *Binding) { b.ProviderRunID = "run-2" },
		func(b *Binding) { b.Outcome = OutcomeNoEffect },
		func(b *Binding) {
			b.EvidenceSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
	} {
		bad := b
		mutate(&bad)
		if err := VerifyReceipt(raw, bad, trusted); err == nil {
			t.Error("binding mismatch must be rejected")
		}
	}
}

func TestVerifyRejectsMissingReceipt(t *testing.T) {
	trusted := map[string]bool{"any": true}
	if err := VerifyReceipt(nil, testBinding(), trusted); err == nil {
		t.Error("missing receipt must be rejected")
	}
}

func TestParseRejectsUnknownAndDuplicateFields(t *testing.T) {
	signer, _ := GenerateSigner()
	raw, err := signer.Sign(testBinding())
	if err != nil {
		t.Fatal(err)
	}
	// Unknown field.
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["extra_field"] = "x"
	withExtra, _ := json.Marshal(m)
	if _, err := ParseReceipt(withExtra); err == nil {
		t.Error("unknown field must be rejected")
	}
	// Duplicate key.
	dup := strings.Replace(string(raw), `"signer"`, `"signer":"x","signer"`, 1)
	if _, err := ParseReceipt(json.RawMessage(dup)); err == nil {
		t.Error("duplicate key must be rejected")
	}
}

func TestLoadOrCreateSignerRoundtrip(t *testing.T) {
	path := t.TempDir() + "/attest/id_ed25519.pem"
	s1, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Fingerprint() != s2.Fingerprint() {
		t.Error("reloaded signer must be the same key")
	}
	// The persisted key must sign verifiable receipts.
	raw, err := s2.Sign(testBinding())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(raw, testBinding(), map[string]bool{s1.Fingerprint(): true}); err != nil {
		t.Fatalf("reloaded signer receipt failed verification: %v", err)
	}
}

func TestGenerateSignerProducesValidKey(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	if len(signer.PublicKey()) != ed25519.PublicKeySize {
		t.Error("public key has wrong size")
	}
}
