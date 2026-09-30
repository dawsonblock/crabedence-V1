package idempotency

import (
	"encoding/json"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
)

// testEvidenceSigner creates a fresh Ed25519 receipt signer and trusts
// it on the store. CRITICAL definitive transitions require a signed
// effect receipt from a trusted signer.
func testEvidenceSigner(t *testing.T, store *Store) *evidence.Signer {
	t.Helper()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("failed to generate evidence signer: %v", err)
	}
	store.SetTrustedEvidenceSigners(signer.Fingerprint())
	return signer
}

// signTestReceipt signs an evidence receipt for the given binding.
func signTestReceipt(t *testing.T, signer *evidence.Signer, b evidence.Binding) json.RawMessage {
	t.Helper()
	receipt, err := signer.Sign(b)
	if err != nil {
		t.Fatalf("failed to sign evidence receipt: %v", err)
	}
	return receipt
}
