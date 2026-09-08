package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// receiptContractFixture is a single case in the shared V2/V3 receipt
// evidence_sha256 contract corpus. Both Go and TypeScript must accept or
// reject each case identically.
type receiptContractFixture struct {
	Name           string  `json:"name"`
	Description    string  `json:"description"`
	SchemaVersion  int     `json:"schema_version"`
	EvidenceSHA256 *string `json:"evidence_sha256"`
	Expected       string  `json:"expected"` // "accept" or "reject"
	ErrorContains  string  `json:"error_contains,omitempty"`
}

type receiptContractFile struct {
	Description string                   `json:"description"`
	Fixtures    []receiptContractFixture `json:"fixtures"`
}

// TestReceiptContractConformance loads the shared V2/V3 receipt contract
// fixture file and verifies that the Go receipt validator accepts or rejects
// each case as expected. The same fixture file is consumed by the TypeScript
// test (worker/test/receipt-contract-conformance.test.ts), and both must
// agree.
//
// This is the protocol-contract gate: V2 = legacy (no evidence binding),
// V3 = evidence binding mandatory. If Go accepts a case that TypeScript
// rejects (or vice versa), the wire contract is broken.
func TestReceiptContractConformance(t *testing.T) {
	path := filepath.Join("testdata", "receipt-contract", "fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipt contract fixtures: %v", err)
	}
	var file receiptContractFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse receipt contract fixtures: %v", err)
	}
	if len(file.Fixtures) == 0 {
		t.Fatal("no receipt contract fixtures found")
	}
	for _, fx := range file.Fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			receipt := buildTestReceipt(t)
			receipt.SchemaVersion = fx.SchemaVersion
			if fx.EvidenceSHA256 == nil {
				receipt.EvidenceSHA256 = ""
			} else {
				receipt.EvidenceSHA256 = *fx.EvidenceSHA256
			}
			// Re-sign because schema/evidence changed.
			pub, priv, _ := ed25519.GenerateKey(nil)
			receipt.PublicKey = base64.StdEncoding.EncodeToString(pub)
			receipt.Signer = attestFingerprint(pub)
			receipt.Signature = base64.StdEncoding.EncodeToString(
				ed25519.Sign(priv, terminalReceiptSigningBytes(receipt)),
			)
			err := validateTerminalRunReceipt(receipt)
			if fx.Expected == "reject" {
				if err == nil {
					t.Fatalf("expected rejection but validation passed")
				}
				if fx.ErrorContains != "" && !strings.Contains(err.Error(), fx.ErrorContains) {
					t.Errorf("expected error containing %q, got: %v", fx.ErrorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected acceptance but got error: %v", err)
				}
			}
		})
	}
}
