package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func buildTestReceipt(t *testing.T) terminalRunReceipt {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	startedAt := time.Date(2026, 1, 15, 12, 30, 0, 0, time.UTC)
	endedAt := startedAt.Add(5 * time.Second)
	commandDigest := sha256.Sum256([]byte("npm test"))
	logDigest := sha256.Sum256([]byte("log content"))
	evidenceDigest := sha256.Sum256([]byte("evidence content"))
	receipt := terminalRunReceipt{
		SchemaVersion:     terminalReceiptSchemaVersion,
		ReceiptType:       terminalReceiptType,
		StartedAt:         startedAt.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano),
		EndedAt:           endedAt.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano),
		Provider:          "hetzner",
		LeaseID:           "cbx_tamper001",
		Slug:              "blue-lobster",
		RunID:             "run_tamper001",
		Command:           "npm test",
		CommandSHA256:     "sha256:" + hex.EncodeToString(commandDigest[:]),
		ExitCode:          0,
		SyncMs:            2000,
		CommandMs:         3000,
		DurationMs:        5000,
		LogSHA256:         "sha256:" + hex.EncodeToString(logDigest[:]),
		RetainedLogSHA256: "sha256:" + hex.EncodeToString(logDigest[:]),
		EvidenceSHA256:    hex.EncodeToString(evidenceDigest[:]),
		PublicKey:         base64.StdEncoding.EncodeToString(pub),
		Signer:            attestFingerprint(pub),
	}
	receipt.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(priv, terminalReceiptSigningBytes(receipt)),
	)
	return receipt
}

func TestTerminalReceiptTamperedEvidenceSHA256FailsVerification(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Tamper with evidence_sha256 — should fail signature verification.
	receipt.EvidenceSHA256 = strings.Repeat("a", 64)
	if err := verifyTerminalRunReceiptSignature(receipt); err == nil {
		t.Fatal("signature verification should fail after evidence_sha256 tampering")
	}
}

func TestTerminalReceiptTamperedStartedAtFailsVerification(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Tamper with started_at — should fail signature verification.
	receipt.StartedAt = "2026-01-15T12:31:00Z"
	if err := verifyTerminalRunReceiptSignature(receipt); err == nil {
		t.Fatal("signature verification should fail after started_at tampering")
	}
}

func TestTerminalReceiptTamperedExitCodeFailsVerification(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Tamper with exit_code — should fail signature verification.
	receipt.ExitCode = 1
	if err := verifyTerminalRunReceiptSignature(receipt); err == nil {
		t.Fatal("signature verification should fail after exit_code tampering")
	}
}

func TestTerminalReceiptTamperedCommandSHA256FailsVerification(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Tamper with command_sha256 — should fail signature verification.
	receipt.CommandSHA256 = "sha256:" + strings.Repeat("b", 64)
	if err := verifyTerminalRunReceiptSignature(receipt); err == nil {
		t.Fatal("signature verification should fail after command_sha256 tampering")
	}
}

func TestTerminalReceiptTamperedDurationMsFailsValidation(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Tamper with duration_ms — should fail validation (duration != timestamps).
	receipt.DurationMs = 9999
	if err := validateTerminalRunReceipt(receipt); err == nil {
		t.Fatal("validation should fail when duration_ms doesn't match timestamps")
	}
}

func TestTerminalReceiptTamperedSignatureFailsVerification(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Tamper with the signature itself.
	receipt.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := verifyTerminalRunReceiptSignature(receipt); err == nil {
		t.Fatal("verification should fail with wrong signature")
	}
}

func TestTerminalReceiptMissingSignatureFailsVerification(t *testing.T) {
	receipt := buildTestReceipt(t)
	receipt.Signature = ""
	if err := verifyTerminalRunReceiptSignature(receipt); err == nil {
		t.Fatal("verification should fail with missing signature")
	}
}

func TestTerminalReceiptInvalidPublicKeyFailsValidation(t *testing.T) {
	receipt := buildTestReceipt(t)
	receipt.PublicKey = base64.StdEncoding.EncodeToString([]byte("short"))
	if err := validateTerminalRunReceipt(receipt); err == nil {
		t.Fatal("validation should fail with invalid public_key")
	}
}

func TestTerminalReceiptSignerMismatchFailsValidation(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Use a different valid public key but keep the old signer fingerprint.
	_, _, _ = ed25519.GenerateKey(nil)
	receipt.Signer = strings.Repeat("a", 16)
	if err := validateTerminalRunReceipt(receipt); err == nil {
		t.Fatal("validation should fail when signer doesn't match public_key")
	}
}

func TestTerminalReceiptNegativeExitCodeFailsValidation(t *testing.T) {
	receipt := buildTestReceipt(t)
	receipt.ExitCode = -1
	if err := validateTerminalRunReceipt(receipt); err == nil {
		t.Fatal("validation should fail with negative exit_code")
	}
}

func TestTerminalReceiptEndedBeforeStartedFailsValidation(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Swap started_at and ended_at.
	receipt.StartedAt, receipt.EndedAt = receipt.EndedAt, receipt.StartedAt
	if err := validateTerminalRunReceipt(receipt); err == nil {
		t.Fatal("validation should fail when ended_at is before started_at")
	}
}

func TestTerminalReceiptEmptyRequiredFieldFailsValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*terminalRunReceipt)
	}{
		{"command_sha256", func(r *terminalRunReceipt) { r.CommandSHA256 = "" }},
		{"log_sha256", func(r *terminalRunReceipt) { r.LogSHA256 = "" }},
		{"public_key", func(r *terminalRunReceipt) { r.PublicKey = "" }},
		{"signer", func(r *terminalRunReceipt) { r.Signer = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipt := buildTestReceipt(t)
			tc.mutate(&receipt)
			if err := validateTerminalRunReceipt(receipt); err == nil {
				t.Fatalf("validation should fail with empty %s", tc.name)
			}
		})
	}
}

func TestTerminalReceiptInvalidEvidenceSHA256FailsValidation(t *testing.T) {
	receipt := buildTestReceipt(t)
	receipt.EvidenceSHA256 = "not-a-hex-digest"
	if err := validateTerminalRunReceipt(receipt); err == nil {
		t.Fatal("validation should fail with invalid evidence_sha256")
	}
}

func TestTerminalReceiptEmptyEvidenceSHA256RejectedForV3(t *testing.T) {
	// V3 receipts MUST bind evidence_sha256. An empty evidence_sha256 is
	// rejected so that schema_version 3 has a clean semantic meaning:
	// V3 == authenticated evidence binding.
	receipt := buildTestReceipt(t)
	receipt.EvidenceSHA256 = ""
	receipt.SchemaVersion = terminalReceiptSchemaVersion
	// Re-sign because the evidence_sha256 changed.
	pub, priv, _ := ed25519.GenerateKey(nil)
	receipt.PublicKey = base64.StdEncoding.EncodeToString(pub)
	receipt.Signer = attestFingerprint(pub)
	receipt.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(priv, terminalReceiptSigningBytes(receipt)),
	)
	if err := validateTerminalRunReceipt(receipt); err == nil {
		t.Fatal("validation should reject V3 receipt with empty evidence_sha256")
	} else if !strings.Contains(err.Error(), "v3 terminal receipt must bind evidence_sha256") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerminalReceiptJSONTamperingDetected(t *testing.T) {
	receipt := buildTestReceipt(t)
	// Serialize to JSON, tamper with a field, deserialize, and verify.
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Tamper with the exit_code in the JSON.
	tampered := strings.Replace(string(data), `"exit_code":0`, `"exit_code":42`, 1)
	if tampered == string(data) {
		t.Fatal("tampering replacement did not match")
	}
	var tamperedReceipt terminalRunReceipt
	if err := json.Unmarshal([]byte(tampered), &tamperedReceipt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The signature was computed over the original exit_code, so
	// verification should fail.
	if err := verifyTerminalRunReceiptSignature(tamperedReceipt); err == nil {
		t.Fatal("signature verification should fail after JSON tampering")
	}
}
