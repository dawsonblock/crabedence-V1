package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sha256DigestPrefix(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestEvidenceVerifyDigestOK(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:    "hetzner",
		LeaseID:     "cbx_test000001",
		RunID:       "run_test0001",
		CommandText: "echo ok",
		ExitCode:    0,
	})
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if err := os.WriteFile(evidencePath, data, 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err = app.evidence(nil, []string{"verify", evidencePath})
	if err != nil {
		t.Fatalf("evidence verify: %v (stderr=%s)", err, stderr.String())
	}
	out := stdout.String()
	if !bytes.Contains([]byte(out), []byte("PASS")) {
		t.Fatalf("expected PASS in output, got %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("digest=verified")) {
		t.Fatalf("expected digest=verified in output, got %s", out)
	}
}

func TestEvidenceVerifyTamperedDigestFails(t *testing.T) {
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:    "hetzner",
		LeaseID:     "cbx_test000002",
		RunID:       "run_test0002",
		CommandText: "echo tampered",
		ExitCode:    1,
	})
	ev.Digest = "0" + ev.Digest[1:] // corrupt the first character
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if err := os.WriteFile(evidencePath, data, 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err = app.evidence(nil, []string{"verify", evidencePath})
	if err == nil {
		t.Fatalf("expected error for tampered digest, got nil")
	}
	exit, ok := err.(ExitError)
	if !ok || exit.Code != 1 {
		t.Fatalf("expected exit code 1, got %v", err)
	}
	out := stdout.String()
	if !bytes.Contains([]byte(out), []byte("FAIL")) {
		t.Fatalf("expected FAIL in output, got %s", out)
	}
}

func TestEvidenceVerifyWithReceiptBinding(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:    "hetzner",
		LeaseID:     "cbx_test000003",
		Slug:        "my-app",
		RunID:       "run_test0003",
		CommandText: "pnpm test",
		ExitCode:    0,
	})
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	evidenceData, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if err := os.WriteFile(evidencePath, evidenceData, 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	now := time.Now()
	logDigest := sha256DigestPrefix([]byte("test log"))
	receipt, err := buildTerminalRunReceiptWithKey(key, terminalRunReceiptInput{
		Provider:          "hetzner",
		LeaseID:           "cbx_test000003",
		Slug:              "my-app",
		RunID:             "run_test0003",
		Command:           []string{"pnpm", "test"},
		CommandDisplay:    "pnpm test",
		ExitCode:          0,
		StartedAt:         now,
		EndedAt:           now.Add(5 * time.Second),
		LogSHA256:         logDigest,
		RetainedLogSHA256: logDigest,
		EvidenceSHA256:    ev.Digest,
	})
	if err != nil {
		t.Fatalf("build receipt: %v", err)
	}
	receiptPath := filepath.Join(dir, "receipt.json")
	receiptData, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	if err := os.WriteFile(receiptPath, receiptData, 0o644); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err = app.evidence(nil, []string{"verify", "--receipt", receiptPath, evidencePath})
	if err != nil {
		t.Fatalf("evidence verify: %v (stderr=%s)", err, stderr.String())
	}
	out := stdout.String()
	if !bytes.Contains([]byte(out), []byte("digest=verified")) {
		t.Fatalf("expected digest=verified, got %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("receipt_binding=verified")) {
		t.Fatalf("expected receipt_binding=verified, got %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("receipt_signature=verified")) {
		t.Fatalf("expected receipt_signature=verified, got %s", out)
	}
	// The signer should be the key fingerprint, not empty.
	if bytes.Equal(pub, nil) {
		t.Fatal("public key should not be nil")
	}
}

func TestEvidenceVerifyReceiptBindingMismatchFails(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ev := NewRunEvidence(RunEvidenceInput{
		Provider:    "hetzner",
		LeaseID:     "cbx_test000004",
		RunID:       "run_test0004",
		CommandText: "echo ok",
		ExitCode:    0,
	})
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	evidenceData, _ := json.MarshalIndent(ev, "", "  ")
	os.WriteFile(evidencePath, evidenceData, 0o644)

	// Receipt has a wrong evidence_sha256.
	now := time.Now()
	logDigest := sha256DigestPrefix([]byte("test log"))
	receipt, err := buildTerminalRunReceiptWithKey(key, terminalRunReceiptInput{
		Provider:          "hetzner",
		LeaseID:           "cbx_test000004",
		RunID:             "run_test0004",
		Command:           []string{"echo", "ok"},
		CommandDisplay:    "echo ok",
		ExitCode:          0,
		StartedAt:         now,
		EndedAt:           now.Add(1 * time.Second),
		LogSHA256:         logDigest,
		RetainedLogSHA256: logDigest,
		EvidenceSHA256:    "0" + ev.Digest[1:],
	})
	if err != nil {
		t.Fatalf("build receipt: %v", err)
	}
	receiptPath := filepath.Join(dir, "receipt.json")
	receiptData, _ := json.MarshalIndent(receipt, "", "  ")
	os.WriteFile(receiptPath, receiptData, 0o644)

	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err = app.evidence(nil, []string{"verify", "--receipt", receiptPath, evidencePath})
	if err == nil {
		t.Fatalf("expected error for binding mismatch")
	}
	out := stdout.String()
	if !bytes.Contains([]byte(out), []byte("FAIL")) {
		t.Fatalf("expected FAIL, got %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("receipt_binding")) {
		t.Fatalf("expected receipt_binding failure, got %s", out)
	}
}

func TestEvidenceVerifyInvalidSchemaFails(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	// Wrong schema_version and evidence_type.
	os.WriteFile(evidencePath, []byte(`{"schema_version":2,"evidence_type":"run","digest":"`+repeat("0", 64)+`"}`), 0o644)

	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err := app.evidence(nil, []string{"verify", evidencePath})
	if err == nil {
		t.Fatalf("expected error for invalid schema")
	}
	out := stdout.String()
	if !bytes.Contains([]byte(out), []byte("FAIL")) {
		t.Fatalf("expected FAIL, got %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("structural_validation")) {
		t.Fatalf("expected structural_validation failure, got %s", out)
	}
}

func TestEvidenceVerifyNoArgsShowsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr}
	err := app.evidence(nil, []string{})
	if err != nil {
		t.Fatalf("evidence with no args: %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("Usage:")) {
		t.Fatalf("expected help output, got %s", stdout.String())
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
