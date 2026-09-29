package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/ed25519"
)

// TestFinalizeRunOutcomeImmutabilityOnCoordinatorFailure verifies the core
// immutability rule: when the coordinator commit fails after a successful
// remote execution, the signed receipt and evidence must NOT be rebuilt with
// a failure exit code. The coordinator receives the original execution receipt,
// and the failure is reported as an auxiliary error.
//
// This is the regression guard for the user's rule:
// "A local --evidence-json write failure can make the CLI operation report
// an auxiliary error. It cannot retroactively change a successful remote
// execution into a failed signed execution."
func TestFinalizeRunOutcomeImmutabilityOnCoordinatorFailure(t *testing.T) {
	dir := t.TempDir()
	isolateRunTestUserDirs(t, dir)
	sshPath := filepath.Join(dir, "ssh")
	receiptPath := filepath.Join(dir, "receipt.json")
	keyPath := filepath.Join(dir, "signer.pem")
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	writeRunTestAttestKey(t, keyPath, key)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, sshPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	installWorkspaceOwnerAwareSSH(t, sshPath, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CRABBOX_CONFIG", filepath.Join(dir, ".crabbox.yaml"))

	const (
		leaseID = "cbx_immutable_test"
		runID   = "run_immutable_test"
	)
	lease := CoordinatorLease{
		ID:         leaseID,
		Slug:       "immutable-test",
		Provider:   "run-ready-pool-preflight-test",
		Owner:      "test@example.com",
		Org:        "test",
		Class:      "standard",
		ServerType: "test",
		Host:       "127.0.0.1",
		SSHUser:    "crabbox",
		SSHPort:    sshPort,
		WorkRoot:   "/work/crabbox",
		State:      "active",
	}

	var (
		mu             sync.Mutex
		finishReceipts []terminalRunReceipt
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/control":
			http.NotFound(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/leases/"+leaseID:
			_ = json.NewEncoder(w).Encode(map[string]any{"lease": lease})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/leases/"+leaseID+"/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]any{"lease": lease})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"run": CoordinatorRun{
				ID: runID, LeaseID: leaseID, Provider: lease.Provider, State: "running",
				StartedAt: "2026-09-05T00:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/runs/"+runID+"/events":
			_ = json.NewEncoder(w).Encode(map[string]any{"event": CoordinatorRunEvent{
				RunID: runID, Seq: 1, Type: "run.event", CreatedAt: "2026-09-05T00:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/runs/"+runID+"/finish":
			var body struct {
				ExitCode int                `json:"exitCode"`
				Receipt  terminalRunReceipt `json:"receipt"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			finishReceipts = append(finishReceipts, body.Receipt)
			mu.Unlock()
			http.Error(w, "terminal store unavailable", http.StatusServiceUnavailable)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/runs/"+runID+"/receipt":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("CRABBOX_COORDINATOR", server.URL)
	t.Setenv("CRABBOX_COORDINATOR_TOKEN", "test-token")

	var stdout, stderr bytes.Buffer
	err = (App{Stdout: &stdout, Stderr: &stderr}).runCommand(context.Background(), []string{
		"--provider", "run-ready-pool-preflight-test",
		"--id", leaseID,
		"--no-sync",
		"--stop-after", "never",
		"--attest", receiptPath,
		"--attest-key", keyPath,
		"--", "true",
	})

	var exitErr ExitError
	if !AsExitError(err, &exitErr) || exitErr.Code == 0 {
		t.Fatalf("expected non-zero exit from coordinator failure, got: %v\nstderr=%s", err, stderr.String())
	}

	data, readErr := os.ReadFile(receiptPath)
	if readErr != nil {
		t.Fatalf("read receipt: %v\nstderr=%s", readErr, stderr.String())
	}
	localReceipt, decodeErr := decodeTerminalRunReceipt(data)
	if decodeErr != nil {
		t.Fatalf("decode receipt: %v", decodeErr)
	}
	if localReceipt.ExitCode != 0 {
		t.Fatalf("local receipt exit=%d, want 0 (execution outcome must be immutable)", localReceipt.ExitCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(finishReceipts) == 0 {
		t.Fatal("no finish calls received by coordinator")
	}
	for i, receipt := range finishReceipts {
		if receipt.ExitCode != 0 {
			t.Fatalf("coordinator finish attempt %d: receipt exit=%d, want 0 (immutable)", i+1, receipt.ExitCode)
		}
	}

	if !strings.Contains(stderr.String(), "coordinator commit failed") {
		t.Fatalf("expected 'coordinator commit failed' warning in stderr:\n%s", stderr.String())
	}
}

// TestBuildTerminalBundleSelfVerifiesEvidenceBinding verifies that
// BuildTerminalBundle produces a receipt whose evidence_sha256 exactly
// matches the evidence digest, and that the signature verifies.
func TestBuildTerminalBundleSelfVerifiesEvidenceBinding(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Date(2026, 1, 15, 12, 30, 0, 0, time.UTC)
	outcome := FinalRunOutcome{
		ExitCode:    0,
		RunStatus:   RunStatusSucceeded,
		Command:     []string{"npm", "test"},
		CommandText: "npm test",
		Provider:    "hetzner",
		LeaseID:     "cbx_bundle001",
		Slug:        "blue-lobster",
		RunID:       "run_bundle001",
		StartedAt:   startedAt,
		EndedAt:     startedAt.Add(5 * time.Second),
		Timing: TimingReport{
			TotalMs:   5000,
			CommandMs: 3000,
			SyncMs:    2000,
		},
	}
	bundle, err := BuildTerminalBundle(outcome, key)
	if err != nil {
		t.Fatalf("BuildTerminalBundle: %v", err)
	}
	// Evidence binding: receipt.evidence_sha256 == evidence.digest.
	if bundle.Receipt.EvidenceSHA256 != bundle.Evidence.Digest {
		t.Fatalf("evidence binding mismatch: receipt %s != evidence %s",
			bundle.Receipt.EvidenceSHA256, bundle.Evidence.Digest)
	}
	// Signature must verify.
	if err := verifyTerminalRunReceiptSignature(bundle.Receipt); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
	// Evidence digest must verify.
	if !VerifyRunEvidenceDigest(bundle.Evidence) {
		t.Fatal("evidence digest verification failed")
	}
}

// TestBuildTerminalBundleImmutRejectsNilKey verifies that BuildTerminalBundle
// fails closed when no signing key is provided.
func TestBuildTerminalBundleImmutRejectsNilKey(t *testing.T) {
	outcome := FinalRunOutcome{
		ExitCode:    0,
		RunStatus:   RunStatusSucceeded,
		Command:     []string{"echo", "hello"},
		CommandText: "echo hello",
		Provider:    "aws",
		LeaseID:     "cbx_nokey001",
		RunID:       "run_nokey001",
		StartedAt:   time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		EndedAt:     time.Date(2026, 1, 15, 12, 0, 5, 0, time.UTC),
	}
	_, err := BuildTerminalBundle(outcome, nil)
	if err == nil {
		t.Fatal("BuildTerminalBundle should fail with nil key")
	}
	if !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("expected 'signing key' error, got: %v", err)
	}
}

// TestBuildTerminalBundleSelfVerifiesLogBinding verifies that for
// non-truncated logs, the full and retained log SHA-256 digests match.
func TestBuildTerminalBundleSelfVerifiesLogBinding(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	logContent := "line1\nline2\nline3\n"
	logDigest := sha256Digest([]byte(logContent))
	outcome := FinalRunOutcome{
		ExitCode:    0,
		RunStatus:   RunStatusSucceeded,
		Command:     []string{"echo", "hello"},
		CommandText: "echo hello",
		Provider:    "gcp",
		LeaseID:     "cbx_logbind001",
		RunID:       "run_logbind001",
		StartedAt:   time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		EndedAt:     time.Date(2026, 1, 15, 12, 0, 5, 0, time.UTC),
		Timing: TimingReport{
			TotalMs:   5000,
			CommandMs: 5000,
		},
		TerminalLog: runLogSnapshot{
			Log:        logContent,
			FullSHA256: logDigest,
		},
	}
	bundle, err := BuildTerminalBundle(outcome, key)
	if err != nil {
		t.Fatalf("BuildTerminalBundle: %v", err)
	}
	// For non-truncated logs, full and retained digests must match.
	if bundle.LogSHA256 != bundle.RetainedLogSHA256 {
		t.Fatalf("log binding mismatch: full %s != retained %s",
			bundle.LogSHA256, bundle.RetainedLogSHA256)
	}
}

// TestFinalRunOutcomeFieldsNotMutatedByBundleBuild verifies that
// BuildTerminalBundle does not mutate the outcome's fields.
func TestFinalRunOutcomeFieldsNotMutatedByBundleBuild(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Date(2026, 1, 15, 12, 30, 0, 0, time.UTC)
	endedAt := startedAt.Add(5 * time.Second)
	outcome := FinalRunOutcome{
		ExitCode:    42,
		RunStatus:   RunStatusFailed,
		ErrorKind:   RunErrorCommandExit,
		Command:     []string{"go", "test"},
		CommandText: "go test",
		Provider:    "azure",
		LeaseID:     "cbx_immut001",
		Slug:        "test-slug",
		RunID:       "run_immut001",
		StartedAt:   startedAt,
		EndedAt:     endedAt,
		Timing: TimingReport{
			TotalMs:   5000,
			CommandMs: 3000,
			SyncMs:    2000,
		},
	}
	// Snapshot the outcome fields before building the bundle.
	originalExitCode := outcome.ExitCode
	originalRunStatus := outcome.RunStatus
	originalErrorKind := outcome.ErrorKind
	originalStartedAt := outcome.StartedAt
	originalEndedAt := outcome.EndedAt

	_, err = BuildTerminalBundle(outcome, key)
	if err != nil {
		t.Fatalf("BuildTerminalBundle: %v", err)
	}

	// Verify the outcome was not mutated.
	if outcome.ExitCode != originalExitCode {
		t.Fatalf("ExitCode mutated: %d != %d", outcome.ExitCode, originalExitCode)
	}
	if outcome.RunStatus != originalRunStatus {
		t.Fatalf("RunStatus mutated: %s != %s", outcome.RunStatus, originalRunStatus)
	}
	if outcome.ErrorKind != originalErrorKind {
		t.Fatalf("ErrorKind mutated: %s != %s", outcome.ErrorKind, originalErrorKind)
	}
	if !outcome.StartedAt.Equal(originalStartedAt) {
		t.Fatalf("StartedAt mutated: %s != %s", outcome.StartedAt, originalStartedAt)
	}
	if !outcome.EndedAt.Equal(originalEndedAt) {
		t.Fatalf("EndedAt mutated: %s != %s", outcome.EndedAt, originalEndedAt)
	}
}

// TestBuildTerminalBundleEvidenceBindingIsCryptographic verifies that
// the evidence_sha256 in the receipt is a SHA-256 digest, not just a
// non-empty string. This ensures the binding is cryptographically meaningful.
func TestBuildTerminalBundleEvidenceBindingIsCryptographic(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome := FinalRunOutcome{
		ExitCode:    0,
		RunStatus:   RunStatusSucceeded,
		Command:     []string{"echo", "hello"},
		CommandText: "echo hello",
		Provider:    "aws",
		LeaseID:     "cbx_crypto001",
		RunID:       "run_crypto001",
		StartedAt:   time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		EndedAt:     time.Date(2026, 1, 15, 12, 0, 5, 0, time.UTC),
	}
	bundle, err := BuildTerminalBundle(outcome, key)
	if err != nil {
		t.Fatalf("BuildTerminalBundle: %v", err)
	}
	// evidence_sha256 must be a valid 64-character hex string.
	if !validHexDigest(bundle.Receipt.EvidenceSHA256, 32) {
		t.Fatalf("evidence_sha256 is not a valid SHA-256 hex digest: %s",
			bundle.Receipt.EvidenceSHA256)
	}
	// The evidence digest must also be valid.
	if !validHexDigest(bundle.Evidence.Digest, 32) {
		t.Fatalf("evidence digest is not a valid SHA-256 hex digest: %s",
			bundle.Evidence.Digest)
	}
}
