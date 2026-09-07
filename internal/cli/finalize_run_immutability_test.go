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
