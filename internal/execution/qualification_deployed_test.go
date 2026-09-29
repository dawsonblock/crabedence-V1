package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/authority"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/qualprovider"
)

// TestServeDeployedQualificationProvider exercises the deployed
// provider path end to end with no harness substitutes: a real Serve
// process, a real SQLite ledger, a real qualprovider server, a real
// Unix socket, and a real grant — the same wiring proof 09's deployed
// tier drives on staging.
func TestServeDeployedQualificationProvider(t *testing.T) {
	dir := t.TempDir()
	// The durable ledger must live under an owner-only directory.
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(stateDir, "crabedence.db")

	// Provision the grant before the service opens its own connection.
	db, err := idempotency.OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	grantStore, err := authority.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("authority store: %v", err)
	}
	grant, err := grantStore.IssueGrant(context.Background(), "qual-deployed-grant",
		"alice@example.com", []string{QualificationCapabilityID}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}
	db.Close()

	provider, err := qualprovider.New(filepath.Join(dir, "provider"), "")
	if err != nil {
		t.Fatalf("qualification provider: %v", err)
	}
	providerSrv := httptest.NewServer(provider.Handler())
	defer providerSrv.Close()

	socketPath := testSocketPath(t)
	t.Setenv("CRABEDENCE_STORE_BACKEND", "sqlite")
	t.Setenv("CRABEDENCE_STORE_PATH", dbPath)
	t.Setenv("CRABEDENCE_QUAL_PROVIDER_URL", providerSrv.URL)
	t.Setenv("CRABBOX_EVIDENCE_KEY", filepath.Join(dir, "evidence.pem"))
	t.Setenv("CRABBOX_GITHUB_ENABLED", "false")
	t.Setenv("CRABBOX_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("CRABBOX_REPLICAS", "")
	t.Setenv("CRABEDENCE_DATABASE_URL", "")
	t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "")
	t.Setenv("CRABEDENCE_PROVIDER_EXECUTION_MAX", "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ServeOptions{SocketPath: socketPath, ReconcileInterval: 1}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("serve returned an error: %v", err)
		}
	})

	// Wait for the socket to exist — the service must have passed its
	// provider-reachability gate to get this far.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("service did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial deployed service: %v", err)
	}
	defer conn.Close()
	resp := sendRequest(t, conn, Request{
		Capability:     QualificationCapabilityID,
		Arguments:      json.RawMessage(`{"operation":"deployed-smoke"}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: grant.ID},
		IdempotencyKey: "deployed-smoke-1",
	})
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED through the deployed provider path, got %s: %s", resp.Status, resp.Error)
	}
	if resp.Execution == nil || resp.Execution.Provider != QualificationAdapterID {
		t.Fatalf("expected provider=%q, got %+v", QualificationAdapterID, resp.Execution)
	}
	// CRITICAL outcome must carry a signed evidence reference.
	if resp.Evidence == nil || len(resp.Evidence.Digest) != 64 {
		t.Fatalf("expected a 64-char evidence digest, got %+v", resp.Evidence)
	}

	// The provider's own stats prove the request crossed the process
	// boundary — this was not an in-process handler.
	statsResp, err := http.Get(providerSrv.URL + "/stats")
	if err != nil {
		t.Fatalf("provider stats: %v", err)
	}
	defer statsResp.Body.Close()
	var stats struct {
		Operations int `json:"operations"`
	}
	if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
		t.Fatalf("provider stats decode: %v", err)
	}
	if stats.Operations != 1 {
		t.Fatalf("expected exactly 1 provider operation, got %d", stats.Operations)
	}
}

// TestServeRejectsUnreachableQualificationProvider proves the
// fail-closed startup gate: a configured provider that does not answer
// must not start a service that would mint unreconcilable UNKNOWNs.
func TestServeRejectsUnreachableQualificationProvider(t *testing.T) {
	t.Setenv("CRABEDENCE_STORE_BACKEND", "none")
	t.Setenv("CRABEDENCE_QUAL_PROVIDER_URL", "http://127.0.0.1:1")
	err := Serve(context.Background(), ServeOptions{SocketPath: testSocketPath(t)})
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("expected a provider-unreachable startup error, got %v", err)
	}
}

// TestServeRejectsMalformedQualificationProviderURL covers the
// configuration validation boundary.
func TestServeRejectsMalformedQualificationProviderURL(t *testing.T) {
	t.Setenv("CRABEDENCE_STORE_BACKEND", "none")
	for _, raw := range []string{"not-a-url", "ftp://example.com", "http://"} {
		t.Setenv("CRABEDENCE_QUAL_PROVIDER_URL", raw)
		err := Serve(context.Background(), ServeOptions{SocketPath: testSocketPath(t)})
		if err == nil {
			t.Fatalf("URL %q: expected startup failure", raw)
		}
	}
}

// TestServeRejectsMalformedPeerPrincipalMap proves a malformed map is a
// startup error, not a silently ignored control.
func TestServeRejectsMalformedPeerPrincipalMap(t *testing.T) {
	t.Setenv("CRABEDENCE_STORE_BACKEND", "none")
	t.Setenv("CRABEDENCE_PEER_PRINCIPALS", "not-a-uid:alice")
	err := Serve(context.Background(), ServeOptions{SocketPath: testSocketPath(t)})
	if err == nil || !strings.Contains(err.Error(), "CRABEDENCE_PEER_PRINCIPALS") {
		t.Fatalf("expected a CRABEDENCE_PEER_PRINCIPALS startup error, got %v", err)
	}
}

// TestPeerAuthDeployEndToEnd combines both new controls: peer
// authentication replaces the claimed principal, so a grant issued to
// the mapped principal resolves even if the caller claims nothing —
// while a mismatched claim is denied before admission.
func TestPeerAuthDeployEndToEnd(t *testing.T) {
	dir := t.TempDir()
	// The durable ledger must live under an owner-only directory.
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(stateDir, "crabedence.db")
	db, err := idempotency.OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	grantStore, err := authority.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("authority store: %v", err)
	}
	grant, err := grantStore.IssueGrant(context.Background(), "peer-grant",
		"alice@example.com", []string{QualificationCapabilityID}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}
	db.Close()

	provider, err := qualprovider.New(filepath.Join(dir, "provider"), "")
	if err != nil {
		t.Fatalf("qualification provider: %v", err)
	}
	providerSrv := httptest.NewServer(provider.Handler())
	defer providerSrv.Close()

	socketPath := testSocketPath(t)
	t.Setenv("CRABEDENCE_STORE_BACKEND", "sqlite")
	t.Setenv("CRABEDENCE_STORE_PATH", dbPath)
	t.Setenv("CRABEDENCE_QUAL_PROVIDER_URL", providerSrv.URL)
	t.Setenv("CRABBOX_EVIDENCE_KEY", filepath.Join(dir, "evidence.pem"))
	t.Setenv("CRABBOX_GITHUB_ENABLED", "false")
	t.Setenv("CRABBOX_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("CRABBOX_REPLICAS", "")
	t.Setenv("CRABEDENCE_DATABASE_URL", "")
	// Our own UID authenticates as alice; anything else is denied.
	t.Setenv("CRABEDENCE_PEER_PRINCIPALS", fmt.Sprintf("%d:alice@example.com", os.Getuid()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ServeOptions{SocketPath: socketPath, ReconcileInterval: 1}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("serve returned an error: %v", err)
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("service did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A claim that disagrees with the authenticated peer is denied
	// before admission — the grant is for alice, and the claim itself
	// is rejected rather than merely failing grant resolution.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	resp := sendRequest(t, conn, Request{
		Capability:     QualificationCapabilityID,
		Arguments:      json.RawMessage(`{"operation":"spoofed"}`),
		Authority:      RequestAuthority{Principal: "mallory@example.com", AuthorityRef: grant.ID},
		IdempotencyKey: "peer-spoof-1",
	})
	conn.Close()
	if resp.Status != StatusDenied {
		t.Fatalf("expected DENIED for a mismatched principal claim, got %s", resp.Status)
	}
	if !strings.Contains(resp.Error, "peer authentication") {
		t.Fatalf("expected a peer-authentication denial, got %q", resp.Error)
	}

	// The authenticated identity is server-assigned: the same request
	// with no claim at all still resolves the alice grant.
	conn, err = net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	resp = sendRequest(t, conn, Request{
		Capability:     QualificationCapabilityID,
		Arguments:      json.RawMessage(`{"operation":"authenticated"}`),
		Authority:      RequestAuthority{Principal: "", AuthorityRef: grant.ID},
		IdempotencyKey: "peer-auth-1",
	})
	conn.Close()
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED with server-assigned principal, got %s: %s", resp.Status, resp.Error)
	}
}
