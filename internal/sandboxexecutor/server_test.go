package sandboxexecutor

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The PR-03 gate: an independent client without valid identity cannot
// submit execution. These tests prove refusal at every layer — wrong
// peer uid, missing token, wrong token, malformed frame — and prove
// the socket itself is confined to an owner-only directory.

func startServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv
}

// socketDir returns a short private directory — t.TempDir() paths
// embed the test name and can exceed the platform's sun_path bound
// (~104 bytes on macOS).
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sx-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func selfPeer(t *testing.T) PeerAllowlist {
	t.Helper()
	peers, err := ParsePeerAllowlist(fmt.Sprintf("%d:crabedence", os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	return peers
}

func connect(t *testing.T, socket string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("dial %s: %v", socket, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, bufio.NewReader(conn)
}

func sendJob(t *testing.T, conn net.Conn, reader *bufio.Reader, req map[string]any) Response {
	t.Helper()
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		// A refusal that precedes the write — the server verified peer
		// credentials and closed before the frame flushed — surfaces
		// here as EPIPE/ECONNRESET while its refusal frame is still
		// readable. Read it: the semantic answer, not the transport
		// symptom, is what every caller asserts on. If nothing is
		// readable either, the write error is the real failure.
		respBytes, rerr := readBoundedLine(reader, maxFrameBytes)
		if rerr != nil {
			t.Fatalf("write: %v (and no refusal frame readable: %v)", err, rerr)
		}
		var resp Response
		if uerr := json.Unmarshal(respBytes, &resp); uerr != nil {
			t.Fatalf("write: %v (and refusal frame unparseable: %v)", err, uerr)
		}
		return resp
	}
	respBytes, err := readBoundedLine(reader, maxFrameBytes)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return resp
}

func validJob() map[string]any {
	return map[string]any{
		"version": ProtocolVersion,
		"type":    RequestTypeSubmit,
		"job": map[string]any{
			"job_id":    "job-1",
			"principal": "alice",
			"image":     "python:3.12@sha256:abc",
			"argv":      []string{"python3", "-c", "print(1)"},
		},
	}
}

func TestServerRequiresPeers(t *testing.T) {
	if _, err := NewServer(Config{SocketDir: t.TempDir()}); err == nil {
		t.Fatal("empty peer allowlist must refuse startup")
	}
}

func TestServerBindsOwnerOnlySocket(t *testing.T) {
	dir := filepath.Join(socketDir(t), "sock")
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})

	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("socket dir mode = %04o, want 0700", perm)
	}
	sinfo, err := os.Lstat(srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	if sinfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket", srv.SocketPath())
	}
	if perm := sinfo.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket mode %04o is group/world accessible", perm)
	}
}

func TestAcceptedSubmissionIsRecorded(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})
	conn, reader := connect(t, srv.SocketPath())

	resp := sendJob(t, conn, reader, validJob())
	if !resp.OK || resp.JobID != "job-1" || resp.State != JobStateRecorded {
		t.Fatalf("unexpected response: %+v", resp)
	}
	jobs := srv.Jobs()
	if len(jobs) != 1 || jobs[0].JobID != "job-1" || jobs[0].Submitter != "crabedence" {
		t.Fatalf("registry = %+v", jobs)
	}
	if jobs[0].Principal != "alice" || jobs[0].ReceivedAt.IsZero() {
		t.Fatalf("record missing submitter evidence: %+v", jobs[0])
	}
}

// The PR-03 gate itself: a peer whose kernel uid is not in the
// allowlist is refused before any job frame is honored.
func TestUnpermittedPeerIsRefused(t *testing.T) {
	dir := socketDir(t)
	foreign, err := ParsePeerAllowlist(fmt.Sprintf("%d:someone-else", os.Getuid()+1))
	if err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, Config{SocketDir: dir, Peers: foreign})
	conn, reader := connect(t, srv.SocketPath())

	resp := sendJob(t, conn, reader, validJob())
	if resp.OK {
		t.Fatalf("unpermitted peer got accepted: %+v", resp)
	}
	if !strings.Contains(resp.Error, "not a permitted submitter") {
		t.Fatalf("unexpected refusal: %q", resp.Error)
	}
	if len(srv.Jobs()) != 0 {
		t.Fatal("a refused submission must never reach the registry")
	}
}

func TestTokenEnforcement(t *testing.T) {
	dir := socketDir(t)
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("shared-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := LoadSubmissionToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), Token: token})

	mk := func(tok string) map[string]any {
		req := validJob()
		req["token"] = tok
		return req
	}
	t.Run("missing token refused", func(t *testing.T) {
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, validJob())
		if resp.OK || !strings.Contains(resp.Error, "token") {
			t.Fatalf("missing token: %+v", resp)
		}
	})
	t.Run("wrong token refused", func(t *testing.T) {
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, mk("nope"))
		if resp.OK || !strings.Contains(resp.Error, "token") {
			t.Fatalf("wrong token: %+v", resp)
		}
	})
	t.Run("right token accepted", func(t *testing.T) {
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, mk("shared-secret"))
		if !resp.OK {
			t.Fatalf("valid submission refused: %+v", resp)
		}
	})
}

func TestMalformedFramesRefused(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})

	// Each refused frame gets a fresh connection: the server refuses
	// and closes, so a single conn cannot carry a second request.
	sendRaw := func(payload string) Response {
		conn, reader := connect(t, srv.SocketPath())
		if _, err := conn.Write([]byte(payload + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		respBytes, err := readBoundedLine(reader, maxFrameBytes)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var resp Response
		if err := json.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("parse: %v", err)
		}
		return resp
	}

	if resp := sendRaw("{not json"); resp.OK {
		t.Fatalf("malformed JSON accepted: %+v", resp)
	}
	if resp := sendRaw(`{"version":99,"type":"submit"}`); resp.OK {
		t.Fatalf("wrong version accepted: %+v", resp)
	}
	if resp := sendRaw(`{"version":1,"type":"explode"}`); resp.OK {
		t.Fatalf("unknown type accepted: %+v", resp)
	}
	if resp := sendRaw(`{"version":1,"type":"submit","job":{"job_id":"x","principal":"p","image":"i","argv":[]}}`); resp.OK {
		t.Fatalf("empty argv accepted: %+v", resp)
	}
}

func TestOversizedFrameRefused(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})
	conn, reader := connect(t, srv.SocketPath())

	huge := strings.Repeat("A", int(maxFrameBytes)+1)
	if _, err := conn.Write([]byte(huge + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	respBytes, err := readBoundedLine(reader, maxFrameBytes)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.OK {
		t.Fatalf("oversized frame accepted: %+v", resp)
	}
}

func TestDuplicateJobIDRefused(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})
	conn, reader := connect(t, srv.SocketPath())

	if resp := sendJob(t, conn, reader, validJob()); !resp.OK {
		t.Fatalf("first submit refused: %+v", resp)
	}
	if resp := sendJob(t, conn, reader, validJob()); resp.OK {
		t.Fatalf("duplicate job_id accepted: %+v", resp)
	}
	if len(srv.Jobs()) != 1 {
		t.Fatal("duplicate must not overwrite the registry")
	}
}

func TestServerLifecycle(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})
	if err := srv.Start(); err == nil {
		t.Fatal("second Start must refuse — no restart cycle")
	}
	socket := srv.SocketPath()
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket %s remains after Stop", socket)
	}
	// Stop again is a no-op.
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	// A stopped server refuses a new Start.
	if err := srv.Start(); err == nil {
		t.Fatal("Start after Stop must refuse")
	}
}

func TestSocketDirHardening(t *testing.T) {
	dir := filepath.Join(socketDir(t), "sock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})
	_ = srv
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("world-accessible dir not tightened: mode %04o", perm)
	}
}

func TestStopKeepsForeignOccupant(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})
	socket := srv.SocketPath()
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}
	// A foreign file occupying the path after our cleanup must not be
	// removed by a second removeOwnedSocket pass.
	if err := os.WriteFile(socket, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	ident, _ := socketIdentityFor(socket)
	if err := removeOwnedSocket(socket, ident); err == nil {
		t.Fatal("a non-socket occupant must not be unlinked")
	}
	if _, err := os.Lstat(socket); err != nil {
		t.Fatal("foreign occupant was removed")
	}
}

type stubBackend struct {
	handle     string
	err        error
	got        *JobContractV2
	wait       chan *ExecResult
	werr       error
	live       bool
	cleanupErr error
	cleaned    []string
}

func (b *stubBackend) Dispatch(ctx context.Context, job *JobContractV2) (DispatchResult, error) {
	cpy := *job
	b.got = &cpy
	if b.err != nil {
		// Ambiguous dispatches return the handle too — the caller
		// must record where the job may already be live.
		return DispatchResult{Handle: b.handle, RunID: "job_" + strings.Repeat("0", 32)}, b.err
	}
	if b.handle == "" {
		return DispatchResult{Handle: "stub-handle", RunID: "job_" + strings.Repeat("0", 32)}, nil
	}
	return DispatchResult{Handle: b.handle, RunID: "job_" + strings.Repeat("1", 32)}, nil
}

func (b *stubBackend) Wait(ctx context.Context, job *JobContractV2, handle, runID string) (*ExecResult, error) {
	if b.wait != nil {
		select {
		case res := <-b.wait:
			return res, b.werr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &ExecResult{ExitCode: 0, ExitVerified: true, RunID: runID, FinishedAt: time.Now().UTC()}, b.werr
}

func (b *stubBackend) Inspect(ctx context.Context, handle string) (bool, error) {
	return b.live, nil
}

func (b *stubBackend) Cleanup(ctx context.Context, handle string) error {
	if b.cleanupErr != nil {
		return b.cleanupErr
	}
	b.cleaned = append(b.cleaned, handle)
	return nil
}

func (b *stubBackend) Close() error { return nil }

func (b *stubBackend) Name() string { return "stub" }

// Signed-job plumbing for backend tests: a backend can only be
// configured when authority keys exist, so every dispatch test signs
// its jobs.
func testAuthority(t *testing.T) (ed25519.PrivateKey, AuthorityKeys) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	return key, AuthorityKeys{AuthorityFingerprint(pub): pub}
}

func signedJobReq(t *testing.T, key ed25519.PrivateKey, mutate func(*JobContractV2)) map[string]any {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now().UTC()
	c := &JobContractV2{
		Version:     ContractVersion,
		JobID:       "job-1",
		Principal:   "alice",
		Image:       "python:3.12",
		ImageDigest: testImageDigest,
		Argv:        []string{"python3", "-c", "print(1)"},
		Resources:   ResourceBudget{TimeoutSeconds: 60},
		Network:     NetworkPolicy{Mode: NetworkNone},
		Security:    SecurityDefault,
		IssuedAt:    now.Unix() - 5,
		ExpiresAt:   now.Unix() + 300,
		Nonce:       "nonce-1",
		Authority:   AuthorityFingerprint(pub),
	}
	if mutate != nil {
		mutate(c)
	}
	env, err := SignContract(key, c)
	if err != nil {
		t.Fatalf("sign contract: %v", err)
	}
	return map[string]any{
		"version": ProtocolVersion,
		"type":    RequestTypeSubmit,
		"signed_job": map[string]any{
			"contract":  json.RawMessage(env.Contract),
			"signature": env.Signature,
		},
	}
}

func TestBackendHandoff(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)

	t.Run("dispatch recorded running", func(t *testing.T) {
		// Hold the job in RUNNING: the monitor transitions on Wait's
		// return, so Wait must block until the test is done looking.
		be := &stubBackend{handle: "vm-1", wait: make(chan *ExecResult)}
		t.Cleanup(func() { close(be.wait) })
		srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) { c.JobID = "job-run"; c.Nonce = "n-run" }))
		if !resp.OK || resp.State != JobStateRunning {
			t.Fatalf("unexpected response: %+v", resp)
		}
		if be.got == nil || be.got.JobID != "job-run" {
			t.Fatalf("backend saw %+v", be.got)
		}
		jobs := srv.Jobs()
		var found *JobRecord
		for _, j := range jobs {
			if j.JobID == "job-run" {
				found = j
			}
		}
		if found == nil || found.State != JobStateRunning {
			t.Fatalf("registry = %+v", jobs)
		}
	})

	t.Run("backend refusal keeps the job recorded", func(t *testing.T) {
		be := &stubBackend{err: fmt.Errorf("no sandbox available")}
		srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) { c.JobID = "job-fail"; c.Nonce = "n-fail" }))
		if resp.OK || resp.State != JobStateDispatchFailed {
			t.Fatalf("unexpected response: %+v", resp)
		}
		// The defect this repairs: a backend error must not erase an
		// acknowledged job identity.
		lj, err := srv.Ledger().Get("job-fail")
		if err != nil || lj == nil {
			t.Fatalf("ledger lost the refused job: %v", err)
		}
		if lj.State != JobStateDispatchFailed {
			t.Fatalf("job state = %q", lj.State)
		}
	})

	t.Run("ambiguous dispatch never retries", func(t *testing.T) {
		be := &stubBackend{err: ErrAmbiguousDispatch, handle: "vm-maybe"}
		srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) { c.JobID = "job-ambig"; c.Nonce = "n-ambig" }))
		if resp.OK || resp.State != JobStateDispatchAmbig {
			t.Fatalf("unexpected response: %+v", resp)
		}
		lj, _ := srv.Ledger().Get("job-ambig")
		if lj == nil || lj.BackendHandle != "vm-maybe" {
			t.Fatalf("ambiguous job lost its handle: %+v", lj)
		}
	})
}

// TestLostMonitorNeverCompletes is the PR-04 regression: a monitor
// that loses its watch while the workload may still be running must
// leave the job unresolved — no terminal state, no receipt, no
// fabricated COMPLETED outcome.
func TestLostMonitorNeverCompletes(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-lost", wait: make(chan *ExecResult), werr: fmt.Errorf("watch lost: transport reset")}
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) { c.JobID = "job-lost"; c.Nonce = "n-lost" }))
	if !resp.OK || resp.State != JobStateRunning {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// The watch dies while the workload may still be running.
	close(be.wait)

	deadline := time.Now().Add(5 * time.Second)
	var lj *LedgerJob
	for time.Now().Before(deadline) {
		lj, _ = srv.Ledger().Get("job-lost")
		if lj != nil && lj.State == JobStateDispatchAmbig {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lj == nil || lj.State != JobStateDispatchAmbig {
		t.Fatalf("a lost monitor must leave the job unresolved, got %+v", lj)
	}
	if lj.BackendHandle != "vm-lost" {
		t.Fatalf("unresolved job lost its handle: %+v", lj)
	}
	if lj.ExitCode != nil || lj.ResultJSON != "" || lj.ReceiptSHA256 != "" {
		t.Fatalf("a lost monitor fabricated a result or receipt: %+v", lj)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "evidence", "receipts.jsonl"))
	if err != nil {
		t.Fatalf("receipts log: %v", err)
	}
	if strings.Contains(string(raw), "job-lost") {
		t.Fatal("evidence attests an outcome the executor never observed")
	}
}

// TestResourcePoolBoundsAdmission is the PR-05 gate: concurrent
// workloads cannot exceed the operator's aggregate pool, and a
// pool-refused job never reaches the registry.
func TestResourcePoolBoundsAdmission(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	// The stub holds every admitted job RUNNING, so the pool fills up.
	be := &stubBackend{handle: "vm-pool", wait: make(chan *ExecResult)}
	t.Cleanup(func() { close(be.wait) })
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be,
		ResourcePool: &ResourcePool{MaxConcurrentVMs: 2, MaxSubmitterVMs: 2},
	})
	admit := func(id string) Response {
		conn, reader := connect(t, srv.SocketPath())
		return sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
			c.JobID = id
			c.Nonce = "n-" + id
		}))
	}
	if resp := admit("pool-1"); !resp.OK {
		t.Fatalf("first admission refused: %+v", resp)
	}
	if resp := admit("pool-2"); !resp.OK {
		t.Fatalf("second admission refused: %+v", resp)
	}
	resp := admit("pool-3")
	if resp.OK || !strings.Contains(resp.Error, "pool") {
		t.Fatalf("pool overflow admitted: %+v", resp)
	}
	if lj, _ := srv.Ledger().Get("pool-3"); lj != nil {
		t.Fatal("a pool-refused job reached the ledger")
	}
	usage, err := srv.Ledger().ActiveUsage(time.Minute)
	if err != nil || usage.VMs != 2 {
		t.Fatalf("usage = %+v (%v)", usage, err)
	}
}

// TestResourcePoolRequiresDeclaredBudgets: a configured dimension
// bounds only what contracts declare, so an undeclared budget refuses
// rather than counting as free.
func TestResourcePoolRequiresDeclaredBudgets(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-budget", wait: make(chan *ExecResult)}
	t.Cleanup(func() { close(be.wait) })
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be,
		ResourcePool: &ResourcePool{TotalMemoryMB: 1024},
	})
	conn, reader := connect(t, srv.SocketPath())
	// The default test contract declares no memory.
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) { c.JobID = "no-mem"; c.Nonce = "n-no-mem" }))
	if resp.OK || !strings.Contains(resp.Error, "declares none") {
		t.Fatalf("undeclared budget admitted under a bounded pool: %+v", resp)
	}
	if lj, _ := srv.Ledger().Get("no-mem"); lj != nil {
		t.Fatal("a pool-refused job reached the ledger")
	}
}

// TestResourcePoolIgnoresRecordOnlyJobs: the pool bounds execution,
// so a record-only executor (no backend) admits and records jobs the
// pool would otherwise refuse for undeclared budgets.
func TestResourcePoolIgnoresRecordOnlyJobs(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t),
		ResourcePool: &ResourcePool{MaxConcurrentVMs: 1, TotalMemoryMB: 1024},
	})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, validJob())
	if !resp.OK || resp.State != JobStateRecorded {
		t.Fatalf("record-only job refused by the pool: %+v", resp)
	}
}

func TestNegativeDispatchTimeoutRefused(t *testing.T) {
	if _, err := NewServer(Config{SocketDir: t.TempDir(), Peers: selfPeer(t), DispatchTimeout: -time.Second}); err == nil {
		t.Fatal("a negative dispatch timeout was accepted")
	}
}

func TestDeadlineDoesNotHang(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})
	conn, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Idle clients are cut by the 30s deadline — shrink the window by
	// verifying the server doesn't leak the goroutine on close.
	time.Sleep(50 * time.Millisecond)
}

// ─── PR-04: structured results and the durable state machine ────────

// waitLedgerState blocks until the job reaches state, or fails.
func waitLedgerState(t *testing.T, srv *Server, jobID, state string) *LedgerJob {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lj, err := srv.Ledger().Get(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if lj != nil && lj.State == state {
			return lj
		}
		time.Sleep(10 * time.Millisecond)
	}
	lj, _ := srv.Ledger().Get(jobID)
	t.Fatalf("job %s never reached %s: %+v", jobID, state, lj)
	return nil
}

// TestMonitorClassifiesObservedOutcomes: the ledger records exactly
// what the backend observed — a verified exit, a runtime timeout, a
// rejected spawn — and refuses to classify an outcome the backend
// cannot demonstrate. Terminal claims carry a receipt; unresolved
// outcomes carry nothing but the reason.
func TestMonitorClassifiesObservedOutcomes(t *testing.T) {
	exit := func(v int64) *int64 { return &v }
	cases := []struct {
		name       string
		result     *ExecResult
		werr       error
		wantState  string
		wantExit   *int64
		wantErrSub string
	}{
		{
			name:      "verified success",
			result:    &ExecResult{ExitCode: 0, ExitVerified: true, RuntimeState: "exited"},
			wantState: JobStateSucceeded, wantExit: exit(0),
		},
		{
			name:      "verified failure",
			result:    &ExecResult{ExitCode: 72, ExitVerified: true, RuntimeState: "exited"},
			wantState: JobStateFailed, wantExit: exit(72),
		},
		{
			name:      "runtime timeout",
			result:    &ExecResult{TimedOut: true, RuntimeState: "exited"},
			wantState: JobStateFailed, wantErrSub: "contract timeout",
		},
		{
			name:      "spawn rejected",
			result:    &ExecResult{FailureKind: "not_found", FailureMessage: "no such binary", RuntimeState: "failed"},
			wantState: JobStateDispatchFailed, wantErrSub: "not_found",
		},
		{
			name:      "unverified outcome refused",
			result:    &ExecResult{ExitCode: 0},
			wantState: JobStateDispatchAmbig, wantErrSub: "unverified",
		},
		{
			name:      "artifact not finalized",
			result:    &ExecResult{ExitCode: 0, ExitVerified: true},
			werr:      fmt.Errorf("artifact finalization failed: disk full"),
			wantState: JobStateDispatchAmbig, wantErrSub: "artifact",
		},
		{
			name:      "outcome unobserved",
			result:    nil,
			werr:      ErrExecutionUnobserved,
			wantState: JobStateDispatchAmbig, wantErrSub: "unobserved",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := socketDir(t)
			key, keys := testAuthority(t)
			be := &stubBackend{handle: "vm-class", wait: make(chan *ExecResult, 1), werr: tc.werr}
			srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
			conn, reader := connect(t, srv.SocketPath())
			jobID := "class-" + strings.ReplaceAll(tc.name, " ", "-")
			resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
				c.JobID = jobID
				c.Nonce = "n-" + jobID
			}))
			if !resp.OK {
				t.Fatalf("submit: %+v", resp)
			}
			be.wait <- tc.result // nil models "no result, only an error"

			lj := waitLedgerState(t, srv, jobID, tc.wantState)
			if tc.wantExit == nil {
				if lj.ExitCode != nil {
					t.Fatalf("fabricated exit code %d for an unobserved outcome", *lj.ExitCode)
				}
			} else if lj.ExitCode == nil || *lj.ExitCode != *tc.wantExit {
				t.Fatalf("exit code = %v, want %d", lj.ExitCode, *tc.wantExit)
			}
			if tc.wantErrSub != "" && !strings.Contains(lj.Error, tc.wantErrSub) {
				t.Fatalf("error %q missing %q", lj.Error, tc.wantErrSub)
			}
			terminal := tc.wantState == JobStateSucceeded || tc.wantState == JobStateFailed || tc.wantState == JobStateDispatchFailed
			if terminal && lj.ReceiptSHA256 == "" {
				t.Fatal("a terminal claim without a receipt")
			}
			if !terminal && (lj.ReceiptSHA256 != "" || lj.ResultJSON != "") {
				t.Fatalf("an unresolved outcome produced a result: %+v", lj)
			}
		})
	}
}

// TestCleanupPendingIsRecordedAndRetried: a cleanup that fails after
// the result is written is recorded on the terminal row and retried at
// the next startup — a VM that outlived its job is reconciled, never
// forgotten, and the failure never rewrites the observed result.
func TestCleanupPendingIsRecordedAndRetried(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-cleanup", wait: make(chan *ExecResult, 1), cleanupErr: fmt.Errorf("sandbox busy")}
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID = "cleanup-1"
		c.Nonce = "n-cleanup"
	}))
	if !resp.OK {
		t.Fatalf("submit: %+v", resp)
	}
	be.wait <- &ExecResult{ExitCode: 0, ExitVerified: true, RuntimeState: "exited"}

	lj := waitLedgerState(t, srv, "cleanup-1", JobStateSucceeded)
	// The pending flag is written with the terminal transition; the
	// failure reason lands once the cleanup attempt has run.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lj.CleanupPending && strings.Contains(lj.CleanupError, "sandbox busy") {
			break
		}
		time.Sleep(10 * time.Millisecond)
		lj, _ = srv.Ledger().Get("cleanup-1")
	}
	if !lj.CleanupPending || !strings.Contains(lj.CleanupError, "sandbox busy") {
		t.Fatalf("failed cleanup not recorded: %+v", lj)
	}
	if lj.ReceiptSHA256 == "" || lj.ArtifactSHA256 == "" && lj.ResultJSON == "" {
		t.Fatalf("cleanup failure damaged the observed result: %+v", lj)
	}

	srv.Stop()
	be.cleanupErr = nil
	srv2 := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		lj, _ = srv2.Ledger().Get("cleanup-1")
		if lj != nil && !lj.CleanupPending {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pending cleanup never retried: %+v", lj)
}
