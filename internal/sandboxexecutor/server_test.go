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
	handle string
	err    error
	got    *JobContractV1
	wait   chan *ExecResult
	werr   error
	live   bool
}

func (b *stubBackend) Dispatch(ctx context.Context, job *JobContractV1) (string, error) {
	cpy := *job
	b.got = &cpy
	if b.err != nil {
		// Ambiguous dispatches return the handle too — the caller
		// must record where the job may already be live.
		return b.handle, b.err
	}
	if b.handle == "" {
		return "stub-handle", nil
	}
	return b.handle, nil
}

func (b *stubBackend) Wait(ctx context.Context, handle string) (*ExecResult, error) {
	if b.wait != nil {
		select {
		case res := <-b.wait:
			return res, b.werr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &ExecResult{ExitCode: 0, FinishedAt: time.Now().UTC()}, b.werr
}

func (b *stubBackend) Inspect(ctx context.Context, handle string) (bool, error) {
	return b.live, nil
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

func signedJobReq(t *testing.T, key ed25519.PrivateKey, mutate func(*JobContractV1)) map[string]any {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now().UTC()
	c := &JobContractV1{
		Version:   ContractVersion,
		JobID:     "job-1",
		Principal: "alice",
		Image:     "python:3.12@sha256:abc",
		Argv:      []string{"python3", "-c", "print(1)"},
		Resources: ResourceBudget{TimeoutSeconds: 60},
		Network:   NetworkPolicy{Mode: NetworkNone},
		IssuedAt:  now.Unix() - 5,
		ExpiresAt: now.Unix() + 300,
		Nonce:     "nonce-1",
		Authority: AuthorityFingerprint(pub),
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
		resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV1) { c.JobID = "job-run"; c.Nonce = "n-run" }))
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
		resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV1) { c.JobID = "job-fail"; c.Nonce = "n-fail" }))
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
		resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV1) { c.JobID = "job-ambig"; c.Nonce = "n-ambig" }))
		if resp.OK || resp.State != JobStateDispatchAmbig {
			t.Fatalf("unexpected response: %+v", resp)
		}
		lj, _ := srv.Ledger().Get("job-ambig")
		if lj == nil || lj.BackendHandle != "vm-maybe" {
			t.Fatalf("ambiguous job lost its handle: %+v", lj)
		}
	})
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
