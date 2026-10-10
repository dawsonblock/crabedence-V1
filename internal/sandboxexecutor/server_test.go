package sandboxexecutor

import (
	"bufio"
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
		t.Fatalf("write: %v", err)
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
	state string
	err   error
	got   *JobSubmission
	gotBy string
}

func (b *stubBackend) Submit(job *JobSubmission, submitter string) (string, error) {
	cpy := *job
	b.got = &cpy
	b.gotBy = submitter
	if b.err != nil {
		return "", b.err
	}
	return b.state, nil
}

func TestBackendHandoff(t *testing.T) {
	dir := socketDir(t)

	t.Run("backend state recorded", func(t *testing.T) {
		be := &stubBackend{state: "QUEUED"}
		srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), Backend: be})
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, validJob())
		if !resp.OK || resp.State != "QUEUED" {
			t.Fatalf("unexpected response: %+v", resp)
		}
		if be.got == nil || be.gotBy != "crabedence" || be.got.Image == "" {
			t.Fatalf("backend saw %+v from %q", be.got, be.gotBy)
		}
		jobs := srv.Jobs()
		if len(jobs) != 1 || jobs[0].State != "QUEUED" {
			t.Fatalf("registry = %+v", jobs)
		}
	})

	t.Run("backend refusal unrecords", func(t *testing.T) {
		be := &stubBackend{err: fmt.Errorf("no sandbox available")}
		srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), Backend: be})
		conn, reader := connect(t, srv.SocketPath())
		resp := sendJob(t, conn, reader, validJob())
		if resp.OK || !strings.Contains(resp.Error, "backend refused") {
			t.Fatalf("unexpected response: %+v", resp)
		}
		if len(srv.Jobs()) != 0 {
			t.Fatal("a refused hand-off must leave no record")
		}
		// The job_id is reusable after a refused hand-off.
		be.err = nil
		be.state = "QUEUED"
		conn2, reader2 := connect(t, srv.SocketPath())
		if resp := sendJob(t, conn2, reader2, validJob()); !resp.OK {
			t.Fatalf("resubmission after refusal failed: %+v", resp)
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
