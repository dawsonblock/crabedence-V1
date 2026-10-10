package sandboxexecutor

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// The PR-04/05/06 gates at the socket: connection floods cannot
// exceed the configured bound, shutdown drains before reporting, and
// signed contracts are mandatory once a trust set exists.

// readResp reads one bounded response line.
func readResp(t *testing.T, conn net.Conn) Response {
	t.Helper()
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := readBoundedLine(reader, maxFrameBytes)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return resp
}

func TestConnectionLimitRefusesOverflow(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), MaxConns: 3})

	// Saturate the bound with idle connections.
	held := make([]net.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("unix", srv.SocketPath())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer conn.Close()
		held = append(held, conn)
		// Let the server register the slot before the next dial.
		time.Sleep(20 * time.Millisecond)
	}

	// The next connection must be refused loudly, not queued.
	conn, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	resp := readResp(t, conn)
	if resp.OK || !strings.Contains(resp.Error, "connection limit") {
		t.Fatalf("overflow connection: %+v", resp)
	}

	// A freed slot admits the next client.
	held[0].Close()
	time.Sleep(50 * time.Millisecond)
	conn2, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	reader := bufio.NewReader(conn2)
	resp2 := sendJob(t, conn2, reader, validJob())
	if !resp2.OK {
		t.Fatalf("freed slot did not admit: %+v", resp2)
	}
}

func TestStopDrainsBeforeDone(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})

	// A live connection the handler is blocked on.
	conn, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(30 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- srv.Stop() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not drain the live connection")
	}
	// Done() fires only after Stop completed — handlers are gone.
	select {
	case <-srv.Done():
	default:
		t.Fatal("Done() did not close after Stop")
	}
}

func TestUnsignedRefusedWhenKeysConfigured(t *testing.T) {
	dir := socketDir(t)
	_, keys := testAuthority(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	conn, reader := connect(t, srv.SocketPath())

	resp := sendJob(t, conn, reader, validJob())
	if resp.OK || !strings.Contains(resp.Error, "signed job contract is required") {
		t.Fatalf("unsigned job under a trust set: %+v", resp)
	}
}

func TestSignedJobAcceptedEndToEnd(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	conn, reader := connect(t, srv.SocketPath())

	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV1) {
		c.JobID = "signed-1"
		c.Nonce = "nonce-x"
	}))
	if !resp.OK || resp.State != JobStateRecorded {
		t.Fatalf("signed job: %+v", resp)
	}
	lj, err := srv.Ledger().Get("signed-1")
	if err != nil || lj == nil {
		t.Fatalf("signed job not persisted: %v", err)
	}
	if lj.ContractHash == "" || lj.State != JobStateRecorded {
		t.Fatalf("ledger row = %+v", lj)
	}

	// Replay: the same signed envelope again — refused as duplicate
	// (job_id) or replay (contract hash); either way not re-run.
	conn2, reader2 := connect(t, srv.SocketPath())
	resp2 := sendJob(t, conn2, reader2, signedJobReq(t, key, func(c *JobContractV1) {
		c.JobID = "signed-1"
		c.Nonce = "nonce-x"
	}))
	if resp2.OK {
		t.Fatal("replayed signed job accepted")
	}
	if n, _ := srv.Ledger().Count(); n != 1 {
		t.Fatalf("registry = %d rows", n)
	}
}

func TestForgedJobRefusedEndToEnd(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	conn, reader := connect(t, srv.SocketPath())

	// Sign with the real key, then tamper argv — signature fails.
	req := signedJobReq(t, key, func(c *JobContractV1) { c.JobID = "forged-1" })
	sj := req["signed_job"].(map[string]any)
	var c JobContractV1
	if err := json.Unmarshal(sj["contract"].(json.RawMessage), &c); err != nil {
		t.Fatal(err)
	}
	c.Argv = []string{"sh", "-c", "id>/tmp/pwn"}
	raw, _ := json.Marshal(&c)
	sj["contract"] = json.RawMessage(raw)
	resp := sendJob(t, conn, reader, req)
	if resp.OK {
		t.Fatal("forged job accepted")
	}
	if n, _ := srv.Ledger().Count(); n != 0 {
		t.Fatal("forged job reached the ledger")
	}
}

func TestBackendRefusesWithoutKeys(t *testing.T) {
	if _, err := NewServer(Config{
		SocketDir: t.TempDir(),
		Peers:     selfPeer(t),
		Backend:   &stubBackend{},
	}); err == nil {
		t.Fatal("backend without authority keys must refuse startup")
	}
}

func TestCrashRecoveryAcrossRestart(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)

	srv1 := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	conn, reader := connect(t, srv1.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV1) {
		c.JobID = "durable-1"
		c.Nonce = "d-nonce"
	}))
	if !resp.OK {
		t.Fatalf("submit: %+v", resp)
	}
	// Stop cleanly — simulating restart either way: the job must
	// still exist and must not have been re-executed or forgotten.
	if err := srv1.Stop(); err != nil {
		t.Fatal(err)
	}

	srv2 := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	lj, err := srv2.Ledger().Get("durable-1")
	if err != nil || lj == nil {
		t.Fatal("acknowledged job lost across restart")
	}
	if lj.State != JobStateRecorded {
		t.Fatalf("job state after restart = %s", lj.State)
	}
	// The ledger carries a new fence epoch for the new lifetime.
	if srv2.Ledger().Epoch() <= 1 {
		t.Fatal("fence epoch did not advance")
	}
}
