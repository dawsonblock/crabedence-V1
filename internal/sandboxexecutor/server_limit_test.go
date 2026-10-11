package sandboxexecutor

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
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

	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
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
	resp2 := sendJob(t, conn2, reader2, signedJobReq(t, key, func(c *JobContractV2) {
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
	req := signedJobReq(t, key, func(c *JobContractV2) { c.JobID = "forged-1" })
	sj := req["signed_job"].(map[string]any)
	var c JobContractV2
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
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
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

// One submitter identity must not hold every connection slot while
// others wait — the per-peer ceiling is lower than the global bound.
func TestPerPeerConnectionCap(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), MaxConns: maxPeerConns + 8})

	held := make([]net.Conn, 0, maxPeerConns)
	for i := 0; i < maxPeerConns; i++ {
		conn, err := net.Dial("unix", srv.SocketPath())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer conn.Close()
		held = append(held, conn)
		time.Sleep(15 * time.Millisecond) // let serve() account the peer
	}
	conn, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	resp := readResp(t, conn)
	if resp.OK || !strings.Contains(resp.Error, "too many connections") {
		t.Fatalf("peer over its cap: %+v", resp)
	}
	// The refusal freed nothing — the server is still inside its
	// global bound, so a released peer slot admits again.
	held[0].Close()
	time.Sleep(50 * time.Millisecond)
	conn2, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	reader := bufio.NewReader(conn2)
	if resp := sendJob(t, conn2, reader, validJob()); !resp.OK {
		t.Fatalf("freed peer slot did not admit: %+v", resp)
	}
}

// A persistent client is not one-shot: the admission loop must keep
// serving further jobs on the same connection.
func TestPipelinedJobsShareOneConnection(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	conn, reader := connect(t, srv.SocketPath())
	defer conn.Close()

	for i, jobID := range []string{"pipe-1", "pipe-2"} {
		resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
			c.JobID, c.Nonce = jobID, jobID
		}))
		if !resp.OK || resp.JobID != jobID {
			t.Fatalf("pipelined job %d: %+v", i, resp)
		}
	}
	if n, _ := srv.Ledger().Count(); n != 2 {
		t.Fatalf("registry = %d rows, want 2", n)
	}
}

// The registry bound is durable: once the ledger holds maxJobs
// records, admission refuses before any new identity can be created.
func TestJobRegistryBound(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})

	// Fill the registry directly — InsertJob's contract-hash
	// uniqueness is orthogonal to what the bound checks.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "executor-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().UnixMilli()
	for i := 0; i < maxJobs; i++ {
		if _, err := db.Exec(
			`INSERT INTO jobs (job_id, contract_hash, seq, submitter, principal, image,
			 contract_json, state, fence_epoch, received_at, updated_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			fmt.Sprintf("fill-%d", i), fmt.Sprintf("h%d", i), i+1, "t", "p", "img",
			"{}", JobStateRecorded, 1, now, now); err != nil {
			t.Fatalf("fill row %d: %v", i, err)
		}
	}
	db.Close()

	conn, reader := connect(t, srv.SocketPath())
	defer conn.Close()
	resp := sendJob(t, conn, reader, validJob())
	if resp.OK || !strings.Contains(resp.Error, "registry full") {
		t.Fatalf("over-full registry admitted: %+v", resp)
	}
}

// A signed contract replayed across a daemon restart must refuse —
// replay protection is durable, not per-lifetime.
func TestReplayAcrossRestart(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)

	srv1 := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	conn, reader := connect(t, srv1.SocketPath())
	env := signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "replay-1", "replay-nonce"
	})
	if resp := sendJob(t, conn, reader, env); !resp.OK {
		t.Fatalf("submit: %+v", resp)
	}
	conn.Close()
	if err := srv1.Stop(); err != nil {
		t.Fatal(err)
	}

	srv2 := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys})
	conn2, reader2 := connect(t, srv2.SocketPath())
	defer conn2.Close()
	resp := sendJob(t, conn2, reader2, env)
	if resp.OK || !strings.Contains(resp.Error, "already submitted") {
		t.Fatalf("replayed contract admitted after restart: %+v", resp)
	}
}

// An interrupted or ambiguous job from a previous lifetime must
// surface in the audit log at startup — the operator learns a handle
// may still be live instead of discovering it manually.
func TestReconcileInspectsUnresolvedHandles(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)

	// First lifetime: job reaches RUNNING, then the daemon stops —
	// INTERRUPTED with a live-looking handle behind it.
	be1 := &stubBackend{handle: "vm-orphan", wait: make(chan *ExecResult)}
	srv1 := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be1})
	conn, reader := connect(t, srv1.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "orphan-1", "orphan-n"
	}))
	conn.Close()
	if resp.State != JobStateRunning {
		t.Fatalf("dispatch state = %s", resp.State)
	}
	srv1.Stop()

	// Second lifetime: the audit sink must capture the reconcile
	// line reporting the handle as STILL RUNNING.
	audits := make(chan string, 64)
	sink := func(format string, args ...any) { audits <- fmt.Sprintf(format, args...) }
	be2 := &stubBackend{live: true}
	srv2 := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be2, Audit: sink,
	})
	defer srv2.Stop()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case line := <-audits:
			if strings.Contains(line, "orphan-1") && strings.Contains(line, "STILL RUNNING") {
				return
			}
		case <-deadline:
			t.Fatal("reconcile never surfaced the orphaned handle")
		}
	}
}

// The operator ceiling is a hard bound on the authority's grant: a
// validly-signed contract asking for more than the ceiling refuses.
func TestCeilingRefusesOverBudgetContract(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		ResourceCeiling: &ResourceBudget{CPUs: 2, MemoryMB: 512, DiskMB: 2048, MaxOutputBytes: 8192, TimeoutSeconds: 60},
	})

	for name, mutate := range map[string]func(*JobContractV2){
		"cpus":   func(c *JobContractV2) { c.Resources.CPUs = 8 },
		"memory": func(c *JobContractV2) { c.Resources.MemoryMB = 1024 },
		"disk":   func(c *JobContractV2) { c.Resources.DiskMB = 4096 },
		"output": func(c *JobContractV2) { c.Resources.MaxOutputBytes = 16384 },
		"ttl":    func(c *JobContractV2) { c.Resources.TimeoutSeconds = 600 },
	} {
		t.Run(name, func(t *testing.T) {
			// A refusal ends the connection — each case gets its own.
			conn, reader := connect(t, srv.SocketPath())
			defer conn.Close()
			resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
				c.JobID, c.Nonce = "ceil-"+name, "ceil-n-"+name
				mutate(c)
			}))
			if resp.OK || !strings.Contains(resp.Error, "ceiling") {
				t.Fatalf("over-ceiling %s admitted: %+v", name, resp)
			}
		})
	}
}
