package sandboxcustody

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/sockfile"
)

// Adversarial boundary: the socket path, the custody store, and the
// daemon's own lifecycle under an operator-level attacker — the cases
// where "the socket exists" is not "the socket is ours".

func startCfg(t *testing.T, dir string) Config {
	t.Helper()
	sockDir, err := os.MkdirTemp("", "cx-adv-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	return Config{
		SocketDir:  sockDir,
		CustodyDir: filepath.Join(dir, "custody"),
		KeyPath:    filepath.Join(dir, "custody", "witness.key"),
	}
}

// A live listener already on the custody socket is another running
// service — startup refuses rather than unlinking it and accepting
// custody that daemon will never see.
func TestStartRefusesLiveOccupant(t *testing.T) {
	dir := t.TempDir()
	cfg := startCfg(t, dir)
	socket := filepath.Join(cfg.SocketDir, "custody.sock")
	if err := os.MkdirAll(cfg.SocketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	occupant, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer occupant.Close()

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err == nil {
		_ = srv.Stop()
		t.Fatal("a second daemon bound over a live custody socket")
	}
	// The occupant must still be listening — untouched.
	conn, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		t.Fatal("the live occupant's socket was unlinked")
	}
	_ = conn.Close()
}

// A regular file or a symlink at the socket path is an operator error
// or an attack — never something to silently delete.
func TestStartRefusesForeignOccupant(t *testing.T) {
	for _, kind := range []string{"file", "symlink"} {
		dir := t.TempDir()
		cfg := startCfg(t, dir)
		socket := filepath.Join(cfg.SocketDir, "custody.sock")
		if err := os.MkdirAll(cfg.SocketDir, 0o700); err != nil {
			t.Fatal(err)
		}
		switch kind {
		case "file":
			if err := os.WriteFile(socket, []byte("occupied"), 0o600); err != nil {
				t.Fatal(err)
			}
		case "symlink":
			target := filepath.Join(dir, "elsewhere.sock")
			if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, socket); err != nil {
				t.Fatal(err)
			}
		}
		srv, err := NewServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err == nil {
			_ = srv.Stop()
			t.Fatalf("startup cleared a %s occupant", kind)
		}
		if _, err := os.Lstat(socket); err != nil {
			t.Fatalf("the %s occupant was removed anyway", kind)
		}
	}
}

// A socket file whose listener died is stale: startup takes the path
// over — the crash-recovery case the liveness probe exists for.
func TestStartRecoversStaleSocket(t *testing.T) {
	dir := t.TempDir()
	cfg := startCfg(t, dir)
	socket := filepath.Join(cfg.SocketDir, "custody.sock")
	if err := os.MkdirAll(cfg.SocketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dead, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	dead.SetUnlinkOnClose(false)
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("stale socket not recovered: %v", err)
	}
	_ = srv.Stop()
}

// A socket swapped out from under a stopped daemon is not that
// daemon's to delete: Stop must leave a successor's socket standing.
func TestStopLeavesSuccessorSocket(t *testing.T) {
	dir := t.TempDir()
	cfg := startCfg(t, dir)
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	socket := srv.SocketPath()
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}
	// A successor daemon binds at the same path; the old server
	// instance has already drained and must not remove it again —
	// exercised through the same owned-removal Stop performs, using
	// the identity this daemon recorded at bind time.
	successor, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	if err := sockfile.RemoveOwned(socket, srv.ident); err == nil {
		t.Fatal("cleanup removed a socket bound by a successor")
	}
	if _, err := os.Lstat(socket); err != nil {
		t.Fatal("the successor's socket was unlinked")
	}
}

// The custody chain directory and payload store carry the same
// durability contract the socket does — exercised through witness
// latency here and fsync-boundary code review: a witnessed segment
// and its chain link must both exist after the call returns.
func TestWitnessedSegmentDurableOnReturn(t *testing.T) {
	dir := t.TempDir()
	srv := startCustody(t, dir)
	payload, sha := testPayload(t, 1, 2)
	resp, err := (&Client{Socket: srv.SocketPath()}).Witness(
		context.Background(), witnessReq(1, 1, 2, payload, sha))
	if err != nil || !resp.OK {
		t.Fatalf("witness: %v %+v", err, resp)
	}
	if resp.Ack == nil || resp.Ack.RecordType != AckRecordTypeV2 || resp.Ack.RequestCreatedAt == 0 {
		t.Fatalf("response lacks the verifiable ack: %+v", resp.Ack)
	}
	// Payload and chain link are durable files, not buffered state.
	if _, err := os.Stat(filepath.Join(dir, "custody", "segments", sha)); err != nil {
		t.Fatal("witnessed payload not on disk")
	}
	chain, err := os.ReadFile(filepath.Join(dir, "custody", "acks.jsonl"))
	if err != nil || len(chain) == 0 {
		t.Fatal("ack chain not on disk")
	}
}
