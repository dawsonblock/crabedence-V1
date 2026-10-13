package sandboxexecutor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDaemonCrashPreservesAcknowledgedJobs is the PR-06 crash-
// consistency qualification. The real daemon is SIGKILLed mid-job — no
// shutdown path runs, no buffer is flushed, no defer executes — and the
// durable records must still say exactly what was true:
//
//   - the acknowledged job survives in the ledger, with the dispatch
//     authorization that was written before the VM existed;
//   - the dispatch was not duplicated: the runtime's own records hold
//     exactly one job for the contract;
//   - the outcome is unresolved — a crash is never a fabricated result;
//   - the next lifetime recovers the run from the runtime's own record
//     and settles it there, without launching anything.
func TestDaemonCrashPreservesAcknowledgedJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and SIGKILLs the daemon")
	}
	dir := socketDir(t)
	daemon := filepath.Join(dir, "sandbox-executord")
	build := exec.Command("go", "build", "-o", daemon, "github.com/openclaw/crabbox/cmd/sandbox-executord")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build the daemon (%v): %s", err, out)
	}

	// The fake runtime the daemon will qualify and use: this test
	// binary acting as msb, a firmware file, and the manifest that pins
	// both. The job it launches stays "running" for a very long time —
	// the crash must find real work in flight.
	bin := os.Args[0]
	fakeState := filepath.Join(dir, "fake-msb")
	if err := os.MkdirAll(fakeState, 0o700); err != nil {
		t.Fatal(err)
	}
	firmware := filepath.Join(dir, "lib", "libkrunfw.dylib")
	if err := os.MkdirAll(filepath.Dir(firmware), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firmware, []byte("fake firmware bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "runtime-manifest.json")
	manifest := RuntimeManifest{
		Version:         PinnedMSBVersion,
		MSBSHA256:       sha256File(t, bin),
		LibkrunfwSHA256: sha256File(t, firmware),
	}
	rawManifest, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, rawManifest, 0o600); err != nil {
		t.Fatal(err)
	}

	key, keys := testAuthority(t)
	keyFile := filepath.Join(dir, "authority.pubkeys")
	lines := make([]string, 0, len(keys))
	for fp, pub := range keys {
		lines = append(lines, fp+":"+base64.StdEncoding.EncodeToString(pub))
	}
	if err := os.WriteFile(keyFile, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	logFile, err := os.Create(filepath.Join(dir, "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(daemon,
		"-socket-dir", dir,
		"-peer-uids", fmt.Sprintf("%d:crash-test", os.Getuid()),
		"-job-pubkey-file", keyFile,
		"-backend", "microsandbox",
		"-msb-bin", bin,
		"-runtime-manifest", manifestPath,
		"-state-dir", filepath.Join(dir, "artifacts"),
		"-pool-vms", "1", "-pool-submitter-vms", "1",
		"-pool-cpus", "2", "-pool-memory-mb", "1024",
		"-pool-disk-mb", "2048", "-pool-output-bytes", "1048576",
	)
	cmd.Env = append(os.Environ(),
		"MSB_FAKE_HELPER=1",
		"MSB_FAKE_DIR="+fakeState,
		"MSB_FAKE_FIRMWARE="+firmware,
		"MSB_FAKE_JOB_RUNNING=100000",
	)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	crashed := false
	t.Cleanup(func() {
		if !crashed {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	socket := filepath.Join(dir, "executor.sock")
	if err := waitForPath(socket, 30*time.Second); err != nil {
		out, _ := os.ReadFile(filepath.Join(dir, "daemon.log"))
		t.Fatalf("%v — daemon log:\n%s", err, out)
	}

	conn, reader := connect(t, socket)
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID = "crash-1"
		c.Nonce = "n-crash-1"
	}))
	if !resp.OK || resp.State != JobStateRunning {
		t.Fatalf("submit = %+v", resp)
	}
	_ = conn.Close()

	// SIGKILL: the process dies mid-observation with no chance to flush
	// or clean up.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill daemon: %v", err)
	}
	_, _ = cmd.Process.Wait()
	crashed = true

	// The acknowledged job survived, with the authorization written
	// before the VM existed.
	inspected, err := InspectLedger(ledgerPathOf(dir))
	if err != nil {
		t.Fatalf("reopen the ledger after the crash: %v", err)
	}
	row, gerr := inspected.Get("crash-1")
	inspected.Close()
	if gerr != nil || row == nil {
		t.Fatalf("the crash erased an acknowledged job: %v", gerr)
	}
	if row.DispatchNonce == "" || row.PolicyDigest == "" || row.BackendHandle == "" {
		t.Fatalf("the crash erased the dispatch authorization: %+v", row)
	}
	if row.ReceiptSHA256 != "" || row.ResultJSON != "" {
		t.Fatalf("a crash produced a result it never observed: %+v", row)
	}

	// No duplicate dispatch: the runtime's own records hold exactly one
	// job for this contract.
	records, rerr := fakeReadJobs(fakeState, row.BackendHandle)
	if rerr != nil {
		t.Fatalf("read the runtime's job records: %v", rerr)
	}
	if len(records) != 1 {
		t.Fatalf("the crash produced %d runtime job records, want exactly 1", len(records))
	}
	if records[0].RuntimeBoot != row.BackendBootID {
		t.Fatalf("the runtime record's boot generation %q is not the dispatch's %q", records[0].RuntimeBoot, row.BackendBootID)
	}

	// The next lifetime recovers the run from the runtime's own record —
	// and, while the job is still running, leaves it unresolved rather
	// than inventing an outcome.
	t.Setenv("MSB_FAKE_HELPER", "1")
	t.Setenv("MSB_FAKE_DIR", fakeState)
	t.Setenv("MSB_FAKE_FIRMWARE", firmware)
	backend := &MSBBackend{
		Bin: bin, StateDir: filepath.Join(dir, "artifacts"),
		PollInterval: 20 * time.Millisecond,
		RuntimeManifest: &RuntimeManifest{
			Version:         PinnedMSBVersion,
			MSBSHA256:       sha256File(t, bin),
			LibkrunfwSHA256: sha256File(t, firmware),
		},
	}
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend})
	deadline := time.Now().Add(20 * time.Second)
	var recovered *LedgerJob
	for time.Now().Before(deadline) {
		recovered, _ = srv.Ledger().Get("crash-1")
		if recovered != nil && recovered.State != JobStateRunning {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if recovered == nil {
		t.Fatal("the recovered row vanished")
	}
	if recovered.ResultJSON != "" || recovered.ReceiptSHA256 != "" {
		t.Fatalf("a still-running recovered job was given an outcome: %+v", recovered)
	}
	if records, _ := fakeReadJobs(fakeState, row.BackendHandle); len(records) != 1 {
		t.Fatalf("recovery duplicated the dispatch: %d runtime job records", len(records))
	}

	// Let the job finish in the runtime's own record (the truth), then a
	// further lifetime settles the run from that record — no relaunch.
	if err := os.WriteFile(fakePollsPath(fakeState, row.BackendHandle), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.Stop()
	srv2 := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend})
	deadline = time.Now().Add(20 * time.Second)
	var settled *LedgerJob
	for time.Now().Before(deadline) {
		settled, _ = srv2.Ledger().Get("crash-1")
		if settled != nil && settled.State == JobStateSucceeded {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if settled == nil || settled.State != JobStateSucceeded {
		t.Fatalf("the recovered run did not settle from the runtime's record: %+v", settled)
	}
	if settled.BackendJobID != records[0].ID {
		t.Fatalf("the settled run %q is not the runtime's job %q", settled.BackendJobID, records[0].ID)
	}
	if settled.ReceiptSHA256 == "" || settled.ArtifactSHA256 == "" {
		t.Fatalf("the settled run carries no evidence: %+v", settled)
	}
}

// waitForPath waits until the daemon's socket answers a dial.
func waitForPath(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("daemon socket %s did not appear", path)
}
