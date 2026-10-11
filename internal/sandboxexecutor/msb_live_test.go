package sandboxexecutor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Live Microsandbox qualification: exercises the real backend end to
// end — signed contract in, microVM execution, bound result out. It
// creates actual VMs and needs an msb binary plus a cached image, so
// it only runs when CRABBOX_MSB_LIVE=1:
//
//	CRABBOX_MSB_LIVE=1 go test -race -timeout=900s -run 'TestMSBLive' ./internal/sandboxexecutor/
//
// The suite covers the isolation properties a source-level fake can
// never prove: a real VM boots with the authorized policy, refuses
// reuse of a pre-existing sandbox, cannot reach the network or host
// credentials, and produces artifacts whose digests survive
// independent verification.

const liveImage = "python:3.12"

func msbOrSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("CRABBOX_MSB_LIVE") != "1" {
		t.Skip("CRABBOX_MSB_LIVE=1 not set — skipping live microsandbox test")
	}
	candidates := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".microsandbox", "bin", "msb"))
	}
	if p, err := exec.LookPath("msb"); err == nil {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	t.Skip("no msb binary found")
	return ""
}

// liveImageDigest resolves the cached image's manifest digest from the
// CLI itself: the contract must pin a digest, and hardcoding one would
// rot the moment the image is refreshed.
func liveImageDigest(t *testing.T, bin string) string {
	t.Helper()
	out, err := exec.Command(bin, "image", "list", "--format", "json").Output()
	if err != nil {
		t.Skipf("msb image list failed: %v", err)
	}
	var images []struct {
		Digest    string `json:"digest"`
		Reference string `json:"reference"`
	}
	if err := json.Unmarshal(out, &images); err != nil {
		t.Fatalf("parse msb image list: %v", err)
	}
	for _, img := range images {
		if img.Reference == liveImage || strings.HasPrefix(img.Reference, liveImage+"@") {
			return img.Digest
		}
	}
	t.Skipf("image %s is not cached locally — pull it first", liveImage)
	return ""
}

// liveServer stands up a real server backed by a real MSBBackend and
// returns it with its directory and authority key. The runtime pin is
// verified first: the live suite qualifies the pinned runtime, so a
// different one refuses the run instead of silently qualifying
// behavior the adapter was never tested against.
func liveServer(t *testing.T, bin string) (*Server, string, ed25519.PrivateKey) {
	t.Helper()
	key, keys := testAuthority(t)
	dir := socketDir(t)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(dir, "artifacts")}
	if _, err := backend.VerifyRuntime(context.Background()); err != nil {
		t.Fatalf("live suite requires the pinned runtime: %v", err)
	}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: backend,
	})
	return srv, dir, key
}

// liveJob renders one live submission with the pinned image and a
// caller-supplied job identity and command.
func liveJob(t *testing.T, key ed25519.PrivateKey, digest, jobID string, mutate func(*JobContractV2)) map[string]any {
	t.Helper()
	return signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID = jobID
		c.Nonce = "n-" + jobID
		c.Image = liveImage
		c.ImageDigest = digest
		c.Resources.TimeoutSeconds = 120
		c.Security = SecurityDefault
		c.Argv = []string{"python3", "-c", "print('default')"}
		if mutate != nil {
			mutate(c)
		}
	})
}

func waitLiveTerminal(t *testing.T, srv *Server, jobID string) *LedgerJob {
	t.Helper()
	deadline := time.Now().Add(180 * time.Second)
	var terminal *LedgerJob
	for time.Now().Before(deadline) {
		lj, err := srv.Ledger().Get(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if lj != nil {
			switch lj.State {
			case JobStateSucceeded, JobStateFailed, JobStateDispatchFailed:
				terminal = lj
			}
		}
		if terminal != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if terminal == nil {
		lj, _ := srv.Ledger().Get(jobID)
		t.Fatalf("job %s never reached a terminal state: %+v", jobID, lj)
	}
	// The terminal write records cleanup intent before the removal
	// runs; wait for it to settle so a test that ends right after
	// the result cannot cancel the cleanup mid-flight and leave a
	// sandbox behind for the next suite run to trip over.
	for time.Now().Before(deadline) {
		lj, err := srv.Ledger().Get(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if lj != nil && !lj.CleanupPending {
			return lj
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("job %s cleanup never settled: %+v", jobID, terminal)
	return nil
}

func liveResult(t *testing.T, lj *LedgerJob) *ExecResult {
	t.Helper()
	var res ExecResult
	if err := json.Unmarshal([]byte(lj.ResultJSON), &res); err != nil {
		t.Fatalf("result_json: %v", err)
	}
	return &res
}

func TestMSBLiveJobLifecycle(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, dir, key := liveServer(t, bin)
	conn, reader := connect(t, srv.SocketPath())
	jobID := "msb-live-ok"
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Env = []string{"LIVE_MARKER=live-env"}
		c.Argv = []string{"python3", "-c", "import os; print('live-ok', os.environ.get('LIVE_MARKER'))"}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	lj := waitLiveTerminal(t, srv, jobID)
	if lj.State != JobStateSucceeded {
		t.Fatalf("job did not succeed: %+v", lj)
	}
	if lj.ExitCode == nil || *lj.ExitCode != 0 {
		t.Fatalf("exit code = %+v", lj.ExitCode)
	}
	res := liveResult(t, lj)
	// The result must carry the runtime's own observation, not a
	// CLI process exit code: a verified exit from a named run.
	if !res.ExitVerified || res.RuntimeState != "exited" {
		t.Fatalf("result does not carry the runtime's verified exit: %+v", res)
	}
	if !jobIDPattern.MatchString(res.RunID) || lj.BackendJobID != res.RunID {
		t.Fatalf("run identity not bound to the ledger: res=%q ledger=%q", res.RunID, lj.BackendJobID)
	}
	data, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
	if !strings.Contains(string(data), "live-ok live-env") {
		t.Fatalf("artifact does not carry the command output and authorized env: %q", data)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != res.OutputSHA256 || res.OutputSHA256 != lj.ArtifactSHA256 {
		t.Fatalf("artifact digest disagrees with result/ledger: %s vs %s vs %s",
			hex.EncodeToString(sum[:]), res.OutputSHA256, lj.ArtifactSHA256)
	}
	t.Logf("artifact %s sha=%s bytes=%d", res.OutputPath, res.OutputSHA256[:16], res.OutputBytes)

	// Independent verification: the ledger, receipts, checkpoints and
	// artifacts must satisfy a verifier that trusts only the signer
	// fingerprint — the executor's own word is not part of the chain.
	srv.Stop()
	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("independent verification failed: %v", rep.Failures)
	}
	if rep.Receipts == 0 || rep.Artifacts == 0 || rep.CheckpointCount < 0 {
		t.Fatalf("verifier checked nothing: %+v", rep)
	}
}

// liveBurstScript writes 256 KiB to stdout and stderr concurrently —
// far beyond the contract's bound — so the artifact, its digest and
// the truncation flag must all agree on what was actually stored.
const liveBurstScript = `
import sys, threading
def w(stream, ch):
    chunk = ch * 4096
    for _ in range(64):
        stream.write(chunk)
        stream.flush()
threads = [threading.Thread(target=w, args=(sys.stdout, 'A')),
           threading.Thread(target=w, args=(sys.stderr, 'B'))]
for th in threads:
    th.start()
for th in threads:
    th.join()
`

func TestMSBLiveArtifactIntegrityUnderConcurrency(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, dir, key := liveServer(t, bin)
	conn, reader := connect(t, srv.SocketPath())
	jobID := "msb-live-artifact"
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Resources.MaxOutputBytes = 64 * 1024
		c.Argv = []string{"python3", "-c", liveBurstScript}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	lj := waitLiveTerminal(t, srv, jobID)
	if lj.State != JobStateSucceeded {
		t.Fatalf("job did not succeed: %+v", lj)
	}
	res := liveResult(t, lj)
	data, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
	if len(data) != 64*1024 {
		t.Fatalf("artifact holds %d bytes, want the contract's 64KiB bound", len(data))
	}
	if !res.Truncated {
		t.Fatal("truncation not reported for output beyond the bound")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != res.OutputSHA256 {
		t.Fatalf("digest %s does not cover the stored bytes %s", res.OutputSHA256, hex.EncodeToString(sum[:]))
	}
	if int64(len(data)) != res.OutputBytes {
		t.Fatalf("artifact size %d disagrees with the result's %d", len(data), res.OutputBytes)
	}
	srv.Stop()
	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("independent verification failed: %v", rep.Failures)
	}
}

// TestMSBLiveRefusesPreexistingSandbox is the live sandbox-reuse
// attack: a permissive VM already exists under the deterministic
// handle the job will ask for. The job must refuse — never execute
// inside it, never destroy it.
func TestMSBLiveRefusesPreexistingSandbox(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, dir, key := liveServer(t, bin)
	jobID := "msb-live-reuse"
	name := "sx-" + jobID

	// Pre-create the trap: the expected handle with permissive network.
	pre := exec.Command(bin, "create", "-q", "-n", name, "--net", "public", liveImage)
	if out, err := pre.CombinedOutput(); err != nil {
		t.Fatalf("could not pre-create the trap sandbox: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(bin, "rm", "-f", name).Run() })

	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Argv = []string{"python3", "-c", "print('must-not-run')"}
	}))
	if resp.OK {
		t.Fatal("job dispatched into a pre-existing sandbox")
	}
	if resp.State != JobStateDispatchFailed {
		t.Fatalf("refusal state = %q, want %s", resp.State, JobStateDispatchFailed)
	}
	// The trap VM is untouched — still present, still permissive.
	out, err := exec.Command(bin, "inspect", "--format", "json", name).Output()
	if err != nil {
		t.Fatalf("the pre-existing sandbox was destroyed: %v", err)
	}
	if !strings.Contains(string(out), `"group": "public"`) {
		t.Fatalf("the pre-existing sandbox's policy changed: %s", out)
	}
	// No artifact may exist for a job that never ran.
	entries, err := os.ReadDir(filepath.Join(dir, "artifacts"))
	if err == nil {
		for _, e := range entries {
			if strings.Contains(e.Name(), jobID) {
				t.Fatalf("a refused job left an artifact: %s", e.Name())
			}
		}
	}
}

// liveNetworkProbe tries public internet, DNS, cloud metadata and
// private-range addresses from an offline VM. Reachability means a
// byte actually crossed the boundary: the sandbox gateway can accept
// a SYN locally (port 53 in particular), so a bare connect proves
// nothing — the probe requires a response.
const liveNetworkProbe = `
import socket, sys
reachable = []
def probe(host, port, payload):
    try:
        s = socket.create_connection((host, port), timeout=2)
    except Exception:
        return
    try:
        s.settimeout(2)
        s.sendall(payload)
        if s.recv(256):
            reachable.append("%s:%d" % (host, port))
    except Exception:
        pass
    finally:
        s.close()
http = b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n"
probe("1.1.1.1", 80, http)
probe("8.8.8.8", 53, b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
probe("169.254.169.254", 80, http)
probe("192.168.0.1", 80, http)
probe("10.0.0.1", 80, http)
try:
    socket.getaddrinfo("example.com", 80)
    reachable.append("dns")
except Exception:
    pass
if reachable:
    print("REACHABLE:" + ",".join(reachable))
    sys.exit(1)
print("isolated")
`

func TestMSBLiveNetworkIsolation(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, _, key := liveServer(t, bin)
	conn, reader := connect(t, srv.SocketPath())
	jobID := "msb-live-net"
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Network = NetworkPolicy{Mode: NetworkNone}
		c.Argv = []string{"python3", "-c", liveNetworkProbe}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	lj := waitLiveTerminal(t, srv, jobID)
	if lj.State != JobStateSucceeded {
		res := ""
		if lj.ResultJSON != "" {
			data, _ := os.ReadFile(liveResult(t, lj).OutputPath)
			res = string(data)
		}
		t.Fatalf("network probe failed (state=%s): %s", lj.State, res)
	}
	res := liveResult(t, lj)
	data, _ := os.ReadFile(res.OutputPath)
	if !strings.Contains(string(data), "isolated") {
		t.Fatalf("offline VM reported reachability: %q", data)
	}
}

// liveCredentialProbe proves the guest cannot read host credentials,
// home directories or the executor's own state — while proving the
// probe itself runs against a real guest rootfs. The guest's own
// files (its /etc/shadow, its root home) are deliberately not part of
// the check: isolation is about the host's files, not the image's.
func liveCredentialProbe(hostHome, executorDir string) string {
	paths := []string{
		filepath.Join(hostHome, ".ssh", "id_ed25519"),
		filepath.Join(hostHome, ".microsandbox", "bin", "msb"),
		filepath.Join(hostHome, ".config", "crabbox", "config.yaml"),
		filepath.Join(executorDir, "executor-ledger.db"),
		filepath.Join(executorDir, "evidence", "executor-evidence.pem"),
	}
	var quoted []string
	for _, p := range paths {
		quoted = append(quoted, fmt.Sprintf("%q", p))
	}
	return `
import os, sys
must_read = ["/etc/os-release"]
must_fail = [` + strings.Join(quoted, ", ") + `]
for p in must_read:
    if not os.path.exists(p):
        print("missing expected guest file: " + p)
        sys.exit(2)
leaked = []
for p in must_fail:
    try:
        with open(p, "rb") as f:
            f.read(1)
        leaked.append(p)
    except Exception:
        pass
if os.path.isdir("` + hostHome + `"):
    leaked.append("host home visible")
if leaked:
    print("LEAKED:" + ",".join(leaked))
    sys.exit(1)
print("credential-isolated")
`
}

func TestMSBLiveCredentialIsolation(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no host home directory: %v", err)
	}
	srv, dir, key := liveServer(t, bin)
	conn, reader := connect(t, srv.SocketPath())
	jobID := "msb-live-creds"
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Network = NetworkPolicy{Mode: NetworkNone}
		c.Argv = []string{"python3", "-c", liveCredentialProbe(home, dir)}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	lj := waitLiveTerminal(t, srv, jobID)
	res := liveResult(t, lj)
	data, _ := os.ReadFile(res.OutputPath)
	if lj.State != JobStateSucceeded || !strings.Contains(string(data), "credential-isolated") {
		t.Fatalf("credential isolation probe failed (state=%s): %q", lj.State, data)
	}
}

// TestMSBLiveMonitorInterruptedLeavesJobUncertain is the live
// monitoring-failure scenario: the executor stops watching while the
// guest is still running. The job must stay unresolved — never
// SUCCEEDED, never FAILED, never a COMPLETED receipt — and the
// abandoned VM must die at its contract timeout, not outlive it.
func TestMSBLiveMonitorInterruptedLeavesJobUncertain(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, dir, key := liveServer(t, bin)
	jobID := "msb-live-interrupt"
	name := "sx-" + jobID
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Resources.TimeoutSeconds = 10
		c.Argv = []string{"python3", "-c", "import time; print('started', flush=True); time.sleep(30)"}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	// Let the guest start and the monitor attach, then stop watching.
	time.Sleep(2 * time.Second)
	srv.Stop()

	l2, err := InspectLedger(ledgerPathOf(dir))
	if err != nil {
		t.Fatalf("inspect ledger: %v", err)
	}
	defer l2.Close()
	lj, err := l2.Get(jobID)
	if err != nil || lj == nil {
		t.Fatalf("job lost across the interrupted lifetime: %v", err)
	}
	switch lj.State {
	case JobStateInterrupted, JobStateDispatchAmbig:
	default:
		t.Fatalf("an unobserved outcome was not left uncertain: %+v", lj)
	}
	if lj.ReceiptSHA256 != "" {
		t.Fatalf("a receipt was emitted for an unobserved outcome: %+v", lj)
	}
	raw, err := os.ReadFile(filepath.Join(evidenceDirOf(dir), "receipts.jsonl"))
	if err == nil && strings.Contains(string(raw), jobID) {
		t.Fatal("evidence attests an outcome the executor never observed")
	}

	// The abandoned VM is bounded by its contract: --max-duration is
	// pinned to the contract timeout plus the fixed observation
	// grace, so it must stop on its own inside that bound.
	bounded := false
	deadline := time.Now().Add(55 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command(bin, "inspect", "--format", "json", name).Output()
		if err != nil {
			bounded = true // the sandbox is gone — bounded and reaped
			break
		}
		var doc map[string]any
		if json.Unmarshal(out, &doc) == nil {
			if status, _ := doc["status"].(string); !strings.EqualFold(status, "running") {
				bounded = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !bounded {
		t.Fatal("the abandoned VM outlived its contract timeout plus the observation grace")
	}
	_ = exec.Command(bin, "rm", "-f", name).Run()
}

// TestMSBLiveTransportFailureLeavesJobUncertain is the authenticity
// scenario the repair exists for: the executor's observation of a
// running job is destroyed mid-flight (the sandbox vanishes). The job
// must stay unresolved — never a fabricated guest failure, never a
// completed receipt — and the ledger must say reconciliation is owed.
func TestMSBLiveTransportFailureLeavesJobUncertain(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	key, keys := testAuthority(t)
	dir := socketDir(t)
	backend := &MSBBackend{
		Bin: bin, StateDir: filepath.Join(dir, "artifacts"),
		// A short observation window keeps the test bounded; the
		// production default is the contract timeout plus grace.
		ObservationSlack: 5 * time.Second,
	}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})
	jobID := "msb-live-transport"
	name := "sx-" + jobID
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Resources.TimeoutSeconds = 3
		c.Argv = []string{"python3", "-c", "import time; print('started', flush=True); time.sleep(60)"}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	time.Sleep(2 * time.Second)
	// Destroy the runtime's record out from under the observation —
	// the "transport failed" shape, which a CLI exit code alone
	// would misreport as a guest failure.
	if out, err := exec.Command(bin, "rm", "-f", name).CombinedOutput(); err != nil {
		t.Fatalf("remove sandbox: %v: %s", err, out)
	}

	deadline := time.Now().Add(30 * time.Second)
	var lj *LedgerJob
	for time.Now().Before(deadline) {
		var err error
		lj, err = srv.Ledger().Get(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if lj != nil && lj.State == JobStateDispatchAmbig {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lj == nil || lj.State != JobStateDispatchAmbig {
		t.Fatalf("an unobservable outcome was not left unresolved: %+v", lj)
	}
	if lj.ExitCode != nil || lj.ReceiptSHA256 != "" || lj.ResultJSON != "" {
		t.Fatalf("an unobserved outcome produced a result: %+v", lj)
	}
	raw, err := os.ReadFile(filepath.Join(evidenceDirOf(dir), "receipts.jsonl"))
	if err == nil && strings.Contains(string(raw), jobID) {
		t.Fatal("evidence attests an outcome the executor never observed")
	}
}

// TestMSBLiveContractTimeoutIsObserved: a job that outlives its
// contract deadline is killed by the runtime at that deadline — an
// observed outcome that is not a guest exit. The result must say
// "timed out" and invent no exit code for it.
func TestMSBLiveContractTimeoutIsObserved(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, dir, key := liveServer(t, bin)
	jobID := "msb-live-timeout"
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Resources.TimeoutSeconds = 3
		c.Argv = []string{"python3", "-c", "import time; print('started', flush=True); time.sleep(120)"}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	lj := waitLiveTerminal(t, srv, jobID)
	if lj.State != JobStateFailed {
		t.Fatalf("timed-out job state = %s, want %s", lj.State, JobStateFailed)
	}
	if lj.ExitCode != nil {
		t.Fatalf("a timed-out job fabricated exit code %d", *lj.ExitCode)
	}
	if !strings.Contains(lj.Error, "contract timeout") {
		t.Fatalf("timeout reason = %q", lj.Error)
	}
	res := liveResult(t, lj)
	if !res.TimedOut || res.ExitVerified {
		t.Fatalf("timeout result = %+v", res)
	}
	// The workload demonstrably ran, so the receipt attests
	// COMPLETED — the timeout is part of the observed outcome.
	srv.Stop()
	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("independent verification failed: %v", rep.Failures)
	}
}

// TestMSBLiveMountIsReadOnly: an authorized host mount is visible in
// the guest exactly as signed — and a mount the authority marked
// read-only refuses guest writes.
func TestMSBLiveMountIsReadOnly(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, _, key := liveServer(t, bin)
	src, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("mounted-ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, reader := connect(t, srv.SocketPath())
	jobID := "msb-live-mount"
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Network = NetworkPolicy{Mode: NetworkNone}
		c.Filesystem = FilesystemPolicy{Mounts: []Mount{{Source: src, Dest: "/mnt/data", Options: "ro"}}}
		c.Argv = []string{"python3", "-c", `
data = open("/mnt/data/hello.txt").read()
try:
    open("/mnt/data/evil.txt", "w").write("x")
    print("WRITABLE:" + data)
    raise SystemExit(1)
except OSError:
    print("mounted-ro-ok:" + data)
`}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	lj := waitLiveTerminal(t, srv, jobID)
	res := liveResult(t, lj)
	data, _ := os.ReadFile(res.OutputPath)
	if lj.State != JobStateSucceeded || !strings.Contains(string(data), "mounted-ro-ok:mounted-ok") {
		t.Fatalf("mount probe failed (state=%s): %q", lj.State, data)
	}
	if _, err := os.Stat(filepath.Join(src, "evil.txt")); err == nil {
		t.Fatal("a read-only mount accepted a guest write")
	}
}

func TestMSBLiveRefusalsAndCleanup(t *testing.T) {
	bin := msbOrSkip(t)
	key, keys := testAuthority(t)
	dir := socketDir(t)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(dir, "artifacts")}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})

	t.Run("forged contract never reaches a VM", func(t *testing.T) {
		conn, reader := connect(t, srv.SocketPath())
		req := signedJobReq(t, key, func(c *JobContractV2) { c.JobID = "msb-forge"; c.Nonce = "n-fg" })
		sj := req["signed_job"].(map[string]any)
		var c JobContractV2
		if err := json.Unmarshal(sj["contract"].(json.RawMessage), &c); err != nil {
			t.Fatal(err)
		}
		c.Image = "alpine:latest" // post-signing tamper
		raw, _ := json.Marshal(&c)
		sj["contract"] = json.RawMessage(raw)
		resp := sendJob(t, conn, reader, req)
		if resp.OK {
			t.Fatal("forged job dispatched")
		}
	})
}

// TestMSBLiveRecoveryResumesInterruptedJob: the executor restarts
// while a job is still running in its VM. The run is runtime-owned, so
// the next lifetime re-establishes observation from the runtime's own
// record — recovering the terminal result, the artifact and the
// receipt a live monitor would have produced, without ever
// re-launching the job or losing the VM.
func TestMSBLiveRecoveryResumesInterruptedJob(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	key, keys := testAuthority(t)
	dir := socketDir(t)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(dir, "artifacts")}
	if _, err := backend.VerifyRuntime(context.Background()); err != nil {
		t.Fatalf("live suite requires the pinned runtime: %v", err)
	}
	jobID := "msb-live-recover"
	name := "sx-" + jobID

	// First lifetime: the job is dispatched and the daemon stops while
	// the guest is still running.
	srv1 := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})
	conn, reader := connect(t, srv1.SocketPath())
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Resources.TimeoutSeconds = 6
		c.Argv = []string{"python3", "-c", "import time; time.sleep(3); print('recovered-ok')"}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	time.Sleep(1 * time.Second)
	srv1.Stop()

	// The guest finishes after the first lifetime is gone.
	time.Sleep(4 * time.Second)

	// Second lifetime: recovery resumes the run from the runtime's
	// record — the outcome is observed, never re-dispatched.
	srv2 := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})
	lj := waitLiveTerminal(t, srv2, jobID)
	if lj.State != JobStateSucceeded {
		t.Fatalf("recovered job state = %s: %+v", lj.State, lj)
	}
	if lj.ExitCode == nil || *lj.ExitCode != 0 {
		t.Fatalf("recovered exit code = %v", lj.ExitCode)
	}
	if lj.ReceiptSHA256 == "" {
		t.Fatal("a recovered job reached a terminal state without a receipt")
	}
	res := liveResult(t, lj)
	data, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("recovered artifact missing: %v", err)
	}
	if !strings.Contains(string(data), "recovered-ok") {
		t.Fatalf("recovered artifact does not hold the guest output: %q", data)
	}
	if !res.ExitVerified || res.RunID != lj.BackendJobID {
		t.Fatalf("recovered result does not carry the runtime's observation: %+v", res)
	}
	// The recovered VM is cleaned up like any other settled job.
	if out, err := exec.Command(bin, "inspect", "--format", "json", name).Output(); err == nil {
		t.Fatalf("recovered sandbox survived cleanup: %s", out)
	}
	srv2.Stop()
	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("independent verification failed: %v", rep.Failures)
	}
}
