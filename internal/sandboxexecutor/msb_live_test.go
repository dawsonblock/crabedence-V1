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
	"runtime"
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

// msbQualifying reports release-qualification mode: under it the suite's
// prerequisites fail rather than skip. A claimed lane whose runtime,
// image, or host capability is missing is a failed gate — never a
// silently-passed one. Ordinary development runs keep skipping so
// portable unit tests stay portable.
func msbQualifying() bool { return os.Getenv("CRABBOX_MSB_QUALIFY") == "1" }

func msbOrSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("CRABBOX_MSB_LIVE") != "1" {
		if msbQualifying() {
			t.Fatal("CRABBOX_MSB_LIVE=1 not set — a qualification run must enable live mode explicitly")
		}
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
	if msbQualifying() {
		t.Fatal("no msb binary found — a claimed lane cannot qualify without the pinned runtime")
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
		if msbQualifying() {
			t.Fatalf("msb image list failed on a claimed lane: %v", err)
		}
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
	if msbQualifying() {
		t.Fatalf("image %s is not cached on a claimed lane — the qualification environment must provide it", liveImage)
	}
	t.Skipf("image %s is not cached locally — pull it first", liveImage)
	return ""
}

// verifyLiveBackend proves the live runtime and host are the ones the
// suite is qualified against: the pinned runtime version, the exact
// executable and firmware bytes (pinned from this machine's install —
// the suite qualifies this runtime), and a host the runtime's own
// prerequisite check accepts.
func verifyLiveBackend(t *testing.T, backend *MSBBackend) {
	t.Helper()
	ctx := context.Background()
	if osName, arch, lane, supported := liveLane(t); supported {
		t.Logf("qualifying the %s lane on %s/%s", lane, osName, arch)
	} else {
		t.Fatalf("no supported virtualization lane on %s/%s", osName, arch)
	}
	if backend.RuntimeManifest == nil {
		backend.RuntimeManifest = liveRuntimeManifest(t, backend)
	}
	if _, err := backend.VerifyRuntime(ctx); err != nil {
		t.Fatalf("live suite requires the pinned runtime: %v", err)
	}
	if _, err := backend.VerifyHost(ctx); err != nil {
		t.Fatalf("live suite requires a supported host: %v", err)
	}
}

// liveRuntimeManifest pins the installed runtime's actual bytes: the
// live suite qualifies this machine's runtime, so the manifest is
// derived from it (version, executable digest, firmware digest) and
// the identity check exercises real hashing.
func liveRuntimeManifest(t *testing.T, backend *MSBBackend) *RuntimeManifest {
	t.Helper()
	fwPath, err := backend.firmwarePath(context.Background())
	if err != nil {
		t.Fatalf("resolve the installed firmware: %v", err)
	}
	return &RuntimeManifest{
		Version:         PinnedMSBVersion,
		MSBSHA256:       sha256File(t, backend.Bin),
		LibkrunfwSHA256: sha256File(t, fwPath),
	}
}

// liveServer stands up a real server backed by a real MSBBackend and
// returns it with its directory and authority key. The runtime pin and
// host confinement are verified first: the live suite qualifies the
// pinned runtime on a supported host, so anything else refuses the run
// instead of silently qualifying behavior the adapter was never tested
// against.
func liveServer(t *testing.T, bin string) (*Server, string, ed25519.PrivateKey) {
	t.Helper()
	key, keys := testAuthority(t)
	dir := socketDir(t)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(dir, "artifacts")}
	verifyLiveBackend(t, backend)
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

// TestMSBLiveRefusesPreexistingSandbox is the live name-squatting
// shape under nonce-bound handles: a permissive VM sits on the job's
// base name — an RC7.5-era leftover or a foreign plant — but the
// dispatch's handle carries its own unforgeable nonce and can never
// name the trap. The dispatch must run on its own nonce-bound handle,
// the job must execute inside the dispatch's VM, and the foreign
// sandbox must be untouched: name occupancy is not authority.
func TestMSBLiveRefusesPreexistingSandbox(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	srv, dir, key := liveServer(t, bin)
	jobID := "msb-live-reuse"
	name := "sx-" + jobID

	// Pre-create the trap: a permissive sandbox squatting the job's
	// base name — the only part of the handle an outsider can predict.
	pre := exec.Command(bin, "create", "-q", "-n", name, "--net", "public", liveImage)
	if out, err := pre.CombinedOutput(); err != nil {
		t.Fatalf("could not pre-create the trap sandbox: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(bin, "rm", "-f", name).Run() })

	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Argv = []string{"python3", "-c", "print('must-not-run')"}
	}))
	if !resp.OK {
		t.Fatalf("a foreign squat on the base name blocked the dispatch: %+v", resp)
	}
	lj := waitLiveTerminal(t, srv, jobID)
	if lj.State != JobStateSucceeded {
		t.Fatalf("the job did not run in its own sandbox: %+v", lj)
	}
	if lj.BackendHandle != name+"-"+lj.DispatchNonce {
		t.Fatalf("the dispatch's handle %q is not the nonce-bound name under %q", lj.BackendHandle, name)
	}
	// The trap VM is untouched — still present, still permissive.
	out, err := exec.Command(bin, "inspect", "--format", "json", name).Output()
	if err != nil {
		t.Fatalf("the pre-existing sandbox was destroyed: %v", err)
	}
	if !strings.Contains(string(out), `"group": "public"`) {
		t.Fatalf("the pre-existing sandbox's policy changed: %s", out)
	}
	// Its storage may never have hosted this dispatch's run: the only
	// artifacts present are the real job's, under the nonce-bound name.
	if entries, err := os.ReadDir(filepath.Join(dir, "artifacts")); err == nil {
		for _, e := range entries {
			if strings.Contains(e.Name(), jobID) && !strings.Contains(e.Name(), lj.BackendHandle) {
				t.Fatalf("an artifact references the job outside its nonce-bound identity: %s", e.Name())
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
	if lj.BackendHandle == "" {
		t.Fatalf("the interrupted dispatch lost its nonce-bound handle: %+v", lj)
	}
	name := lj.BackendHandle
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
	// would misreport as a guest failure. The nonce-bound handle is
	// durable state: read it from the row, never re-derive it.
	row, gerr := srv.Ledger().Get(jobID)
	if gerr != nil || row == nil || row.BackendHandle == "" {
		t.Fatalf("the dispatched row carries no handle: %v %+v", gerr, row)
	}
	if out, err := exec.Command(bin, "rm", "-f", row.BackendHandle).CombinedOutput(); err != nil {
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
	verifyLiveBackend(t, backend)
	jobID := "msb-live-recover"

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
	if out, err := exec.Command(bin, "inspect", "--format", "json", lj.BackendHandle).Output(); err == nil {
		t.Fatalf("recovered sandbox survived cleanup: %s", out)
	}
	srv2.Stop()
	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("independent verification failed: %v", rep.Failures)
	}
}

// TestMSBLiveSubstitutedVMIsNeverAdopted is the live execution-identity
// qualification: after a job completes, the sandbox is removed and a
// new one is created under the same deterministic name — a substituted
// VM instance. Recovery must refuse to adopt it (its boot generation is
// not the dispatch's), leave the row unresolved, and fabricate no
// result.
func TestMSBLiveSubstitutedVMIsNeverAdopted(t *testing.T) {
	bin := msbOrSkip(t)
	digest := liveImageDigest(t, bin)
	key, keys := testAuthority(t)
	dir := socketDir(t)
	backend := &MSBBackend{
		Bin: bin, StateDir: filepath.Join(dir, "artifacts"),
		ObservationSlack: 3 * time.Second,
	}
	verifyLiveBackend(t, backend)
	jobID := "msb-live-substitute"

	// First lifetime: a job runs to completion and the daemon stops
	// before it observes the result, so the row stays unresolved with
	// its boot generation recorded.
	srv1 := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})
	conn, reader := connect(t, srv1.SocketPath())
	resp := sendJob(t, conn, reader, liveJob(t, key, digest, jobID, func(c *JobContractV2) {
		c.Resources.TimeoutSeconds = 20
		c.Argv = []string{"python3", "-c", "import time; time.sleep(6); print('original-vm')"}
	}))
	if !resp.OK {
		t.Fatalf("live dispatch refused: %+v", resp)
	}
	// Stop watching while the job is still running: the row stays
	// unresolved with its boot generation recorded.
	time.Sleep(1500 * time.Millisecond)
	srv1.Stop()
	// Let the job finish in its VM (which outlives the daemon under its
	// own contract bound) so only the substitution remains to test.
	time.Sleep(7 * time.Second)

	lj, err := InspectLedger(ledgerPathOf(dir))
	if err != nil {
		t.Fatalf("inspect ledger: %v", err)
	}
	row, gerr := lj.Get(jobID)
	lj.Close()
	if gerr != nil || row == nil {
		t.Fatalf("ledger row: %v", gerr)
	}
	if row.BackendBootID == "" || !bootIDPattern.MatchString(row.BackendBootID) {
		t.Fatalf("the dispatch did not record a boot generation: %+v", row)
	}
	// The substitute occupies the recorded handle itself — an actor
	// that learned the nonce-bound name (a compromise-scope event):
	// recovery must still refuse it on its boot generation.
	name := row.BackendHandle

	// Substitute the VM: remove the sandbox and create a new one under
	// the same name — a fresh boot generation with no job records.
	if out, err := exec.Command(bin, "rm", "-f", name).CombinedOutput(); err != nil {
		t.Fatalf("remove sandbox: %v: %s", err, out)
	}
	if out, err := exec.Command(bin, "create", "-q", "-n", name, "--net", "none", "--deployment-profile", "single-tenant", liveImage+"@"+digest).CombinedOutput(); err != nil {
		t.Fatalf("re-create sandbox: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(bin, "rm", "-f", name).Run() })

	// Second lifetime: recovery must refuse the substituted instance.
	srv2 := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend,
	})
	deadline := time.Now().Add(30 * time.Second)
	var final *LedgerJob
	for time.Now().Before(deadline) {
		final, _ = srv2.Ledger().Get(jobID)
		if final != nil && (final.State == JobStateDispatchAmbig || final.State == JobStateInterrupted) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if final == nil || (final.State != JobStateDispatchAmbig && final.State != JobStateInterrupted) {
		t.Fatalf("a substituted VM instance was not left unresolved: %+v", final)
	}
	if final.ResultJSON != "" || final.ReceiptSHA256 != "" {
		t.Fatalf("a substituted VM instance produced a result: %+v", final)
	}
	if final.BackendBootID != row.BackendBootID {
		t.Fatalf("the recorded boot generation changed: %q → %q", row.BackendBootID, final.BackendBootID)
	}
}

// liveLane names the virtualization lane a host provides. Microsandbox
// runs on Apple's Hypervisor Framework under macOS and on Linux KVM
// under Linux: the two are independent implementations, and evidence
// from one never qualifies the other. laneSupported is false when the
// host's prerequisite is absent — that is an *unsupported* host for
// this lane, never a failed test.
func liveLane(t *testing.T) (osName, arch, lane string, laneSupported bool) {
	t.Helper()
	osName, arch = runtime.GOOS, runtime.GOARCH
	switch osName {
	case "darwin":
		lane = "apple-hypervisor-framework"
		out, err := exec.Command("sysctl", "-n", "kern.hv_support").Output()
		if err != nil {
			return osName, arch, lane, false
		}
		return osName, arch, lane, strings.TrimSpace(string(out)) == "1"
	case "linux":
		lane = "linux-kvm"
		if _, err := os.Stat("/dev/kvm"); err != nil {
			return osName, arch, lane, false
		}
		return osName, arch, lane, true
	default:
		return osName, arch, "unsupported", false
	}
}

// TestMSBLivePlatformIdentity pins which virtualization lane this host
// qualifies. It is deliberately ungated by CRABBOX_MSB_LIVE: the lane
// identity belongs in every qualification record, and a host whose lane
// prerequisite is missing skips as unsupported rather than failing —
// a Linux KVM lane is not "failed" because it ran on a Mac, and passing
// Apple Hypervisor Framework tests never qualifies the KVM
// implementation.
func TestMSBLivePlatformIdentity(t *testing.T) {
	osName, arch, lane, supported := liveLane(t)
	if !supported {
		if msbQualifying() {
			t.Fatalf("unsupported host for microVM qualification: %s/%s provides no %s lane — a claimed lane cannot qualify here", osName, arch, lane)
		}
		t.Skipf("unsupported host for microVM qualification: %s/%s provides no %s lane", osName, arch, lane)
	}
	t.Logf("microVM qualification lane: %s (%s/%s)", lane, osName, arch)
	// The runtime's own prerequisite check is the authority for the
	// lane being usable at all; the executor refuses a host it rejects.
	bin := msbOrSkip(t)
	backend := &MSBBackend{Bin: bin, StateDir: t.TempDir()}
	if _, err := backend.VerifyHost(context.Background()); err != nil {
		t.Fatalf("%s lane is present but the runtime rejects the host: %v", lane, err)
	}
}

// TestMSBLiveLinuxKVM is the Linux-lane qualification entry point: it
// runs the real microVM suite on a Linux host with KVM and skips as
// unsupported everywhere else. A release that claims Linux support
// requires this lane's own evidence.
func TestMSBLiveLinuxKVM(t *testing.T) {
	osName, arch, lane, supported := liveLane(t)
	if osName != "linux" || !supported {
		t.Skipf("Linux KVM qualification requires a Linux host with KVM: this is %s/%s (lane %s)", osName, arch, lane)
	}
	bin := msbOrSkip(t)
	backend := &MSBBackend{Bin: bin, StateDir: t.TempDir()}
	verifyLiveBackend(t, backend)
	t.Logf("Linux KVM lane qualified on %s/%s", osName, arch)
}
