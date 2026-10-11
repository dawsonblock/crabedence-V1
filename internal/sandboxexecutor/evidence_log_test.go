package sandboxexecutor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	_ "modernc.org/sqlite"
)

// ─── Evidence custody tests ──────────────────────────────────────────
//
// The property under test: an executor can claim anything, but a
// verifier holding the receipts, checkpoints and a trusted signer
// fingerprint must detect every way the claim could stop being true —
// rewritten rows, deleted records, missing receipts, forged
// attestations, substituted artifacts and wholesale rollback.

// waitJob polls the ledger until the job reaches the wanted state.
func waitJob(t *testing.T, l *Ledger, jobID, want string) *LedgerJob {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j, err := l.Get(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if j != nil && j.State == want {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	j, _ := l.Get(jobID)
	t.Fatalf("job %s never reached %s (state=%v)", jobID, want, j)
	return nil
}

// startEvidenceServer stands up a signed-contract server with a stub
// backend and returns it with the authority key every submission must
// carry.
func startEvidenceServer(t *testing.T, dir string, be *stubBackend) (*Server, ed25519.PrivateKey) {
	t.Helper()
	key, keys := testAuthority(t)
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: be,
	})
	return srv, key
}

// submitSigned sends one signed job and returns the admission state.
func submitSigned(t *testing.T, srv *Server, key ed25519.PrivateKey, jobID string) string {
	t.Helper()
	conn, reader := connect(t, srv.SocketPath())
	defer conn.Close()
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = jobID, "n-"+jobID
	}))
	return resp.State
}

func ledgerPathOf(dir string) string  { return filepath.Join(dir, "executor-ledger.db") }
func evidenceDirOf(dir string) string { return filepath.Join(dir, "evidence") }

func TestEvidenceLifecycle(t *testing.T) {
	dir := socketDir(t)
	be := &stubBackend{handle: "vm-ev", wait: make(chan *ExecResult, 1)}
	be.wait <- &ExecResult{ExitCode: 0, FinishedAt: time.Now().UTC()}
	srv, key := startEvidenceServer(t, dir, be)
	if state := submitSigned(t, srv, key, "job-ev"); state != JobStateRunning {
		t.Fatalf("dispatch state = %s", state)
	}
	job := waitJob(t, srv.Ledger(), "job-ev", JobStateSucceeded)
	if job.TerminalSeq != 1 {
		t.Fatalf("terminal_seq = %d, want 1", job.TerminalSeq)
	}
	if job.ReceiptSHA256 == "" || job.BackendID != "stub" {
		t.Fatalf("row missing evidence bindings: %+v", job)
	}
	srv.Stop()

	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("clean evidence failed verification: %v", rep.Failures)
	}
	if rep.Receipts != 1 || rep.TerminalRows != 1 || rep.CheckpointCount != 1 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestEvidenceNOEFFECT(t *testing.T) {
	dir := socketDir(t)
	srv, key := startEvidenceServer(t, dir, &stubBackend{err: fmt.Errorf("no capacity")})
	if state := submitSigned(t, srv, key, "job-nofx"); state != JobStateDispatchFailed {
		t.Fatalf("dispatch state = %s", state)
	}
	srv.Stop()

	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("no-effect evidence failed verification: %v", rep.Failures)
	}
	raw := readReceipts(t, dir)
	var rcpt evidence.ReceiptV3
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &rcpt); err != nil {
		t.Fatal(err)
	}
	if rcpt.Outcome != evidence.OutcomeNoEffect {
		t.Fatalf("outcome = %s, want NO_EFFECT", rcpt.Outcome)
	}
}

func TestInterruptedJobNeverCheckpointed(t *testing.T) {
	dir := socketDir(t)
	be := &stubBackend{handle: "vm-hang", wait: make(chan *ExecResult)} // never completes
	srv, key := startEvidenceServer(t, dir, be)
	if state := submitSigned(t, srv, key, "job-hang"); state != JobStateRunning {
		t.Fatalf("dispatch state = %s", state)
	}
	srv.Stop() // RUNNING → INTERRUPTED, still non-terminal

	rep := VerifyEvidenceDir(ledgerPathOf(dir), evidenceDirOf(dir), "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("interrupted job produced evidence findings: %v", rep.Failures)
	}
	if rep.TerminalRows != 0 || rep.Receipts != 0 {
		t.Fatalf("interrupted job was attested terminal: %+v", rep)
	}
}

// tamper opens the ledger store directly — simulating someone with
// filesystem access rewriting history after the daemon stops.
func tamper(t *testing.T, ledgerPath, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("tamper %q: %v", query, err)
	}
}

// twoTerminalJobs returns a stopped server state holding two
// SUCCEEDED jobs plus the paths a tamperer needs.
func twoTerminalJobs(t *testing.T) (ledger, evdir, dir string) {
	t.Helper()
	dir = socketDir(t)
	be := &stubBackend{handle: "vm-1", wait: make(chan *ExecResult, 2)}
	be.wait <- &ExecResult{ExitCode: 0, FinishedAt: time.Now().UTC()}
	be.wait <- &ExecResult{ExitCode: 3, FinishedAt: time.Now().UTC()}
	srv, key := startEvidenceServer(t, dir, be)
	submitSigned(t, srv, key, "job-a")
	waitJob(t, srv.Ledger(), "job-a", JobStateSucceeded)
	submitSigned(t, srv, key, "job-b")
	waitJob(t, srv.Ledger(), "job-b", JobStateFailed) // exit 3
	srv.Stop()
	ledger, evdir = ledgerPathOf(dir), evidenceDirOf(dir)

	// Baseline must verify clean before any tampering — a test that
	// catches corruption on a dirty baseline proves nothing.
	rep := VerifyEvidenceDir(ledger, evdir, "", trustedSigner(t, dir))
	if len(rep.Failures) != 0 {
		t.Fatalf("baseline verification failed: %v", rep.Failures)
	}
	return ledger, evdir, dir
}

func TestEvidenceDetectsCorruption(t *testing.T) {
	expectFailure := func(t *testing.T, name string, mutate func(ledger, evdir string), want string) {
		t.Run(name, func(t *testing.T) {
			ledger, evdir, dir := twoTerminalJobs(t)
			mutate(ledger, evdir)
			rep := VerifyEvidenceDir(ledger, evdir, "", trustedSigner(t, dir))
			if len(rep.Failures) == 0 {
				t.Fatalf("%s went undetected", name)
			}
			found := false
			for _, f := range rep.Failures {
				if strings.Contains(f, want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("failures %v missing %q", rep.Failures, want)
			}
		})
	}

	expectFailure(t, "terminal row rewritten", func(ledger, _ string) {
		tamper(t, ledger, `UPDATE jobs SET result_json = '{"forged":true}' WHERE job_id = 'job-a'`)
	}, "chain mismatch")

	expectFailure(t, "terminal row deleted", func(ledger, _ string) {
		tamper(t, ledger, `DELETE FROM jobs WHERE job_id = 'job-a'`)
	}, "records deleted or the store rolled back")

	expectFailure(t, "receipt log truncated", func(_, evdir string) {
		path := filepath.Join(evdir, "receipts.jsonl")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data[:len(data)/2], 0o600); err != nil {
			t.Fatal(err)
		}
	}, "")

	expectFailure(t, "forged receipt appended", func(_, evdir string) {
		other, err := evidence.GenerateSigner()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := other.Sign(evidence.Binding{
			ExecutionID: "job-c", Capability: EvidenceCapability, Principal: "mallory",
			RequestDigest: strings.Repeat("0", 64), ProviderID: "stub", ProviderRunID: "vm-x",
			Outcome: evidence.OutcomeCompleted, EvidenceSHA256: strings.Repeat("0", 64),
		})
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(evdir, "receipts.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}, "not trusted")

	expectFailure(t, "receipt swapped for wrong binding", func(_, evdir string) {
		// A trusted signer (the executor's own stolen key) attests a
		// binding that is not job-a's — signature verifies, trust
		// holds, but the ledger row disagrees.
		data, err := os.ReadFile(filepath.Join(evdir, signerFile))
		if err != nil {
			t.Fatal(err)
		}
		signer, err := evidence.ParseSignerPEM(data)
		if err != nil {
			t.Fatal(err)
		}
		forged, err := signer.Sign(evidence.Binding{
			ExecutionID: "job-a", Capability: EvidenceCapability, Principal: "mallory",
			RequestDigest: strings.Repeat("0", 64), ProviderID: "stub", ProviderRunID: "vm-x",
			Outcome: evidence.OutcomeCompleted, EvidenceSHA256: strings.Repeat("0", 64),
		})
		if err != nil {
			t.Fatal(err)
		}
		// Replace job-a's real receipt with the forged line — a pure
		// substitution, not an append, so the binding check is what
		// fires rather than the duplicate check.
		path := filepath.Join(evdir, "receipts.jsonl")
		lines := strings.Split(strings.TrimSpace(readFile(t, path)), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 receipts, got %d", len(lines))
		}
		out := string(forged) + "\n" + lines[1] + "\n"
		if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}, "binding mismatch")

	expectFailure(t, "coordinated rollback detected by held checkpoint", func(ledger, _ string) {
		// The attacker holds filesystem access and deletes a terminal
		// row. A checkpoint issued BEFORE the tampering — the custody
		// copy held off-box — still proves the store shrank.
		tamper(t, ledger, `DELETE FROM jobs WHERE job_id = 'job-b'`)
	}, "records deleted or the store rolled back")

	expectFailure(t, "artifact substituted", func(ledger, _ string) {
		// Give job-a a bound artifact consistent in ledger and
		// result_json, then replace the artifact's bytes — the
		// recorded digest catches it. (The checkpoint also fires on
		// the rewritten row; both findings are correct.)
		artPath := filepath.Join(filepath.Dir(ledger), "forged.out")
		if err := os.WriteFile(artPath, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte("original"))
		res, _ := json.Marshal(ExecResult{ExitCode: 0, OutputPath: artPath, OutputSHA256: hex.EncodeToString(sum[:]), OutputBytes: 8})
		tamper(t, ledger, `UPDATE jobs SET result_json = ?, artifact_sha256 = ? WHERE job_id='job-a'`,
			string(res), hex.EncodeToString(sum[:]))
		if err := os.WriteFile(artPath, []byte("substituted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}, "digest changed")

	expectFailure(t, "artifact size not reported", func(ledger, _ string) {
		// The result claims zero bytes while the artifact holds data:
		// the recorded digest matches the file, but the size claim is
		// still an integrity failure — zero is an exact size, not an
		// absent one.
		artPath := filepath.Join(filepath.Dir(ledger), "unreported.out")
		data := []byte("data")
		if err := os.WriteFile(artPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		res, _ := json.Marshal(ExecResult{
			ExitCode: 0, OutputPath: artPath,
			OutputSHA256: hex.EncodeToString(sum[:]), OutputBytes: 0,
		})
		tamper(t, ledger, `UPDATE jobs SET result_json = ?, artifact_sha256 = ? WHERE job_id='job-a'`,
			string(res), hex.EncodeToString(sum[:]))
	}, "holds 4 bytes but the result reports 0")
}

// TestVerifyDetectsArtifactBeyondContractBound: the artifact is
// hashed correctly and its digest matches the ledger, but it holds
// more bytes than the signed contract's max_output_bytes allowed — a
// bound violation a verifier must still flag.
func TestVerifyDetectsArtifactBeyondContractBound(t *testing.T) {
	dir := socketDir(t)
	be := &stubBackend{handle: "vm-bound", wait: make(chan *ExecResult, 1)}
	be.wait <- &ExecResult{ExitCode: 0, OutputBytes: 12, FinishedAt: time.Now().UTC()}
	srv, key := startEvidenceServer(t, dir, be)
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "job-bound", "n-job-bound"
		c.Resources.MaxOutputBytes = 4
	}))
	if !resp.OK {
		t.Fatalf("dispatch refused: %+v", resp)
	}
	waitJob(t, srv.Ledger(), "job-bound", JobStateSucceeded)
	srv.Stop()

	// A verifier's baseline must be clean before the tamper.
	ledger, evdir := ledgerPathOf(dir), evidenceDirOf(dir)
	if rep := VerifyEvidenceDir(ledger, evdir, "", trustedSigner(t, dir)); len(rep.Failures) != 0 {
		t.Fatalf("baseline verification failed: %v", rep.Failures)
	}

	artPath := filepath.Join(dir, "oversized.out")
	data := []byte("way beyond the bound")
	if err := os.WriteFile(artPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	res, _ := json.Marshal(ExecResult{
		ExitCode: 0, OutputPath: artPath,
		OutputSHA256: hex.EncodeToString(sum[:]), OutputBytes: int64(len(data)),
	})
	tamper(t, ledger, `UPDATE jobs SET result_json = ?, artifact_sha256 = ? WHERE job_id='job-bound'`,
		string(res), hex.EncodeToString(sum[:]))

	rep := VerifyEvidenceDir(ledger, evdir, "", trustedSigner(t, dir))
	found := false
	for _, f := range rep.Failures {
		if strings.Contains(f, "beyond the contract") {
			found = true
		}
	}
	if !found {
		t.Fatalf("failures %v missing the contract-bound finding", rep.Failures)
	}
}

func TestCheckpointPrefixProperty(t *testing.T) {
	dir := socketDir(t)
	be := &stubBackend{handle: "vm-1", wait: make(chan *ExecResult, 2)}
	be.wait <- &ExecResult{ExitCode: 0, FinishedAt: time.Now().UTC()}
	be.wait <- &ExecResult{ExitCode: 0, FinishedAt: time.Now().UTC()}
	srv, key := startEvidenceServer(t, dir, be)
	submitSigned(t, srv, key, "job-p1")
	waitJob(t, srv.Ledger(), "job-p1", JobStateSucceeded)
	// checkpoint-00000001 exists after job-p1's terminal write — the
	// monitor emits it just after the transition commits, so poll.
	ckpt1 := filepath.Join(evidenceDirOf(dir), "checkpoints", "checkpoint-00000001.json")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ckpt1); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("first checkpoint missing: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	submitSigned(t, srv, key, "job-p2")
	waitJob(t, srv.Ledger(), "job-p2", JobStateSucceeded)
	srv.Stop()

	// Both checkpoints verify against the grown store: checkpoint-1
	// proves its prefix forever, checkpoint-2 covers all.
	trusted := trustedSigner(t, dir)
	evdir := evidenceDirOf(dir)
	for _, name := range []string{"checkpoint-00000001.json", "checkpoint-00000002.json"} {
		rep := VerifyEvidenceDir(ledgerPathOf(dir), evdir, filepath.Join(evdir, "checkpoints", name), trusted)
		if len(rep.Failures) != 0 {
			t.Fatalf("%s failed: %v", name, rep.Failures)
		}
	}
}

func TestExecutorRefusesToStartWithoutEvidence(t *testing.T) {
	dir := socketDir(t)
	// EvidenceDir occupied by a regular file — the chain cannot open.
	if err := os.WriteFile(evidenceDirOf(dir), []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, keys := testAuthority(t)
	srv, err := NewServer(Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: &stubBackend{}, EvidenceDir: evidenceDirOf(dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err == nil {
		srv.Stop()
		t.Fatal("executor started without a usable evidence chain")
	}
}

// trustedSigner reads the executor-generated evidence signer's
// fingerprint — the trust anchor a verifier is given out-of-band.
func trustedSigner(t *testing.T, dir string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(evidenceDirOf(dir), signerFile))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := evidence.ParseSignerPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]bool{signer.Fingerprint(): true}
}

func readReceipts(t *testing.T, dir string) string {
	t.Helper()
	return readFile(t, filepath.Join(evidenceDirOf(dir), receiptsFile))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
