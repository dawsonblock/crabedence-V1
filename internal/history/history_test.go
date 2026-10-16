package history

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sandboxcustody"
	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func ev(kind, subject, payload string) *Event {
	return &Event{
		DedupeKey:  kind + ":" + subject,
		Kind:       kind,
		Subject:    subject,
		Source:     "test",
		OccurredAt: 1,
		Payload:    json.RawMessage(payload),
	}
}

func TestAppendQueryVerify(t *testing.T) {
	s := openStore(t)
	appended, err := s.Append(
		ev(KindExperiment, "a", `{"n":1}`),
		ev(KindExperiment, "b", `{"n":2}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(appended) != 2 || appended[0].Seq != 1 || appended[1].Seq != 2 {
		t.Fatalf("appended %+v", appended)
	}
	if appended[1].PrevSHA256 != appended[0].SHA256 {
		t.Fatal("chain link broken")
	}
	// Re-append the same dedupe keys — idempotent.
	again, err := s.Append(ev(KindExperiment, "a", `{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatal("dedupe key did not suppress the re-append")
	}
	got, err := s.Query(QueryOpts{Kinds: []string{KindExperiment}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Seq != 2 {
		t.Fatalf("query returned %+v", got)
	}
	if findings := s.Verify(); len(findings) != 0 {
		t.Fatalf("verify: %v", findings)
	}
	total, perKind, head, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || perKind[KindExperiment] != 2 || head != appended[1].SHA256 {
		t.Fatalf("stats: %d %v %s", total, perKind, head)
	}
}

// A rewritten payload must be detected — memory that can be edited
// silently would let history be rewritten under the learning layer.
func TestVerifyDetectsTamper(t *testing.T) {
	s := openStore(t)
	if _, err := s.Append(ev(KindExperiment, "a", `{"n":1}`), ev(KindExperiment, "b", `{"n":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE events SET payload = '{"n":99}' WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	findings := s.Verify()
	if len(findings) == 0 || !strings.Contains(findings[0], "digest mismatch") {
		t.Fatalf("tamper not detected: %v", findings)
	}
}

// A deleted row breaks seq contiguity; a relinked chain breaks prev.
func TestVerifyDetectsDeletion(t *testing.T) {
	s := openStore(t)
	for i := 0; i < 3; i++ {
		if _, err := s.Append(ev(KindExperiment, fmt.Sprint(i), `{"i":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM events WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	findings := s.Verify()
	if len(findings) == 0 {
		t.Fatal("deletion not detected")
	}
}

func TestAppendRefusesMalformed(t *testing.T) {
	s := openStore(t)
	if _, err := s.Append(&Event{Kind: "x"}); err == nil {
		t.Fatal("empty event accepted")
	}
	if _, err := s.Append(ev("k", "s", `not json`)); err == nil {
		t.Fatal("non-JSON payload accepted")
	}
	if _, err := s.Append(ev("", "s", `{}`)); err == nil {
		t.Fatal("empty kind accepted")
	}
}

// gitRepo builds a two-commit repository in a temp dir.
func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "a.txt")
	run("commit", "-qm", "first")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("commit", "-qam", "second")
	return dir
}

func TestIngestGit(t *testing.T) {
	repo := gitRepo(t)
	s := openStore(t)
	n, err := s.IngestGit(context.Background(), repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("ingested %d commits, want 2", n)
	}
	// Re-ingest: idempotent.
	if n, err := s.IngestGit(context.Background(), repo, ""); err != nil || n != 0 {
		t.Fatalf("re-ingest: n=%d err=%v", n, err)
	}
	events, err := s.Query(QueryOpts{Kinds: []string{KindCodeChange}})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("%d code_change events", len(events))
	}
	var rec gitRecord
	bySubject := map[string]gitRecord{}
	for _, e := range events {
		rec = gitRecord{}
		if err := json.Unmarshal(e.Payload, &rec); err != nil {
			t.Fatal(err)
		}
		bySubject[rec.Subject] = rec
	}
	second, ok := bySubject["second"]
	if !ok || len(second.Files) != 1 || second.Files[0].Adds != 1 {
		t.Fatalf("second commit record %+v", second)
	}
	if first, ok := bySubject["first"]; !ok || !first.RootCommit {
		t.Fatalf("first commit record %+v", bySubject)
	}
}

// testContractJSON builds a structurally valid V2 contract for the
// ledger fixture — the same constructor admission uses.
func testContractJSON(t *testing.T, jobID string) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &sandboxexecutor.JobContractV2{
		Version:     sandboxexecutor.ContractVersion,
		JobID:       jobID,
		Principal:   "tester",
		Image:       "python:3.12",
		ImageDigest: "sha256:" + strings.Repeat("ab", 32),
		Argv:        []string{"python", "-c", "print(1)"},
		Resources: sandboxexecutor.ResourceBudget{
			TimeoutSeconds: 60, CPUs: 1, MemoryMB: 256,
			DiskMB: 128, MaxOutputBytes: 4096,
		},
		Network:   sandboxexecutor.NetworkPolicy{Mode: sandboxexecutor.NetworkNone},
		Security:  sandboxexecutor.SecurityDefault,
		IssuedAt:  time.Now().Unix() - 10,
		ExpiresAt: time.Now().Unix() + 600,
		Nonce:     "n-" + jobID,
		Authority: sandboxexecutor.AuthorityFingerprint(key.Public().(ed25519.PublicKey)),
	}
	env, err := sandboxexecutor.SignContract(key, c)
	if err != nil {
		t.Fatal(err)
	}
	return string(env.Contract)
}

// settledLedger returns a ledger holding one SUCCEEDED job plus its
// evidence dir (receipt emitted, checkpoint issued), closed and
// ready for read-only inspection.
func settledLedger(t *testing.T) (ledgerPath, evidenceDir string, refs []evidence.TerminalRef, signerFP string) {
	t.Helper()
	dir := t.TempDir()
	ledgerPath = filepath.Join(dir, "ledger.db")
	evidenceDir = filepath.Join(dir, "evidence")
	l, err := sandboxexecutor.OpenLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	cj := testContractJSON(t, "job-1")
	j, err := l.InsertJob("job-1", strings.Repeat("cd", 32), "sub", "tester", "python:3.12", cj)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range []struct {
		to   string
		from []string
	}{
		{sandboxexecutor.JobStateDispatching, []string{sandboxexecutor.JobStateRecorded}},
		{sandboxexecutor.JobStateRunning, []string{sandboxexecutor.JobStateDispatching}},
		{sandboxexecutor.JobStateSucceeded, []string{sandboxexecutor.JobStateRunning}},
	} {
		if err := l.Transition("job-1", tr.to, tr.from, func(j *sandboxexecutor.LedgerJob) error {
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = j
	// Emit a receipt bound to the terminal row, then a checkpoint.
	signer, err := evidence.LoadOrCreateSigner(sandboxexecutor.DefaultEvidenceKeyPath(evidenceDir))
	if err != nil {
		t.Fatal(err)
	}
	signerFP = signer.Fingerprint()
	elog, err := sandboxexecutor.OpenEvidenceLog(evidenceDir, signer, "microsandbox")
	if err != nil {
		t.Fatal(err)
	}
	job, err := l.Get("job-1")
	if err != nil {
		t.Fatal(err)
	}
	sha, err := elog.EmitForJob(job, evidence.OutcomeCompleted, strings.Repeat("ef", 32), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-1", sandboxexecutor.JobStateSucceeded, []string{sandboxexecutor.JobStateSucceeded}, func(j *sandboxexecutor.LedgerJob) error {
		j.ReceiptSHA256 = sha
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	refs, err = l.TerminalRefs()
	if err != nil {
		t.Fatal(err)
	}
	if err := elog.Close(refs); err != nil {
		t.Fatal(err)
	}
	l.Close()
	return ledgerPath, evidenceDir, refs, signerFP
}

func TestIngestJobsAndEvidence(t *testing.T) {
	ledgerPath, evidenceDir, _, signerFP := settledLedger(t)
	s := openStore(t)
	l, err := sandboxexecutor.InspectLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	n, err := s.IngestJobs(l)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ingested %d jobs", n)
	}
	// The execution event carries the contract-derived task fields.
	execs, err := s.Query(QueryOpts{Kinds: []string{KindExecution}})
	if err != nil {
		t.Fatal(err)
	}
	var rec jobRecord
	if err := json.Unmarshal(execs[0].Payload, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.JobID != "job-1" || rec.State != sandboxexecutor.JobStateSucceeded ||
		rec.Resources.MemoryMB != 256 || rec.Security != sandboxexecutor.SecurityDefault ||
		rec.NetworkMode != sandboxexecutor.NetworkNone {
		t.Fatalf("execution record %+v", rec)
	}

	trusted := map[string]bool{signerFP: true}
	m, err := s.IngestEvidenceDir(evidenceDir, trusted, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m < 2 {
		t.Fatalf("ingested %d evidence records, want receipt+checkpoint", m)
	}
	rcpts, err := s.Query(QueryOpts{Kinds: []string{KindReceipt}})
	if err != nil {
		t.Fatal(err)
	}
	var rr receiptRecord
	if err := json.Unmarshal(rcpts[0].Payload, &rr); err != nil {
		t.Fatal(err)
	}
	if !rr.SignatureValid || !rr.Trusted || rr.ExecutionID != "job-1" || rr.Outcome != evidence.OutcomeCompleted {
		t.Fatalf("receipt record %+v", rr)
	}
	cps, err := s.Query(QueryOpts{Kinds: []string{KindCheckpoint}})
	if err != nil {
		t.Fatal(err)
	}
	var cr checkpointRecord
	if err := json.Unmarshal(cps[0].Payload, &cr); err != nil {
		t.Fatal(err)
	}
	if !cr.Trusted || cr.Verified != nil {
		t.Fatalf("checkpoint without refs must record unverified: %+v", cr)
	}
}

// A custody dir written by the real witness server ingests with all
// chain links and signatures verified.
func TestIngestCustodyDir(t *testing.T) {
	base := shortDir(t)
	sockDir := filepath.Join(base, "s")
	custodyDir := filepath.Join(base, "c")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	srv, err := sandboxcustody.NewServer(sandboxcustody.Config{
		SocketDir:  sockDir,
		CustodyDir: custodyDir,
		KeyPath:    filepath.Join(custodyDir, "witness.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`[{"job_id":"j","terminal_seq":1}]`)
	sum := sha256.Sum256(payload)
	cli := &sandboxcustody.Client{Socket: srv.SocketPath()}
	resp, err := cli.Witness(context.Background(), &sandboxcustody.WitnessRequest{
		Op:               sandboxcustody.OpWitnessArchive,
		SegmentSeq:       1,
		FirstTerminalSeq: 1,
		LastTerminalSeq:  1,
		RowCount:         1,
		SHA256:           hex.EncodeToString(sum[:]),
		PayloadB64:       base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("witness refused: %s", resp.Error)
	}
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}

	s := openStore(t)
	trusted := map[string]bool{srv.SignerFingerprint(): true}
	n, err := s.IngestCustodyDir(custodyDir, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ingested %d acks", n)
	}
	acks, err := s.Query(QueryOpts{Kinds: []string{KindCustodyAck}})
	if err != nil {
		t.Fatal(err)
	}
	var ar custodyAckRecord
	if err := json.Unmarshal(acks[0].Payload, &ar); err != nil {
		t.Fatal(err)
	}
	if !ar.ChainLinkValid || !ar.SignatureValid || !ar.SegmentHeld || !ar.Trusted {
		t.Fatalf("custody record %+v", ar)
	}
}

func TestIngestDocuments(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notes.md")
	if err := os.WriteFile(p, []byte("# Research\n\nsome findings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := openStore(t)
	n, err := s.IngestDocuments(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ingested %d docs", n)
	}
	// Unchanged: dedupe. Changed: a new event — the doc's own history.
	if n, _ := s.IngestDocuments(p); n != 0 {
		t.Fatalf("re-ingest unchanged doc: %d", n)
	}
	if err := os.WriteFile(p, []byte("# Research\n\nrevised findings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.IngestDocuments(p); n != 1 {
		t.Fatalf("re-ingest changed doc: %d", n)
	}
	docs, err := s.Query(QueryOpts{Kinds: []string{KindDocument}})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("%d doc events", len(docs))
	}
}

const validStream = `{"Package":"p","Action":"start"}
{"Package":"p","Action":"run","Test":"TestA"}
{"Package":"p","Action":"output","Test":"TestA","Output":"=== RUN   TestA\n"}
{"Package":"p","Action":"output","Test":"TestA","Output":"--- PASS: TestA (0.01s)\n"}
{"Package":"p","Action":"pass","Test":"TestA","Elapsed":0.01}
{"Package":"p","Action":"run","Test":"TestB"}
{"Package":"p","Action":"skip","Test":"TestB","Elapsed":0}
{"Package":"p","Action":"output","Output":"ok\n"}
{"Package":"p","Action":"pass","Elapsed":0.02}
`

func TestIngestTestStream(t *testing.T) {
	s := openStore(t)
	n, err := s.IngestTestStream(strings.NewReader(validStream), "suite-x")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("ingested %d events, want 2 cases + 1 run", n)
	}
	runs, err := s.Query(QueryOpts{Kinds: []string{KindTestRun}})
	if err != nil {
		t.Fatal(err)
	}
	var run testRunRecord
	if err := json.Unmarshal(runs[0].Payload, &run); err != nil {
		t.Fatal(err)
	}
	if run.Tests != 2 || run.Passed != 1 || run.Skipped != 1 || len(run.Packages) != 1 {
		t.Fatalf("run record %+v", run)
	}
	// Idempotent: the same stream digests to the same run.
	if n, err := s.IngestTestStream(strings.NewReader(validStream), "suite-x"); err != nil || n != 0 {
		t.Fatalf("re-ingest: n=%d err=%v", n, err)
	}
}

// The strict lifecycle is enforced: malformed streams are refused
// whole, never partially recorded.
func TestIngestTestStreamRefusesMalformed(t *testing.T) {
	s := openStore(t)
	cases := []string{
		// terminal outcome with no preceding run
		`{"Package":"p","Action":"start"}
{"Package":"p","Action":"pass","Test":"T","Elapsed":0}
{"Package":"p","Action":"pass","Elapsed":0}
`,
		// duplicate run
		`{"Package":"p","Action":"start"}
{"Package":"p","Action":"run","Test":"T"}
{"Package":"p","Action":"run","Test":"T"}
{"Package":"p","Action":"pass","Test":"T","Elapsed":0}
{"Package":"p","Action":"pass","Elapsed":0}
`,
		// event after the test's terminal outcome
		`{"Package":"p","Action":"start"}
{"Package":"p","Action":"run","Test":"T"}
{"Package":"p","Action":"pass","Test":"T","Elapsed":0}
{"Package":"p","Action":"output","Test":"T","Output":"x\n"}
{"Package":"p","Action":"pass","Elapsed":0}
`,
		// package never completed
		`{"Package":"p","Action":"start"}
{"Package":"p","Action":"run","Test":"T"}
{"Package":"p","Action":"pass","Test":"T","Elapsed":0}
`,
		// unknown action
		`{"Package":"p","Action":"start"}
{"Package":"p","Action":"explode","Test":"T"}
{"Package":"p","Action":"pass","Elapsed":0}
`,
		// failed package is not passing evidence
		`{"Package":"p","Action":"start"}
{"Package":"p","Action":"run","Test":"T"}
{"Package":"p","Action":"fail","Test":"T","Elapsed":0}
{"Package":"p","Action":"pass","Elapsed":0}
`,
		// not a JSON event line
		`this is not json
`,
	}
	for i, stream := range cases {
		if _, err := s.IngestTestStream(strings.NewReader(stream), fmt.Sprint(i)); err == nil {
			t.Fatalf("case %d: malformed stream accepted", i)
		}
	}
	// Nothing from the refused streams landed in memory.
	if total, _, _, err := s.Stats(); err != nil || total != 0 {
		t.Fatalf("refused streams recorded: %d", total)
	}
}

// shortDir builds a path short enough for unix sockets on macOS
// (sun_path limit), mirroring the executor tests' socketDir helper.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hist-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
