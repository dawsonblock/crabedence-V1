package sandboxexecutor

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/sandboxcustody"
	_ "modernc.org/sqlite"
)

// The archive gate: settled terminal rows leave the active registry
// without losing replay identity, terminal enumeration coverage, or
// the evidence the row carries — and unsettled or unevidenced rows
// never leave.

// settleJob drives one recorded job to a settled terminal state:
// receipt bound (the evidence chain attests the outcome) and cleanup
// verified (no VM may still exist). That is the shape archival takes.
func settleJob(t *testing.T, l *Ledger, id, hash string) {
	t.Helper()
	if _, err := l.InsertJob(id, hash, "s", "p", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition(id, JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition(id, JobStateRunning, []string{JobStateDispatching},
		func(j *LedgerJob) error { j.BackendHandle = "vm-" + id; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition(id, JobStateSucceeded, []string{JobStateRunning}, func(j *LedgerJob) error {
		j.ResultJSON = `{"exit_code":0}`
		j.ReceiptSHA256 = "rcpt-" + id
		j.ArtifactSHA256 = "art-" + id
		j.CleanupPending = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.ClearCleanupPending(id); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveMovesSettledTerminalRows(t *testing.T) {
	l, _ := openLedger(t)
	for i := 0; i < 3; i++ {
		settleJob(t, l, fmt.Sprintf("done-%d", i), fmt.Sprintf("h-done-%d", i))
	}
	// Active work stays: a recorded job and a terminal job whose
	// cleanup is not verified are not history.
	if _, err := l.InsertJob("live-1", "h-live", "s", "p", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.InsertJob("pending-1", "h-pending", "s", "p", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("pending-1", JobStateDispatchFailed, []string{JobStateRecorded}, func(j *LedgerJob) error {
		j.ReceiptSHA256 = "rcpt-pending"
		j.CleanupPending = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	seg, err := l.ArchiveCompleted(0)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if seg == nil || seg.RowCount != 3 || seg.Custody != "local" || seg.SHA256 == "" {
		t.Fatalf("segment = %+v", seg)
	}
	if n, _ := l.Count(); n != 2 {
		t.Fatalf("active registry = %d, want 2", n)
	}
	if n, _ := l.ArchivedCount(); n != 3 {
		t.Fatalf("archive = %d rows, want 3", n)
	}
	if n, _ := l.IdentityCount(); n != 5 {
		t.Fatalf("identities = %d, want all 5 permanent", n)
	}

	// Archived rows still answer Get with their full payload.
	j, err := l.Get("done-1")
	if err != nil || j == nil {
		t.Fatalf("archived job lost: %v", err)
	}
	if !j.Archived || j.State != JobStateSucceeded || j.ReceiptSHA256 != "rcpt-done-1" ||
		j.ResultJSON != `{"exit_code":0}` || j.BackendHandle != "vm-done-1" {
		t.Fatalf("archived payload mangled: %+v", j)
	}
	if j.TerminalSeq != 2 {
		t.Fatalf("terminal seq = %d, want 2", j.TerminalSeq)
	}
	// Active rows are unmarked.
	if live, _ := l.Get("live-1"); live == nil || live.Archived {
		t.Fatalf("active row marked archived: %+v", live)
	}

	// Nothing further is eligible — recorded and cleanup-pending rows
	// are not archivable.
	if seg, err := l.ArchiveCompleted(0); err != nil || seg != nil {
		t.Fatalf("second pass = %+v, %v", seg, err)
	}
}

func TestArchivePreservesReplayForever(t *testing.T) {
	l, path := openLedger(t)
	settleJob(t, l, "job-1", "hash-1")
	if _, err := l.ArchiveCompleted(0); err != nil {
		t.Fatal(err)
	}
	l.Close()

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	// The operational row is long gone — replay must still refuse.
	if _, err := l2.InsertJob("job-1", "hash-1", "s", "p", "i", "{}"); !errors.Is(err, ErrDuplicateJobID) {
		t.Fatalf("reused job_id after archive: %v", err)
	}
	if _, err := l2.InsertJob("job-9", "hash-1", "s", "p", "i", "{}"); !errors.Is(err, ErrContractReplay) {
		t.Fatalf("replayed contract after archive: %v", err)
	}
	if _, err := l2.InsertJob("job-9", "hash-9", "s", "p", "i", "{}"); err != nil {
		t.Fatalf("fresh identity refused: %v", err)
	}
}

func TestArchiveSkipsUnevidencedAndUnresolved(t *testing.T) {
	l, _ := openLedger(t)

	// A terminal row with no bound receipt is an unattested claim —
	// it must never become history.
	if _, err := l.InsertJob("no-receipt", "h-nr", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("no-receipt", JobStateSucceeded, []string{JobStateRecorded},
		func(j *LedgerJob) error { j.ResultJSON = "{}"; return nil }); err != nil {
		t.Fatal(err)
	}
	// An unresolved row is operational, not history.
	if _, err := l.InsertJob("ambig", "h-ambig", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("ambig", JobStateDispatchAmbig, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}

	if seg, err := l.ArchiveCompleted(0); err != nil || seg != nil {
		t.Fatalf("archived ineligible rows: %+v, %v", seg, err)
	}
	if n, _ := l.Count(); n != 2 {
		t.Fatalf("ineligible rows left the registry: %d", n)
	}
	if j, _ := l.Get("no-receipt"); j == nil || j.Archived {
		t.Fatal("an unreceipted terminal claim archived")
	}
}

func TestArchiveWaitsForVerifiedCleanup(t *testing.T) {
	l, _ := openLedger(t)
	if _, err := l.InsertJob("job-c", "h-c", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-c", JobStateSucceeded, []string{JobStateRecorded}, func(j *LedgerJob) error {
		j.ReceiptSHA256 = "rcpt-c"
		j.CleanupPending = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seg, err := l.ArchiveCompleted(0); err != nil || seg != nil {
		t.Fatalf("a job whose VM may still exist archived: %+v, %v", seg, err)
	}
	if err := l.ClearCleanupPending("job-c"); err != nil {
		t.Fatal(err)
	}
	seg, err := l.ArchiveCompleted(0)
	if err != nil || seg == nil || seg.RowCount != 1 {
		t.Fatalf("verified-clean job did not archive: %+v, %v", seg, err)
	}
}

func TestTerminalRefsSpanArchiveInOrder(t *testing.T) {
	l, _ := openLedger(t)
	for i := 0; i < 5; i++ {
		settleJob(t, l, fmt.Sprintf("t-%d", i), fmt.Sprintf("h-t-%d", i))
	}
	if _, err := l.ArchiveCompleted(3); err != nil {
		t.Fatal(err)
	}
	refs, err := l.TerminalRefs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 5 {
		t.Fatalf("terminal enumeration lost rows to archival: %d of 5", len(refs))
	}
	for i, r := range refs {
		if r.Seq != int64(i+1) {
			t.Fatalf("enumeration gap at %d: terminal_seq = %d", i, r.Seq)
		}
		want := fmt.Sprintf("t-%d", i)
		if r.ExecutionID != want {
			t.Fatalf("ref %d = %s, want %s", i, r.ExecutionID, want)
		}
	}
}

func TestArchiveSurvivesRestart(t *testing.T) {
	l, path := openLedger(t)
	settleJob(t, l, "old-1", "h-old-1")
	seg, err := l.ArchiveCompleted(0)
	if err != nil || seg == nil {
		t.Fatalf("archive: %+v, %v", seg, err)
	}
	l.Close()

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	j, err := l2.Get("old-1")
	if err != nil || j == nil || !j.Archived {
		t.Fatalf("archived job lost across restart: %+v, %v", j, err)
	}
	if findings := l2.VerifyArchiveSegments(); len(findings) != 0 {
		t.Fatalf("archive verification after restart: %v", findings)
	}
	// The next archive pass allocates the next segment number — no
	// counter regression across lifetimes.
	settleJob(t, l2, "new-1", "h-new-1")
	seg2, err := l2.ArchiveCompleted(0)
	if err != nil || seg2 == nil {
		t.Fatalf("post-restart archive: %+v, %v", seg2, err)
	}
	if seg2.Seq != seg.Seq+1 {
		t.Fatalf("segment seq regressed: %d after %d", seg2.Seq, seg.Seq)
	}
}

func TestVerifyArchiveSegmentsDetectsTamper(t *testing.T) {
	l, path := openLedger(t)
	settleJob(t, l, "victim", "h-victim")
	if _, err := l.ArchiveCompleted(0); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Someone with filesystem access rewrites the archived result —
	// the segment digest was committed over the original bytes.
	tamper(t, path, `UPDATE jobs_archive SET result_json = '{"exit_code":99}' WHERE job_id = 'victim'`)

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	findings := l2.VerifyArchiveSegments()
	if len(findings) == 0 || !strings.Contains(findings[0], "digest") {
		t.Fatalf("archived tampering went undetected: %v", findings)
	}
}

func TestListMergesActiveAndArchive(t *testing.T) {
	l, _ := openLedger(t)
	settleJob(t, l, "a-old", "h-a-old")
	if _, err := l.ArchiveCompleted(0); err != nil {
		t.Fatal(err)
	}
	if _, err := l.InsertJob("b-new", "h-b-new", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	jobs, err := l.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].JobID != "a-old" || !jobs[0].Archived || jobs[1].JobID != "b-new" || jobs[1].Archived {
		t.Fatalf("merged listing wrong: %+v", jobs)
	}
}

// stubCustodian records witnessed segments and can be told to refuse —
// standing in for the external evidence-custody witness.
type stubCustodian struct {
	failNext int
	seen     []string
}

func (c *stubCustodian) WitnessArchive(seg *ArchiveSegment, payload []byte) (*CustodyAck, error) {
	if c.failNext > 0 {
		c.failNext--
		return nil, fmt.Errorf("custodian offline")
	}
	// A real custodian holds the bytes: the stub enforces the same
	// binding so a payload mismatch can never be attested.
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != seg.SHA256 {
		return nil, fmt.Errorf("payload digest does not match segment %s", seg.SHA256)
	}
	c.seen = append(c.seen, seg.SHA256)
	return &CustodyAck{
		AckSeq:        int64(len(c.seen)),
		Signer:        "stub-witness",
		PayloadSHA256: seg.SHA256,
		AckJSON:       `{"record_type":"stub","payload_sha256":"` + seg.SHA256 + `"}`,
	}, nil
}

func TestCustodialArchiveHoldsRowsUntilWitnessed(t *testing.T) {
	l, _ := openLedger(t)
	c := &stubCustodian{failNext: 1}
	if err := l.SetArchiveCustodian(c); err != nil {
		t.Fatal(err)
	}
	settleJob(t, l, "cust-1", "h-cust-1")

	// The witness refuses: archive rows commit, but the operational
	// row is not released — nothing is claimed before custody holds.
	if _, err := l.ArchiveCompleted(0); err == nil {
		t.Fatal("a refused witness still released the archive")
	}
	if n, _ := l.Count(); n != 1 {
		t.Fatalf("operational row released without custody: %d", n)
	}
	segs, _ := l.ArchiveSegments()
	if len(segs) != 1 || segs[0].Custody != "pending" {
		t.Fatalf("custody = %+v", segs)
	}

	// The next pass re-witnesses the pending segment — idempotent —
	// then releases the row. No second segment is created.
	seg, err := l.ArchiveCompleted(0)
	if err != nil {
		t.Fatalf("custody retry: %v", err)
	}
	if len(c.seen) != 1 {
		t.Fatalf("witness calls = %d", len(c.seen))
	}
	if n, _ := l.Count(); n != 0 {
		t.Fatalf("witnessed row still occupies the registry: %d", n)
	}
	segs, _ = l.ArchiveSegments()
	if len(segs) != 1 || segs[0].Custody != "witnessed" {
		t.Fatalf("custody after retry = %+v", segs)
	}
	_ = seg
	// The archived job still answers and still refuses replay.
	if j, _ := l.Get("cust-1"); j == nil || !j.Archived {
		t.Fatal("custodial archive lost the job")
	}
	if _, err := l.InsertJob("cust-2", "h-cust-1", "s", "p", "i", "{}"); !errors.Is(err, ErrContractReplay) {
		t.Fatalf("replay after custodial archive: %v", err)
	}
}

func TestCustodialArchiveResumesAfterRestart(t *testing.T) {
	l, path := openLedger(t)
	c := &stubCustodian{failNext: 1}
	if err := l.SetArchiveCustodian(c); err != nil {
		t.Fatal(err)
	}
	settleJob(t, l, "crash-1", "h-crash-1")
	// The witness fails: the segment and archive rows are durable,
	// the operational row remains — then the daemon dies mid-handoff.
	if _, err := l.ArchiveCompleted(0); err == nil {
		t.Fatal("expected the refused witness to fail the pass")
	}
	l.Close()

	// New lifetime, custodian healthy: finalize must not release the
	// pending row, and the next pass must re-witness and release it.
	c2 := &stubCustodian{}
	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if n, _ := l2.Count(); n != 1 {
		t.Fatalf("restart released an unwitnessed row: %d", n)
	}
	if err := l2.SetArchiveCustodian(c2); err != nil {
		t.Fatal(err)
	}
	if _, err := l2.ArchiveCompleted(0); err != nil {
		t.Fatalf("post-restart archive: %v", err)
	}
	if n, _ := l2.Count(); n != 0 {
		t.Fatalf("pending handoff never completed: %d rows", n)
	}
	if len(c2.seen) != 1 {
		t.Fatalf("the durable segment was never re-witnessed")
	}
}

func TestInspectLedgerSeesTheArchive(t *testing.T) {
	l, path := openLedger(t)
	settleJob(t, l, "audit-1", "h-audit-1")
	if _, err := l.ArchiveCompleted(0); err != nil {
		t.Fatal(err)
	}
	// The writer stays open — inspection is read-only alongside it.
	ro, err := InspectLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	j, err := ro.Get("audit-1")
	if err != nil || j == nil || !j.Archived {
		t.Fatalf("inspector lost the archived job: %+v, %v", j, err)
	}
	jobs, err := ro.List()
	if err != nil || len(jobs) != 1 || !jobs[0].Archived {
		t.Fatalf("inspector listing = %+v, %v", jobs, err)
	}
	refs, err := ro.TerminalRefs()
	if err != nil || len(refs) != 1 || refs[0].ExecutionID != "audit-1" {
		t.Fatalf("inspector terminal refs = %+v, %v", refs, err)
	}
	if findings := ro.VerifyArchiveSegments(); len(findings) != 0 {
		t.Fatalf("read-only verification flagged a clean archive: %v", findings)
	}
}

// The RC7.3-B admission fix: a registry at the bound archives its
// settled rows and admits — only a registry still full of live or
// unresolved work may refuse. Filling via SQL exercises the bound at
// scale without 4096 socket round-trips.
func TestAdmissionArchivesSettledRowsInsteadOfRefusing(t *testing.T) {
	dir := socketDir(t)
	srv := startServer(t, Config{SocketDir: dir, Peers: selfPeer(t)})

	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "executor-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().UnixMilli()
	for i := 0; i < maxJobs; i++ {
		if _, err := db.Exec(
			`INSERT INTO jobs (job_id, contract_hash, seq, submitter, principal, image,
			 contract_json, state, fence_epoch, received_at, updated_at,
			 terminal_seq, receipt_sha256, cleanup_pending)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0)`,
			fmt.Sprintf("settled-%d", i), fmt.Sprintf("h%d", i), i+1, "t", "p", "img",
			"{}", JobStateSucceeded, 1, now, now, i+1, "rcpt"); err != nil {
			t.Fatalf("fill row %d: %v", i, err)
		}
	}
	db.Close()

	conn, reader := connect(t, srv.SocketPath())
	defer conn.Close()
	resp := sendJob(t, conn, reader, validJob())
	if !resp.OK {
		t.Fatalf("admission refused a registry full of settled rows: %+v", resp)
	}
	if n, _ := srv.Ledger().ArchivedCount(); n == 0 {
		t.Fatal("admission never archived the settled rows")
	}
	if n, _ := srv.Ledger().Count(); n >= maxJobs {
		t.Fatalf("active registry still at the bound: %d", n)
	}
}

// A pre-v7 ledger upgrades in place: every existing job identity is
// backfilled into the permanent replay table, so a job admitted before
// the archive existed is just as replay-proof as one admitted after.
func TestMigrationBackfillsPermanentIdentities(t *testing.T) {
	l, path := openLedger(t)
	settleJob(t, l, "pre-1", "h-pre-1")
	if _, err := l.InsertJob("pre-2", "h-pre-2", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Forge the pre-v7 shape: archive tables dropped, identities
	// emptied, version stamped back — the migration must rebuild them.
	tamper(t, path, `
		DROP TABLE job_identities;
		DROP TABLE jobs_archive;
		DROP TABLE archive_segments;
		PRAGMA user_version = 6`)

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if n, _ := l2.IdentityCount(); n != 2 {
		t.Fatalf("identities after migration = %d, want 2", n)
	}
	if _, err := l2.InsertJob("pre-1", "h-pre-1", "s", "p", "i", "{}"); !errors.Is(err, ErrDuplicateJobID) {
		t.Fatalf("pre-migration job_id reusable: %v", err)
	}
	if _, err := l2.InsertJob("post-1", "h-pre-2", "s", "p", "i", "{}"); !errors.Is(err, ErrContractReplay) {
		t.Fatalf("pre-migration contract replayable: %v", err)
	}
	// And the migrated rows archive normally.
	if seg, err := l2.ArchiveCompleted(0); err != nil || seg == nil || seg.RowCount != 1 {
		t.Fatalf("archive after migration: %+v, %v", seg, err)
	}
}

// End-to-end custody: the ledger releases operational rows only after
// a real custody daemon holds the segment payload and signs its
// acknowledgement — the wire protocol, not a stub.
func TestArchiveCustodyOverSocket(t *testing.T) {
	l, _ := openLedger(t)
	custodyDir := t.TempDir()
	sockDir, err := os.MkdirTemp("", "cx-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	witness, err := sandboxcustody.NewServer(sandboxcustody.Config{
		SocketDir:  sockDir,
		CustodyDir: custodyDir,
		KeyPath:    filepath.Join(custodyDir, "witness.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := witness.Start(); err != nil {
		t.Fatal(err)
	}
	defer witness.Stop()

	// A custodian pinned to a different witness key refuses the
	// acknowledgement — it is not the custody the operator configured.
	wrongPin := &SocketCustodian{Socket: witness.SocketPath(), ExpectedSigner: strings.Repeat("0", 64)}
	l2, _ := openLedger(t)
	if err := l2.SetArchiveCustodian(wrongPin); err != nil {
		t.Fatal(err)
	}
	settleJob(t, l2, "pin-1", "h-pin-1")
	if _, err := l2.ArchiveCompleted(0); err == nil {
		t.Fatal("a foreign signer satisfied the custody pin")
	}

	custodian := &SocketCustodian{
		Socket:         witness.SocketPath(),
		ExpectedSigner: witness.SignerFingerprint(),
	}
	if err := l.SetArchiveCustodian(custodian); err != nil {
		t.Fatal(err)
	}
	settleJob(t, l, "sock-1", "h-sock-1")
	seg, err := l.ArchiveCompleted(0)
	if err != nil {
		t.Fatalf("custodial archive: %v", err)
	}
	if seg == nil || seg.Custody != "witnessed" {
		t.Fatalf("custody = %+v", seg)
	}
	if n, _ := l.Count(); n != 0 {
		t.Fatalf("operational row survived witnessed custody: %d", n)
	}
	// The witness holds the payload — and it verifies independently.
	if findings := sandboxcustody.VerifyCustodyDir(custodyDir); len(findings) != 0 {
		t.Fatalf("custody verify: %v", findings)
	}
	held, err := os.ReadFile(filepath.Join(custodyDir, "segments", seg.SHA256))
	if err != nil {
		t.Fatalf("witness does not hold the segment: %v", err)
	}
	sum := sha256.Sum256(held)
	if hex.EncodeToString(sum[:]) != seg.SHA256 {
		t.Fatal("witness holds bytes that do not digest to the segment sha")
	}
}

// A custody daemon that is down refuses archival without losing the
// rows — the registry keeps them for the retry.
func TestArchiveCustodyOfflineHoldsRows(t *testing.T) {
	l, _ := openLedger(t)
	custodian := &SocketCustodian{
		Socket:         filepath.Join(t.TempDir(), "custody.sock"),
		ExpectedSigner: strings.Repeat("0", 64),
	}
	if err := l.SetArchiveCustodian(custodian); err != nil {
		t.Fatal(err)
	}
	settleJob(t, l, "off-1", "h-off-1")
	if _, err := l.ArchiveCompleted(0); err == nil {
		t.Fatal("unreachable custodian still released the archive")
	}
	if n, _ := l.Count(); n != 1 {
		t.Fatalf("operational row released without custody: %d", n)
	}
	segs, _ := l.ArchiveSegments()
	if len(segs) != 1 || segs[0].Custody != "pending" {
		t.Fatalf("custody = %+v", segs)
	}
}
