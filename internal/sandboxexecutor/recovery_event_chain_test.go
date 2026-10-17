package sandboxexecutor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// The WP4 gate (INV-05): committed recovery history is a hash chain
// an outside verifier can recompute, signed checkpoints commit to its
// head so a wholesale local rewrite is detected, and the custody
// outbox keeps the obligation to replicate durable across crashes.
// Tampering at any layer — a modified row, a deleted range, a forged
// signature, an unknown signer, a competing custody head — must be
// detected, never absorbed.

// recordN writes n recovery events and returns the chain head.
func recordN(t *testing.T, l *Ledger, n int) (head string, last int64) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.RecordRecoveryEvent("probe", "job-1",
			fmt.Sprintf("event %d", i), time.Now().UTC()); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
	}
	head, last, err := l.RecoveryChainHead()
	if err != nil {
		t.Fatalf("chain head: %v", err)
	}
	return head, last
}

func TestRecoveryChainVerifiesClean(t *testing.T) {
	l, _ := openLedger(t)
	head, last := recordN(t, l, 5)
	if last == 0 || head == "" {
		t.Fatalf("empty chain head after 5 events: head=%q last=%d", head, last)
	}
	findings, err := l.VerifyRecoveryEvents()
	if err != nil {
		t.Fatalf("VerifyRecoveryEvents: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean chain reported findings: %v", findings)
	}
	// Every event but the first must name its predecessor's digest.
	var orphans int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM recovery_events
		WHERE prev_event_sha256 = '' AND seq != (SELECT MIN(seq) FROM recovery_events)`).Scan(&orphans); err != nil {
		t.Fatalf("orphan count: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("%d events lost their chain linkage", orphans)
	}
}

func TestRecoveryChainDetectsModifiedEvent(t *testing.T) {
	l, _ := openLedger(t)
	recordN(t, l, 4)
	if _, err := l.db.Exec(`UPDATE recovery_events SET detail = 'forged outcome' WHERE seq = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	findings, err := l.VerifyRecoveryEvents()
	if err != nil {
		t.Fatalf("VerifyRecoveryEvents: %v", err)
	}
	if len(findings) == 0 || !strings.Contains(findings[0], "does not recompute") {
		t.Fatalf("modified event not detected: %v", findings)
	}
}

func TestRecoveryChainDetectsDeletedEvent(t *testing.T) {
	l, _ := openLedger(t)
	recordN(t, l, 4)
	if _, err := l.db.Exec(`DELETE FROM recovery_events WHERE seq = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	findings, err := l.VerifyRecoveryEvents()
	if err != nil {
		t.Fatalf("VerifyRecoveryEvents: %v", err)
	}
	if len(findings) == 0 || !strings.Contains(findings[0], "deleted, reordered or forged predecessor") {
		t.Fatalf("deleted event not detected: %v", findings)
	}
}

func TestRecoveryChainDetectsReorderedEvents(t *testing.T) {
	l, _ := openLedger(t)
	recordN(t, l, 4)
	// Swap the content of events 2 and 3 in place (same seqs, swapped
	// payloads): a reorder attack that keeps row positions.
	var k2, d2, k3, d3 string
	var a2, a3 int64
	if err := l.db.QueryRow(`SELECT kind, detail, at_ms FROM recovery_events WHERE seq = 2`).Scan(&k2, &d2, &a2); err != nil {
		t.Fatalf("read ev2: %v", err)
	}
	if err := l.db.QueryRow(`SELECT kind, detail, at_ms FROM recovery_events WHERE seq = 3`).Scan(&k3, &d3, &a3); err != nil {
		t.Fatalf("read ev3: %v", err)
	}
	if _, err := l.db.Exec(`UPDATE recovery_events SET kind=?, detail=?, at_ms=? WHERE seq=2`, k3, d3, a3); err != nil {
		t.Fatalf("swap ev2: %v", err)
	}
	if _, err := l.db.Exec(`UPDATE recovery_events SET kind=?, detail=?, at_ms=? WHERE seq=3`, k2, d2, a2); err != nil {
		t.Fatalf("swap ev3: %v", err)
	}
	findings, err := l.VerifyRecoveryEvents()
	if err != nil {
		t.Fatalf("VerifyRecoveryEvents: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("reordered events not detected")
	}
}

func TestRecoveryChainDetectsClaimUIDTamper(t *testing.T) {
	l, _ := openLedger(t)
	// An event recorded under claim generation 7 — flipping its
	// durable claim binding must fail verification.
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	if err := l.recordRecoveryEventTx(tx, "probe", "job-1", "under claim 7", time.Now().UTC(), 7); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := l.db.Exec(`UPDATE recovery_events SET claim_uid = 99 WHERE detail = 'under claim 7'`); err != nil {
		t.Fatalf("tamper claim_uid: %v", err)
	}
	findings, err := l.VerifyRecoveryEvents()
	if err != nil {
		t.Fatalf("VerifyRecoveryEvents: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("claim_uid tamper not detected")
	}
}

func TestRecoveryCheckpointSignsAndVerifies(t *testing.T) {
	l, _ := openLedger(t)
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	recordN(t, l, 3)
	seq, emitted, err := l.EmitRecoveryCheckpoint(signer)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !emitted || seq == 0 {
		t.Fatalf("checkpoint not emitted: seq=%d emitted=%v", seq, emitted)
	}
	var blob string
	if err := l.db.QueryRow(`SELECT checkpoint_json FROM recovery_outbox WHERE seq = ?`, seq).Scan(&blob); err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	var cp RecoveryCheckpoint
	if err := json.Unmarshal([]byte(blob), &cp); err != nil {
		t.Fatalf("checkpoint decode: %v", err)
	}
	trust := map[string]bool{cp.Signer: true}
	if err := l.CheckRecoveryCheckpoint(&cp, trust); err != nil {
		t.Fatalf("retained checkpoint rejected: %v", err)
	}
	// Emitting again at the same head is a no-op.
	if _, emitted, err := l.EmitRecoveryCheckpoint(signer); err != nil || emitted {
		t.Fatalf("redundant emission at unchanged head: emitted=%v err=%v", emitted, err)
	}
	// Appending past the tip keeps the retained checkpoint valid
	// (the prefix property).
	recordN(t, l, 2)
	if err := l.CheckRecoveryCheckpoint(&cp, trust); err != nil {
		t.Fatalf("checkpoint rejected after append: %v", err)
	}
}

func TestRecoveryCheckpointRejectsUntrustedAndForged(t *testing.T) {
	l, _ := openLedger(t)
	signer, _ := evidence.GenerateSigner()
	rogue, _ := evidence.GenerateSigner()
	recordN(t, l, 2)
	cp, err := l.signRecoveryCheckpoint(signer, time.Now().UTC())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	trust := map[string]bool{cp.Signer: true}
	// Unknown signer: the checkpoint verifies cryptographically but
	// the fingerprint is not in the trust root.
	if err := VerifyRecoveryCheckpointSignature(cp, map[string]bool{}); err == nil {
		t.Fatalf("untrusted signer accepted")
	}
	// Rogue-signed checkpoint under the trusted map.
	rogueCP, err := l.signRecoveryCheckpoint(rogue, time.Now().UTC())
	if err != nil {
		t.Fatalf("rogue sign: %v", err)
	}
	if err := VerifyRecoveryCheckpointSignature(rogueCP, trust); err == nil {
		t.Fatalf("rogue signer accepted under trust root")
	}
	// Forged signature field.
	forged := *cp
	forged.Signature = cp.Signature[:len(cp.Signature)-2] + "00"
	if err := VerifyRecoveryCheckpointSignature(&forged, trust); err == nil {
		t.Fatalf("forged signature accepted")
	}
	// Tampered covered range under a valid signature.
	tampered := *cp
	tampered.EventCount++
	if err := VerifyRecoveryCheckpointSignature(&tampered, trust); err == nil {
		t.Fatalf("tampered checkpoint field accepted")
	}
}

func TestRecoveryCheckpointDetectsRollbackAndTruncation(t *testing.T) {
	l, _ := openLedger(t)
	signer, _ := evidence.GenerateSigner()
	recordN(t, l, 3)
	cp, err := l.signRecoveryCheckpoint(signer, time.Now().UTC())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	trust := map[string]bool{cp.Signer: true}
	// Local history rolled back past the checkpoint's committed tip:
	// events after it stay, but the tip itself is gone — a store
	// restored from before the commit.
	recordN(t, l, 2)
	if _, err := l.db.Exec(`DELETE FROM recovery_events WHERE seq = ?`, cp.LastSeq); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	err = l.CheckRecoveryCheckpoint(cp, trust)
	if err == nil || !strings.Contains(err.Error(), "no longer holds") {
		t.Fatalf("rollback past checkpoint not detected: %v", err)
	}
}

func TestRecoveryCheckpointDetectsRewrite(t *testing.T) {
	l, _ := openLedger(t)
	signer, _ := evidence.GenerateSigner()
	recordN(t, l, 3)
	cp, err := l.signRecoveryCheckpoint(signer, time.Now().UTC())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	trust := map[string]bool{cp.Signer: true}
	// Rewrite covered history: change a middle event's content and
	// recompute the chain — even a fully recomputed chain fails the
	// retained checkpoint.
	if _, err := l.db.Exec(`UPDATE recovery_events SET detail='attacker-wins' WHERE seq=2`); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := l.backfillRecoveryChain(); err != nil {
		t.Fatalf("recompute after rewrite: %v", err)
	}
	err = l.CheckRecoveryCheckpoint(cp, trust)
	if err == nil {
		t.Fatalf("rewritten chain accepted against retained checkpoint")
	}
}

func TestRecoveryEventWriteIsAtomicWithState(t *testing.T) {
	l, _ := openLedger(t)
	if _, err := l.insertJob("job-1", "h-1", "s", "p", "i", "{}", "RECORDED"); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	// Make the evidence write fail: the state change it guards must
	// roll back with it — an unevidenced cleanup mark never lands.
	if _, err := l.db.Exec(`CREATE TRIGGER block_evidence BEFORE INSERT ON recovery_events
		BEGIN SELECT RAISE(ABORT, 'evidence write forced off'); END;`); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	err := l.MarkCleanupPending("job-1", "deferred")
	if err == nil {
		t.Fatalf("mark succeeded while evidence write was blocked")
	}
	var pending int
	if qerr := l.db.QueryRow(`SELECT cleanup_pending FROM jobs WHERE job_id='job-1'`).Scan(&pending); qerr != nil {
		t.Fatalf("read flag: %v", qerr)
	}
	// The flag write never committed — no phantom cleanup debt.
	if pending != 0 {
		t.Fatalf("cleanup_pending committed without its evidence")
	}
}

// fakeRecoveryCustodian answers WitnessRecoveryCheckpoint from a
// scripted sequence of ack sequences, to drive drain, retry, and
// competing-head tests.
type fakeRecoveryCustodian struct {
	ackSeq   int64
	calls    int
	failNext bool
	seen     map[string]bool
}

func (f *fakeRecoveryCustodian) WitnessRecoveryCheckpoint(outboxSeq int64, checkpointJSON []byte) (*CustodyAck, error) {
	f.calls++
	if f.failNext {
		f.failNext = false
		return nil, fmt.Errorf("custodian unreachable")
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	sum := fmt.Sprintf("%x", checkpointJSON)
	f.seen[sum] = true
	return &CustodyAck{
		AckSeq:        f.ackSeq,
		Signer:        "fake-witness",
		PayloadSHA256: "00",
		AckJSON:       fmt.Sprintf(`{"ack_seq":%d,"signer":"fake-witness"}`, f.ackSeq),
	}, nil
}

func TestRecoveryCustodyOutboxDrainsAndRetries(t *testing.T) {
	l, _ := openLedger(t)
	signer, _ := evidence.GenerateSigner()
	recordN(t, l, 2)
	if _, emitted, err := l.EmitRecoveryCheckpoint(signer); err != nil || !emitted {
		t.Fatalf("emit: emitted=%v err=%v", emitted, err)
	}
	pending, err := l.PendingRecoveryCustody(0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending after emit: %d err=%v", len(pending), err)
	}
	// A failed witness leaves the obligation durable.
	fc := &fakeRecoveryCustodian{ackSeq: 1, failNext: true}
	if err := l.DrainRecoveryCustody(fc, nil); err != nil {
		t.Fatalf("drain: %v", err)
	}
	pending, _ = l.PendingRecoveryCustody(0)
	if len(pending) != 1 {
		t.Fatalf("failed witness dropped the obligation")
	}
	// A successful witness records custody; the outbox empties.
	if err := l.DrainRecoveryCustody(fc, nil); err != nil {
		t.Fatalf("drain: %v", err)
	}
	pending, _ = l.PendingRecoveryCustody(0)
	if len(pending) != 0 {
		t.Fatalf("acknowledged checkpoint still pending")
	}
	// Idempotent re-drain: nothing pending, no calls.
	if err := l.DrainRecoveryCustody(fc, nil); err != nil {
		t.Fatalf("idempotent drain: %v", err)
	}
}

func TestRecoveryCustodyDetectsCompetingHead(t *testing.T) {
	l, _ := openLedger(t)
	signer, _ := evidence.GenerateSigner()
	recordN(t, l, 2)
	if _, _, err := l.EmitRecoveryCheckpoint(signer); err != nil {
		t.Fatalf("emit: %v", err)
	}
	recordN(t, l, 1)
	if _, _, err := l.EmitRecoveryCheckpoint(signer); err != nil {
		t.Fatalf("emit2: %v", err)
	}
	// A custodian answering two different checkpoints with the same
	// ack sequence is presenting a competing checkpoint head — the
	// second ack is escalated and left pending, never recorded.
	var audits []string
	fc := &fakeRecoveryCustodian{ackSeq: 5}
	if err := l.DrainRecoveryCustody(fc, func(f string, a ...any) {
		audits = append(audits, fmt.Sprintf(f, a...))
	}); err != nil {
		t.Fatalf("drain1: %v", err)
	}
	pending, _ := l.PendingRecoveryCustody(0)
	if len(pending) != 1 {
		t.Fatalf("competing-head ack was recorded as custody")
	}
	if len(audits) == 0 || !strings.Contains(audits[0], "competing checkpoint head") {
		t.Fatalf("competing head not escalated: %v", audits)
	}
	// An honestly advancing sequence clears the pending row.
	fc.ackSeq = 6
	if err := l.DrainRecoveryCustody(fc, nil); err != nil {
		t.Fatalf("drain2: %v", err)
	}
	pending, _ = l.PendingRecoveryCustody(0)
	if len(pending) != 0 {
		t.Fatalf("advancing ack did not record custody")
	}
}

func TestRecoveryChainMigrationBackfillsLegacyEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.db")
	// Build a pre-chain ledger by hand: stamped at schema 6 so every
	// intermediate migration runs — v7 creates the archive tables,
	// v9 the recovery tables (already present here in old shape),
	// v10/v11 fence the attempts, and v12 must ALTER the
	// pre-existing old-shape recovery_events and backfill the chain
	// over the legacy rows seeded here.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE executor_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE jobs (job_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL UNIQUE,
			seq INTEGER NOT NULL UNIQUE, submitter TEXT NOT NULL, principal TEXT NOT NULL,
			image TEXT NOT NULL DEFAULT '', contract_json TEXT NOT NULL, state TEXT NOT NULL,
			fence_epoch INTEGER NOT NULL, backend_id TEXT NOT NULL DEFAULT '',
			backend_handle TEXT NOT NULL DEFAULT '', backend_job_id TEXT NOT NULL DEFAULT '',
			backend_boot_id TEXT NOT NULL DEFAULT '', policy_digest TEXT NOT NULL DEFAULT '',
			dispatch_nonce TEXT NOT NULL DEFAULT '', image_digest TEXT NOT NULL DEFAULT '',
			runtime_identity TEXT NOT NULL DEFAULT '', dispatch_class TEXT NOT NULL DEFAULT '',
			received_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, exit_code INTEGER,
			error TEXT NOT NULL DEFAULT '', result_json TEXT NOT NULL DEFAULT '',
			terminal_seq INTEGER, receipt_sha256 TEXT NOT NULL DEFAULT '',
			artifact_sha256 TEXT NOT NULL DEFAULT '', cleanup_pending INTEGER NOT NULL DEFAULT 0,
			cleanup_error TEXT NOT NULL DEFAULT '');
		CREATE TABLE recovery_attempts (job_id TEXT NOT NULL, action TEXT NOT NULL,
			attempts INTEGER NOT NULL, next_due_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL,
			PRIMARY KEY (job_id, action));
		CREATE TABLE recovery_events (seq INTEGER PRIMARY KEY AUTOINCREMENT,
			at_ms INTEGER NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '');
		INSERT INTO recovery_events (at_ms, kind, subject, detail) VALUES
			(1000, 'claim', 'job-old', 'legacy claim record'),
			(2000, 'cleanup', 'job-old', 'legacy cleanup record');
		PRAGMA user_version = 6;
	`)
	if err != nil {
		db.Close()
		t.Fatalf("build legacy db: %v", err)
	}
	db.Close()

	l, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("OpenLedger over v6: %v", err)
	}
	defer l.Close()
	// Legacy rows are bound into the chain but honestly unauthenticated.
	var unauth, hashed int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM recovery_events WHERE authenticated = 0`).Scan(&unauth); err != nil {
		t.Fatalf("count legacy: %v", err)
	}
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM recovery_events WHERE event_sha256 != ''`).Scan(&hashed); err != nil {
		t.Fatalf("count hashed: %v", err)
	}
	if unauth != 2 || hashed != 2 {
		t.Fatalf("legacy rows: unauth=%d hashed=%d, want 2/2", unauth, hashed)
	}
	findings, err := l.VerifyRecoveryEvents()
	if err != nil {
		t.Fatalf("verify migrated chain: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("migrated legacy chain does not verify: %v", findings)
	}
	// New writes after migration are authenticated and extend the
	// same chain — no seam between legacy and attested history.
	if err := l.RecordRecoveryEvent("probe", "job-new", "post-migration", time.Now().UTC()); err != nil {
		t.Fatalf("record after migration: %v", err)
	}
	var auth int
	if err := l.db.QueryRow(`SELECT authenticated FROM recovery_events ORDER BY seq DESC LIMIT 1`).Scan(&auth); err != nil {
		t.Fatalf("read new row: %v", err)
	}
	if auth != 1 {
		t.Fatalf("post-migration event not authenticated")
	}
	findings, _ = l.VerifyRecoveryEvents()
	if len(findings) != 0 {
		t.Fatalf("mixed chain does not verify: %v", findings)
	}
}
