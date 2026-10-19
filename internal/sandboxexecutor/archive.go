package sandboxexecutor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/sandboxcustody"
)

// Durable archival: the jobs table is the ACTIVE registry — every row
// whose outcome or cleanup could still change. A terminal job whose
// resources are verifiably gone is history: it cannot move again, so
// holding it in the active set only burns the admission bound. Archival
// moves the settled row's full payload to jobs_archive, atomically,
// inside a content-addressed segment — and leaves the job's identity
// (job_id, contract_hash, seq) in job_identities forever, so replay
// protection never depends on a row still being operational.
//
// Guarantees this file keeps:
//
//   - a job_id or contract_hash is never reusable, archived or not;
//   - a terminal row is archived only after the terminal write is
//     durable (terminal_seq assigned) and its receipt bound;
//   - a row carrying cleanup_pending is never archived — a VM that may
//     still exist is operational state, not history;
//   - the terminal enumeration (TerminalRefs) reads jobs ∪ archive, so
//     a checkpoint's committed enumeration cannot lose a row to
//     archival;
//   - every stage is transaction-scoped: a crash leaves either the
//     pre- or post-image, never a half-moved row. The one multi-
//     transaction path (external custody) is finalized idempotently on
//     open by finalizeArchives.

// ArchiveCustodian is the pluggable evidence-custody hook. When one is
// configured, archival commits the segment and the archive rows first,
// then asks the custodian to witness them — the operational rows are
// deleted only after the custodian acknowledges. A custodian failure
// aborts archival without losing anything. With no custodian the whole
// transition is one transaction and custody records "local": the
// archive is its own custody.
type ArchiveCustodian interface {
	// WitnessArchive durably acknowledges the segment's content to
	// external custody. It is called after the segment rows are
	// committed, before the operational rows are released, and must be
	// idempotent on the same segment digest. The payload is the
	// canonical segment bytes — sha256(payload) == seg.SHA256 — so the
	// custodian holds the archived content itself, not just a promise
	// that it existed. The returned acknowledgement is the verified
	// custody reference the ledger persists with the segment before
	// any row may leave.
	WitnessArchive(seg *ArchiveSegment, payload []byte) (*CustodyAck, error)
	// CustodyTrustRoot declares the witness trust under which this
	// custodian's acknowledgements must verify — controlled
	// configuration, never learned from an acknowledgement. The
	// recording boundary re-verifies every returned ack against it:
	// an empty root means no custody can be recorded, failing closed.
	CustodyTrustRoot() *sandboxcustody.TrustRoot
}

// CustodyAck is the verified custody acknowledgement reference the
// ledger stores with its segment — the durable link between "the rows
// were released" and "an independent witness provably holds them".
type CustodyAck struct {
	// AckSeq is the acknowledgement's position in the witness's chain.
	AckSeq int64 `json:"ack_seq"`
	// Signer is the witness key that signed it.
	Signer string `json:"signer"`
	// PayloadSHA256 is the segment digest the ack commits to.
	PayloadSHA256 string `json:"payload_sha256"`
	// AckJSON is the canonical signed acknowledgement record — the
	// complete evidence an auditor re-verifies, not a summary.
	AckJSON string `json:"ack_json"`
	// RequestCreatedAt is the witness-request timestamp a v2
	// acknowledgement binds — surfaced so the recording boundary can
	// re-verify request-instance identity, not just the adapter.
	RequestCreatedAt int64 `json:"request_created_at,omitempty"`
}

// ArchiveSegment is the immutable record of one archival transition:
// which terminal rows moved, the digest of the canonical payload, and
// how the archive's custody is held.
type ArchiveSegment struct {
	Seq              int64     `json:"segment_seq"`
	FirstTerminalSeq int64     `json:"first_terminal_seq"`
	LastTerminalSeq  int64     `json:"last_terminal_seq"`
	RowCount         int       `json:"row_count"`
	SHA256           string    `json:"sha256"`
	Custody          string    `json:"custody"`
	CreatedAt        time.Time `json:"created_at"`
}

// archiveRow is one archived job's canonical payload — the fields the
// segment digest covers, in declared order. JSON marshaling a struct is
// field-order deterministic, so the digest is reproducible by any
// verifier that reads the archive back.
type archiveRow struct {
	JobID           string `json:"job_id"`
	ContractHash    string `json:"contract_hash"`
	Seq             uint64 `json:"seq"`
	Submitter       string `json:"submitter"`
	Principal       string `json:"principal"`
	Image           string `json:"image"`
	ContractJSON    string `json:"contract_json"`
	State           string `json:"state"`
	FenceEpoch      uint64 `json:"fence_epoch"`
	BackendID       string `json:"backend_id"`
	BackendHandle   string `json:"backend_handle"`
	BackendJobID    string `json:"backend_job_id"`
	BackendBootID   string `json:"backend_boot_id"`
	PolicyDigest    string `json:"policy_digest"`
	DispatchNonce   string `json:"dispatch_nonce"`
	ImageDigest     string `json:"image_digest"`
	RuntimeIdentity string `json:"runtime_identity"`
	DispatchClass   string `json:"dispatch_class"`
	ReceivedAt      int64  `json:"received_at"`
	UpdatedAt       int64  `json:"updated_at"`
	ExitCode        *int64 `json:"exit_code"`
	Error           string `json:"error"`
	ResultJSON      string `json:"result_json"`
	TerminalSeq     int64  `json:"terminal_seq"`
	ReceiptSHA256   string `json:"receipt_sha256"`
	ArtifactSHA256  string `json:"artifact_sha256"`
}

func jobArchiveRow(j *LedgerJob) archiveRow {
	return archiveRow{
		JobID: j.JobID, ContractHash: j.ContractHash, Seq: j.Seq,
		Submitter: j.Submitter, Principal: j.Principal, Image: j.Image,
		ContractJSON: j.ContractJSON, State: j.State, FenceEpoch: j.FenceEpoch,
		BackendID: j.BackendID, BackendHandle: j.BackendHandle,
		BackendJobID: j.BackendJobID, BackendBootID: j.BackendBootID,
		PolicyDigest: j.PolicyDigest, DispatchNonce: j.DispatchNonce,
		ImageDigest: j.ImageDigest, RuntimeIdentity: j.RuntimeIdentity,
		DispatchClass: j.DispatchClass,
		ReceivedAt:    j.receivedAtRaw, UpdatedAt: j.updatedAtRaw,
		ExitCode: j.ExitCode, Error: j.Error, ResultJSON: j.ResultJSON,
		TerminalSeq: j.TerminalSeq, ReceiptSHA256: j.ReceiptSHA256,
		ArtifactSHA256: j.ArtifactSHA256,
	}
}

// archiveColumns is jobs_archive's payload projection — jobColumns in
// the same order — used by both the INSERT ... SELECT and the archive
// read path.
const archiveInsertCols = `job_id, contract_hash, seq, submitter, principal, image, contract_json,
	state, fence_epoch, backend_id, backend_handle, backend_job_id, backend_boot_id, policy_digest,
	dispatch_nonce, image_digest, runtime_identity, dispatch_class,
	received_at, updated_at,
	exit_code, error, result_json, terminal_seq, receipt_sha256, artifact_sha256`

// settledSQL is the safety predicate: terminal enumeration
// membership (terminal_seq), verified cleanup (cleanup_pending = 0),
// and a bound receipt — the evidence chain must already attest the
// outcome before the operational row may leave. Release deletes carry
// it too, so a row that stopped settling cannot leave.
const settledSQL = `terminal_seq IS NOT NULL AND cleanup_pending = 0
	AND receipt_sha256 != ''`

// archiveEligibleSQL adds "not already archived" — the candidate-scan
// predicate; archival of an already-archived id would collide on the
// archive primary key anyway, but skipping them keeps the scan honest.
const archiveEligibleSQL = settledSQL + `
	AND job_id NOT IN (SELECT job_id FROM jobs_archive)`

// SetArchiveCustodian installs the evidence-custody hook. It must be
// called before any ArchiveCompleted — replacing the custodian after
// segments exist is refused, because pending segments' custody would
// change hands silently.
func (l *Ledger) SetArchiveCustodian(c ArchiveCustodian) error {
	l.custMu.Lock()
	defer l.custMu.Unlock()
	if l.custodian != nil && c != l.custodian {
		return fmt.Errorf("archive custodian already installed")
	}
	l.custodian = c
	return nil
}

// nextArchiveSeq allocates the archive's monotonic segment counter —
// persisted like next_seq/next_terminal_seq so ordering survives
// restarts.
func (l *Ledger) nextArchiveSeq(tx *sql.Tx) (int64, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM executor_meta WHERE key = 'next_archive_seq'`).Scan(&raw)
	var seq int64
	switch {
	case err == sql.ErrNoRows:
		seq = 0
	case err != nil:
		return 0, fmt.Errorf("read archive seq: %w", err)
	default:
		if _, err := fmt.Sscanf(raw, "%d", &seq); err != nil {
			return 0, fmt.Errorf("corrupt archive seq %q: %w", raw, err)
		}
	}
	seq++
	if _, err := tx.Exec(
		`INSERT INTO executor_meta (key, value) VALUES ('next_archive_seq', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprint(seq)); err != nil {
		return 0, err
	}
	return seq, nil
}

// ArchiveCompleted moves up to limit settled terminal jobs into the
// immutable archive and returns the segment that carries them, or nil
// when nothing was eligible. It is safe to call repeatedly — eligibility
// is a query, not a flag — and safe across a crash at any point: the
// only externally visible mutation is transaction-committed, and an
// interrupted custodial handoff resumes through finalizeArchives.
//
// The segment digest binds the canonical payload of every row moved;
// VerifyArchiveSegments re-derives it from the archive, so a post-
// commit rewrite of archived bytes is detectable tampering.
func (l *Ledger) ArchiveCompleted(limit int) (*ArchiveSegment, error) {
	l.archiveMu.Lock()
	defer l.archiveMu.Unlock()

	l.custMu.Lock()
	custodian := l.custodian
	l.custMu.Unlock()

	// Resume any custodial handoff a previous pass or lifetime left
	// pending: its archive rows are durable but the operational rows
	// were never released, and eligibility excludes them — without
	// this retry a pending segment starves the registry forever.
	// Witnessing is idempotent on the segment digest.
	if custodian != nil {
		if err := l.retryPendingCustody(custodian); err != nil {
			return nil, err
		}
	} else if err := l.finalizeArchives(); err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 256
	}
	rows, err := l.archiveEligible(limit)
	if err != nil {
		return nil, fmt.Errorf("select archive candidates: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	payload := make([]archiveRow, 0, len(rows))
	for _, j := range rows {
		payload = append(payload, jobArchiveRow(j))
	}
	segBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal archive segment: %w", err)
	}
	segSum := sha256.Sum256(segBytes)
	seg := &ArchiveSegment{
		FirstTerminalSeq: rows[0].TerminalSeq,
		LastTerminalSeq:  rows[len(rows)-1].TerminalSeq,
		RowCount:         len(rows),
		SHA256:           hex.EncodeToString(segSum[:]),
		CreatedAt:        time.Now().UTC(),
	}

	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("archive begin: %w", err)
	}
	defer tx.Rollback()
	seq, err := l.nextArchiveSeq(tx)
	if err != nil {
		return nil, err
	}
	seg.Seq = seq
	custody := "local"
	if custodian != nil {
		// External custody: rows stay operational until the custodian
		// acknowledges — custody pending means not yet releasable.
		custody = "pending"
	}
	seg.Custody = custody
	if _, err := tx.Exec(
		`INSERT INTO archive_segments (segment_seq, first_terminal_seq, last_terminal_seq,
		 row_count, sha256, custody, created_at) VALUES (?,?,?,?,?,?,?)`,
		seq, seg.FirstTerminalSeq, seg.LastTerminalSeq, seg.RowCount,
		seg.SHA256, custody, seg.CreatedAt.UnixMilli()); err != nil {
		return nil, fmt.Errorf("insert archive segment: %w", err)
	}
	for _, j := range rows {
		// The copy re-checks eligibility against the committed row —
		// a candidate read outside this transaction may have changed
		// underneath (a cleanup marked pending, say), and archiving a
		// row that no longer settles would release a VM that may
		// still exist. Rows-copied must be exactly one or the row is
		// not what the eligibility scan saw.
		res, err := tx.Exec(
			`INSERT INTO jobs_archive (`+archiveInsertCols+`, archived_at, archive_seq)
			 SELECT `+archiveInsertCols+`, ?, ? FROM jobs
			 WHERE job_id = ? AND `+archiveEligibleSQL,
			seg.CreatedAt.UnixMilli(), seq, j.JobID)
		if err != nil {
			return nil, fmt.Errorf("archive row %s: %w", j.JobID, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, fmt.Errorf("archive row %s: row changed underneath the pass", j.JobID)
		}
	}
	if custodian == nil {
		// Single-transaction path: segment, archive rows, operational
		// release and identity bookkeeping commit or roll back together.
		if err := l.releaseArchivedTx(tx, rows); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("archive commit: %w", err)
	}

	if custodian != nil {
		ack, err := custodian.WitnessArchive(seg, segBytes)
		if err != nil {
			// The archive rows and the pending segment are durable; the
			// operational rows were never released. A later pass retries
			// the handoff — nothing is lost and nothing was claimed.
			return nil, fmt.Errorf("archive custody witness refused: %w", err)
		}
		// The boundary verifies — the adapter's own check is defense
		// in depth, never the enforcement point: the recorded ack must
		// bind this exact segment and verify under the custodian's
		// declared trust root before any operational row may leave.
		if err := verifyArchiveCustodyAck(seg, ack, custodian.CustodyTrustRoot()); err != nil {
			return nil, fmt.Errorf("archive custody acknowledgement failed boundary verification — the segment stays pending: %w", err)
		}
		if err := l.completeCustodial(seg, ack); err != nil {
			return nil, err
		}
		seg.Custody = "witnessed"
	}
	return seg, nil
}

// releaseArchivedTx deletes the archived operational rows and marks
// their identities archived — inside the caller's transaction so the
// move is atomic.
func (l *Ledger) releaseArchivedTx(tx *sql.Tx, rows []*LedgerJob) error {
	for _, j := range rows {
		res, err := tx.Exec(
			`DELETE FROM jobs WHERE job_id = ? AND `+settledSQL, j.JobID)
		if err != nil {
			return fmt.Errorf("release archived row %s: %w", j.JobID, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("release archived row %s: row changed underneath the pass", j.JobID)
		}
		if _, err := tx.Exec(
			`UPDATE job_identities SET archived_at = ? WHERE job_id = ?`,
			time.Now().UTC().UnixMilli(), j.JobID); err != nil {
			return fmt.Errorf("mark identity archived %s: %w", j.JobID, err)
		}
	}
	return nil
}

// completeCustodial finishes a witnessed archive: custody flips to
// 'witnessed', the verified acknowledgement reference persists, and
// the operational rows release — one transaction, so a crash rolls
// back to the pending shape a custody retry can resume. Only the pass
// that actually flips custody releases rows; a retry that finds the
// segment already witnessed leaves the release to the finalize pass,
// which makes the whole handoff idempotent.
func (l *Ledger) completeCustodial(seg *ArchiveSegment, ack *CustodyAck) error {
	ackJSON := ""
	if ack != nil {
		raw, err := json.Marshal(ack)
		if err != nil {
			return fmt.Errorf("marshal custody ack reference: %w", err)
		}
		ackJSON = string(raw)
	}
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("custodial finalize begin: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(
		`UPDATE archive_segments SET custody = 'witnessed', custody_ack = ?
		 WHERE segment_seq = ? AND custody = 'pending'`,
		ackJSON, seg.Seq)
	if err != nil {
		return fmt.Errorf("mark segment witnessed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return tx.Commit()
	}
	rows, err := l.archivedRowsTx(tx, seg.Seq)
	if err != nil {
		return err
	}
	if err := l.releaseArchivedTx(tx, rows); err != nil {
		return err
	}
	return tx.Commit()
}

// retryPendingCustody re-witnesses every segment still awaiting
// custody acknowledgement — the crash window between the archive
// commit and the custodian call. Each is idempotent: the custodian
// keys on the segment digest, and completeCustodial no-ops once the
// custody flip already landed.
func (l *Ledger) retryPendingCustody(c ArchiveCustodian) error {
	pending, err := l.pendingSegments()
	if err != nil {
		return err
	}
	for _, seg := range pending {
		// Re-derive the canonical payload from the durable archive
		// rows — the custodian holds the bytes, so the retry hands
		// over the same content the first attempt computed.
		payload, err := l.segmentPayload(seg.Seq)
		if err != nil {
			return fmt.Errorf("archive custody retry for segment %d cannot rebuild payload: %w", seg.Seq, err)
		}
		ack, err := c.WitnessArchive(seg, payload)
		if err != nil {
			return fmt.Errorf("archive custody witness refused segment %d: %w", seg.Seq, err)
		}
		if err := verifyArchiveCustodyAck(seg, ack, c.CustodyTrustRoot()); err != nil {
			return fmt.Errorf("archive custody acknowledgement for segment %d failed boundary verification: %w", seg.Seq, err)
		}
		if err := l.completeCustodial(seg, ack); err != nil {
			return err
		}
	}
	return nil
}

// pendingSegments lists segments whose custody handoff never finished.
func (l *Ledger) pendingSegments() ([]*ArchiveSegment, error) {
	rows, err := l.db.Query(
		`SELECT segment_seq, first_terminal_seq, last_terminal_seq, row_count,
		 sha256, custody, created_at FROM archive_segments
		 WHERE custody = 'pending' ORDER BY segment_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ArchiveSegment
	for rows.Next() {
		s := &ArchiveSegment{}
		var created int64
		if err := rows.Scan(&s.Seq, &s.FirstTerminalSeq, &s.LastTerminalSeq,
			&s.RowCount, &s.SHA256, &s.Custody, &created); err != nil {
			return nil, err
		}
		s.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, s)
	}
	return out, rows.Err()
}

// finalizeArchives runs at open and before each archive pass: rows
// already copied into the archive whose segment no longer pends custody
// are released from the active table — the crash window between the
// archive commit and the release commit of a custodial archive.
// Rows whose segment still pends custody stay: deleting them before
// the custodian acknowledges would drop the only copy custody saw.
func (l *Ledger) finalizeArchives() error {
	_, err := l.db.Exec(
		`DELETE FROM jobs WHERE ` + settledSQL + ` AND job_id IN (
			SELECT a.job_id FROM jobs_archive a
			JOIN archive_segments s ON s.segment_seq = a.archive_seq
			WHERE s.custody != 'pending')`)
	if err != nil {
		return fmt.Errorf("finalize archives: %w", err)
	}
	if _, err := l.db.Exec(
		`UPDATE job_identities SET archived_at = COALESCE(archived_at, ?)
		 WHERE job_id IN (SELECT job_id FROM jobs_archive)`, time.Now().UTC().UnixMilli()); err != nil {
		return fmt.Errorf("finalize archive identities: %w", err)
	}
	return nil
}

// archiveEligible returns the oldest settled rows eligible to archive.
func (l *Ledger) archiveEligible(limit int) ([]*LedgerJob, error) {
	rows, err := l.db.Query(
		`SELECT `+jobColumns+` FROM jobs WHERE `+archiveEligibleSQL+`
		 ORDER BY terminal_seq ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LedgerJob
	for rows.Next() {
		j := &LedgerJob{}
		if err := rows.Scan(scanFields(j)...); err != nil {
			return nil, err
		}
		if err := finishScan(j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// archivedRowsTx reads one segment's archive rows inside a tx.
func (l *Ledger) archivedRowsTx(tx *sql.Tx, segSeq int64) ([]*LedgerJob, error) {
	rows, err := tx.Query(
		`SELECT `+jobColumns+` FROM jobs_archive WHERE archive_seq = ? ORDER BY terminal_seq`, segSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LedgerJob
	for rows.Next() {
		j := &LedgerJob{}
		if err := rows.Scan(scanFields(j)...); err != nil {
			return nil, err
		}
		if err := finishScan(j); err != nil {
			return nil, err
		}
		j.Archived = true
		out = append(out, j)
	}
	return out, rows.Err()
}

// ArchiveSegments lists every recorded archive segment in order.
func (l *Ledger) ArchiveSegments() ([]*ArchiveSegment, error) {
	rows, err := l.db.Query(
		`SELECT segment_seq, first_terminal_seq, last_terminal_seq, row_count,
		 sha256, custody, created_at FROM archive_segments ORDER BY segment_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ArchiveSegment
	for rows.Next() {
		s := &ArchiveSegment{}
		var created int64
		if err := rows.Scan(&s.Seq, &s.FirstTerminalSeq, &s.LastTerminalSeq,
			&s.RowCount, &s.SHA256, &s.Custody, &created); err != nil {
			return nil, err
		}
		s.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, s)
	}
	return out, rows.Err()
}

// ArchivedCount reports how many settled rows the archive holds.
func (l *Ledger) ArchivedCount() (int, error) {
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(1) FROM jobs_archive`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// IdentityCount reports the permanent replay-guard cardinality — every
// job_id the registry has ever admitted, archived or not.
func (l *Ledger) IdentityCount() (int, error) {
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(1) FROM job_identities`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetArchived returns the archive row for a job whose identity is known
// but whose operational row is gone — distinguishing "archived" from
// "never seen". The second return is false when no archive row exists.
func (l *Ledger) GetArchived(jobID string) (*LedgerJob, error) {
	j := &LedgerJob{}
	err := l.db.QueryRow(
		`SELECT `+jobColumns+` FROM jobs_archive WHERE job_id = ?`, jobID).
		Scan(scanFields(j)...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j.Archived = true
	return j, finishScan(j)
}

// VerifyArchiveSegments re-derives every recorded segment's digest from
// the archive rows it claims and compares — a post-commit rewrite of
// archived content changes the bytes, so the recomputed digest diverges
// and the tampering surfaces. Also verifies coverage: each segment's
// row count must equal the rows it actually holds.
func (l *Ledger) VerifyArchiveSegments() []string {
	segs, err := l.ArchiveSegments()
	if err != nil {
		return []string{fmt.Sprintf("list archive segments: %v", err)}
	}
	var findings []string
	for _, seg := range segs {
		rows, err := l.archivedRows(seg.Seq)
		if err != nil {
			findings = append(findings, fmt.Sprintf("archive segment %d unreadable: %v", seg.Seq, err))
			continue
		}
		if len(rows) != seg.RowCount {
			findings = append(findings, fmt.Sprintf(
				"archive segment %d claims %d rows but holds %d — the archive lost rows",
				seg.Seq, seg.RowCount, len(rows)))
			continue
		}
		segBytes, err := l.segmentPayload(seg.Seq)
		if err != nil {
			findings = append(findings, fmt.Sprintf("archive segment %d: marshal: %v", seg.Seq, err))
			continue
		}
		got := sha256.Sum256(segBytes)
		if hex.EncodeToString(got[:]) != seg.SHA256 {
			findings = append(findings, fmt.Sprintf(
				"archive segment %d content digest does not match the recorded %s — archived bytes were modified",
				seg.Seq, seg.SHA256))
		}
	}
	return findings
}

// segmentPayload rebuilds a segment's canonical payload bytes — the
// exact byte string its digest commits to — for custody handoffs and
// custody retries.
func (l *Ledger) segmentPayload(segSeq int64) ([]byte, error) {
	rows, err := l.archivedRows(segSeq)
	if err != nil {
		return nil, err
	}
	payload := make([]archiveRow, 0, len(rows))
	for _, j := range rows {
		payload = append(payload, jobArchiveRow(j))
	}
	return json.Marshal(payload)
}

// archivedRows reads one segment's rows outside a tx.
func (l *Ledger) archivedRows(segSeq int64) ([]*LedgerJob, error) {
	tx, err := l.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return l.archivedRowsTx(tx, segSeq)
}

// sortJobs merges active and archived rows into seq order — both tables
// emit seq-sorted rows, so a merge keeps the union ordered without
// re-reading the whole archive into the sort.
func sortJobs(active, archived []*LedgerJob) []*LedgerJob {
	out := make([]*LedgerJob, 0, len(active)+len(archived))
	i, j := 0, 0
	for i < len(active) && j < len(archived) {
		if active[i].Seq < archived[j].Seq {
			out = append(out, active[i])
			i++
		} else {
			out = append(out, archived[j])
			j++
		}
	}
	out = append(out, active[i:]...)
	out = append(out, archived[j:]...)
	return out
}

// listArchived returns every archived row in seq order.
func (l *Ledger) listArchived() ([]*LedgerJob, error) {
	rows, err := l.db.Query(
		`SELECT ` + jobColumns + ` FROM jobs_archive ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LedgerJob
	for rows.Next() {
		j := &LedgerJob{}
		if err := rows.Scan(scanFields(j)...); err != nil {
			return nil, err
		}
		if err := finishScan(j); err != nil {
			return nil, err
		}
		j.Archived = true
		out = append(out, j)
	}
	return out, rows.Err()
}
