package sandboxexecutor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/openclaw/crabbox/internal/evidence"
	_ "modernc.org/sqlite"
)

// Durable job states. The order is a one-way lifecycle: a job that
// reaches a terminal state never leaves it, and a job in an ambiguous
// state is never silently re-dispatched — an operator must reconcile
// it against the backend first.
const (
	// JobStateRecorded means the executor accepted and persisted the
	// submission. No backend has been asked to run it.
	// JobStateRecorded is declared in server.go.
	JobStateDispatching    = "DISPATCHING"        // durable intent to launch, fence written
	JobStateRunning        = "RUNNING"            // backend acknowledged the launch
	JobStateSucceeded      = "SUCCEEDED"          // exit 0, result bound
	JobStateFailed         = "FAILED"             // ran, non-zero exit or backend-reported failure
	JobStateDispatchFailed = "DISPATCH_FAILED"    // backend definitively refused — job identity persists
	JobStateDispatchAmbig  = "DISPATCH_AMBIGUOUS" // outcome unknown (dispatch or lost monitor) — never auto-retry
	JobStateInterrupted    = "INTERRUPTED"        // was RUNNING when the daemon stopped
)

// Ledger is the executor's durable job registry: a SQLite store that
// records every admitted job before dispatch, every state transition
// under a fencing epoch, and every terminal result bound to the
// contract hash. It exists so that:
//
//   - a daemon crash cannot erase an acknowledged job identity,
//   - an uncertain dispatch is recorded as ambiguous rather than
//     retried blind (a duplicate VM is worse than a stalled job),
//   - a second executor process cannot take over the same registry
//     — the ledger holds an exclusive flock for its whole lifetime.
type Ledger struct {
	db   *sql.DB
	lock *flock.Flock

	// epoch is this daemon lifetime's fencing token, incremented in
	// an IMMEDIATE transaction at open. Every row this daemon writes
	// carries it; a row whose epoch is newer than ours was written by
	// a successor, which the flock makes impossible — so finding one
	// means the lock was bypassed and the row is evidence, not state.
	epoch uint64

	// reconciled counts rows moved to DISPATCH_AMBIGUOUS at open.
	reconciled int
}

// ErrDuplicateJobID is returned when a job_id already exists in the
// ledger — admission stays idempotent across retries.
var ErrDuplicateJobID = errors.New("job_id already recorded")

// ErrContractReplay is returned when a different job_id presents a
// contract hash already seen — a signed contract is single-use.
var ErrContractReplay = errors.New("contract already submitted (replay)")

// ErrTransitionConflict is returned when a state transition finds the
// job is no longer in an expected source state — the row moved on
// without us, which for a single-writer daemon means a logic error or
// ledger tampering, either way loud.
var ErrTransitionConflict = errors.New("job state transition conflict")

// LedgerJob is one persisted registry row.
type LedgerJob struct {
	JobID         string
	ContractHash  string
	Seq           uint64
	Submitter     string
	Principal     string
	Image         string
	ContractJSON  string
	State         string
	FenceEpoch    uint64
	BackendID     string
	BackendHandle string
	ReceivedAt    time.Time
	UpdatedAt     time.Time
	ExitCode      *int64
	Error         string
	ResultJSON    string
	// TerminalSeq is the job's position in the durable terminal
	// enumeration — assigned transactionally with the terminal write
	// so the enumeration checkpoints commit to is append-only by
	// construction. Zero while the job is non-terminal.
	TerminalSeq int64
	// ReceiptSHA256 is the digest of the signed execution receipt
	// emitted at the terminal transition; the evidence chain's link
	// back into this row.
	ReceiptSHA256  string
	ArtifactSHA256 string

	receivedAtRaw int64
	updatedAtRaw  int64
	exitRaw       sql.NullInt64
	termSeqRaw    sql.NullInt64
}

// OpenLedger opens (creating if needed) the durable registry at path,
// takes its exclusive advisory lock, bumps the fencing epoch, and
// reconciles leftover in-flight states from any previous lifetime.
//
// The lock is the fencing mechanism: a second executor pointing at
// the same ledger refuses to start rather than interleaving writes
// with a live owner. Stale lock files are harmless — flock is held by
// the process, not the file's existence.
func OpenLedger(path string) (*Ledger, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("ledger path must not contain '?' or '#': %q", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ledger directory %s: %w", dir, err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("ledger %s is a symlink", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("ledger %s is not a regular file", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect ledger %s: %w", path, err)
	}

	lock := flock.New(path + ".lock")
	locked, err := lock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("take ledger fence lock %s: %w", lock.Path(), err)
	}
	if !locked {
		return nil, fmt.Errorf("ledger %s is fenced by another executor (lock %s held)", path, lock.Path())
	}
	// The lock file must stay owner-only like the ledger itself.
	_ = os.Chmod(lock.Path(), 0o600)

	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"+
		"&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)"+
		"&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = lock.Unlock()
		return nil, err
	}
	// One connection: the ledger is single-writer by design, and a
	// single conn keeps BEGIN IMMEDIATE honest about who writes.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		_ = lock.Unlock()
		return nil, fmt.Errorf("open ledger %s: %w", path, err)
	}
	// The journal creates sidecar files at the umask — tighten the
	// whole set before accepting work.
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !os.IsNotExist(err) {
			db.Close()
			_ = lock.Unlock()
			return nil, fmt.Errorf("secure ledger %s: %w", path+suffix, err)
		}
	}

	l := &Ledger{db: db, lock: lock}
	if err := l.migrate(); err != nil {
		l.Close()
		return nil, err
	}
	if err := l.bumpEpoch(); err != nil {
		l.Close()
		return nil, err
	}
	reconciled, err := l.reconcile()
	if err != nil {
		l.Close()
		return nil, err
	}
	l.reconciled = reconciled
	return l, nil
}

// reconciled counts jobs the last reconcile pass moved to ambiguous.
// Reported by the server at startup so an interrupted lifetime is
// observable rather than silent.
func (l *Ledger) Reconciled() int { return l.reconciled }

// Epoch is the current fencing token.
func (l *Ledger) Epoch() uint64 { return l.epoch }

// ledgerSchemaVersion bumps when the schema gains columns; pre-v2
// ledgers (from the admission-only spike) get their new columns via
// ALTER TABLE rather than a destructive rebuild.
const ledgerSchemaVersion = 2

func (l *Ledger) migrate() error {
	var version int
	if err := l.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read ledger schema version: %w", err)
	}
	_, err := l.db.Exec(`
		CREATE TABLE IF NOT EXISTS executor_meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS jobs (
			job_id         TEXT PRIMARY KEY,
			contract_hash  TEXT NOT NULL UNIQUE,
			seq            INTEGER NOT NULL UNIQUE,
			submitter      TEXT NOT NULL,
			principal      TEXT NOT NULL,
			image          TEXT NOT NULL DEFAULT '',
			contract_json  TEXT NOT NULL,
			state          TEXT NOT NULL,
			fence_epoch    INTEGER NOT NULL,
			backend_id     TEXT NOT NULL DEFAULT '',
			backend_handle TEXT NOT NULL DEFAULT '',
			received_at    INTEGER NOT NULL,
			updated_at     INTEGER NOT NULL,
			exit_code      INTEGER,
			error          TEXT NOT NULL DEFAULT '',
			result_json    TEXT NOT NULL DEFAULT '',
			terminal_seq   INTEGER,
			receipt_sha256 TEXT NOT NULL DEFAULT '',
			artifact_sha256 TEXT NOT NULL DEFAULT ''
		);
	`)
	if err != nil {
		return fmt.Errorf("migrate ledger: %w", err)
	}
	if version < 2 {
		// v1 → v2: evidence columns. ADD COLUMN is additive-only —
		// existing rows keep their history with empty digests, which
		// checkpoint verification treats honestly as unattested.
		for _, ddl := range []string{
			`ALTER TABLE jobs ADD COLUMN backend_id TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE jobs ADD COLUMN terminal_seq INTEGER`,
			`ALTER TABLE jobs ADD COLUMN receipt_sha256 TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE jobs ADD COLUMN artifact_sha256 TEXT NOT NULL DEFAULT ''`,
		} {
			if _, err := l.db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migrate ledger v%d→v2: %w", version, err)
			}
		}
		if _, err := l.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, ledgerSchemaVersion)); err != nil {
			return fmt.Errorf("stamp ledger schema version: %w", err)
		}
	}
	return nil
}

// bumpEpoch increments executor_meta.epoch inside an IMMEDIATE
// transaction — the fencing write that both claims the ledger for
// this lifetime and gives every subsequent write a monotonic epoch.
// A previous epoch's rows never move backwards; a crash mid-bump
// rolls the transaction back and the next open retries cleanly.
func (l *Ledger) bumpEpoch() error {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("bump ledger epoch: %w", err)
	}
	defer tx.Rollback()
	var epoch uint64
	row := tx.QueryRow(`SELECT value FROM executor_meta WHERE key = 'epoch'`)
	var raw string
	switch err := row.Scan(&raw); {
	case err == sql.ErrNoRows:
		epoch = 0
	case err != nil:
		return fmt.Errorf("read ledger epoch: %w", err)
	default:
		if _, err := fmt.Sscanf(raw, "%d", &epoch); err != nil {
			return fmt.Errorf("corrupt ledger epoch %q: %w", raw, err)
		}
	}
	epoch++
	if _, err := tx.Exec(
		`INSERT INTO executor_meta (key, value) VALUES ('epoch', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprint(epoch)); err != nil {
		return fmt.Errorf("write ledger epoch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit ledger epoch: %w", err)
	}
	l.epoch = epoch
	return nil
}

// reconcile marks every job left in a non-terminal, non-recorded
// state by a previous lifetime as ambiguous. DISPATCHING means the
// backend may or may not have received the job; RUNNING means it was
// definitely launched and we no longer know how it ended. Neither is
// safe to retry blind — both become DISPATCH_AMBIGUOUS for operator
// reconciliation, recorded with the previous fence epoch intact.
func (l *Ledger) reconcile() (int, error) {
	res, err := l.db.Exec(
		`UPDATE jobs SET state = ?, updated_at = ?
		 WHERE state IN (?, ?)`,
		JobStateDispatchAmbig, time.Now().UTC().UnixMilli(),
		JobStateDispatching, JobStateRunning)
	if err != nil {
		return 0, fmt.Errorf("reconcile ledger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// InterruptRunning marks every RUNNING job INTERRUPTED at clean
// shutdown — distinguishable from a crash (which leaves RUNNING rows
// for reconcile to mark ambiguous) while still telling the operator
// the workload may be live in the backend.
func (l *Ledger) InterruptRunning() (int, error) {
	res, err := l.db.Exec(
		`UPDATE jobs SET state = ?, updated_at = ? WHERE state = ?`,
		JobStateInterrupted, time.Now().UTC().UnixMilli(), JobStateRunning)
	if err != nil {
		return 0, fmt.Errorf("interrupt running jobs: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// nextSeq allocates the ledger's monotonic sequence — persisted so
// ordering survives restarts, unlike an in-memory counter.
func (l *Ledger) nextSeq(tx *sql.Tx) (uint64, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM executor_meta WHERE key = 'next_seq'`).Scan(&raw)
	var seq uint64
	switch {
	case err == sql.ErrNoRows:
		seq = 0
	case err != nil:
		return 0, fmt.Errorf("read ledger seq: %w", err)
	default:
		if _, err := fmt.Sscanf(raw, "%d", &seq); err != nil {
			return 0, fmt.Errorf("corrupt ledger seq %q: %w", raw, err)
		}
	}
	seq++
	if _, err := tx.Exec(
		`INSERT INTO executor_meta (key, value) VALUES ('next_seq', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprint(seq)); err != nil {
		return 0, err
	}
	return seq, nil
}

// InsertJob durably records a newly admitted job in RECORDED state
// inside one IMMEDIATE transaction that also allocates its sequence.
// The record exists before any backend is asked to run it — dispatch
// never precedes persistence. Duplicate job_id and replayed contract
// hashes are refused distinctly.
func (l *Ledger) InsertJob(jobID, contractHash, submitter, principal, image, contractJSON string) (*LedgerJob, error) {
	now := time.Now().UTC().UnixMilli()
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("insert job %s: %w", jobID, err)
	}
	defer tx.Rollback()
	seq, err := l.nextSeq(tx)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(
		`INSERT INTO jobs (job_id, contract_hash, seq, submitter, principal, image,
		 contract_json, state, fence_epoch, received_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		jobID, contractHash, seq, submitter, principal, image, contractJSON,
		JobStateRecorded, l.epoch, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			if existing, gerr := l.getTx(tx, jobID); gerr == nil && existing != nil {
				if existing.ContractHash == contractHash {
					return nil, ErrDuplicateJobID
				}
			}
			if l.hashExistsTx(tx, contractHash) {
				return nil, ErrContractReplay
			}
			return nil, ErrDuplicateJobID
		}
		return nil, fmt.Errorf("insert job %s: %w", jobID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit job %s: %w", jobID, err)
	}
	return l.Get(jobID)
}

func (l *Ledger) hashExistsTx(tx *sql.Tx, hash string) bool {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM jobs WHERE contract_hash = ?`, hash).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// jobColumns is the canonical SELECT list for a full jobs row.
const jobColumns = `job_id, contract_hash, seq, submitter, principal, image, contract_json,
	state, fence_epoch, backend_id, backend_handle, received_at, updated_at,
	exit_code, error, result_json, terminal_seq, receipt_sha256, artifact_sha256`

func (l *Ledger) getTx(tx *sql.Tx, jobID string) (*LedgerJob, error) {
	j := &LedgerJob{}
	err := tx.QueryRow(
		`SELECT `+jobColumns+` FROM jobs WHERE job_id = ?`, jobID).
		Scan(scanFields(j)...)
	if err != nil {
		return nil, err
	}
	return j, finishScan(j)
}

// scanFields exposes the scan destinations in jobColumns order so
// QueryRow.Scan, getTx and List share exactly one column mapping.
func scanFields(j *LedgerJob) []any {
	return []any{
		&j.JobID, &j.ContractHash, &j.Seq, &j.Submitter, &j.Principal, &j.Image,
		&j.ContractJSON, &j.State, &j.FenceEpoch, &j.BackendID, &j.BackendHandle,
		&j.receivedAtRaw, &j.updatedAtRaw, &j.exitRaw, &j.Error, &j.ResultJSON,
		&j.termSeqRaw, &j.ReceiptSHA256, &j.ArtifactSHA256,
	}
}

// finishScan converts the raw scanned values into the typed fields.
func finishScan(j *LedgerJob) error {
	j.ReceivedAt = time.UnixMilli(j.receivedAtRaw).UTC()
	j.UpdatedAt = time.UnixMilli(j.updatedAtRaw).UTC()
	if j.exitRaw.Valid {
		j.ExitCode = &j.exitRaw.Int64
	}
	if j.termSeqRaw.Valid {
		j.TerminalSeq = j.termSeqRaw.Int64
	}
	return nil
}

// Get returns one job, or nil when absent.
func (l *Ledger) Get(jobID string) (*LedgerJob, error) {
	j := &LedgerJob{}
	err := l.db.QueryRow(
		`SELECT `+jobColumns+` FROM jobs WHERE job_id = ?`, jobID).
		Scan(scanFields(j)...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return j, finishScan(j)
}

// ReconcileCandidates returns jobs whose backend outcome is
// unresolved — DISPATCH_AMBIGUOUS (may or may not have launched) and
// INTERRUPTED (definitely launched, result unknown) — newest first,
// capped at limit. The startup pass inspects their handles against
// the live backend so an orphaned workload surfaces in the audit log
// instead of being discovered manually.
func (l *Ledger) ReconcileCandidates(limit int) ([]*LedgerJob, error) {
	if limit <= 0 {
		limit = 64
	}
	rows, err := l.db.Query(
		`SELECT `+jobColumns+` FROM jobs
		 WHERE state IN (?, ?) AND backend_handle != ''
		 ORDER BY seq DESC LIMIT ?`,
		JobStateDispatchAmbig, JobStateInterrupted, limit)
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

// PoolUsage is the aggregate declared consumption of every job whose
// VM may exist — the set admission must subtract from the operator's
// resource pool. It is computed from durable rows, so the bound holds
// across restarts and crashes rather than living in process memory.
type PoolUsage struct {
	VMs          int
	CPUs         float64
	MemoryMB     uint64
	DiskMB       uint64
	OutputBytes  uint64
	PerSubmitter map[string]int
}

// ActiveUsage aggregates the declared budgets of every job in a state
// where a VM may exist: DISPATCHING and RUNNING are in flight;
// DISPATCH_AMBIGUOUS and INTERRUPTED mean a VM may still be live under
// its own contract timeout, so their reservation is held until an
// operator reconciles the row — releasing it would let uncertainty
// consume budget twice. A row whose contract cannot be parsed counts
// as one VM with no declared dimensions: fail closed on the VM bound
// rather than silently free.
func (l *Ledger) ActiveUsage() (*PoolUsage, error) {
	rows, err := l.db.Query(
		`SELECT submitter, contract_json FROM jobs WHERE state IN (?, ?, ?, ?)`,
		JobStateDispatching, JobStateRunning, JobStateDispatchAmbig, JobStateInterrupted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	usage := &PoolUsage{PerSubmitter: map[string]int{}}
	for rows.Next() {
		var submitter, raw string
		if err := rows.Scan(&submitter, &raw); err != nil {
			return nil, err
		}
		usage.VMs++
		usage.PerSubmitter[submitter]++
		if c, err := ParseContract(json.RawMessage(raw)); err == nil {
			usage.CPUs += c.Resources.CPUs
			usage.MemoryMB += c.Resources.MemoryMB
			usage.DiskMB += c.Resources.DiskMB
			usage.OutputBytes += c.Resources.MaxOutputBytes
		}
	}
	return usage, rows.Err()
}

// Count reports the durable registry size.
func (l *Ledger) Count() (int, error) {
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(1) FROM jobs`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// List returns every recorded job in sequence order.
func (l *Ledger) List() ([]*LedgerJob, error) {
	rows, err := l.db.Query(`SELECT ` + jobColumns + ` FROM jobs ORDER BY seq`)
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

// Transition performs a compare-and-swap state move: the row must be
// in one of `from`, or the write conflicts. Every transition stamps
// this lifetime's fence epoch — a row that moved under an epoch that
// is not ours was moved by someone who bypassed the lock.
func (l *Ledger) Transition(jobID, to string, from []string, mutate func(*LedgerJob) error) error {
	if len(from) == 0 {
		return fmt.Errorf("transition of %s requires source states", jobID)
	}
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("transition %s: %w", jobID, err)
	}
	defer tx.Rollback()
	job, err := l.getTx(tx, jobID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("transition %s: no such job", jobID)
	}
	if err != nil {
		return fmt.Errorf("transition %s: %w", jobID, err)
	}
	if job == nil {
		return fmt.Errorf("transition %s: no such job", jobID)
	}
	allowed := false
	for _, s := range from {
		if job.State == s {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%w: %s is %s, not one of %v", ErrTransitionConflict, jobID, job.State, from)
	}
	if job.FenceEpoch > l.epoch {
		return fmt.Errorf("job %s carries fence epoch %d from a later lifetime (ours is %d) — the ledger lock was bypassed", jobID, job.FenceEpoch, l.epoch)
	}
	job.State = to
	job.FenceEpoch = l.epoch
	if mutate != nil {
		if err := mutate(job); err != nil {
			return err
		}
	}
	// A terminal write joins the durable terminal enumeration: the
	// sequence is allocated inside the same transaction so a crash
	// can never leave a number skipped — the enumeration a
	// checkpoint covers is dense and append-only.
	var termSeq any
	if isTerminalState(to) {
		next, err := l.nextTerminalSeq(tx)
		if err != nil {
			return fmt.Errorf("transition %s: %w", jobID, err)
		}
		job.TerminalSeq = next
		termSeq = next
	}
	var exit any
	if job.ExitCode != nil {
		exit = *job.ExitCode
	}
	res, err := tx.Exec(
		`UPDATE jobs SET state = ?, fence_epoch = ?, backend_id = ?, backend_handle = ?,
		 updated_at = ?, exit_code = ?, error = ?, result_json = ?,
		 terminal_seq = ?, receipt_sha256 = ?, artifact_sha256 = ?
		 WHERE job_id = ? AND seq = ?`,
		job.State, job.FenceEpoch, job.BackendID, job.BackendHandle,
		time.Now().UTC().UnixMilli(), exit, job.Error, job.ResultJSON,
		termSeq, job.ReceiptSHA256, job.ArtifactSHA256,
		jobID, job.Seq)
	if err != nil {
		return fmt.Errorf("transition %s: %w", jobID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: %s changed underneath the transition", ErrTransitionConflict, jobID)
	}
	return tx.Commit()
}

// isTerminalState reports whether a state closes the job's lifecycle
// and joins the checkpointable terminal enumeration. INTERRUPTED and
// DISPATCH_AMBIGUOUS are deliberately excluded — they mean "an
// operator must reconcile", not "the outcome is known"; enrolling
// them would let a checkpoint certify uncertainty as fact.
func isTerminalState(state string) bool {
	switch state {
	case JobStateSucceeded, JobStateFailed, JobStateDispatchFailed:
		return true
	}
	return false
}

// nextTerminalSeq allocates the monotonic terminal-sequence counter —
// persisted in executor_meta so ordering survives restarts and
// concurrent terminal writes serialize through the IMMEDIATE tx.
func (l *Ledger) nextTerminalSeq(tx *sql.Tx) (int64, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM executor_meta WHERE key = 'next_terminal_seq'`).Scan(&raw)
	var seq int64
	switch {
	case err == sql.ErrNoRows:
		seq = 0
	case err != nil:
		return 0, fmt.Errorf("read terminal seq: %w", err)
	default:
		if _, err := fmt.Sscanf(raw, "%d", &seq); err != nil {
			return 0, fmt.Errorf("corrupt terminal seq %q: %w", raw, err)
		}
	}
	seq++
	if _, err := tx.Exec(
		`INSERT INTO executor_meta (key, value) VALUES ('next_terminal_seq', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprint(seq)); err != nil {
		return 0, err
	}
	return seq, nil
}

// TerminalRefs returns the durable terminal enumeration in
// terminal_seq order — the exact set a checkpoint commits to and a
// verifier recomputes. Non-terminal jobs (RECORDED, RUNNING,
// DISPATCHING, INTERRUPTED, DISPATCH_AMBIGUOUS) are excluded: a
// checkpoint must never certify an outcome the executor has not
// attested.
func (l *Ledger) TerminalRefs() ([]evidence.TerminalRef, error) {
	return terminalRefs(l.db)
}

func terminalRefs(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}) ([]evidence.TerminalRef, error) {
	rows, err := q.Query(
		`SELECT terminal_seq, job_id, state, contract_hash, result_json,
		 artifact_sha256, receipt_sha256, backend_id, backend_handle, updated_at
		 FROM jobs WHERE terminal_seq IS NOT NULL ORDER BY terminal_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []evidence.TerminalRef
	for rows.Next() {
		var ref evidence.TerminalRef
		var resultJSON string
		var updatedAt int64
		if err := rows.Scan(&ref.Seq, &ref.ExecutionID, &ref.State, &ref.RequestDigest,
			&resultJSON, &ref.TerminalEvidenceDigest, &ref.TerminalReceiptDigest,
			&ref.ProviderID, &ref.ProviderRunID, &updatedAt); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(resultJSON))
		ref.TerminalResultDigest = hex.EncodeToString(sum[:])
		ref.UpdatedAt = time.UnixMilli(updatedAt).UTC().Format(time.RFC3339Nano)
		out = append(out, ref)
	}
	return out, rows.Err()
}

// InspectLedger opens a ledger read-only for independent audit: no
// flock, no epoch bump, no reconcile, no schema writes. A verifier
// must never mutate the store it is checking — including the
// side-effects a normal open performs. The returned Ledger is usable
// only through TerminalRefs/List/Get; writes will fail against the
// read-only connection.
func InspectLedger(path string) (*Ledger, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("ledger path must not contain '?' or '#': %q", path)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("inspect ledger %s: %w", path, err)
	}
	return &Ledger{db: db}, nil
}

// Close releases the ledger: database first, then the fence lock —
// order matters, the lock must outlive the last write. An inspected
// (read-only) ledger has no lock to release.
func (l *Ledger) Close() error {
	err := l.db.Close()
	if l.lock != nil {
		if uerr := l.lock.Unlock(); err == nil {
			err = uerr
		}
	}
	return err
}

// isUniqueViolation detects SQLite uniqueness failures across the
// driver's error shapes (message matching is what modernc.org/sqlite
// exposes for constraint failures).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed")
}
