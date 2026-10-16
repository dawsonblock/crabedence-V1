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
	"sync"
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
	JobStateDispatchFailed = "DISPATCH_FAILED"    // definitively never ran: refused, or the guest rejected the command before it started
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

	// custodian, when set, is the evidence-custody witness archival
	// consults before releasing operational rows (see archive.go).
	custMu    sync.Mutex
	custodian ArchiveCustodian

	// archiveMu serializes archive passes — two concurrent passes
	// would pick the same candidates and collide on the archive
	// primary key.
	archiveMu sync.Mutex
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
	// BackendJobID is the runtime-owned run identity (e.g. the
	// Microsandbox job id) the launch was observed through. Empty
	// for backends without one.
	BackendJobID string
	// BackendBootID is the VM boot generation the run was verified
	// in — the substituted-instance control the recovery pass
	// enforces.
	BackendBootID string
	// PolicyDigest is the digest of the effective policy the run was
	// authorized under.
	PolicyDigest string
	// DispatchNonce is the per-dispatch authorization nonce, carried on
	// the VM as its dispatch label: recovery admits a discovered VM
	// only when it presents this exact nonce.
	DispatchNonce string
	// ImageDigest is the image manifest digest the dispatch authorized.
	ImageDigest string
	// RuntimeIdentity is the qualified runtime identity (version and
	// component digests) the dispatch was made under.
	RuntimeIdentity string
	// DispatchClass is the explicit outcome class of the dispatch
	// attempt (NOT_ATTEMPTED, PROVEN_REJECTED, STARTED, UNCERTAIN).
	DispatchClass string
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
	// Archived marks a row read from jobs_archive — the durable
	// terminal history rather than the operational registry.
	Archived bool
	// CleanupPending is set when the job's backend resources (its VM)
	// could not be removed after the result was observed — tracked
	// separately from the result so a cleanup failure never masks or
	// rewrites what happened. CleanupError carries the reason.
	CleanupPending bool
	CleanupError   string

	receivedAtRaw     int64
	updatedAtRaw      int64
	exitRaw           sql.NullInt64
	termSeqRaw        sql.NullInt64
	cleanupPendingRaw int64
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
	// Finish any archive transition a previous lifetime committed
	// part-way: archive rows already durable under a non-pending
	// segment release their operational rows idempotently.
	if err := l.finalizeArchives(); err != nil {
		l.Close()
		return nil, err
	}
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
// ALTER TABLE rather than a destructive rebuild, v3 adds the runtime
// run identity plus cleanup tracking, v7 adds the archive set —
// job_identities, jobs_archive, archive_segments — separating settled
// history from operational state without surrendering replay identity,
// and v8 records the verified custody acknowledgement on each
// witnessed segment. v9 makes the recovery scheduler durable:
// recovery_attempts paces retries across restarts so a crash-looping
// daemon cannot re-attempt every row on every open, and
// recovery_events is the durable escalation trail the audit line
// previously left only in logs.
const ledgerSchemaVersion = 9

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
			backend_job_id TEXT NOT NULL DEFAULT '',
			backend_boot_id TEXT NOT NULL DEFAULT '',
			policy_digest  TEXT NOT NULL DEFAULT '',
			dispatch_nonce TEXT NOT NULL DEFAULT '',
			image_digest   TEXT NOT NULL DEFAULT '',
			runtime_identity TEXT NOT NULL DEFAULT '',
			dispatch_class TEXT NOT NULL DEFAULT '',
			received_at    INTEGER NOT NULL,
			updated_at     INTEGER NOT NULL,
			exit_code      INTEGER,
			error          TEXT NOT NULL DEFAULT '',
			result_json    TEXT NOT NULL DEFAULT '',
			terminal_seq   INTEGER,
			receipt_sha256 TEXT NOT NULL DEFAULT '',
			artifact_sha256 TEXT NOT NULL DEFAULT '',
			cleanup_pending INTEGER NOT NULL DEFAULT 0,
			cleanup_error   TEXT NOT NULL DEFAULT ''
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
	}
	if version < 3 {
		// v2 → v3: the runtime run identity and cleanup tracking.
		// Existing rows keep empty identities — a job dispatched by a
		// pre-v3 executor has no runtime job id to reconcile with,
		// which its DISPATCH_AMBIGUOUS state already says.
		for _, ddl := range []string{
			`ALTER TABLE jobs ADD COLUMN backend_job_id TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE jobs ADD COLUMN cleanup_pending INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE jobs ADD COLUMN cleanup_error TEXT NOT NULL DEFAULT ''`,
		} {
			if _, err := l.db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migrate ledger v%d→v3: %w", version, err)
			}
		}
	}
	if version < 4 {
		// v3 → v4: the VM boot generation and the effective-policy
		// digest the run was authorized under. Existing rows keep
		// empty values — a pre-v4 executor recorded neither, which
		// their unresolved or unverified state already says.
		for _, ddl := range []string{
			`ALTER TABLE jobs ADD COLUMN backend_boot_id TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE jobs ADD COLUMN policy_digest TEXT NOT NULL DEFAULT ''`,
		} {
			if _, err := l.db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migrate ledger v%d→v4: %w", version, err)
			}
		}
	}
	if version < 5 {
		// v4 → v5: the dispatch authorization — the nonce, image digest
		// and qualified runtime identity persisted before any VM exists.
		// Existing rows keep empty values; their unresolved state
		// already says their authorization was not recorded.
		for _, ddl := range []string{
			`ALTER TABLE jobs ADD COLUMN dispatch_nonce TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE jobs ADD COLUMN image_digest TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE jobs ADD COLUMN runtime_identity TEXT NOT NULL DEFAULT ''`,
		} {
			if _, err := l.db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migrate ledger v%d→v5: %w", version, err)
			}
		}
	}
	if version < 6 {
		// v5 → v6: the explicit dispatch outcome class — recorded so
		// evidence rules and operators read the classification rather
		// than inferring it from an error's shape.
		if _, err := l.db.Exec(`ALTER TABLE jobs ADD COLUMN dispatch_class TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate ledger v%d→v6: %w", version, err)
		}
	}
	if version < 7 {
		// v6 → v7: the archive set. job_identities is the permanent
		// replay guard — every admitted job_id/contract_hash pair for
		// the registry's whole life, populated from the existing jobs
		// rows so a pre-v7 ledger's identities remain replay-proof.
		// jobs_archive holds settled terminal payloads; archive_segments
		// records each content-addressed transition.
		_, err := l.db.Exec(`
			CREATE TABLE IF NOT EXISTS job_identities (
				job_id        TEXT PRIMARY KEY,
				contract_hash TEXT NOT NULL UNIQUE,
				seq           INTEGER NOT NULL UNIQUE,
				terminal_seq  INTEGER,
				archived_at   INTEGER
			);
			CREATE TABLE IF NOT EXISTS jobs_archive (
				job_id         TEXT PRIMARY KEY,
				contract_hash  TEXT NOT NULL,
				seq            INTEGER NOT NULL,
				submitter      TEXT NOT NULL,
				principal      TEXT NOT NULL,
				image          TEXT NOT NULL DEFAULT '',
				contract_json  TEXT NOT NULL,
				state          TEXT NOT NULL,
				fence_epoch    INTEGER NOT NULL,
				backend_id     TEXT NOT NULL DEFAULT '',
				backend_handle TEXT NOT NULL DEFAULT '',
				backend_job_id TEXT NOT NULL DEFAULT '',
				backend_boot_id TEXT NOT NULL DEFAULT '',
				policy_digest  TEXT NOT NULL DEFAULT '',
				dispatch_nonce TEXT NOT NULL DEFAULT '',
				image_digest   TEXT NOT NULL DEFAULT '',
				runtime_identity TEXT NOT NULL DEFAULT '',
				dispatch_class TEXT NOT NULL DEFAULT '',
				received_at    INTEGER NOT NULL,
				updated_at     INTEGER NOT NULL,
				exit_code      INTEGER,
				error          TEXT NOT NULL DEFAULT '',
				result_json    TEXT NOT NULL DEFAULT '',
				terminal_seq   INTEGER,
				receipt_sha256 TEXT NOT NULL DEFAULT '',
				artifact_sha256 TEXT NOT NULL DEFAULT '',
				cleanup_pending INTEGER NOT NULL DEFAULT 0,
				cleanup_error   TEXT NOT NULL DEFAULT '',
				archived_at    INTEGER NOT NULL,
				archive_seq    INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_jobs_archive_seq ON jobs_archive(archive_seq);
			CREATE INDEX IF NOT EXISTS idx_jobs_archive_tseq ON jobs_archive(terminal_seq);
			CREATE TABLE IF NOT EXISTS archive_segments (
				segment_seq        INTEGER PRIMARY KEY,
				first_terminal_seq INTEGER NOT NULL,
				last_terminal_seq  INTEGER NOT NULL,
				row_count          INTEGER NOT NULL,
				sha256             TEXT NOT NULL,
				custody            TEXT NOT NULL DEFAULT 'local',
				custody_ack        TEXT NOT NULL DEFAULT '',
				created_at         INTEGER NOT NULL
			);
			INSERT INTO job_identities (job_id, contract_hash, seq, terminal_seq)
				SELECT job_id, contract_hash, seq, terminal_seq FROM jobs
				WHERE job_id NOT IN (SELECT job_id FROM job_identities);
		`)
		if err != nil {
			return fmt.Errorf("migrate ledger v%d→v7: %w", version, err)
		}
	}
	if version < 8 {
		// v7 → v8: the verified custody acknowledgement reference on
		// each archive segment. Segments witnessed before the
		// acknowledgement became evidence-carrying keep an empty
		// reference — the custody chain still attests them.
		if _, err := l.db.Exec(`ALTER TABLE archive_segments ADD COLUMN custody_ack TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate ledger v%d→v8: %w", version, err)
		}
	}
	if version < 9 {
		// v8 → v9: durable recovery scheduling. Attempt pacing used
		// to live in per-lifetime maps, so every restart re-attempted
		// every unresolved row once — tolerable on a planned restart,
		// a spin on a crash loop. Durable pacing makes the schedule
		// itself survive: a reopen inside the backoff keeps waiting.
		_, err := l.db.Exec(`
			CREATE TABLE IF NOT EXISTS recovery_attempts (
				job_id          TEXT NOT NULL,
				action          TEXT NOT NULL,
				last_attempt_ms INTEGER NOT NULL,
				attempts        INTEGER NOT NULL,
				PRIMARY KEY (job_id, action)
			);
			CREATE TABLE IF NOT EXISTS recovery_events (
				seq      INTEGER PRIMARY KEY AUTOINCREMENT,
				at_ms    INTEGER NOT NULL,
				kind     TEXT NOT NULL,
				subject  TEXT NOT NULL,
				detail   TEXT NOT NULL DEFAULT ''
			);
			CREATE INDEX IF NOT EXISTS idx_recovery_events_kind ON recovery_events(kind, at_ms);
		`)
		if err != nil {
			return fmt.Errorf("migrate ledger v%d→v9: %w", version, err)
		}
	}
	if version < ledgerSchemaVersion {
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
	return l.insertJob(jobID, contractHash, submitter, principal, image, contractJSON, JobStateRecorded)
}

// AdmitJob is InsertJob with the dispatch intent claimed atomically:
// a backend executor writes the row already DISPATCHING, so a crash
// cannot strand a durable RECORDED row no driver will ever pick up.
func (l *Ledger) AdmitJob(jobID, contractHash, submitter, principal, image, contractJSON string) (*LedgerJob, error) {
	return l.insertJob(jobID, contractHash, submitter, principal, image, contractJSON, JobStateDispatching)
}

// insertJob is the shared admission write — identity, sequence and the
// operational row commit or roll back together.
func (l *Ledger) insertJob(jobID, contractHash, submitter, principal, image, contractJSON, state string) (*LedgerJob, error) {
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
	// The permanent identity is written first: job_identities survives
	// archival, so a replayed contract or reused job_id is caught even
	// after the operational row has long since left the registry.
	_, err = tx.Exec(
		`INSERT INTO job_identities (job_id, contract_hash, seq) VALUES (?,?,?)`,
		jobID, contractHash, seq)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, l.classifyIdentityConflict(tx, jobID, contractHash)
		}
		return nil, fmt.Errorf("record job identity %s: %w", jobID, err)
	}
	_, err = tx.Exec(
		`INSERT INTO jobs (job_id, contract_hash, seq, submitter, principal, image,
		 contract_json, state, fence_epoch, received_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		jobID, contractHash, seq, submitter, principal, image, contractJSON,
		state, l.epoch, now, now)
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

// classifyIdentityConflict reports which permanent identity a rejected
// insert collided with: an identical resubmission is ErrDuplicateJobID
// (idempotent retry), the same signed contract under any other job_id
// is ErrContractReplay, and a new contract under a taken job_id is a
// duplicate identity claim.
func (l *Ledger) classifyIdentityConflict(tx *sql.Tx, jobID, contractHash string) error {
	var existingHash string
	err := tx.QueryRow(
		`SELECT contract_hash FROM job_identities WHERE job_id = ?`, jobID).Scan(&existingHash)
	if err == nil {
		// The job_id is taken — identical resubmission is the idempotent
		// retry; a different contract under it is an identity claim.
		return ErrDuplicateJobID
	}
	var n int
	if err := tx.QueryRow(
		`SELECT COUNT(1) FROM job_identities WHERE contract_hash = ?`, contractHash).Scan(&n); err == nil && n > 0 {
		return ErrContractReplay
	}
	return ErrDuplicateJobID
}

// jobColumns is the canonical SELECT list for a full jobs row.
const jobColumns = `job_id, contract_hash, seq, submitter, principal, image, contract_json,
	state, fence_epoch, backend_id, backend_handle, backend_job_id, backend_boot_id, policy_digest,
	dispatch_nonce, image_digest, runtime_identity, dispatch_class,
	received_at, updated_at,
	exit_code, error, result_json, terminal_seq, receipt_sha256, artifact_sha256,
	cleanup_pending, cleanup_error`

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
		&j.BackendJobID, &j.BackendBootID, &j.PolicyDigest,
		&j.DispatchNonce, &j.ImageDigest, &j.RuntimeIdentity, &j.DispatchClass,
		&j.receivedAtRaw, &j.updatedAtRaw, &j.exitRaw, &j.Error, &j.ResultJSON,
		&j.termSeqRaw, &j.ReceiptSHA256, &j.ArtifactSHA256,
		&j.cleanupPendingRaw, &j.CleanupError,
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
	j.CleanupPending = j.cleanupPendingRaw != 0
	return nil
}

// Get returns one job, or nil when absent. Active rows win; a job whose
// operational row was archived answers from the archive and marks
// itself Archived — archive-aware lookup never confuses "settled and
// stored" with "never admitted".
func (l *Ledger) Get(jobID string) (*LedgerJob, error) {
	j := &LedgerJob{}
	err := l.db.QueryRow(
		`SELECT `+jobColumns+` FROM jobs WHERE job_id = ?`, jobID).
		Scan(scanFields(j)...)
	if err == sql.ErrNoRows {
		return l.GetArchived(jobID)
	}
	if err != nil {
		return nil, err
	}
	return j, finishScan(j)
}

// ReconcileCandidates returns one page of jobs whose backend outcome
// is unresolved — DISPATCH_AMBIGUOUS (may or may not have launched)
// and INTERRUPTED (definitely launched, result unknown) — newest
// first, capped at limit. beforeSeq is the keyset cursor: zero starts
// at the newest row, and the last row's Seq continues after it.
//
// The startup pass follows the cursor to exhaustion, so an unresolved
// row is never omitted for having fallen outside the newest page. The
// cursor is stable while rows change state: a row's Seq never moves,
// so no row can be skipped, and a row that leaves the result set is
// simply never returned again.
func (l *Ledger) ReconcileCandidates(limit int, beforeSeq uint64) ([]*LedgerJob, error) {
	if limit <= 0 {
		limit = 64
	}
	rows, err := l.db.Query(
		`SELECT `+jobColumns+` FROM jobs
		 WHERE state IN (?, ?) AND backend_handle != '' AND (? = 0 OR seq < ?)
		 ORDER BY seq DESC LIMIT ?`,
		JobStateDispatchAmbig, JobStateInterrupted, beforeSeq, beforeSeq, limit)
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

// RecordedCandidates returns one page of jobs still in RECORDED —
// admitted and persisted but with no dispatch intent claimed. Only a
// previous lifetime interrupted mid-admission, or a ledger migrated
// from a record-only deployment, can produce these; the maintenance
// scheduler sweeps them under the same CAS claim the live path uses.
// Keyset-paginated like the other walks: seq never moves, so no row
// is skipped while rows leave the set.
func (l *Ledger) RecordedCandidates(limit int, beforeSeq uint64) ([]*LedgerJob, error) {
	if limit <= 0 {
		limit = 64
	}
	rows, err := l.db.Query(
		`SELECT `+jobColumns+` FROM jobs
		 WHERE state = ? AND (? = 0 OR seq > ?)
		 ORDER BY seq ASC LIMIT ?`,
		JobStateRecorded, beforeSeq, beforeSeq, limit)
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

// DispatchingStragglers returns DISPATCHING rows last written before
// the cutoff. Every context on the dispatch drive is bounded, so a
// row older than prepare+dispatch has no live driver — the lifetime
// that claimed it is gone, or the drive returned without recording a
// claim outcome. Either way the job's execution is genuinely
// uncertain: the backend may have launched it.
func (l *Ledger) DispatchingStragglers(limit int, cutoff time.Time) ([]*LedgerJob, error) {
	if limit <= 0 {
		limit = 64
	}
	rows, err := l.db.Query(
		`SELECT `+jobColumns+` FROM jobs
		 WHERE state = ? AND updated_at < ?
		 ORDER BY seq ASC LIMIT ?`,
		JobStateDispatching, cutoff.UTC().UnixMilli(), limit)
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

// RegistryResidue is the operational remainder the maintenance loop
// escalates on: rows still waiting on something — an unresolved
// backend outcome or an unverified cleanup — and the age of the
// oldest of each. Archived history is deliberately excluded: it is
// settled, not residue.
type RegistryResidue struct {
	Unresolved       int
	CleanupPending   int
	OldestUnresolved time.Time
	OldestCleanup    time.Time
}

// PendingResidue counts the residue without loading rows — the
// escalation summary needs counts and ages, not payloads.
func (l *Ledger) PendingResidue() (*RegistryResidue, error) {
	r := &RegistryResidue{}
	var oldestU, oldestC sql.NullInt64
	err := l.db.QueryRow(
		`SELECT
			(SELECT COUNT(1) FROM jobs WHERE state IN (?, ?)),
			(SELECT MIN(updated_at) FROM jobs WHERE state IN (?, ?)),
			(SELECT COUNT(1) FROM jobs WHERE cleanup_pending = 1),
			(SELECT MIN(updated_at) FROM jobs WHERE cleanup_pending = 1)`,
		JobStateDispatchAmbig, JobStateInterrupted,
		JobStateDispatchAmbig, JobStateInterrupted).
		Scan(&r.Unresolved, &oldestU, &r.CleanupPending, &oldestC)
	if err != nil {
		return nil, err
	}
	if oldestU.Valid {
		r.OldestUnresolved = time.UnixMilli(oldestU.Int64).UTC()
	}
	if oldestC.Valid {
		r.OldestCleanup = time.UnixMilli(oldestC.Int64).UTC()
	}
	return r, nil
}

// RecordDispatchPlan writes the dispatch authorization — the nonce,
// the effective-policy digest, the image digest and the qualified
// runtime identity — onto a non-terminal row. It is called before the
// backend creates anything, so a crash can never leave a VM whose
// authorization is not on disk. It never touches a terminal row.
func (l *Ledger) RecordDispatchPlan(jobID, backendName string, plan *DispatchPlan) error {
	if plan == nil {
		return fmt.Errorf("record dispatch plan for %s: no plan", jobID)
	}
	if plan.Handle == "" || plan.Nonce == "" || plan.PolicyDigest == "" {
		return fmt.Errorf("record dispatch plan for %s: incomplete plan", jobID)
	}
	runtimeIdentity := plan.RuntimeVersion
	if plan.RuntimeMSBSHA256 != "" || plan.RuntimeFirmwareSHA256 != "" {
		runtimeIdentity = fmt.Sprintf("%s msb=%s firmware=%s",
			plan.RuntimeVersion, plan.RuntimeMSBSHA256, plan.RuntimeFirmwareSHA256)
	}
	res, err := l.db.Exec(
		`UPDATE jobs SET backend_id = ?, backend_handle = ?, dispatch_nonce = ?, policy_digest = ?,
		 image_digest = ?, runtime_identity = ? WHERE job_id = ? AND terminal_seq IS NULL`,
		backendName, plan.Handle, plan.Nonce, plan.PolicyDigest,
		plan.ImageDigest, runtimeIdentity, jobID)
	if err != nil {
		return fmt.Errorf("record dispatch plan for %s: %w", jobID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("record dispatch plan for %s: no non-terminal row", jobID)
	}
	return nil
}

// AdoptBackendRun records the runtime-owned run identity and boot
// generation a reconcile pass recovered for a non-terminal row — the
// crash window between the runtime admitting a job and the ledger
// naming it. It is only ever called on unresolved rows: a terminal
// row's identity is already committed to by its receipt and
// checkpoint.
func (l *Ledger) AdoptBackendRun(jobID, runID, bootID string) error {
	if runID == "" {
		return fmt.Errorf("adopt run identity for %s: empty run id", jobID)
	}
	if bootID == "" {
		return fmt.Errorf("adopt run identity for %s: empty boot generation", jobID)
	}
	res, err := l.db.Exec(
		`UPDATE jobs SET backend_job_id = ?, backend_boot_id = ? WHERE job_id = ? AND terminal_seq IS NULL`,
		runID, bootID, jobID)
	if err != nil {
		return fmt.Errorf("adopt run identity for %s: %w", jobID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("adopt run identity for %s: no unresolved row", jobID)
	}
	return nil
}

// MarkCleanupPending records that a job's backend resources could not
// be removed after its result was observed. It is a targeted update,
// not a state transition: the outcome is already terminal and a
// cleanup failure must never rewrite what happened — only say that
// something was left behind.
//
// It deliberately does not touch updated_at: a terminal row's covered
// fields are committed to by signed checkpoints, and mutating any of
// them after the terminal write would invalidate the chain. Cleanup
// state is operational bookkeeping, outside the attested result.
func (l *Ledger) MarkCleanupPending(jobID, reason string) error {
	res, err := l.db.Exec(
		`UPDATE jobs SET cleanup_pending = 1, cleanup_error = ? WHERE job_id = ?`,
		reason, jobID)
	if err != nil {
		return fmt.Errorf("mark cleanup pending for %s: %w", jobID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("mark cleanup pending for %s: no such job", jobID)
	}
	return nil
}

// ClearCleanupPending records that a previously pending cleanup
// finally succeeded. Like MarkCleanupPending it leaves every
// checkpoint-covered field untouched.
func (l *Ledger) ClearCleanupPending(jobID string) error {
	res, err := l.db.Exec(
		`UPDATE jobs SET cleanup_pending = 0, cleanup_error = '' WHERE job_id = ?`, jobID)
	if err != nil {
		return fmt.Errorf("clear cleanup pending for %s: %w", jobID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("clear cleanup pending for %s: no such job", jobID)
	}
	return nil
}

// CleanupCandidates returns one page of terminal jobs whose backend
// resources are recorded as still present, newest first, capped at
// limit. beforeSeq is the keyset cursor, exactly as
// ReconcileCandidates uses it. The startup pass follows it to
// exhaustion — a VM that outlived its job is reconciled rather than
// forgotten for having fallen outside the newest page.
func (l *Ledger) CleanupCandidates(limit int, beforeSeq uint64) ([]*LedgerJob, error) {
	if limit <= 0 {
		limit = 64
	}
	rows, err := l.db.Query(
		`SELECT `+jobColumns+` FROM jobs
		 WHERE cleanup_pending = 1 AND backend_handle != '' AND (? = 0 OR seq < ?)
		 ORDER BY seq DESC LIMIT ?`, beforeSeq, beforeSeq, limit)
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
// DISPATCH_AMBIGUOUS and INTERRUPTED mean a VM may still be live, so
// their reservation is held until an operator reconciles the row or
// the bound below proves the VM gone.
//
// A terminal row whose VM could not be removed (cleanup_pending)
// holds its reservation too. The guest process finishing is not the
// VM ceasing to exist: the microVM still occupies host capacity until
// its removal is verified, so capacity is released on verified
// cleanup, never merely because the workload completed.
//
// grace is the longest interval between a row's last transition and
// the creation of the VM it may represent — the caller's dispatch
// timeout plus a margin. A VM cannot outlive its contract (the
// backend pins --max-duration to the declared timeout), so once that
// timeout plus grace has certainly elapsed the reservation is
// released even though the row stays unresolved for the operator's
// audit. A row whose contract cannot be parsed counts as one VM with
// no declared dimensions: fail closed on the VM bound rather than
// silently free.
func (l *Ledger) ActiveUsage(grace time.Duration) (*PoolUsage, error) {
	rows, err := l.db.Query(
		`SELECT submitter, contract_json, updated_at FROM jobs
		 WHERE state IN (?, ?, ?, ?) OR cleanup_pending = 1`,
		JobStateDispatching, JobStateRunning, JobStateDispatchAmbig, JobStateInterrupted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	usage := &PoolUsage{PerSubmitter: map[string]int{}}
	for rows.Next() {
		var submitter, raw string
		var updatedAt int64
		if err := rows.Scan(&submitter, &raw, &updatedAt); err != nil {
			return nil, err
		}
		c, cerr := ParseContract(json.RawMessage(raw))
		if vmProvablyDead(time.UnixMilli(updatedAt), c, grace, now) {
			continue
		}
		usage.VMs++
		usage.PerSubmitter[submitter]++
		if cerr == nil {
			usage.CPUs += c.Resources.CPUs
			usage.MemoryMB += c.Resources.MemoryMB
			usage.DiskMB += c.Resources.DiskMB
			usage.OutputBytes += c.Resources.MaxOutputBytes
		}
	}
	return usage, rows.Err()
}

// vmProvablyDead reports whether the VM a row may represent can no
// longer exist.
//
// There are exactly two ways a reservation ends. The first is verified
// cleanup: the removal succeeded and the ledger cleared
// cleanup_pending, so the row stops being a candidate here at all. The
// second is this one — a time bound — and it is not verification of
// anything. A VM cannot outlive its own runtime-enforced --max-duration,
// which the backend pins to the contract timeout plus the observation
// grace, so once that bound plus the caller's grace has certainly
// elapsed the reservation is released even though the row stays
// unresolved for the operator's audit.
//
// The bound therefore rests on the pinned runtime honouring
// --max-duration, which is part of what the runtime identity is pinned
// by digest to guarantee. It is deliberately conservative — the caller's
// grace is larger than the VM's own, and a terminal row's last
// transition is always later than the VM's creation — so the release
// never outruns the VM. A row whose contract cannot be parsed, or that
// declares no timeout, is never released this way: the bound cannot be
// established, so the reservation is held rather than guessed away.
func vmProvablyDead(updatedAt time.Time, contract *JobContractV2, grace time.Duration, now time.Time) bool {
	if contract == nil || contract.Resources.TimeoutSeconds == 0 {
		return false
	}
	return now.After(updatedAt.Add(time.Duration(contract.Resources.TimeoutSeconds)*time.Second + grace))
}

// Count reports the durable registry size.
func (l *Ledger) Count() (int, error) {
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(1) FROM jobs`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// List returns every recorded job in sequence order — the active
// registry merged with the archive, so a verifier enumerating the
// ledger sees every job it ever admitted, not only the operational
// remainder. Archived rows carry Archived=true.
func (l *Ledger) List() ([]*LedgerJob, error) {
	active, err := l.listActive()
	if err != nil {
		return nil, err
	}
	archived, err := l.listArchived()
	if err != nil {
		return nil, err
	}
	return sortJobs(active, archived), nil
}

// listArchived and sortJobs live in archive.go.

// listActive returns the operational registry in seq order.
func (l *Ledger) listActive() ([]*LedgerJob, error) {
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
		// The permanent identity carries the terminal position too —
		// the enumeration must still resolve after the row archives.
		if _, err := tx.Exec(
			`UPDATE job_identities SET terminal_seq = ? WHERE job_id = ?`,
			next, jobID); err != nil {
			return fmt.Errorf("stamp terminal identity %s: %w", jobID, err)
		}
	}
	var exit any
	if job.ExitCode != nil {
		exit = *job.ExitCode
	}
	cleanupPending := 0
	if job.CleanupPending {
		cleanupPending = 1
	}
	res, err := tx.Exec(
		`UPDATE jobs SET state = ?, fence_epoch = ?, backend_id = ?, backend_handle = ?,
		 backend_job_id = ?, backend_boot_id = ?, policy_digest = ?,
		 dispatch_nonce = ?, image_digest = ?, runtime_identity = ?, dispatch_class = ?,
		 updated_at = ?, exit_code = ?, error = ?, result_json = ?,
		 terminal_seq = ?, receipt_sha256 = ?, artifact_sha256 = ?,
		 cleanup_pending = ?, cleanup_error = ?
		 WHERE job_id = ? AND seq = ?`,
		job.State, job.FenceEpoch, job.BackendID, job.BackendHandle,
		job.BackendJobID, job.BackendBootID, job.PolicyDigest,
		job.DispatchNonce, job.ImageDigest, job.RuntimeIdentity, job.DispatchClass,
		time.Now().UTC().UnixMilli(), exit, job.Error, job.ResultJSON,
		termSeq, job.ReceiptSHA256, job.ArtifactSHA256,
		cleanupPending, job.CleanupError,
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
	// The terminal enumeration spans both tables: an archived terminal
	// row is still a checkpoint-covered record. The archive side
	// excludes any job_id still present in jobs — the crash window of a
	// custodial handoff — so the enumeration stays dense and dup-free.
	rows, err := q.Query(
		`SELECT terminal_seq, job_id, state, contract_hash, result_json,
		 artifact_sha256, receipt_sha256, backend_id, backend_handle, updated_at
		 FROM jobs WHERE terminal_seq IS NOT NULL
		 UNION ALL
		 SELECT terminal_seq, job_id, state, contract_hash, result_json,
		 artifact_sha256, receipt_sha256, backend_id, backend_handle, updated_at
		 FROM jobs_archive a WHERE a.terminal_seq IS NOT NULL
		 AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.job_id = a.job_id)
		 ORDER BY terminal_seq`)
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
