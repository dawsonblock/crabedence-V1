package sandboxexecutor

import (
	"database/sql"
	"fmt"
	"time"
)

// Durable recovery scheduling (ledger schema v9).
//
// The maintenance loop used to pace retries in per-lifetime maps: a
// restart re-attempted every unresolved row once, on the argument
// that the world may have changed while the daemon was down. True —
// but a crash-looping daemon restarted inside a backoff window got a
// free retry every open, so a wedged backend could be hammered by
// its own recovery. Durable pacing keeps the schedule in the ledger
// itself: a claim that fired recently stays claimed across lifetimes,
// while downtime longer than the backoff still makes the next pass
// due immediately — the two honest behaviors, kept apart.
//
// Recovery actions — the named, retryable maintenance operations.
const (
	// RecoveryActionResume re-observes an unresolved run through the
	// backend (DISPATCH_AMBIGUOUS, INTERRUPTED).
	RecoveryActionResume = "resume"
	// RecoveryActionCleanup retries a pending backend removal.
	RecoveryActionCleanup = "cleanup"
)

// RecoveryEvent is one durable record of recovery activity: what the
// maintenance loop claimed, marked, terminated, or escalated. The
// audit line tells an operator now; this table is what stays true
// when the log is gone — and what history ingests later.
type RecoveryEvent struct {
	Seq     int64
	AtMS    int64
	Kind    string
	Subject string
	Detail  string
}

// ClaimRecoveryAttempt is the durable version of the old pacing map:
// the first sighting of a job/action is always due; then once per
// backoff — across restarts, because the stamp lives in the ledger.
// Returns whether the attempt may proceed and the ordinal of this
// attempt (the audit trail can say "attempt 14" and mean it).
func (l *Ledger) ClaimRecoveryAttempt(jobID, action string, backoff time.Duration, now time.Time) (bool, int, error) {
	var lastMS int64
	var attempts int
	err := l.db.QueryRow(`SELECT last_attempt_ms, attempts FROM recovery_attempts
		WHERE job_id = ? AND action = ?`, jobID, action).Scan(&lastMS, &attempts)
	if err != nil && err != sql.ErrNoRows {
		return false, 0, fmt.Errorf("recovery claim %s/%s: %w", jobID, action, err)
	}
	if err == nil && now.Sub(time.UnixMilli(lastMS)) < backoff {
		return false, attempts, nil
	}
	attempts++
	if _, err := l.db.Exec(`INSERT INTO recovery_attempts (job_id, action, last_attempt_ms, attempts)
		VALUES (?,?,?,?)
		ON CONFLICT(job_id, action) DO UPDATE SET last_attempt_ms = excluded.last_attempt_ms,
		attempts = excluded.attempts`,
		jobID, action, now.UnixMilli(), attempts); err != nil {
		return false, 0, fmt.Errorf("recovery claim %s/%s: %w", jobID, action, err)
	}
	return true, attempts, nil
}

// ForgetRecoveryAttempt drops pacing state for a job that resolved —
// the table must not grow on history the registry no longer holds.
func (l *Ledger) ForgetRecoveryAttempt(jobID, action string) error {
	_, err := l.db.Exec(`DELETE FROM recovery_attempts WHERE job_id = ? AND action = ?`, jobID, action)
	return err
}

// RecordRecoveryEvent appends one durable recovery record. These are
// written inside the maintenance pass's own cadence, so growth is
// bounded by residue — a healthy registry logs nothing here.
func (l *Ledger) RecordRecoveryEvent(kind, subject, detail string, at time.Time) error {
	_, err := l.db.Exec(`INSERT INTO recovery_events (at_ms, kind, subject, detail) VALUES (?,?,?,?)`,
		at.UnixMilli(), kind, subject, detail)
	return err
}

// hasTable reports whether the named table exists — read-only
// InspectLedger opens skip migrations, so a pre-v9 ledger answered
// for a table it never had.
func (l *Ledger) hasTable(name string) (bool, error) {
	var n int
	err := l.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return n > 0, err
}

// RecoveryEvents returns the durable recovery trail, newest first.
// Read-only callers (InspectLedger) use it to audit what recovery
// actually did; limit 0 means everything. A pre-v9 ledger carries no
// durable trail — its maintenance state lived in process memory, so
// an empty result is the honest answer rather than an error.
func (l *Ledger) RecoveryEvents(limit int) ([]*RecoveryEvent, error) {
	ok, err := l.hasTable("recovery_events")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	q := `SELECT seq, at_ms, kind, subject, detail FROM recovery_events ORDER BY seq DESC`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := l.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RecoveryEvent
	for rows.Next() {
		e := &RecoveryEvent{}
		if err := rows.Scan(&e.Seq, &e.AtMS, &e.Kind, &e.Subject, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecoveryState reads an operator-set recovery bookkeeping key from
// executor_meta — pacing state that must survive restarts (the
// residue escalation throttle) without its own table.
func (l *Ledger) RecoveryState(key string) (string, bool, error) {
	var v string
	err := l.db.QueryRow(`SELECT value FROM executor_meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetRecoveryState persists one recovery bookkeeping key.
func (l *Ledger) SetRecoveryState(key, value string) error {
	_, err := l.db.Exec(`INSERT INTO executor_meta (key, value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
