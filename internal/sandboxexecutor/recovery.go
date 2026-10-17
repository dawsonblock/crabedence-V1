package sandboxexecutor

import (
	"context"
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

// RecoveryClaim is the durable, fenced ownership of one recovery
// attempt — permission to run exactly one attempt of action on jobID,
// held exclusively until LeaseUntil. OwnerEpoch is the claiming ledger
// lifetime's fence epoch: the audit trail can name which generation of
// the executor held each attempt, and a claim replayed by anything but
// the owner generation cannot be mistaken for current permission.
// Attempt is the monotonic ordinal of attempts granted for the pair —
// it never repeats and never decreases for the life of the pacing row.
type RecoveryClaim struct {
	JobID      string
	Action     string
	Attempt    int
	OwnerEpoch uint64
	ClaimedAt  time.Time
	LeaseUntil time.Time
}

// ClaimRecoveryAttempt is the durable version of the old pacing map:
// the first sighting of a job/action is always due; then once per
// backoff — across restarts, because the stamp lives in the ledger.
//
// The claim is one atomic write, not a read-check-write pair. The
// conditional upsert updates the pacing row only when the previous
// attempt is older than backoff AND the previous claim's lease has
// expired, and it commits together with the recovery_events row that
// records the grant — a claim that cannot be durably evidenced is a
// claim that never happened, so a failed write leaves the row
// untouched rather than granting an unrecorded attempt.
//
// Returns nil without error when the row is not due. lease bounds how
// long the grant belongs to this claimant: an abandoned claim expires
// at ClaimedAt+lease and only then can another claimant take the row —
// and only when backoff has also elapsed, so a lease can never shorten
// the pacing window.
func (l *Ledger) ClaimRecoveryAttempt(jobID, action string, backoff, lease time.Duration, now time.Time) (*RecoveryClaim, error) {
	if backoff < 0 {
		return nil, fmt.Errorf("recovery claim %s/%s: negative backoff %s", jobID, action, backoff)
	}
	if lease <= 0 {
		// No explicit window: the pacing window is the ownership
		// lease — an abandoned claim re-arms exactly when the next
		// attempt would be due anyway.
		lease = backoff
	}
	if lease <= 0 {
		return nil, fmt.Errorf("recovery claim %s/%s: non-positive lease %s", jobID, action, lease)
	}
	nowMS := now.UnixMilli()
	dueBeforeMS := now.Add(-backoff).UnixMilli()
	untilMS := now.Add(lease).UnixMilli()

	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("recovery claim %s/%s: %w", jobID, action, err)
	}
	defer tx.Rollback()
	var attempts int
	err = tx.QueryRow(`INSERT INTO recovery_attempts
		(job_id, action, last_attempt_ms, attempts, claim_epoch, claim_until_ms)
		VALUES (?, ?, ?, 1, ?, ?)
		ON CONFLICT(job_id, action) DO UPDATE SET
			last_attempt_ms = MAX(recovery_attempts.last_attempt_ms, excluded.last_attempt_ms),
			attempts        = recovery_attempts.attempts + 1,
			claim_epoch     = excluded.claim_epoch,
			claim_until_ms  = excluded.claim_until_ms
		WHERE recovery_attempts.last_attempt_ms <= ?
		  AND recovery_attempts.claim_until_ms  <= ?
		RETURNING attempts`,
		jobID, action, nowMS, l.epoch, untilMS, dueBeforeMS, nowMS).Scan(&attempts)
	if err == sql.ErrNoRows {
		// Not due or still claimed: no write landed, no evidence is
		// owed, and no permission was granted.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("recovery claim %s/%s: %w", jobID, action, err)
	}
	// The grant and its record are one commit: a maintenance pass that
	// cannot durably record that it took ownership does not run the
	// attempt — the unresolved row simply waits for the next pass.
	if err := l.recordRecoveryEventTx(tx, "claim", jobID,
		fmt.Sprintf("%s attempt %d claimed by epoch %d (lease until %d)",
			action, attempts, l.epoch, untilMS), now); err != nil {
		return nil, fmt.Errorf("recovery claim %s/%s: %w", jobID, action, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit recovery claim %s/%s: %w", jobID, action, err)
	}
	return &RecoveryClaim{
		JobID:      jobID,
		Action:     action,
		Attempt:    attempts,
		OwnerEpoch: l.epoch,
		ClaimedAt:  time.UnixMilli(nowMS).UTC(),
		LeaseUntil: time.UnixMilli(untilMS).UTC(),
	}, nil
}

// ForgetRecoveryAttempt drops pacing state for a job that resolved —
// the table must not grow on history the registry no longer holds.
func (l *Ledger) ForgetRecoveryAttempt(jobID, action string) error {
	_, err := l.db.Exec(`DELETE FROM recovery_attempts WHERE job_id = ? AND action = ?`, jobID, action)
	return err
}

// recordRecoveryEventTx inserts one durable recovery record inside an
// in-flight transaction — the write that lets a state change and its
// mandatory audit evidence commit or roll back as one.
func (l *Ledger) recordRecoveryEventTx(tx *sql.Tx, kind, subject, detail string, at time.Time) error {
	_, err := tx.Exec(`INSERT INTO recovery_events (at_ms, kind, subject, detail) VALUES (?,?,?,?)`,
		at.UnixMilli(), kind, subject, detail)
	return err
}

// RecordRecoveryEvent appends one durable recovery record. These are
// written inside the maintenance pass's own cadence, so growth is
// bounded by residue — a healthy registry logs nothing here.
func (l *Ledger) RecordRecoveryEvent(kind, subject, detail string, at time.Time) error {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := l.recordRecoveryEventTx(tx, kind, subject, detail, at); err != nil {
		return err
	}
	return tx.Commit()
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
