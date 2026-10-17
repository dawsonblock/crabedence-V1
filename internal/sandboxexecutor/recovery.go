package sandboxexecutor

import (
	"context"
	"database/sql"
	"errors"
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
	// ClaimID is the claim's durable generation identifier — a
	// monotonic, never-reused ordinal allocated inside the claim
	// transaction, so a token held from a deleted-and-recreated
	// pacing row can never be mistaken for the current generation.
	ClaimID    int64
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
	// Allocate the claim's durable generation first: the counter and
	// the claim it identifies commit together, so a generation that
	// could not be durably recorded never exists.
	var uid int64
	if _, err = tx.Exec(`INSERT INTO executor_meta (key, value) VALUES ('recovery_claim_seq', '0')
		ON CONFLICT(key) DO NOTHING`); err != nil {
		return nil, fmt.Errorf("recovery claim %s/%s: seed claim counter: %w", jobID, action, err)
	}
	err = tx.QueryRow(`UPDATE executor_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
		WHERE key = 'recovery_claim_seq' RETURNING value`).Scan(&uid)
	if err != nil {
		return nil, fmt.Errorf("recovery claim %s/%s: allocate claim generation: %w", jobID, action, err)
	}
	var attempts int
	err = tx.QueryRow(`INSERT INTO recovery_attempts
		(job_id, action, last_attempt_ms, attempts, claim_epoch, claim_until_ms, claim_uid)
		VALUES (?, ?, ?, 1, ?, ?, ?)
		ON CONFLICT(job_id, action) DO UPDATE SET
			last_attempt_ms = MAX(recovery_attempts.last_attempt_ms, excluded.last_attempt_ms),
			attempts        = recovery_attempts.attempts + 1,
			claim_epoch     = excluded.claim_epoch,
			claim_until_ms  = excluded.claim_until_ms,
			claim_uid       = excluded.claim_uid
		WHERE recovery_attempts.last_attempt_ms <= ?
		  AND recovery_attempts.claim_until_ms  <= ?
		RETURNING attempts`,
		jobID, action, nowMS, l.epoch, untilMS, uid, dueBeforeMS, nowMS).Scan(&attempts)
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
		fmt.Sprintf("%s attempt %d claimed by epoch %d (generation %d, lease until %d)",
			action, attempts, l.epoch, uid, untilMS), now, uid); err != nil {
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
		ClaimID:    uid,
		ClaimedAt:  time.UnixMilli(nowMS).UTC(),
		LeaseUntil: time.UnixMilli(untilMS).UTC(),
	}, nil
}

// ErrClaimStale marks a recovery claim that no longer matches the
// durable ownership: superseded by a newer claimant, generated by a
// deleted-and-recreated pacing row, or past its lease. Operations
// gated on the claim refuse — a stale claimant holds no authority.
var ErrClaimStale = errors.New("recovery claim is stale — ownership has moved on")

// claimValidTx validates the claim against the durable pacing row
// inside tx: the current generation must still be exactly the one the
// claim names. When requireLive is true the lease must also still be
// live at now — the check an effect boundary runs before issue and the
// commit gate runs before landing a protected transition. A release
// calls with requireLive=false: erasing only its own generation is
// safe even after the lease lapses, because a superseded generation
// already fails the identity check.
func (l *Ledger) claimValidTx(tx *sql.Tx, claim *RecoveryClaim, now time.Time, requireLive bool) error {
	if claim == nil {
		return fmt.Errorf("%w: no claim supplied", ErrClaimStale)
	}
	var attempts int
	var epoch, uid, untilMS int64
	err := tx.QueryRow(`SELECT attempts, claim_epoch, claim_uid, claim_until_ms
		FROM recovery_attempts WHERE job_id = ? AND action = ?`,
		claim.JobID, claim.Action).Scan(&attempts, &epoch, &uid, &untilMS)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: %s/%s has no durable claim row", ErrClaimStale, claim.JobID, claim.Action)
	}
	if err != nil {
		return fmt.Errorf("validate recovery claim %s/%s: %w", claim.JobID, claim.Action, err)
	}
	if uid != claim.ClaimID || attempts != claim.Attempt || epoch != int64(claim.OwnerEpoch) {
		return fmt.Errorf("%w: %s/%s held generation %d (attempt %d, epoch %d) but the durable row is generation %d (attempt %d, epoch %d)",
			ErrClaimStale, claim.JobID, claim.Action, claim.ClaimID, claim.Attempt, claim.OwnerEpoch, uid, attempts, epoch)
	}
	if requireLive && untilMS <= now.UnixMilli() {
		return fmt.Errorf("%w: %s/%s lease expired at %s", ErrClaimStale, claim.JobID, claim.Action, time.UnixMilli(untilMS).UTC().Format(time.RFC3339))
	}
	return nil
}

// ValidateRecoveryClaim reports whether the claim is still the durable,
// live owner — the read-only check an operation runs before issuing an
// external effect it cannot recall.
func (l *Ledger) ValidateRecoveryClaim(claim *RecoveryClaim, now time.Time) error {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("validate recovery claim %s/%s: %w", claim.JobID, claim.Action, err)
	}
	defer tx.Rollback()
	return l.claimValidTx(tx, claim, now, true)
}

// ExtendRecoveryLease pushes the claim's lease forward, conditioned on
// the claim still being the current durable owner. An operation that
// will outlive its lease extends before issuing the effect — a stale
// claimant's extension is refused, never granted.
func (l *Ledger) ExtendRecoveryLease(claim *RecoveryClaim, lease time.Duration, now time.Time) error {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("extend recovery claim %s/%s: %w", claim.JobID, claim.Action, err)
	}
	defer tx.Rollback()
	if err := l.claimValidTx(tx, claim, now, true); err != nil {
		return err
	}
	untilMS := now.Add(lease).UnixMilli()
	res, err := tx.Exec(`UPDATE recovery_attempts SET claim_until_ms = MAX(claim_until_ms, ?)
		WHERE job_id = ? AND action = ? AND claim_uid = ?`,
		untilMS, claim.JobID, claim.Action, claim.ClaimID)
	if err != nil {
		return fmt.Errorf("extend recovery claim %s/%s: %w", claim.JobID, claim.Action, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: %s/%s generation moved during extension", ErrClaimStale, claim.JobID, claim.Action)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recovery lease extension %s/%s: %w", claim.JobID, claim.Action, err)
	}
	if until := time.UnixMilli(untilMS).UTC(); until.After(claim.LeaseUntil) {
		claim.LeaseUntil = until
	}
	return nil
}

// releaseClaimTx is the shared conditioned-release: the pacing row is
// deleted only while the claim is still the durable owner — a stale
// claimant's release cannot erase the current owner's claim. The
// generation check (not the lease) is what conditions a release: the
// work the claim authorized already ran under a live lease.
func (l *Ledger) releaseClaimTx(claim *RecoveryClaim, kind, detail string, now time.Time) error {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("%s recovery claim %s/%s: %w", kind, claim.JobID, claim.Action, err)
	}
	defer tx.Rollback()
	if err := l.claimValidTx(tx, claim, now, false); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM recovery_attempts
		WHERE job_id = ? AND action = ? AND claim_uid = ?`,
		claim.JobID, claim.Action, claim.ClaimID)
	if err != nil {
		return fmt.Errorf("%s recovery claim %s/%s: %w", kind, claim.JobID, claim.Action, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: %s/%s generation moved during release", ErrClaimStale, claim.JobID, claim.Action)
	}
	if err := l.recordRecoveryEventTx(tx, kind, claim.JobID, detail, now, claim.ClaimID); err != nil {
		return fmt.Errorf("%s recovery claim %s/%s: %w", kind, claim.JobID, claim.Action, err)
	}
	return tx.Commit()
}

// CompleteRecoveryClaim is the success release: the work the claim
// authorized is durably done, and its pacing state is erased under
// the same generation check — completed work stops pacing.
func (l *Ledger) CompleteRecoveryClaim(claim *RecoveryClaim, detail string, now time.Time) error {
	return l.releaseClaimTx(claim, "claim_complete", detail, now)
}

// ReleaseRecoveryClaim abandons the claim's durable ownership — again
// only while the claim is still the durable owner. A stale claimant's
// release is refused outright: it can never erase current ownership.
func (l *Ledger) ReleaseRecoveryClaim(claim *RecoveryClaim, detail string, now time.Time) error {
	return l.releaseClaimTx(claim, "claim_release", detail, now)
}

// recordRecoveryEventTx moved to recovery_event_chain.go: the
// mandatory-evidence write now binds each event into the hash chain
// inside the same transaction as the state change it records.

// RecordRecoveryEvent appends one durable recovery record. These are
// written inside the maintenance pass's own cadence, so growth is
// bounded by residue — a healthy registry logs nothing here.
func (l *Ledger) RecordRecoveryEvent(kind, subject, detail string, at time.Time) error {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := l.recordRecoveryEventTx(tx, kind, subject, detail, at, 0); err != nil {
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
