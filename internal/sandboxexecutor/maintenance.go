package sandboxexecutor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// Continuous recovery: the startup walks (reconcile, cleanup retry)
// fix what a previous lifetime left, but a daemon that runs forever
// leaves things mid-lifetime too — a RECORDED row whose driver died
// before claiming it, a cleanup that keeps failing, an unresolved run
// whose backend settles an hour later, a registry filling with settled
// history. The maintenance loop is the durable continuation: it
// re-drives each category on a bounded cadence, under the same CAS
// claims and fence epoch the live path uses, never creating work —
// only moving durable intents toward their recorded conclusion.
//
// Per-attempt pacing is durable (recovery_attempts): a claim stays
// claimed across restarts, so a daemon reopened inside a backoff
// window keeps waiting instead of re-attempting every row — while
// downtime longer than the backoff still makes the next pass due
// immediately, because the world may have changed while down. What
// the loop did is itself evidence: claims, markings, terminations
// and escalations land in recovery_events, the durable trail a log
// line never was.

const (
	// defaultMaintenanceInterval paces the recovery scheduler.
	defaultMaintenanceInterval = 60 * time.Second
	// resumeRetryBackoff and cleanupRetryBackoff bound how often one
	// unresolved run or one pending cleanup is re-attempted.
	resumeRetryBackoff  = 2 * time.Minute
	cleanupRetryBackoff = 5 * time.Minute
	// residueEscalationRepeat throttles the residue escalation line:
	// an unchanged residue shape re-audits at this cadence; a changed
	// shape audits immediately.
	residueEscalationRepeat = 10 * time.Minute
)

// maintenanceLoop runs one recovery pass per interval until shutdown.
// A negative MaintenanceInterval disables the periodic passes — the
// startup walks still run; zero takes the default.
func (s *Server) maintenanceLoop() {
	defer s.acceptWg.Done()
	iv := s.cfg.MaintenanceInterval
	if iv == 0 {
		iv = defaultMaintenanceInterval
	}
	if iv < 0 {
		return
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-s.shutdown.Done():
			return
		case <-t.C:
		}
		s.maintenancePass()
	}
}

// maintenancePass runs one round of each recovery phase in drain
// order: claim stranded dispatch intents, re-observe unresolved runs,
// retry removals, then archive what has fully settled and report what
// has not.
func (s *Server) maintenancePass() {
	if s.cfg.Backend != nil {
		s.dispatchRecorded()
		s.markStaleDispatching()
		s.reconcileWalk()
		s.cleanupWalk()
	}
	if _, err := s.ledger.ArchiveCompleted(maxArchiveBatch); err != nil {
		s.audit("maintenance: archive pass failed: %v", err)
	}
	s.recoveryCustodyPass()
	s.escalateResidue()
}

// recoveryCustodyPass attests the recovery history once per
// maintenance pass: a signed checkpoint is queued whenever the chain
// head advanced, then every pending outbox row is offered to the
// configured custodian. Emission failures are audited, never silent —
// an unattested head is a custody gap, not a crash.
func (s *Server) recoveryCustodyPass() {
	if s.evidence == nil {
		return
	}
	if _, emitted, err := s.ledger.EmitRecoveryCheckpoint(s.evidence.Signer()); err != nil {
		s.audit("maintenance: recovery checkpoint emission failed: %v", err)
	} else if emitted {
		s.audit("maintenance: recovery checkpoint queued for custody")
	}
	if rc, ok := s.cfg.ArchiveCustodian.(RecoveryCustodian); ok && rc != nil {
		if err := s.ledger.DrainRecoveryCustody(rc, s.audit); err != nil {
			s.audit("maintenance: recovery custody drain failed: %v", err)
		}
	}
}

// resumeBackoff/cleanupBackoff resolve the configured pacing windows,
// falling back to the defaults. The values are validated at startup,
// so a configured window is never negative here.
func (s *Server) resumeBackoff() time.Duration {
	if s.cfg.ResumeBackoff > 0 {
		return s.cfg.ResumeBackoff
	}
	return resumeRetryBackoff
}

func (s *Server) cleanupBackoff() time.Duration {
	if s.cfg.CleanupBackoff > 0 {
		return s.cfg.CleanupBackoff
	}
	return cleanupRetryBackoff
}

// claimRecovery returns the durable recovery claim under which this
// lifetime may run one more attempt of action on a row — the first
// sighting is always due, then once per backoff, with the schedule
// itself durable in the ledger so a restart inside the backoff does
// not re-attempt. The grant is atomic and fenced: at most one
// claimant wins the window, its owning epoch and generation are
// stamped, and the durable claim record commits in the same
// transaction as the grant itself, so an attempt whose ownership
// could not be evidenced never runs. The claim is the fencing token
// every protected operation and commit boundary validates — it is
// carried whole, never reduced to a boolean. Ledger failures are
// reported and the row skipped: an unpaceable retry is never run
// unpaced.
func (s *Server) claimRecovery(jobID, action string, backoff time.Duration) *RecoveryClaim {
	claim, err := s.ledger.ClaimRecoveryAttempt(jobID, action, backoff, backoff, s.now())
	if err != nil {
		s.audit("maintenance: cannot pace %s attempt for %s: %v", action, jobID, err)
		return nil
	}
	return claim
}

// releaseRecovery completes the claim's pacing state for work that
// resolved — the release is ownership-conditioned, so a claimant
// that went stale mid-operation cannot erase the claim a newer owner
// now holds.
func (s *Server) releaseRecovery(claim *RecoveryClaim, detail string) {
	if claim == nil {
		return
	}
	if err := s.ledger.CompleteRecoveryClaim(claim, detail, s.now()); err != nil {
		s.audit("maintenance: cannot complete %s claim for %s: %v", claim.Action, claim.JobID, err)
	}
}

// dispatchRecorded sweeps jobs whose durable intent never reached a
// DISPATCHING claim — a crash mid-admission, or rows recorded by a
// record-only deployment later given a backend. Each row is claimed
// through the same RECORDED→DISPATCHING CAS the live path uses, so a
// claim race with a live admission resolves exactly once. A row whose
// contract can no longer run — expired, or unreadable — is terminated
// with a NO_EFFECT receipt: RECORDED proves no backend was ever asked,
// so the executor may attest the job never ran.
func (s *Server) dispatchRecorded() {
	var cursor uint64
	for {
		if s.isStopped() {
			return
		}
		rows, err := s.ledger.RecordedCandidates(recoveryPageSize, cursor)
		if err != nil {
			s.audit("maintenance: cannot enumerate recorded jobs: %v", err)
			return
		}
		if len(rows) == 0 {
			return
		}
		for _, j := range rows {
			if s.isStopped() {
				return
			}
			s.dispatchRecordedOne(j)
		}
		cursor = rows[len(rows)-1].Seq
	}
}

// dispatchRecordedOne drives one RECORDED row toward dispatch, or
// terminates it when the contract can no longer authorize a run.
func (s *Server) dispatchRecordedOne(j *LedgerJob) {
	contract, cerr := ParseContract(json.RawMessage(j.ContractJSON))
	if cerr != nil {
		s.expireRecorded(j, fmt.Sprintf("stored contract unreadable — never dispatched: %v", cerr))
		return
	}
	if contract.ExpiresAt > 0 && !s.now().Before(time.Unix(contract.ExpiresAt, 0)) {
		s.expireRecorded(j, fmt.Sprintf("contract expired at %d before any dispatch — never ran", contract.ExpiresAt))
		return
	}
	// The admission-time pool check is stale by definition for a
	// deferred claim — re-check against current usage, under admitMu
	// so a live admission cannot pass the same budget concurrently.
	// The claim and the check are one critical section, exactly like
	// admitJob's insert-and-reserve.
	s.admitMu.Lock()
	usage, err := s.ledger.ActiveUsage(s.cfg.DispatchTimeout + time.Minute)
	if err != nil {
		s.admitMu.Unlock()
		s.audit("maintenance: cannot read pool usage for deferred dispatch of %s: %v", j.JobID, err)
		return
	}
	if s.cfg.ResourcePool != nil {
		if perr := s.cfg.ResourcePool.check(usage, j.Submitter, contractBudget(contract)); perr != nil {
			s.admitMu.Unlock()
			s.audit("maintenance: deferred dispatch of %s held — pool exhausted: %v", j.JobID, perr)
			return
		}
	}
	claimErr := s.ledger.TransitionWithRecoveryEvent(j.JobID, JobStateDispatching, []string{JobStateRecorded},
		"claim", "stranded dispatch intent claimed by maintenance", nil)
	s.admitMu.Unlock()
	if claimErr != nil {
		// A live admission claimed it first, the row moved on its
		// own, or the mandatory claim record could not be written —
		// either way this pass must not drive it.
		return
	}
	s.audit("maintenance: claiming stranded dispatch of %s", j.JobID)
	state, reason := s.driveDispatch(j, contract)
	if state != JobStateRunning {
		s.audit("maintenance: deferred dispatch of %s -> %s: %v", j.JobID, state, reason)
	}
}

// markStaleDispatching resolves DISPATCHING rows with no live driver.
// Every context on the dispatch drive is bounded — prepare plus the
// dispatch timeout — so a row written before the cutoff was abandoned:
// the process crashed mid-drive (survivable — reconcile() at open also
// catches these) or the drive returned without recording an outcome.
// The only honest resolution is uncertainty, so the row becomes
// DISPATCH_AMBIGUOUS: the observation walk tries to settle it, and the
// residue escalation reports it. A genuinely live driver would already
// have recorded its outcome — and its CAS refuses to overwrite the
// mark, so no row is ever marked twice.
func (s *Server) markStaleDispatching() {
	cutoff := s.now().Add(-(prepareTimeout + 2*s.cfg.DispatchTimeout))
	rows, err := s.ledger.DispatchingStragglers(recoveryPageSize, cutoff)
	if err != nil {
		s.audit("maintenance: cannot enumerate stranded dispatching jobs: %v", err)
		return
	}
	for _, j := range rows {
		if s.isStopped() {
			return
		}
		// The mark and its mandatory record commit together: a row
		// whose outcome-uncertainty cannot be durably evidenced stays
		// DISPATCHING for the next pass, never silently rewritten.
		if err := s.ledger.TransitionWithRecoveryEvent(j.JobID, JobStateDispatchAmbig, []string{JobStateDispatching},
			"mark_ambiguous", "dispatching row had no live driver",
			func(lj *LedgerJob) error {
				lj.DispatchClass = string(DispatchUncertain)
				lj.Error = "dispatch driver lost mid-flight — outcome uncertain; reconciled as ambiguous rather than retried or claimed dead"
				return nil
			}); err != nil {
			s.audit("maintenance: cannot mark dispatching job %s uncertain: %v", j.JobID, err)
			continue
		}
		s.audit("maintenance: dispatching job %s has no live driver — marked outcome uncertain", j.JobID)
	}
}

// expireRecorded terminates a RECORDED row that can never run. The
// NO_EFFECT claim is sound precisely because the row never left
// RECORDED: no backend was asked, so nothing ran. A failed write is
// retried on the next pass — the row stays RECORDED meanwhile.
func (s *Server) expireRecorded(j *LedgerJob, reason string) {
	receiptSHA, rerr := s.emitReceipt(j, evidence.OutcomeNoEffect, "", "")
	if rerr != nil {
		s.audit("maintenance: job %s cannot be terminated — evidence emission failed: %v", j.JobID, rerr)
		return
	}
	// The terminal decision and its mandatory record are one commit —
	// a termination whose evidence cannot be durably written leaves
	// the row RECORDED for the next pass.
	if err := s.ledger.TransitionWithRecoveryEvent(j.JobID, JobStateDispatchFailed, []string{JobStateRecorded},
		"expire", reason,
		func(lj *LedgerJob) error {
			lj.ReceiptSHA256 = receiptSHA
			lj.DispatchClass = string(DispatchNotAttempted)
			lj.Error = reason
			return nil
		}); err != nil {
		s.audit("maintenance: job %s termination refused: %v", j.JobID, err)
		return
	}
	s.audit("maintenance: job %s terminated without dispatch: %s", j.JobID, reason)
	s.checkpoint()
}

// residueStateKey is the durable throttle state: the last-audited
// residue shape and when. Kept in the ledger so a daemon reopened
// mid-throttle does not re-escalate an unchanged shape.
const residueStateKey = "residue_escalation"

// escalateResidue audits what maintenance could not resolve. The line
// fires immediately when the residue shape changes, then repeats on a
// throttle — with the throttle state durable, so a crash-looping
// daemon escalates an unchanged shape once, not once per restart.
// Every escalation also lands in recovery_events: the trail survives
// the log it was printed to.
func (s *Server) escalateResidue() {
	r, err := s.ledger.PendingResidue()
	if err != nil {
		s.audit("maintenance: cannot read registry residue: %v", err)
		return
	}
	if r.Unresolved == 0 && r.CleanupPending == 0 && r.Retained == 0 {
		return
	}
	now := s.now()
	sig := fmt.Sprintf("%d/%d/%d/%d/%d/%d", r.Unresolved, r.CleanupPending, r.Retained,
		r.OldestUnresolved.Unix(), r.OldestCleanup.Unix(), r.OldestRetained.Unix())
	prev, found, err := s.ledger.RecoveryState(residueStateKey)
	if err != nil {
		s.audit("maintenance: cannot read residue throttle state: %v", err)
		return
	}
	var lastAudit time.Time
	if found {
		if at := strings.LastIndex(prev, "@"); at >= 0 && prev[:at] == sig {
			if ms, perr := strconv.ParseInt(prev[at+1:], 10, 64); perr == nil {
				lastAudit = time.UnixMilli(ms)
			}
		}
	}
	if !lastAudit.IsZero() && now.Sub(lastAudit) < residueEscalationRepeat {
		return
	}
	// Evidence before the throttle mark: an escalation whose durable
	// record cannot be written must not mark the shape as reported —
	// the next pass escalates again rather than going quiet on an
	// unrecorded residue.
	retainedNote := ""
	if r.Retained > 0 {
		retainedNote = fmt.Sprintf(", %d retained by policy (oldest %s ago — live resources, not residue-free)",
			r.Retained, now.Sub(r.OldestRetained).Round(time.Second))
	}
	if err := s.ledger.RecordRecoveryEvent("escalation", "registry",
		fmt.Sprintf("residue persists: %d unresolved (oldest %s ago), %d cleanup pending (oldest %s ago)%s",
			r.Unresolved, now.Sub(r.OldestUnresolved).Round(time.Second),
			r.CleanupPending, now.Sub(r.OldestCleanup).Round(time.Second), retainedNote), now); err != nil {
		s.audit("maintenance: cannot record residue escalation durably: %v", err)
		return
	}
	if err := s.ledger.SetRecoveryState(residueStateKey,
		fmt.Sprintf("%s@%d", sig, now.UnixMilli())); err != nil {
		s.audit("maintenance: cannot persist residue throttle state: %v", err)
		return
	}
	s.audit("ESCALATION: registry residue persists — %d unresolved job(s) (oldest %s ago), %d cleanup pending (oldest %s ago) — operator reconciliation required; these are never auto-retried blind or auto-destroyed",
		r.Unresolved, now.Sub(r.OldestUnresolved).Round(time.Second),
		r.CleanupPending, now.Sub(r.OldestCleanup).Round(time.Second))
}

// reconcileWalk re-attempts observation of unresolved rows: a run the
// backend can now prove settles to the same terminal record a live
// monitor would have written. Rows attempted within the backoff are
// skipped, so a run the runtime lost audits periodically rather than
// every tick.
func (s *Server) reconcileWalk() {
	var cursor uint64
	for {
		jobs, err := s.ledger.ReconcileCandidates(recoveryPageSize, cursor)
		if err != nil {
			s.audit("reconcile failed: cannot enumerate unresolved jobs: %v", err)
			return
		}
		if len(jobs) == 0 {
			return
		}
		for _, j := range jobs {
			if s.isStopped() {
				return
			}
			claim := s.claimRecovery(j.JobID, RecoveryActionResume, s.resumeBackoff())
			if claim == nil {
				continue
			}
			s.reconcileOne(j, claim)
			if done, _ := s.ledger.Get(j.JobID); done == nil || done.State != JobStateDispatchAmbig && done.State != JobStateInterrupted {
				s.releaseRecovery(claim, "unresolved run settled")
			}
		}
		cursor = jobs[len(jobs)-1].Seq
	}
}

// cleanupWalk retries pending removals on the same backoff cadence.
func (s *Server) cleanupWalk() {
	var cursor uint64
	for {
		jobs, err := s.ledger.CleanupCandidates(recoveryPageSize, cursor)
		if err != nil {
			s.audit("cleanup retry failed: cannot enumerate pending cleanups: %v", err)
			return
		}
		if len(jobs) == 0 {
			return
		}
		for _, j := range jobs {
			if s.isStopped() {
				return
			}
			claim := s.claimRecovery(j.JobID, RecoveryActionCleanup, s.cleanupBackoff())
			if claim == nil {
				continue
			}
			s.cleanupOne(j, claim)
		}
		cursor = jobs[len(jobs)-1].Seq
	}
}
