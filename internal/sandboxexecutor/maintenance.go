package sandboxexecutor

import (
	"encoding/json"
	"fmt"
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
// Per-attempt pacing lives in small in-memory backoff maps: a restart
// re-tries everything once immediately (correct — state may have
// changed while the daemon was down), then each row backs off, so a
// permanently failing cleanup audits rather than spams.

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
	s.escalateResidue()
}

// maintMu guards the retry-pacing and escalation bookkeeping — maps
// of last-attempt times and the last-audited residue shape.
// The maps are per-lifetime by design: a restart re-attempts every
// candidate once, because the world may have changed while down.

// claimAttempt reports whether a row is due for another attempt — the
// first sighting is always due, then once per backoff. The map is
// stamped on every true return, so a row attempted once per pass is
// attempted at most once per backoff window.
func (s *Server) claimAttempt(m map[string]time.Time, jobID string, backoff time.Duration) bool {
	s.maintMu.Lock()
	defer s.maintMu.Unlock()
	now := s.now()
	if last, ok := m[jobID]; ok && now.Sub(last) < backoff {
		return false
	}
	m[jobID] = now
	return true
}

// forgetAttempt drops pacing state for a job that resolved — the map
// must not grow on history the ledger no longer holds.
func (s *Server) forgetAttempt(m map[string]time.Time, jobID string) {
	s.maintMu.Lock()
	defer s.maintMu.Unlock()
	delete(m, jobID)
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
	claimErr := s.ledger.Transition(j.JobID, JobStateDispatching, []string{JobStateRecorded}, nil)
	s.admitMu.Unlock()
	if claimErr != nil {
		// A live admission claimed it first, or the row moved on its
		// own — either way this pass must not drive it.
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
		if err := s.ledger.Transition(j.JobID, JobStateDispatchAmbig, []string{JobStateDispatching},
			func(lj *LedgerJob) error {
				lj.DispatchClass = string(DispatchUncertain)
				lj.Error = "dispatch driver lost mid-flight — outcome uncertain; reconciled as ambiguous rather than retried or claimed dead"
				return nil
			}); err != nil {
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
	if err := s.ledger.Transition(j.JobID, JobStateDispatchFailed, []string{JobStateRecorded},
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

// escalateResidue audits what maintenance could not resolve. The line
// fires immediately when the residue shape changes, then repeats on a
// throttle so a permanently unresolved workload stays visible without
// drowning the log.
func (s *Server) escalateResidue() {
	r, err := s.ledger.PendingResidue()
	if err != nil {
		s.audit("maintenance: cannot read registry residue: %v", err)
		return
	}
	if r.Unresolved == 0 && r.CleanupPending == 0 {
		return
	}
	now := s.now()
	sig := fmt.Sprintf("%d/%d/%d/%d", r.Unresolved, r.CleanupPending,
		r.OldestUnresolved.Unix(), r.OldestCleanup.Unix())
	s.maintMu.Lock()
	if sig == s.lastResidueSig && now.Sub(s.lastResidueAudit) < residueEscalationRepeat {
		s.maintMu.Unlock()
		return
	}
	s.lastResidueSig, s.lastResidueAudit = sig, now
	s.maintMu.Unlock()
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
			if !s.claimAttempt(s.lastResumeAttempt, j.JobID, resumeRetryBackoff) {
				continue
			}
			s.reconcileOne(j)
			if done, _ := s.ledger.Get(j.JobID); done == nil || done.State != JobStateDispatchAmbig && done.State != JobStateInterrupted {
				s.forgetAttempt(s.lastResumeAttempt, j.JobID)
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
			if !s.claimAttempt(s.lastCleanupAttempt, j.JobID, cleanupRetryBackoff) {
				continue
			}
			s.cleanupOne(j)
		}
		cursor = jobs[len(jobs)-1].Seq
	}
}
