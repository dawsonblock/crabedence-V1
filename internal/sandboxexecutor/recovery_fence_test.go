package sandboxexecutor

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// Recovery-claim fencing (INV-03/INV-04): a claim is permission, not
// a schedule entry. Losing ownership — by lease expiry, supersession,
// or release — must revoke every power it granted: validating,
// extending, committing a protected transition, clearing a pending
// cleanup, and releasing the claim itself.

func intPtr(v int64) *int64 { return &v }

// claimPair takes over ownership: A claims, then after A's lease and
// backoff have both elapsed B claims. A is now a stale generation —
// the durable row names B.
func claimPair(t *testing.T, l *Ledger, jobID string, now time.Time) (a, b *RecoveryClaim, atB time.Time) {
	t.Helper()
	var err error
	a, err = l.ClaimRecoveryAttempt(jobID, RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil || a == nil {
		t.Fatalf("claim A: a=%v err=%v", a, err)
	}
	atB = now.Add(2 * time.Minute)
	b, err = l.ClaimRecoveryAttempt(jobID, RecoveryActionResume, time.Minute, time.Minute, atB)
	if err != nil || b == nil {
		t.Fatalf("claim B (takeover): b=%v err=%v", b, err)
	}
	if b.ClaimID == a.ClaimID {
		t.Fatalf("claim generations collided: %d == %d", b.ClaimID, a.ClaimID)
	}
	return a, b, atB
}

// TestStaleClaimantCannotRelease: A suspended mid-recovery, B took
// the row over — A's release must refuse and must leave B's ownership
// intact. The old DELETE BY (job, action) erased whoever owned the
// row; this is the regression the fence exists for.
func TestStaleClaimantCannotRelease(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, b, atB := claimPair(t, l, "job-x", now)

	err := l.ReleaseRecoveryClaim(a, "stale claimant abandons", atB)
	if !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale release returned %v, want ErrClaimStale", err)
	}
	// B's ownership is intact: B validates, extends, completes.
	if err := l.ValidateRecoveryClaim(b, atB.Add(time.Second)); err != nil {
		t.Fatalf("B lost ownership to a stale release: %v", err)
	}
	if err := l.CompleteRecoveryClaim(b, "resolved", atB.Add(time.Second)); err != nil {
		t.Fatalf("B cannot complete its own claim after a stale release attempt: %v", err)
	}
}

// TestStaleClaimCannotReleaseAfterLeaseExpiry: A's lease lapsed but B
// has not claimed yet — the row still names A's generation, but a
// release is a generation check, not a lease check: A may still
// release *its own* generation (that work already ran under a live
// lease). What A can never do is commit a protected transition on an
// expired lease.
func TestStaleClaimCannotReleaseAfterLeaseExpiry(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, err := l.ClaimRecoveryAttempt("job-y", RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil || a == nil {
		t.Fatalf("claim A: %v %v", a, err)
	}
	past := now.Add(90 * time.Second)
	// Lease expired, generation still current: validation is live-
	// gated, so A can no longer run effects.
	if err := l.ValidateRecoveryClaim(a, past); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("validation past the lease returned %v, want ErrClaimStale", err)
	}
	// But releasing its own generation still works — erasing only
	// itself is safe.
	if err := l.ReleaseRecoveryClaim(a, "abandoning after expiry", past); err != nil {
		t.Fatalf("same-generation release refused: %v", err)
	}
}

// TestStaleClaimCannotCommitTransition is the commit-boundary fence:
// A is mid-recovery, loses the row to B, then A's protected state
// transition refuses — the observed outcome A holds never commits
// under someone else's ownership.
func TestStaleClaimCannotCommitTransition(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, b, _ := claimPair(t, l, "job-z", now)

	if _, err := l.InsertJob("job-z", "h-z", "alice", "alice", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-z", JobStateDispatchAmbig, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	// A's commit: refused — the row names B's generation now.
	err := l.TransitionWithClaim("job-z", JobStateSucceeded, []string{JobStateDispatchAmbig}, a, nil)
	if !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale transition returned %v, want ErrClaimStale", err)
	}
	// The job is exactly where it was — a stale claimant commits
	// nothing.
	j, _ := l.Get("job-z")
	if j.State != JobStateDispatchAmbig {
		t.Fatalf("stale claimant moved the job to %s", j.State)
	}
	// B's commit lands.
	if err := l.TransitionWithClaim("job-z", JobStateSucceeded, []string{JobStateDispatchAmbig}, b,
		func(j *LedgerJob) error { j.ExitCode = intPtr(0); return nil }); err != nil {
		t.Fatalf("live claimant could not commit: %v", err)
	}
}

// TestStaleClaimCannotExtend: a superseded claimant cannot push its
// lease forward — extending is conditioned on still being the owner.
func TestStaleClaimCannotExtend(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, _, atB := claimPair(t, l, "job-e", now)

	if err := l.ExtendRecoveryLease(a, time.Hour, atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale extension returned %v, want ErrClaimStale", err)
	}
}

// TestExtendLeaseKeepsALiveClaimOwner: a long backend observation can
// outlive its lease — extending before the effect keeps the claim the
// live owner, and the extension is monotonic (it can never shorten).
func TestExtendLeaseKeepsALiveClaimOwner(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, err := l.ClaimRecoveryAttempt("job-k", RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil || a == nil {
		t.Fatalf("claim: %v %v", a, err)
	}
	if err := l.ExtendRecoveryLease(a, time.Hour, now); err != nil {
		t.Fatalf("extension on a live claim refused: %v", err)
	}
	// Past the original lease but inside the extension: still owner.
	if err := l.ValidateRecoveryClaim(a, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("extended claim did not stay owner: %v", err)
	}
	// A shorter extension can never pull the lease backwards.
	if err := l.ExtendRecoveryLease(a, time.Second, now); err != nil {
		t.Fatalf("re-extension refused: %v", err)
	}
	if err := l.ValidateRecoveryClaim(a, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("a shorter extension shortened the lease: %v", err)
	}
}

// TestStaleClaimCannotClearCleanup: the cleanup clear is claim-fenced
// — a stale claimant whose backend removal succeeded mid-takeover
// cannot commit the clear under the new owner's generation. The flag
// stays pending for B's own pass.
func TestStaleClaimCannotClearCleanup(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, _, atB := claimPair(t, l, "job-c", now)

	if _, err := l.InsertJob("job-c", "h-c", "alice", "alice", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-c", JobStateSucceeded, []string{JobStateRecorded},
		func(j *LedgerJob) error { j.CleanupPending = true; j.ExitCode = intPtr(0); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := l.ClearCleanupPendingFor("job-c", a, atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale cleanup clear returned %v, want ErrClaimStale", err)
	}
	j, _ := l.Get("job-c")
	if !j.CleanupPending {
		t.Fatal("a stale claimant cleared the pending flag")
	}
}

// TestNilClaimClearsForTheLivePath: the live monitor owns its job's
// cleanup outright — no claim needed. This is the boundary between
// "unfenced because exclusively owned" and "fenced because
// contestable".
func TestNilClaimClearsForTheLivePath(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	if _, err := l.InsertJob("job-live", "h-l", "alice", "alice", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-live", JobStateSucceeded, []string{JobStateRecorded},
		func(j *LedgerJob) error { j.CleanupPending = true; j.ExitCode = intPtr(0); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := l.ClearCleanupPendingFor("job-live", nil, time.Now().UTC()); err != nil {
		t.Fatalf("live-path clear refused: %v", err)
	}
	j, _ := l.Get("job-live")
	if j.CleanupPending {
		t.Fatal("live-path clear did not land")
	}
}

// TestClaimGenerationsAreNeverReused: a claim token that outlives the
// pacing row's deletion and recreation must still be distinguishable —
// claim_uid is a ledger-wide monotonic, so generation N of the row
// can never masquerade as generation M>N.
func TestClaimGenerationsAreNeverReused(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	c1, err := l.ClaimRecoveryAttempt("job-g", RecoveryActionCleanup, time.Minute, time.Minute, now)
	if err != nil || c1 == nil {
		t.Fatalf("claim 1: %v %v", c1, err)
	}
	if err := l.CompleteRecoveryClaim(c1, "done", now); err != nil {
		t.Fatal(err)
	}
	// Row deleted and recreated: the generation still advanced.
	c2, err := l.ClaimRecoveryAttempt("job-g", RecoveryActionCleanup, time.Minute, time.Minute, now)
	if err != nil || c2 == nil {
		t.Fatalf("claim 2: %v %v", c2, err)
	}
	if c2.ClaimID <= c1.ClaimID {
		t.Fatalf("claim generation did not advance across delete/recreate: %d -> %d", c1.ClaimID, c2.ClaimID)
	}
	// The stale token is refused at every boundary even though the
	// row it names exists again under a new generation.
	later := now.Add(2 * time.Hour)
	if err := l.ValidateRecoveryClaim(c1, later); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("token from a deleted generation validated: %v", err)
	}
	if err := l.ReleaseRecoveryClaim(c1, "stale", later); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("token from a deleted generation released: %v", err)
	}
}

// TestClaimValidationReadsPersistedState: a claim token is validated
// against the durable row — a ledger reopened mid-claim sees the same
// owner, so a stale epoch from a previous lifetime cannot commit.
func TestClaimValidationReadsPersistedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	now := time.Now().UTC()
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.ClaimRecoveryAttempt("job-r", RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil || a == nil {
		t.Fatalf("claim: %v %v", a, err)
	}
	l.Close()

	// The process holding token A died. The reopened ledger is a new
	// epoch; after A's lease lapses the reopened lifetime takes over.
	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	atB := now.Add(2 * time.Minute)
	b, err := l2.ClaimRecoveryAttempt("job-r", RecoveryActionResume, time.Minute, time.Minute, atB)
	if err != nil || b == nil {
		t.Fatalf("post-reopen takeover claim: %v %v", b, err)
	}
	if b.OwnerEpoch == a.OwnerEpoch {
		t.Fatal("the reopened lifetime did not advance the owner epoch")
	}
	// The stale token the dead lifetime held is refused by the new
	// lifetime's checks.
	if err := l2.ValidateRecoveryClaim(a, atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("the dead lifetime's token validated after takeover: %v", err)
	}
	if err := l2.ReleaseRecoveryClaim(a, "zombie", atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("the dead lifetime's token released B's claim: %v", err)
	}
}

// TestClaimTakeoverBlocksMidFlightCommit is the end-to-end fence
// sequence the plan's scenario E demands: claimant A is suspended
// while performing recovery; B takes over; A resumes and attempts the
// whole protected sequence — every boundary refuses.
func TestClaimTakeoverBlocksMidFlightCommit(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, b, atB := claimPair(t, l, "job-t", now)

	if _, err := l.InsertJob("job-t", "h-t", "alice", "alice", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-t", JobStateDispatchAmbig, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}

	if err := l.ValidateRecoveryClaim(a, atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("pre-effect validation let stale A through: %v", err)
	}
	if err := l.TransitionWithClaim("job-t", JobStateSucceeded, []string{JobStateDispatchAmbig}, a, nil); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale A committed a terminal transition: %v", err)
	}
	if err := l.ExtendRecoveryLease(a, time.Hour, atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale A extended its lease: %v", err)
	}
	if err := l.CompleteRecoveryClaim(a, "A's stale work", atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale A completed B's claim: %v", err)
	}
	// B's own sequence still works end to end.
	if err := l.TransitionWithClaim("job-t", JobStateSucceeded, []string{JobStateDispatchAmbig}, b,
		func(j *LedgerJob) error { j.ExitCode = intPtr(0); return nil }); err != nil {
		t.Fatalf("B's fenced transition refused: %v", err)
	}
	if err := l.CompleteRecoveryClaim(b, "resolved", atB); err != nil {
		t.Fatalf("B's completion refused: %v", err)
	}
	j, _ := l.Get("job-t")
	if j.State != JobStateSucceeded {
		t.Fatalf("job state %s — B's commit did not land", j.State)
	}
	// And the durable trail records the takeover honestly.
	events, err := l.RecoveryEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	claims := 0
	for _, e := range events {
		if e.Kind == "claim" && e.Subject == "job-t" {
			claims++
		}
	}
	if claims != 2 {
		t.Fatalf("durable trail holds %d claims for the contested row, want 2", claims)
	}
}

// TestClaimCommitLeavesNoPartialState: a fenced commit that fails
// mid-transaction leaves no half-written state — the transition and
// its evidence are one commit.
func TestClaimCommitLeavesNoPartialState(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	c, err := l.ClaimRecoveryAttempt("job-p", RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil || c == nil {
		t.Fatalf("claim: %v %v", c, err)
	}
	if _, err := l.InsertJob("job-p", "h-p", "alice", "alice", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	// Rollback during ownership transfer: the transition's own write
	// fails (mutate error), and nothing — no state, no claim change —
	// may persist.
	if err := l.Transition("job-p", JobStateDispatchAmbig, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected mutation failure")
	err = l.TransitionWithClaim("job-p", JobStateSucceeded, []string{JobStateDispatchAmbig}, c,
		func(j *LedgerJob) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("mutation failure surfaced as %v", err)
	}
	j, _ := l.Get("job-p")
	if j.State != JobStateDispatchAmbig {
		t.Fatalf("a rolled-back transition moved the job to %s", j.State)
	}
	// The claim is still valid — the failure consumed nothing.
	if err := l.ValidateRecoveryClaim(c, now.Add(time.Second)); err != nil {
		t.Fatalf("a rolled-back transition consumed the claim: %v", err)
	}
}
