package sandboxexecutor

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The crash-loop gate: pacing state lives in the ledger, so a daemon
// reopened inside a backoff window keeps waiting instead of getting a
// free retry on every restart.
func TestRecoveryPacingSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	now := time.Now().UTC()

	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := l.ClaimRecoveryAttempt("job-1", RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if claim == nil || claim.Attempt != 1 {
		t.Fatalf("first claim %+v, want granted/attempt 1", claim)
	}
	l.Close()

	// "Restart" 5s later — inside the 1m backoff. A per-lifetime map
	// would grant a free retry here; the durable schedule must not.
	l, err = OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	claim, err = l.ClaimRecoveryAttempt("job-1", RecoveryActionResume, time.Minute, time.Minute, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claim != nil {
		t.Fatalf("reopen inside backoff granted a retry (attempt %d) — crash loops could hammer the backend", claim.Attempt)
	}
}

// Downtime longer than the backoff still makes the next pass due
// immediately — the schedule fences frequency, never progress.
func TestRecoveryDowntimeMakesAttemptDue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	now := time.Now().UTC()
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.ClaimRecoveryAttempt("job-1", RecoveryActionCleanup, time.Minute, time.Minute, now)
	l.Close()

	l, err = OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	claim, err := l.ClaimRecoveryAttempt("job-1", RecoveryActionCleanup, time.Minute, time.Minute, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if claim == nil || claim.Attempt != 2 {
		t.Fatalf("post-backoff claim %+v, want granted/attempt 2", claim)
	}
}

// A resolved row drops its pacing so the table never grows on
// history the registry no longer holds.
func TestRecoveryForgetClearsPacing(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	if claim, _ := l.ClaimRecoveryAttempt("job-9", RecoveryActionResume, time.Hour, time.Hour, now); claim == nil {
		t.Fatal("first claim refused")
	}
	if err := l.ForgetRecoveryAttempt("job-9", RecoveryActionResume); err != nil {
		t.Fatal(err)
	}
	// Same clock — inside the backoff — but forgotten means resolved,
	// and a resolved job re-sighting is a first sighting again.
	claim, err := l.ClaimRecoveryAttempt("job-9", RecoveryActionResume, time.Hour, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if claim == nil || claim.Attempt != 1 {
		t.Fatalf("forgotten claim %+v, want granted/attempt 1", claim)
	}
}

// The recovery trail is durable and survives read-only inspection —
// what the audit log printed is no longer the only record.
func TestRecoveryEventsDurable(t *testing.T) {
	l, path := openLedger(t)
	if err := l.RecordRecoveryEvent("escalation", "registry", "2 unresolved", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := l.RecordRecoveryEvent("claim", "job-5", "stranded dispatch claimed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	l.Close()

	ro, err := InspectLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	events, err := ro.RecoveryEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("read-only inspection saw %d recovery events, want 2", len(events))
	}
	if events[0].Kind != "claim" || events[1].Kind != "escalation" {
		t.Fatalf("recovery trail order/content wrong: %+v", events)
	}
}

// The residue throttle persists across reopens: an unchanged residue
// shape escalates once per window, not once per restart — while the
// escalation itself lands in the durable trail.
func TestResidueThrottleSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	now := time.Now().UTC()
	var lines []string
	audit := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}

	// First lifetime: an unresolved row makes residue; the
	// escalation fires and stamps the durable throttle.
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.InsertJob("u-1", "h-u-1", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("u-1", JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("u-1", JobStateDispatchAmbig, []string{JobStateDispatching}, nil); err != nil {
		t.Fatal(err)
	}
	s1 := &Server{ledger: l, audit: audit, now: func() time.Time { return now }}
	s1.escalateResidue()
	l.Close()
	if count := countEscalations(lines); count != 1 {
		t.Fatalf("first lifetime emitted %d escalations, want 1", count)
	}

	// Second lifetime minutes later — inside the throttle window.
	// Same residue, no new line: a crash loop cannot spam.
	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	s2 := &Server{ledger: l2, audit: audit, now: func() time.Time { return now.Add(time.Minute) }}
	s2.escalateResidue()
	if count := countEscalations(lines); count != 1 {
		t.Fatalf("reopen inside throttle re-escalated unchanged residue: %d lines", count)
	}

	// Past the window the same shape escalates again — the throttle
	// paces, it does not silence.
	s3 := &Server{ledger: l2, audit: audit, now: func() time.Time { return now.Add(residueEscalationRepeat + time.Minute) }}
	s3.escalateResidue()
	l2.Close()
	if count := countEscalations(lines); count != 2 {
		t.Fatalf("post-window escalation count %d, want 2", count)
	}

	// And the durable trail recorded each firing.
	ro, err := InspectLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	events, err := ro.RecoveryEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	esc := 0
	for _, e := range events {
		if e.Kind == "escalation" {
			esc++
		}
	}
	if esc != 2 {
		t.Fatalf("durable trail holds %d escalations, want 2", esc)
	}
}

func countEscalations(lines []string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l, "ESCALATION") {
			n++
		}
	}
	return n
}

// ─── Fenced, atomic claim ownership (schema v10) ────────────────────

// Fifty concurrent claimants for the same job/action/window: the
// claim is one conditional atomic write, so exactly one is granted
// and every loser is denied — the read-check-write scheduler this
// replaced granted the same window to a crowd.
func TestRecoveryClaimAtomicUnderContention(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	type result struct {
		claim *RecoveryClaim
		err   error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, err := l.ClaimRecoveryAttempt("job-race", RecoveryActionResume, time.Hour, time.Hour, time.Now().UTC())
			results <- result{c, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var granted []*RecoveryClaim
	for r := range results {
		if r.err != nil {
			t.Fatalf("claim errored under contention: %v", r.err)
		}
		if r.claim != nil {
			granted = append(granted, r.claim)
		}
	}
	if len(granted) != 1 {
		t.Fatalf("%d claimants won the same window — the grant is not exclusive", len(granted))
	}
	if granted[0].Attempt != 1 {
		t.Fatalf("the sole winner reports attempt %d, want 1", granted[0].Attempt)
	}
	// And the durable trail holds exactly one claim event for it —
	// the grant and its evidence committed atomically.
	events, err := l.RecoveryEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	claims := 0
	for _, e := range events {
		if e.Kind == "claim" && e.Subject == "job-race" {
			claims++
		}
	}
	if claims != 1 {
		t.Fatalf("durable trail holds %d claim events for the contested window, want 1", claims)
	}
}

// Contention across distinct jobs: every job's window is independent,
// so each is claimed exactly once while no job is double-granted.
func TestRecoveryClaimDistinctJobsAllWin(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	const jobs = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	grants := map[string]int{}
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			c, err := l.ClaimRecoveryAttempt(id, RecoveryActionResume, time.Hour, time.Hour, time.Now().UTC())
			if err != nil {
				t.Errorf("claim %s: %v", id, err)
				return
			}
			mu.Lock()
			grants[id] += map[bool]int{true: 1, false: 0}[c != nil]
			mu.Unlock()
		}(fmt.Sprintf("job-%d", i))
	}
	close(start)
	wg.Wait()
	if len(grants) != jobs {
		t.Fatalf("claims resolved for %d jobs, want %d", len(grants), jobs)
	}
	for id, n := range grants {
		if n != 1 {
			t.Fatalf("job %s granted %d times, want 1", id, n)
		}
	}
}

// The lease bounds how long an abandoned claim can block reassignment:
// with a lease longer than the backoff, the row stays owned even after
// the pacing window elapses; once the lease too has expired, a new
// claimant takes it. With lease < backoff the pacing window still
// governs — a claim can never shorten the backoff.
func TestRecoveryClaimLeaseBoundsReassignment(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()

	// Long lease: backoff elapsed but ownership has not expired.
	if c, err := l.ClaimRecoveryAttempt("job-L", RecoveryActionResume, 5*time.Minute, time.Hour, now); err != nil || c == nil {
		t.Fatalf("first claim: c=%v err=%v", c, err)
	}
	if c, err := l.ClaimRecoveryAttempt("job-L", RecoveryActionResume, 5*time.Minute, time.Hour, now.Add(10*time.Minute)); err != nil || c != nil {
		t.Fatalf("claim inside the live lease was granted (%+v, %v) — an abandoned attempt must hold the row until its lease", c, err)
	}
	c, err := l.ClaimRecoveryAttempt("job-L", RecoveryActionResume, 5*time.Minute, time.Hour, now.Add(61*time.Minute))
	if err != nil || c == nil {
		t.Fatalf("claim after lease expiry: c=%v err=%v", c, err)
	}
	if c.Attempt != 2 {
		t.Fatalf("post-lease claim attempt %d, want 2", c.Attempt)
	}

	// Short lease: pacing still requires the full backoff.
	if c, err := l.ClaimRecoveryAttempt("job-S", RecoveryActionResume, time.Hour, 5*time.Minute, now); err != nil || c == nil {
		t.Fatalf("first claim: c=%v err=%v", c, err)
	}
	if c, err := l.ClaimRecoveryAttempt("job-S", RecoveryActionResume, time.Hour, 5*time.Minute, now.Add(10*time.Minute)); err != nil || c != nil {
		t.Fatalf("claim inside backoff granted on an expired lease (%+v, %v) — the lease may never shorten pacing", c, err)
	}
	if c, err := l.ClaimRecoveryAttempt("job-S", RecoveryActionResume, time.Hour, 5*time.Minute, now.Add(61*time.Minute)); err != nil || c == nil {
		t.Fatalf("claim after backoff: c=%v err=%v", c, err)
	}
}

// Generation-aware fencing: each ledger lifetime claims under its own
// fence epoch, and the durable row records which generation owns the
// attempt — a stale generation's claim can never masquerade as the
// current owner's.
func TestRecoveryClaimOwnershipFollowsTheFenceEpoch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	now := time.Now().UTC()

	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := l.ClaimRecoveryAttempt("job-e", RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil || c1 == nil {
		t.Fatalf("first claim: c=%v err=%v", c1, err)
	}
	epoch1 := c1.OwnerEpoch
	l.Close()

	// The next lifetime reopens the same ledger: a fresh fence epoch,
	// and inside the window the row stays owned by the old claim.
	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if c, err := l2.ClaimRecoveryAttempt("job-e", RecoveryActionResume, time.Minute, time.Minute, now.Add(30*time.Second)); err != nil || c != nil {
		t.Fatalf("claim inside the prior window granted to the new epoch (%+v, %v)", c, err)
	}
	c2, err := l2.ClaimRecoveryAttempt("job-e", RecoveryActionResume, time.Minute, time.Minute, now.Add(2*time.Minute))
	if err != nil || c2 == nil {
		t.Fatalf("claim after the window: c=%v err=%v", c2, err)
	}
	if c2.OwnerEpoch == epoch1 {
		t.Fatalf("claim epoch did not advance across lifetimes: %d", c2.OwnerEpoch)
	}
	if c2.Attempt != 2 {
		t.Fatalf("reclaimed attempt %d, want the monotonic 2", c2.Attempt)
	}
}

// A clock that rolls backwards can never mint a retry: every
// comparison is against durable stamps, so a rewound wall clock keeps
// the row claimed rather than re-granting it early.
func TestRecoveryClaimClockRollbackStaysClosed(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	if c, err := l.ClaimRecoveryAttempt("job-c", RecoveryActionResume, time.Minute, time.Minute, now); err != nil || c == nil {
		t.Fatalf("first claim: c=%v err=%v", c, err)
	}
	past := now.Add(-10 * time.Minute)
	if c, err := l.ClaimRecoveryAttempt("job-c", RecoveryActionResume, time.Minute, time.Minute, past); err != nil || c != nil {
		t.Fatalf("a rewound clock re-granted the window: %+v, %v", c, err)
	}
	// And the durable stamp must not have regressed.
	var lastMS int64
	if err := l.db.QueryRow(`SELECT last_attempt_ms FROM recovery_attempts WHERE job_id='job-c'`).Scan(&lastMS); err != nil {
		t.Fatal(err)
	}
	if lastMS != now.UnixMilli() {
		t.Fatalf("claim stamp regressed under a rewound clock: %d != %d", lastMS, now.UnixMilli())
	}
}

// Resume and cleanup are independent claims on the same job — one
// action's window never blocks the other's.
func TestRecoveryClaimActionsAreIndependent(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	for _, action := range []string{RecoveryActionResume, RecoveryActionCleanup} {
		c, err := l.ClaimRecoveryAttempt("job-a", action, time.Hour, time.Hour, now)
		if err != nil || c == nil {
			t.Fatalf("%s claim: c=%v err=%v", action, c, err)
		}
	}
}

// Every granted claim commits its durable record in the same
// transaction; a denied claim writes nothing at all.
func TestRecoveryClaimWritesItsEventAtomically(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	c, err := l.ClaimRecoveryAttempt("job-ev", RecoveryActionResume, time.Minute, time.Minute, now)
	if err != nil || c == nil {
		t.Fatalf("first claim: c=%v err=%v", c, err)
	}
	events, err := l.RecoveryEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "claim" || events[0].Subject != "job-ev" {
		t.Fatalf("granted claim left %+v — the ownership record must commit with the grant", events)
	}
	if c, err := l.ClaimRecoveryAttempt("job-ev", RecoveryActionResume, time.Minute, time.Minute, now.Add(10*time.Second)); err != nil || c != nil {
		t.Fatalf("denied window still claimed: %+v %v", c, err)
	}
	events, err = l.RecoveryEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("a denied claim left %d events — silence must be written nowhere", len(events))
	}
}

// Fail-closed evidence: when the recovery_events write cannot commit,
// the claim itself rolls back — no grant is ever issued without its
// mandatory record, and the pacing row is left exactly as it was.
func TestRecoveryClaimFailsClosedWhenEvidenceCannotCommit(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	if _, err := l.db.Exec(`CREATE TRIGGER fail_recovery_events
		BEFORE INSERT ON recovery_events
		BEGIN SELECT RAISE(ABORT, 'injected recovery_events failure'); END`); err != nil {
		t.Fatal(err)
	}
	c, err := l.ClaimRecoveryAttempt("job-fe", RecoveryActionResume, time.Minute, time.Minute, time.Now().UTC())
	if err == nil {
		t.Fatal("a claim whose mandatory record cannot commit was granted anyway")
	}
	if c != nil {
		t.Fatalf("claim granted despite the failed commit: %+v", c)
	}
	// The rollback is total: no pacing row was left behind, so the
	// next pass — once the store recovers — sees a first sighting,
	// not a half-recorded claim.
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM recovery_attempts WHERE job_id='job-fe'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a rolled-back claim left %d pacing rows", n)
	}
	if _, err := l.db.Exec(`DROP TRIGGER fail_recovery_events`); err != nil {
		t.Fatal(err)
	}
	if c, err := l.ClaimRecoveryAttempt("job-fe", RecoveryActionResume, time.Minute, time.Minute, time.Now().UTC()); err != nil || c == nil || c.Attempt != 1 {
		t.Fatalf("claim after recovery: c=%v err=%v — a first sighting must be due", c, err)
	}
}
