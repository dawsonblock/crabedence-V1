package sandboxexecutor

import (
	"fmt"
	"path/filepath"
	"strings"
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
	due, attempts, err := l.ClaimRecoveryAttempt("job-1", RecoveryActionResume, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if !due || attempts != 1 {
		t.Fatalf("first claim due=%v attempts=%d, want due/1", due, attempts)
	}
	l.Close()

	// "Restart" 5s later — inside the 1m backoff. A per-lifetime map
	// would grant a free retry here; the durable schedule must not.
	l, err = OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	due, attempts, err = l.ClaimRecoveryAttempt("job-1", RecoveryActionResume, time.Minute, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if due {
		t.Fatalf("reopen inside backoff granted a retry (attempts=%d) — crash loops could hammer the backend", attempts)
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
	l.ClaimRecoveryAttempt("job-1", RecoveryActionCleanup, time.Minute, now)
	l.Close()

	l, err = OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	due, attempts, err := l.ClaimRecoveryAttempt("job-1", RecoveryActionCleanup, time.Minute, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !due || attempts != 2 {
		t.Fatalf("post-backoff claim due=%v attempts=%d, want due/2", due, attempts)
	}
}

// A resolved row drops its pacing so the table never grows on
// history the registry no longer holds.
func TestRecoveryForgetClearsPacing(t *testing.T) {
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	if due, _, _ := l.ClaimRecoveryAttempt("job-9", RecoveryActionResume, time.Hour, now); !due {
		t.Fatal("first claim refused")
	}
	if err := l.ForgetRecoveryAttempt("job-9", RecoveryActionResume); err != nil {
		t.Fatal(err)
	}
	// Same clock — inside the backoff — but forgotten means resolved,
	// and a resolved job re-sighting is a first sighting again.
	due, attempts, err := l.ClaimRecoveryAttempt("job-9", RecoveryActionResume, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !due || attempts != 1 {
		t.Fatalf("forgotten claim due=%v attempts=%d, want due/1", due, attempts)
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
