package sandboxexecutor

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The PR-06 gate: job identity is durable, the ledger is fenced
// against a second executor, dispatch ambiguity is never silently
// retried, and a previous lifetime's in-flight rows reconcile as
// ambiguous — not forgotten, not rerun.

func openLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.db")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func TestLedgerPersistsJobIdentity(t *testing.T) {
	l, path := openLedger(t)
	j, err := l.InsertJob("job-1", "hash-1", "crabedence", "alice", "python:3.12", `{"job_id":"job-1"}`)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if j.State != JobStateRecorded || j.FenceEpoch != l.Epoch() {
		t.Fatalf("record = %+v", j)
	}
	l.Close()

	// A daemon "crash" and restart: the acknowledged job must still
	// be there. Reopen without closing the first lock is the crash
	// case — but we closed cleanly here; either way durability holds.
	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	got, err := l2.Get("job-1")
	if err != nil || got == nil {
		t.Fatalf("job lost across restart: %v", err)
	}
	if got.State != JobStateRecorded || got.Submitter != "crabedence" {
		t.Fatalf("job = %+v", got)
	}
	if l2.Epoch() <= l.Epoch() {
		t.Fatalf("fence epoch did not advance: %d -> %d", l.Epoch(), l2.Epoch())
	}
}

func TestLedgerDuplicateAndReplayRefused(t *testing.T) {
	l, _ := openLedger(t)
	if _, err := l.InsertJob("job-1", "hash-1", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.InsertJob("job-1", "hash-1", "s", "p", "i", "{}"); !errors.Is(err, ErrDuplicateJobID) {
		t.Fatalf("duplicate job_id: %v", err)
	}
	// Same signed contract under a different job_id = replay.
	if _, err := l.InsertJob("job-2", "hash-1", "s", "p", "i", "{}"); !errors.Is(err, ErrContractReplay) {
		t.Fatalf("replayed contract: %v", err)
	}
	// New contract under a new id is fine.
	if _, err := l.InsertJob("job-2", "hash-2", "s", "p", "i", "{}"); err != nil {
		t.Fatalf("distinct contract refused: %v", err)
	}
}

func TestLedgerTransitionCAS(t *testing.T) {
	l, _ := openLedger(t)
	if _, err := l.InsertJob("job-1", "h1", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	// Legal: RECORDED -> DISPATCHING.
	if err := l.Transition("job-1", JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatalf("legal transition refused: %v", err)
	}
	// Illegal: RECORDED is gone — a second DISPATCHING marks conflict.
	if err := l.Transition("job-1", JobStateRunning, []string{JobStateRecorded}, nil); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("transition from wrong source: %v", err)
	}
	// Terminal states never move.
	if err := l.Transition("job-1", JobStateDispatchFailed, []string{JobStateDispatching}, nil); err != nil {
		t.Fatal(err)
	}
	// Terminal states never move: the live dispatch path only offers
	// DISPATCHING as the source, which this row no longer is.
	if err := l.Transition("job-1", JobStateRunning, []string{JobStateDispatching}, nil); err == nil {
		t.Fatal("a terminal job moved")
	}
}

func TestLedgerFenceLockRefusesSecondExecutor(t *testing.T) {
	l, path := openLedger(t)
	defer l.Close() // cleanup also closes; double Close is harmless
	if _, err := OpenLedger(path); err == nil {
		t.Fatal("a second executor opened the fenced ledger")
	}
}

func TestLedgerReconcileMarksAmbiguous(t *testing.T) {
	l, path := openLedger(t)
	if _, err := l.InsertJob("job-dispatching", "h1", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-dispatching", JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := l.InsertJob("job-running", "h2", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-running", JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("job-running", JobStateRunning, []string{JobStateDispatching},
		func(j *LedgerJob) error { j.BackendHandle = "vm-9"; return nil }); err != nil {
		t.Fatal(err)
	}
	l.Close()

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	if l2.Reconciled() != 2 {
		t.Fatalf("reconciled = %d", l2.Reconciled())
	}
	for _, id := range []string{"job-dispatching", "job-running"} {
		j, _ := l2.Get(id)
		if j.State != JobStateDispatchAmbig {
			t.Fatalf("%s state = %s", id, j.State)
		}
	}
	// The ambiguous running job kept its backend handle for the
	// operator to reconcile against.
	j, _ := l2.Get("job-running")
	if j.BackendHandle != "vm-9" {
		t.Fatalf("handle lost: %+v", j)
	}
	// And a reconciled-ambiguous job cannot transition back into the
	// live path — the dispatch path only accepts RECORDED sources,
	// which this row no longer is. No blind re-dispatch.
	if err := l2.Transition("job-running", JobStateDispatching, []string{JobStateRecorded}, nil); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("ambiguous job re-entered the dispatch path: %v", err)
	}
}

func TestLedgerInterruptRunning(t *testing.T) {
	l, _ := openLedger(t)
	l.InsertJob("j1", "h1", "s", "p", "i", "{}")
	l.Transition("j1", JobStateDispatching, []string{JobStateRecorded}, nil)
	l.Transition("j1", JobStateRunning, []string{JobStateDispatching}, nil)
	l.InsertJob("j2", "h2", "s", "p", "i", "{}")
	n, err := l.InterruptRunning()
	if err != nil || n != 1 {
		t.Fatalf("interrupt: n=%d err=%v", n, err)
	}
	j, _ := l.Get("j1")
	if j.State != JobStateInterrupted {
		t.Fatalf("state = %s", j.State)
	}
	j2, _ := l.Get("j2")
	if j2.State != JobStateRecorded {
		t.Fatalf("recorded job disturbed: %s", j2.State)
	}
}

// TestActiveUsageReservesAndReleases is the durable half of the PR-05
// gate: a reservation exists exactly while a VM may exist, and the
// aggregate is recomputed from rows — not from process memory.
func TestActiveUsageReservesAndReleases(t *testing.T) {
	l, _ := openLedger(t)
	key, _ := testAuthority(t)
	c := testContract(t, key, func(c *JobContractV2) {
		c.JobID = "usage-1"
		c.Resources = ResourceBudget{TimeoutSeconds: 60, CPUs: 2, MemoryMB: 512, DiskMB: 1024, MaxOutputBytes: 4096}
	})
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	if usage, err := l.ActiveUsage(time.Minute); err != nil || usage.VMs != 0 {
		t.Fatalf("fresh ledger usage = %+v (%v)", usage, err)
	}
	if _, err := l.InsertJob(c.JobID, ContractHash(c), "s", "alice", c.Image, string(raw)); err != nil {
		t.Fatal(err)
	}
	// RECORDED is not yet in flight — it holds no reservation.
	if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 0 {
		t.Fatalf("a recorded job holds a reservation: %+v", usage)
	}
	if err := l.Transition(c.JobID, JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	usage, err := l.ActiveUsage(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if usage.VMs != 1 || usage.CPUs != 2 || usage.MemoryMB != 512 || usage.DiskMB != 1024 || usage.OutputBytes != 4096 {
		t.Fatalf("usage = %+v", usage)
	}
	if usage.PerSubmitter["s"] != 1 {
		t.Fatalf("per-submitter usage = %+v", usage.PerSubmitter)
	}
	if err := l.Transition(c.JobID, JobStateRunning, []string{JobStateDispatching}, nil); err != nil {
		t.Fatal(err)
	}
	if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 1 {
		t.Fatalf("a running job lost its reservation: %+v", usage)
	}
	// Terminal: the reservation is released.
	if err := l.Transition(c.JobID, JobStateSucceeded, []string{JobStateRunning},
		func(j *LedgerJob) error { j.ResultJSON = "{}"; return nil }); err != nil {
		t.Fatal(err)
	}
	if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 0 || usage.CPUs != 0 || usage.PerSubmitter["s"] != 0 {
		t.Fatalf("a terminal job still reserves: %+v", usage)
	}
}

// TestActiveUsageHoldsUnresolvedReservations: an ambiguous or
// interrupted row means a VM may still be live under its own contract
// timeout, so its reservation is held until an operator reconciles it.
func TestActiveUsageHoldsUnresolvedReservations(t *testing.T) {
	l, path := openLedger(t)
	key, _ := testAuthority(t)
	c := testContract(t, key, func(c *JobContractV2) { c.JobID = "usage-ambig" })
	raw, _ := json.Marshal(c)
	if _, err := l.InsertJob(c.JobID, ContractHash(c), "s", "alice", c.Image, string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition(c.JobID, JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	l.Close()

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	lj, _ := l2.Get(c.JobID)
	if lj.State != JobStateDispatchAmbig {
		t.Fatalf("state = %s", lj.State)
	}
	if usage, _ := l2.ActiveUsage(time.Minute); usage.VMs != 1 {
		t.Fatalf("an unresolved VM was released from the pool: %+v", usage)
	}
}

// TestActiveUsageReleasesProvablyDeadVMs: a VM cannot outlive its
// contract (--max-duration is pinned to the declared timeout), so once
// that timeout plus the dispatch grace has certainly elapsed the
// reservation is released — the unresolved row stays for the
// operator's audit, but it stops consuming budget forever.
func TestActiveUsageReleasesProvablyDeadVMs(t *testing.T) {
	l, path := openLedger(t)
	key, _ := testAuthority(t)
	c := testContract(t, key, func(c *JobContractV2) {
		c.JobID = "usage-dead"
		c.Resources.TimeoutSeconds = 5
	})
	raw, _ := json.Marshal(c)
	if _, err := l.InsertJob(c.JobID, ContractHash(c), "s", "alice", c.Image, string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition(c.JobID, JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 1 {
		t.Fatalf("fresh dispatch not reserved: %+v", usage)
	}
	// The row's last transition is far older than its own contract
	// timeout plus the grace: the VM provably cannot exist.
	tamper(t, path, `UPDATE jobs SET updated_at = ? WHERE job_id = ?`,
		time.Now().Add(-time.Hour).UnixMilli(), c.JobID)
	if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 0 {
		t.Fatalf("a provably dead VM still holds a reservation: %+v", usage)
	}
	// Inside the grace window the reservation is still held — the
	// release must never outrun the VM's own bound.
	tamper(t, path, `UPDATE jobs SET updated_at = ? WHERE job_id = ?`,
		time.Now().Add(-time.Second).UnixMilli(), c.JobID)
	if usage, _ := l.ActiveUsage(time.Hour); usage.VMs != 1 {
		t.Fatalf("a VM inside the grace window was released: %+v", usage)
	}
}

// TestActiveUsageHoldsCleanupPendingVMs: a completed workload may
// still have a live microVM. The guest process finishing is not the VM
// ceasing to exist, so a terminal row whose VM could not be removed
// keeps its reservation until cleanup is verified — capacity is never
// freed merely because the workload completed.
func TestActiveUsageHoldsCleanupPendingVMs(t *testing.T) {
	l, path := openLedger(t)
	key, _ := testAuthority(t)
	c := testContract(t, key, func(c *JobContractV2) {
		c.JobID = "usage-cleanup"
		c.Resources = ResourceBudget{TimeoutSeconds: 60, CPUs: 2, MemoryMB: 512, DiskMB: 1024, MaxOutputBytes: 4096}
	})
	raw, _ := json.Marshal(c)
	if _, err := l.InsertJob(c.JobID, ContractHash(c), "s", "alice", c.Image, string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition(c.JobID, JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatalf("transition to dispatching: %v", err)
	}
	if err := l.Transition(c.JobID, JobStateRunning, []string{JobStateDispatching}, nil); err != nil {
		t.Fatalf("transition to running: %v", err)
	}

	t.Run("terminal with cleanup verified releases", func(t *testing.T) {
		if err := l.Transition(c.JobID, JobStateSucceeded, []string{JobStateRunning},
			func(j *LedgerJob) error { j.ResultJSON = "{}"; return nil }); err != nil {
			t.Fatal(err)
		}
		if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 0 || usage.CPUs != 0 {
			t.Fatalf("a cleaned-up terminal job still reserves: %+v", usage)
		}
	})

	t.Run("terminal with cleanup pending holds", func(t *testing.T) {
		if err := l.MarkCleanupPending(c.JobID, "msb rm failed"); err != nil {
			t.Fatal(err)
		}
		usage, err := l.ActiveUsage(time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if usage.VMs != 1 || usage.CPUs != 2 || usage.MemoryMB != 512 || usage.DiskMB != 1024 || usage.OutputBytes != 4096 {
			t.Fatalf("a live microVM behind a terminal job lost its reservation: %+v", usage)
		}
		if usage.PerSubmitter["s"] != 1 {
			t.Fatalf("per-submitter usage = %+v", usage.PerSubmitter)
		}
	})

	t.Run("verified cleanup releases", func(t *testing.T) {
		if err := l.ClearCleanupPending(c.JobID); err != nil {
			t.Fatal(err)
		}
		if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 0 {
			t.Fatalf("capacity was not released after verified cleanup: %+v", usage)
		}
	})

	t.Run("a provably dead VM releases even while cleanup is pending", func(t *testing.T) {
		if err := l.MarkCleanupPending(c.JobID, "msb rm failed"); err != nil {
			t.Fatal(err)
		}
		if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 1 {
			t.Fatalf("a pending cleanup was not reserved: %+v", usage)
		}
		// The VM cannot outlive its own contract timeout plus the
		// grace, so once that has certainly elapsed the reservation
		// stops consuming budget forever.
		tamper(t, path, `UPDATE jobs SET updated_at = ? WHERE job_id = ?`,
			time.Now().Add(-time.Hour).UnixMilli(), c.JobID)
		if usage, _ := l.ActiveUsage(time.Minute); usage.VMs != 0 {
			t.Fatalf("a provably dead VM still holds a reservation: %+v", usage)
		}
	})
}

// insertWalkJob records one job and moves it into `to` carrying a
// backend handle, so it is a candidate for the startup recovery walk.
func insertWalkJob(t *testing.T, l *Ledger, key ed25519.PrivateKey, id, to string) {
	t.Helper()
	c := testContract(t, key, func(c *JobContractV2) { c.JobID = id; c.Nonce = "n-" + id })
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.InsertJob(c.JobID, ContractHash(c), "s", "alice", c.Image, string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition(c.JobID, to, []string{JobStateRecorded},
		func(j *LedgerJob) error { j.BackendHandle = "sx-" + c.JobID; return nil }); err != nil {
		t.Fatal(err)
	}
}

// walkCandidates follows a candidate query's keyset cursor to
// exhaustion and reports how many times each row was returned.
func walkCandidates(t *testing.T, page func(uint64) ([]*LedgerJob, error)) map[string]int {
	t.Helper()
	seen := map[string]int{}
	var cursor uint64
	for {
		rows, err := page(cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			return seen
		}
		for _, j := range rows {
			seen[j.JobID]++
		}
		cursor = rows[len(rows)-1].Seq
	}
}

// TestReconcileCandidatesWalkEveryRow (F-049): the startup recovery
// walk sees every unresolved candidate, not only the newest page. A
// single bounded query cannot, and the keyset cursor returns each row
// exactly once before stopping.
func TestReconcileCandidatesWalkEveryRow(t *testing.T) {
	l, _ := openLedger(t)
	key, _ := testAuthority(t)

	total := recoveryPageSize*2 + 7
	for i := 0; i < total; i++ {
		insertWalkJob(t, l, key, fmt.Sprintf("walk-%03d", i), JobStateDispatchAmbig)
	}

	first, err := l.ReconcileCandidates(recoveryPageSize, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != recoveryPageSize {
		t.Fatalf("first page holds %d rows, want a full page of %d", len(first), recoveryPageSize)
	}

	seen := walkCandidates(t, func(cursor uint64) ([]*LedgerJob, error) {
		return l.ReconcileCandidates(recoveryPageSize, cursor)
	})
	if len(seen) != total {
		t.Fatalf("the walk saw %d of %d unresolved candidates — the rest were omitted", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("candidate %s was returned %d times", id, n)
		}
	}
}

// TestCleanupCandidatesWalkEveryRow (F-049): pending removals are
// retried for every candidate too — a microVM that outlived its job
// is never abandoned because it fell outside the newest page.
func TestCleanupCandidatesWalkEveryRow(t *testing.T) {
	l, _ := openLedger(t)
	key, _ := testAuthority(t)

	total := recoveryPageSize*2 + 5
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("cleanup-%03d", i)
		insertWalkJob(t, l, key, id, JobStateRunning)
		if err := l.Transition(id, JobStateSucceeded, []string{JobStateRunning},
			func(j *LedgerJob) error { j.ResultJSON = "{}"; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := l.MarkCleanupPending(id, "msb rm failed"); err != nil {
			t.Fatal(err)
		}
	}

	first, err := l.CleanupCandidates(recoveryPageSize, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != recoveryPageSize {
		t.Fatalf("first page holds %d rows, want a full page of %d", len(first), recoveryPageSize)
	}

	seen := walkCandidates(t, func(cursor uint64) ([]*LedgerJob, error) {
		return l.CleanupCandidates(recoveryPageSize, cursor)
	})
	if len(seen) != total {
		t.Fatalf("the walk saw %d of %d pending cleanups — the rest were omitted", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("cleanup candidate %s was returned %d times", id, n)
		}
	}
}

// TestReservationBoundOutlastsTheVMsOwnLifetime (RC7.2, F-048): there
// are two ways a reservation ends — verified cleanup, and the time
// bound — and the bound is not verification of anything, so it must not
// release a reservation while the VM could still exist. It has to
// outlast the runtime's own --max-duration, which the backend pins to
// the contract timeout plus the observation grace.
func TestReservationBoundOutlastsTheVMsOwnLifetime(t *testing.T) {
	key, _ := testAuthority(t)
	contract := testContract(t, key, func(c *JobContractV2) { c.Resources.TimeoutSeconds = 60 })
	grace := defaultDispatchTimeout + time.Minute
	updated := time.Now().UTC()
	lifetime := time.Duration(contract.Resources.TimeoutSeconds) * time.Second

	if grace <= maxDurationGrace {
		t.Fatalf("the caller's grace %s does not exceed the VM's own %s", grace, maxDurationGrace)
	}
	vmDeath := updated.Add(lifetime + maxDurationGrace)
	if vmProvablyDead(updated, contract, grace, vmDeath) {
		t.Fatal("the bound released a reservation while the VM could still be alive")
	}
	if !vmProvablyDead(updated, contract, grace, updated.Add(lifetime+grace+time.Second)) {
		t.Fatal("a provably dead VM still held its reservation")
	}
}

// TestReservationBoundHoldsWhenItCannotBeEstablished: the bound is only
// usable when the VM's lifetime is known. A row whose contract cannot
// be parsed, or that declares no timeout, is held rather than guessed
// away.
func TestReservationBoundHoldsWhenItCannotBeEstablished(t *testing.T) {
	far := time.Now().UTC().Add(1000 * time.Hour)
	if vmProvablyDead(time.Now().UTC(), nil, time.Minute, far) {
		t.Fatal("an unparseable contract was released by the bound")
	}
	if vmProvablyDead(time.Now().UTC(), &JobContractV2{}, time.Minute, far) {
		t.Fatal("a contract declaring no timeout was released by the bound")
	}
}

func TestLedgerRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.db")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLedger(link); err == nil {
		t.Fatal("symlinked ledger opened")
	}
}
