package sandboxexecutor

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The continuous-recovery gates: a durable intent left mid-lifetime is
// re-driven, never replayed, never guessed at — and residue that
// cannot resolve escalates instead of going quiet.

// insertStrandedRecorded writes a signed contract's row as RECORDED —
// the shape a crash between the admission commit and the dispatch
// claim leaves, or a ledger from a record-only deployment carries.
func insertStrandedRecorded(t *testing.T, srv *Server, key ed25519.PrivateKey, id string, mutate func(*JobContractV2)) {
	t.Helper()
	c := testContract(t, key, func(c *JobContractV2) {
		c.JobID = id
		c.Nonce = "n-" + id
		// A row that survives in RECORDED must have passed live
		// admission once — the pool demands a budget on every
		// bounded dimension, as any admitted contract carries.
		c.Resources.DiskMB = 512
		c.Resources.MaxOutputBytes = 4096
		if mutate != nil {
			mutate(c)
		}
	})
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Ledger().InsertJob(c.JobID, ContractHash(c), "crabedence", c.Principal, c.Image, string(raw)); err != nil {
		t.Fatalf("insert stranded row: %v", err)
	}
}

// waitForState polls the ledger until the job reaches one of the
// listed states — maintenance passes are periodic, so tests poll.
func waitForState(t *testing.T, srv *Server, jobID string, want ...string) *LedgerJob {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		j, err := srv.Ledger().Get(jobID)
		if err == nil && j != nil {
			for _, w := range want {
				if j.State == w {
					return j
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	j, _ := srv.Ledger().Get(jobID)
	t.Fatalf("job %s never reached %v — state %+v", jobID, want, j)
	return nil
}

// A stranded RECORDED row is claimed by the maintenance scheduler and
// dispatched — the work the ledger admitted is not silently dropped
// because the driving connection died.
func TestMaintenanceDispatchesStrandedJob(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-rec", wait: make(chan *ExecResult, 1)}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	insertStrandedRecorded(t, srv, key, "stranded-1", nil)

	j := waitForState(t, srv, "stranded-1", JobStateRunning)
	if j.BackendHandle != "vm-rec" {
		t.Fatalf("dispatch identity missing on re-driven job: %+v", j)
	}
	// The observed outcome settles exactly like a live-monitored job.
	be.wait <- &ExecResult{
		ExitCode: 0, ExitVerified: true,
		RunID: "job_" + strings.Repeat("1", 32), BootID: "boot_" + strings.Repeat("1", 32),
		PolicyDigest: strings.Repeat("ab", 32), FinishedAt: time.Now().UTC(),
	}
	j = waitForState(t, srv, "stranded-1", JobStateSucceeded)
	if j.ReceiptSHA256 == "" {
		t.Fatal("settled without a receipt")
	}
}

// A stranded row whose contract expired while unclaimed must never
// run — it terminates with a NO_EFFECT receipt, honest because
// RECORDED proves no backend was ever asked.
func TestMaintenanceExpiresStrandedContract(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-x"}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	insertStrandedRecorded(t, srv, key, "expired-1", func(c *JobContractV2) {
		c.ExpiresAt = time.Now().UTC().Add(-time.Minute).Unix()
	})

	j := waitForState(t, srv, "expired-1", JobStateDispatchFailed)
	if be.got != nil {
		t.Fatal("an expired contract reached the backend")
	}
	if j.ReceiptSHA256 == "" || j.DispatchClass != string(DispatchNotAttempted) {
		t.Fatalf("terminal row carries no no-effect evidence: %+v", j)
	}
	if !strings.Contains(j.Error, "expired") {
		t.Fatalf("terminal reason lost: %q", j.Error)
	}
}

// A deferred claim re-checks the pool — the stranded row's admission-
// time reservation was never a live allocation, and dispatching past
// a now-full pool would oversubscribe it.
func TestMaintenanceDeferredDispatchRespectsPool(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-full", wait: make(chan *ExecResult)}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend:             be,
		ResourcePool:        &ResourcePool{MaxConcurrentVMs: 1, MaxSubmitterVMs: 1, TotalCPUs: 64, TotalMemoryMB: 64 * 1024, TotalDiskMB: 1 << 20, TotalOutputBytes: 1 << 30},
		MaintenanceInterval: 15 * time.Millisecond,
	})
	// One running job occupies the whole pool.
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "occupy", "occupy-n"
	}))
	if resp.State != JobStateRunning {
		t.Fatalf("occupier: %+v", resp)
	}
	insertStrandedRecorded(t, srv, key, "held-1", nil)
	// Several ticks pass: the row stays RECORDED, never dispatched
	// over the pool bound.
	time.Sleep(200 * time.Millisecond)
	j, _ := srv.Ledger().Get("held-1")
	if j.State != JobStateRecorded {
		t.Fatalf("deferred dispatch overran the pool: %s", j.State)
	}
	// Release the pool: the next pass claims and dispatches it.
	be.wait <- &ExecResult{
		ExitCode: 0, ExitVerified: true,
		RunID: "job_" + strings.Repeat("1", 32), BootID: "boot_" + strings.Repeat("1", 32),
		PolicyDigest: strings.Repeat("ab", 32), FinishedAt: time.Now().UTC(),
	}
	waitForState(t, srv, "held-1", JobStateDispatching, JobStateRunning, JobStateSucceeded, JobStateFailed)
}

// Pending removals retry on the maintenance cadence, not only at
// startup — a cleanup that failed mid-lifetime is drained without a
// restart.
func TestMaintenanceRetriesPendingCleanup(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-clean", wait: make(chan *ExecResult, 1)}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "cleanup-me", "cleanup-n"
	}))
	if resp.State != JobStateRunning {
		t.Fatalf("submit: %+v", resp)
	}
	// Terminate it and mark its removal pending — the cleanup hook
	// must pick it up without a restart.
	if err := srv.Ledger().Transition("cleanup-me", JobStateSucceeded, []string{JobStateRunning},
		func(j *LedgerJob) error {
			j.ResultJSON = "{}"
			j.ReceiptSHA256 = "rcpt-cm"
			j.CleanupPending = true
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := srv.Ledger().Get("cleanup-me")
		if j != nil && !j.CleanupPending {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	j, _ := srv.Ledger().Get("cleanup-me")
	t.Fatalf("pending cleanup never retried: %+v", j)
}

// An unresolved row that persists must escalate — the operator learns
// the residue exists rather than discovering it at the next restart.
func TestMaintenanceEscalatesResidue(t *testing.T) {
	dir := socketDir(t)
	_, keys := testAuthority(t)
	audits := make(chan string, 128)
	be := &stubBackend{live: true, resumeErr: ErrExecutionUnobserved}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, Audit: func(format string, args ...any) {
			select {
			case audits <- fmt.Sprintf(format, args...):
			default:
			}
		},
		MaintenanceInterval: 15 * time.Millisecond,
	})
	// An ambiguous row with a handle — unresolved, backend-live.
	if _, err := srv.Ledger().InsertJob("ambig-1", "h-ambig-1", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := srv.Ledger().Transition("ambig-1", JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if err := srv.Ledger().Transition("ambig-1", JobStateDispatchAmbig, []string{JobStateDispatching},
		func(j *LedgerJob) error { j.BackendHandle = "vm-ambig"; return nil }); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(15 * time.Second)
	for {
		select {
		case line := <-audits:
			if strings.Contains(line, "ESCALATION") && strings.Contains(line, "unresolved") {
				return
			}
		case <-deadline:
			t.Fatal("no residue escalation was emitted")
		}
	}
}

// A negative interval disables the periodic passes — startup recovery
// still ran, but nothing continues driving durable intents.
func TestMaintenanceDisabledLeavesRecordedRow(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-off"}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: -1,
	})
	insertStrandedRecorded(t, srv, key, "left", nil)
	time.Sleep(150 * time.Millisecond)
	j, _ := srv.Ledger().Get("left")
	if j.State != JobStateRecorded {
		t.Fatalf("disabled maintenance still drove dispatch: %s", j.State)
	}
	if be.got != nil {
		t.Fatal("disabled maintenance reached the backend")
	}
}

// AdmitJob leaves no mid-admission crash window: the row exists only
// ever as DISPATCHING — durable intent and operational row are one
// commit — and the recorded sweep never sees it.
func TestAdmitJobClaimsDispatchAtomically(t *testing.T) {
	l, _ := openLedger(t)
	j, err := l.AdmitJob("admit-1", "h-admit-1", "s", "p", "i", "{}")
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if j.State != JobStateDispatching {
		t.Fatalf("admitted row is %s, not DISPATCHING", j.State)
	}
	rows, err := l.RecordedCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.JobID == "admit-1" {
			t.Fatal("an admitted job surfaced as a stranded RECORDED row")
		}
	}
}

// A stranded RECORDED row survives a restart: the next lifetime's
// maintenance claims it — recovery is a property of the ledger, not
// of the process that wrote it.
func TestMaintenanceRecoversAfterRestart(t *testing.T) {
	dir := socketDir(t)
	ledgerPath := filepath.Join(t.TempDir(), "ledger.db")
	key, keys := testAuthority(t)

	// Lifetime A: a row stranded in RECORDED, then the daemon dies
	// before any maintenance pass (disabled, then stopped).
	a := startServer(t, Config{
		SocketDir: dir, LedgerPath: ledgerPath,
		Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: &stubBackend{handle: "vm-a"}, MaintenanceInterval: -1,
	})
	insertStrandedRecorded(t, a, key, "restart-1", nil)
	if err := a.Stop(); err != nil {
		t.Fatalf("stop A: %v", err)
	}

	// Lifetime B: a fresh process on the same ledger picks the row up.
	beB := &stubBackend{handle: "vm-b", wait: make(chan *ExecResult, 1)}
	b := startServer(t, Config{
		SocketDir: socketDir(t), LedgerPath: ledgerPath,
		Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: beB, MaintenanceInterval: 15 * time.Millisecond,
	})
	j := waitForState(t, b, "restart-1", JobStateRunning)
	if j.BackendHandle != "vm-b" {
		t.Fatalf("restarted lifetime did not re-drive dispatch: %+v", j)
	}
}

// A settled row is archived by the maintenance cadence — capacity
// relief does not wait for the registry to fill.
func TestMaintenanceArchivesSettledRows(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-arch", wait: make(chan *ExecResult, 1)}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "arch-me", "arch-n"
	}))
	if resp.State != JobStateRunning {
		t.Fatalf("submit: %+v", resp)
	}
	be.wait <- &ExecResult{
		ExitCode: 0, ExitVerified: true,
		RunID: "job_" + strings.Repeat("1", 32), BootID: "boot_" + strings.Repeat("1", 32),
		PolicyDigest: strings.Repeat("ab", 32), FinishedAt: time.Now().UTC(),
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		j, err := srv.Ledger().Get("arch-me")
		if err == nil && j != nil && j.Archived {
			if j.State != JobStateSucceeded {
				t.Fatalf("archived a non-terminal state: %s", j.State)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("settled row was never archived by maintenance")
}

// A deferred dispatch that ends ambiguous is never re-driven: the row
// lands DISPATCH_AMBIGUOUS and only the observation adapter — Resume,
// not a second Dispatch — settles it.
func TestMaintenanceAmbiguousDispatchReconcilesNotRetries(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-ambig", err: ErrAmbiguousDispatch,
		resumeGate: make(chan struct{})}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	insertStrandedRecorded(t, srv, key, "amb-1", nil)

	// The gate holds Resume, so the transient state cannot collapse
	// before the test observes it — the ordering is deterministic,
	// not a poll racing the next maintenance tick.
	j := waitForState(t, srv, "amb-1", JobStateDispatchAmbig)
	if j.DispatchClass != string(DispatchUncertain) || j.BackendHandle == "" {
		t.Fatalf("ambiguous dispatch lost its uncertainty record: %+v", j)
	}
	if j.ReceiptSHA256 != "" {
		t.Fatal("an uncertain outcome carried a receipt")
	}
	// Release the reconcile pass: Resume now observes the run to
	// completion — Dispatch is not called again.
	close(be.resumeGate)
	j = waitForState(t, srv, "amb-1", JobStateSucceeded)
	if j.ReceiptSHA256 == "" {
		t.Fatal("reconciled job settled without a receipt")
	}
	if n := be.dispatches.Load(); n != 1 {
		t.Fatalf("reconcile re-dispatched the job: %d dispatches", n)
	}
}

// A DISPATCHING row older than every dispatch context bound has no
// live driver — the sweep marks its outcome uncertain so the
// reconcile walk and the residue escalation see it, instead of it
// sitting stranded and invisible.
func TestMaintenanceMarksStaleDispatchingAmbiguous(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-stray", live: true}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	insertStrandedRecorded(t, srv, key, "stale-1", nil)
	// Claim it, then age the row past every dispatch context bound —
	// the shape a crashed or dead driver leaves.
	if err := srv.Ledger().Transition("stale-1", JobStateDispatching, []string{JobStateRecorded},
		func(j *LedgerJob) error { j.BackendHandle = "vm-stray"; return nil }); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-(prepareTimeout + 3*srv.cfg.DispatchTimeout)).UnixMilli()
	if _, err := srv.Ledger().db.Exec(`UPDATE jobs SET updated_at = ? WHERE job_id = ?`, old, "stale-1"); err != nil {
		t.Fatal(err)
	}
	j := waitForState(t, srv, "stale-1", JobStateDispatchAmbig)
	if j.DispatchClass != string(DispatchUncertain) {
		t.Fatalf("stranded dispatch marked %q, not uncertain", j.DispatchClass)
	}
	if j.ReceiptSHA256 != "" || j.TerminalSeq != 0 {
		t.Fatal("an uncertain outcome received terminal evidence")
	}
}

// ─── Mandatory recovery evidence is durable or nothing moves ────────

// failRecoveryEvents installs an INSERT abort on recovery_events —
// the injected storage failure the mandatory-evidence tests drive.
func failRecoveryEvents(t *testing.T, srv *Server) {
	t.Helper()
	if _, err := srv.Ledger().db.Exec(`CREATE TRIGGER fail_recovery_events
		BEFORE INSERT ON recovery_events
		BEGIN SELECT RAISE(ABORT, 'injected recovery_events failure'); END`); err != nil {
		t.Fatal(err)
	}
}

func allowRecoveryEvents(t *testing.T, srv *Server) {
	t.Helper()
	if _, err := srv.Ledger().db.Exec(`DROP TRIGGER fail_recovery_events`); err != nil {
		t.Fatal(err)
	}
}

func recoveryEventCount(t *testing.T, srv *Server, kind, subject string) int {
	t.Helper()
	var n int
	if err := srv.Ledger().db.QueryRow(
		`SELECT COUNT(*) FROM recovery_events WHERE kind = ? AND subject = ?`,
		kind, subject).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A deferred dispatch claim whose mandatory record cannot commit
// never happens: the row stays RECORDED and no dispatch is driven —
// an unevidenced ownership grant is no grant.
func TestMaintenanceClaimFailsClosedOnEvidenceFailure(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-fc", wait: make(chan *ExecResult)}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	failRecoveryEvents(t, srv)
	insertStrandedRecorded(t, srv, key, "fc-claim", nil)
	// Several passes run with the store faulted: the claim can never
	// complete, so the row is never claimed and nothing reaches the
	// backend.
	time.Sleep(300 * time.Millisecond)
	j, _ := srv.Ledger().Get("fc-claim")
	if j.State != JobStateRecorded {
		t.Fatalf("a stranded row was claimed while its evidence could not commit: %s", j.State)
	}
	if be.got != nil {
		t.Fatal("a dispatch ran without its mandatory claim record")
	}
	// Once the store recovers, the very next pass claims it — a
	// rolled-back claim left nothing half-recorded behind.
	allowRecoveryEvents(t, srv)
	j = waitForState(t, srv, "fc-claim", JobStateRunning, JobStateDispatching)
	if j.State == JobStateRunning && recoveryEventCount(t, srv, "claim", "fc-claim") == 0 {
		t.Fatal("the claim reached the backend without a durable claim record")
	}
}

// The ambiguous mark of a stranded DISPATCHING row is a terminal-class
// decision: it commits with its recovery record or not at all. Under
// an evidence-store failure the row stays DISPATCHING — never marked
// without proof the mark was recorded.
func TestMaintenanceMarkAmbiguousFailsClosedOnEvidenceFailure(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	be := &stubBackend{handle: "vm-stale", live: true}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	insertStrandedRecorded(t, srv, key, "stale-fc", nil)
	if err := srv.Ledger().Transition("stale-fc", JobStateDispatching, []string{JobStateRecorded},
		func(j *LedgerJob) error { j.BackendHandle = "vm-stale"; return nil }); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-(prepareTimeout + 3*srv.cfg.DispatchTimeout)).UnixMilli()
	if _, err := srv.Ledger().db.Exec(`UPDATE jobs SET updated_at = ? WHERE job_id = ?`, old, "stale-fc"); err != nil {
		t.Fatal(err)
	}
	failRecoveryEvents(t, srv)
	time.Sleep(300 * time.Millisecond)
	j, _ := srv.Ledger().Get("stale-fc")
	if j.State != JobStateDispatching {
		t.Fatalf("the ambiguous mark committed without its mandatory record: %s", j.State)
	}
	allowRecoveryEvents(t, srv)
	j = waitForState(t, srv, "stale-fc", JobStateDispatchAmbig)
	if recoveryEventCount(t, srv, "mark_ambiguous", "stale-fc") != 1 {
		t.Fatal("the ambiguous mark landed without its durable record")
	}
}

// A stranded contract's termination is a terminal outcome decision:
// the receipt is emitted, but if the transition's mandatory record
// cannot commit, the row stays RECORDED — no silent expiry.
func TestMaintenanceExpireFailsClosedOnEvidenceFailure(t *testing.T) {
	dir := socketDir(t)
	key, keys := testAuthority(t)
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: &stubBackend{handle: "vm-x"}, MaintenanceInterval: 15 * time.Millisecond,
	})
	insertStrandedRecorded(t, srv, key, "exp-fc", func(c *JobContractV2) {
		c.ExpiresAt = time.Now().UTC().Add(-time.Minute).Unix()
	})
	failRecoveryEvents(t, srv)
	time.Sleep(300 * time.Millisecond)
	j, _ := srv.Ledger().Get("exp-fc")
	if j.State != JobStateRecorded {
		t.Fatalf("a terminal decision committed without its mandatory record: %s", j.State)
	}
	allowRecoveryEvents(t, srv)
	j = waitForState(t, srv, "exp-fc", JobStateDispatchFailed)
	if recoveryEventCount(t, srv, "expire", "exp-fc") != 1 {
		t.Fatal("the expiry committed without its durable record")
	}
}

// A residue escalation writes its durable record before the throttle
// mark — an escalation that cannot be evidenced is retried, never
// silenced by a throttle stamped on nothing.
func TestMaintenanceEscalationEvidencePrecedesThrottle(t *testing.T) {
	dir := socketDir(t)
	_, keys := testAuthority(t)
	be := &stubBackend{live: true, resumeErr: ErrExecutionUnobserved}
	srv := startServer(t, Config{
		SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: be, MaintenanceInterval: 15 * time.Millisecond,
	})
	if _, err := srv.Ledger().InsertJob("esc-1", "h-esc-1", "s", "p", "i", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := srv.Ledger().Transition("esc-1", JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if err := srv.Ledger().Transition("esc-1", JobStateDispatchAmbig, []string{JobStateDispatching},
		func(j *LedgerJob) error { j.BackendHandle = "vm-esc"; return nil }); err != nil {
		t.Fatal(err)
	}
	failRecoveryEvents(t, srv)
	srv.escalateResidue()
	if _, found, _ := srv.Ledger().RecoveryState(residueStateKey); found {
		t.Fatal("the throttle was stamped while the escalation could not be evidenced")
	}
	allowRecoveryEvents(t, srv)
	srv.escalateResidue()
	if _, found, _ := srv.Ledger().RecoveryState(residueStateKey); !found {
		t.Fatal("the throttle was never stamped after the evidence store recovered")
	}
	if recoveryEventCount(t, srv, "escalation", "registry") != 1 {
		t.Fatal("the escalation never landed in the durable trail")
	}
}
