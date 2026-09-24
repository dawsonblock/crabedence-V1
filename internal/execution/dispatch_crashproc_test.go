package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// TestCrashHelperProcess is the subprocess entry point for real process
// crash tests. It opens the SQLite store itself, runs one execution,
// and SIGKILLs itself at the configured CrashPoint — goroutine
// cancellation cannot simulate a dead process; only a killed process
// leaves a record mid-transition with no cleanup.
//
// Env:
//
//	CRABBOX_CRASH_HELPER=1        — run as helper
//	CRABBOX_CRASH_DB=<path>       — database path
//	CRABBOX_CRASH_POINT=<point>   — CrashPoint to die at
//	CRABBOX_CRASH_KEY=<key>       — idempotency key
func TestCrashHelperProcess(t *testing.T) {
	if os.Getenv("CRABBOX_CRASH_HELPER") != "1" {
		return
	}
	db, err := idempotency.OpenSQLiteDB(os.Getenv("CRABBOX_CRASH_DB"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	leaseCfg := idempotency.DefaultLeaseConfig
	if ms := os.Getenv("CRABBOX_CRASH_LEASE_MS"); ms != "" {
		if d, err := time.ParseDuration(ms + "ms"); err == nil {
			leaseCfg.DefaultDuration = d
			leaseCfg.RenewalWindow = d / 3
		}
	}
	store, err := idempotency.NewSQLiteStoreWithConfig(db, leaseCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	point := CrashPoint(os.Getenv("CRABBOX_CRASH_POINT"))
	var h Handler = &simProvider{effect: true}
	if u := os.Getenv("CRABBOX_PROVIDER_URL"); u != "" {
		// External provider subprocess — the side effect survives
		// this process's death in the provider's own durable log.
		h = &httpProvider{baseURL: u, client: &http.Client{Timeout: 10 * time.Second}}
	}
	exec := NewDispatchExecutor(h, store)
	exec.SetCrashHook(func(cp CrashPoint) {
		if cp == point {
			// Die like a power loss — no defers, no cleanup. Block
			// after the kill so no instruction past the crash boundary
			// can run in the window between Kill returning and signal
			// delivery: a raced Finalize there would commit a terminal
			// state past a crash point that must precede it. SIGKILL
			// cannot be blocked, so the process still dies.
			syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
			select {}
		}
	})
	resp := exec.ExecuteWithIdempotency(context.Background(), Request{
		Capability:     "test.mut",
		Arguments:      json.RawMessage(`{"x":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_x"},
		IdempotencyKey: os.Getenv("CRABBOX_CRASH_KEY"),
	}, capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "test-adapter",
	})
	// The executor returned without reaching the crash point. Report
	// what it returned — the parent test asserts this process died, so
	// a clean exit must explain which pre-dispatch path bailed out.
	encoded, _ := json.Marshal(resp)
	fmt.Fprintf(os.Stderr, "crash helper returned without firing %s: %s\n", point, encoded)
	os.Exit(0)
}

// TestProcessCrashMatrix kills a real executor process at every
// durable boundary, reopens the database in a fresh store, and
// asserts the durable contract: pre-dispatch crash leaves a
// claimable/abandoned record; post-dispatch crash leaves IN_FLIGHT
// (lease still held, expired for reconciliation) or the completed
// terminal state — never a fabricated outcome.
func TestProcessCrashMatrix(t *testing.T) {
	tests := []struct {
		point     CrashPoint
		wantState idempotency.State
	}{
		{CrashAfterAcquire, idempotency.StatePrepared},
		{CrashAfterBeginExecution, idempotency.StateExecuting},
		{CrashAfterMarkInFlight, idempotency.StateInFlight},
		{CrashBeforeProvider, idempotency.StateInFlight},
		{CrashAfterProvider, idempotency.StateInFlight},
		{CrashBeforeObservation, idempotency.StateInFlight},
		{CrashAfterObservation, idempotency.StateInFlight},
		{CrashBeforeFinalize, idempotency.StateInFlight},
		{CrashAfterFinalize, idempotency.StateCommitted},
	}

	for _, tt := range tests {
		t.Run(string(tt.point), func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "db", "crash.db")
			key := fmt.Sprintf("pcrash-%s", tt.point)

			cmd := exec.Command(os.Args[0], "-test.run=TestCrashHelperProcess")
			cmd.Env = append(os.Environ(),
				"CRABBOX_CRASH_HELPER=1",
				"CRABBOX_CRASH_DB="+dbPath,
				"CRABBOX_CRASH_POINT="+string(tt.point),
				"CRABBOX_CRASH_KEY="+key,
			)
			out, err := cmd.CombinedOutput()
			if err == nil && tt.point != CrashAfterFinalize {
				// A nil error means the process exited 0 — only
				// acceptable if the crash point never fired (which
				// would itself be a defect).
				t.Fatalf("helper exited cleanly — crash point %s did not fire\n%s", tt.point, out)
			}

			// Restart: open the SAME database fresh — simulating a
			// new runtime after process death.
			db, err := idempotency.OpenSQLiteDB(dbPath)
			if err != nil {
				t.Fatalf("reopen db: %v", err)
			}
			defer db.Close()
			store, err := idempotency.NewSQLiteStore(db)
			if err != nil {
				t.Fatalf("reopen store: %v", err)
			}
			rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
			if err != nil {
				t.Fatalf("lookup after crash: %v", err)
			}
			if rec.State != tt.wantState {
				t.Errorf("post-crash durable state = %s, want %s", rec.State, tt.wantState)
			}

			// Post-dispatch crash invariants: the record must be
			// reconcilable — IN_FLIGHT with a lease that will expire
			// for ClaimUnknown — never COMMITTED without the full
			// terminal write.
			if tt.point != CrashAfterFinalize && rec.State.IsDurablyFinal() {
				t.Errorf("crash at %s produced terminal state %s without finalization", tt.point, rec.State)
			}
		})
	}
}

// TestProcessCrashRecoveryCompletion kills the process after the
// provider returns but before observation persists, waits out the
// lease, then reconciles the record to UNKNOWN — the complete
// external-effect-then-local-death path.
func TestProcessCrashRecoveryCompletion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "db", "crash.db")
	key := "pcrash-recovery"

	cmd := exec.Command(os.Args[0], "-test.run=TestCrashHelperProcess")
	cmd.Env = append(os.Environ(),
		"CRABBOX_CRASH_HELPER=1",
		"CRABBOX_CRASH_DB="+dbPath,
		"CRABBOX_CRASH_POINT="+string(CrashAfterProvider),
		"CRABBOX_CRASH_KEY="+key,
		"CRABBOX_CRASH_LEASE_MS=200",
	)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("helper should have died at after_provider\n%s", out)
	}

	db, err := idempotency.OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Tiny lease so the dead executor's claim expires quickly.
	store, err := idempotency.NewSQLiteStoreWithConfig(db, idempotency.LeaseConfig{
		DefaultDuration: 200 * time.Millisecond,
		MaxDuration:     time.Second,
		RenewalWindow:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != idempotency.StateInFlight {
		t.Fatalf("state = %s, want IN_FLIGHT", rec.State)
	}

	// Wait out the dead executor's lease, then claim for recovery —
	// this is the path a reconciliation worker takes after a crash.
	time.Sleep(300 * time.Millisecond)
	claimed, err := store.ClaimExpiredBatch(context.Background(), "recovery-worker", 10, time.Minute)
	if err != nil {
		t.Fatalf("ClaimExpiredBatch: %v", err)
	}
	var ours *idempotency.Record
	for _, c := range claimed {
		if c.ExecutionID == rec.ExecutionID {
			ours = c
		}
	}
	if ours == nil {
		t.Fatalf("expired IN_FLIGHT record not claimable for recovery")
	}

	// Drive the record to UNKNOWN — the semantic the reconciliation
	// worker establishes for an orphaned post-dispatch record.
	if err := store.EnterRecovery(context.Background(), rec.ExecutionID,
		idempotency.StateInFlight, ours.Version); err != nil {
		t.Fatalf("EnterRecovery after crash claim: %v", err)
	}
	final, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != idempotency.StateUnknown {
		t.Fatalf("post-recovery state = %s, want UNKNOWN — crashed post-dispatch execution must be reconcilable", final.State)
	}
}
