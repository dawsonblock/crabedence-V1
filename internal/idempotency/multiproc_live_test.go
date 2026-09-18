package idempotency

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Multi-process EffectStore torture. Goroutine concurrency tests
// share one *sql.DB pool — only real OS processes prove the fencing
// holds across independent connections, independent store instances,
// and independent cluster-epoch admissions against one PostgreSQL.
//
// Each helper subprocess opens its own connection and runs the
// executor durable sequence for one idempotency key, printing its
// typed acquire outcome and whether it reached finalize.
//
// Env:
//
//	CRABBOX_MULTIPROC_HELPER=1         — run as helper
//	CRABBOX_MULTIPROC_KEY=<key>        — idempotency key
//	CRABBOX_MULTIPROC_ROLE=executor|reconciler
//	CRABBOX_MULTIPROC_EXECID=<id>      — reconciler: record to hunt
//	CRABBOX_MULTIPROC_DIE=1            — executor: SIGKILL after IN_FLIGHT
//	CRABBOX_MULTIPROC_LEASE_MS=<ms>    — executor: lease duration
func TestMultiProcWorkerHelper(t *testing.T) {
	if os.Getenv("CRABBOX_MULTIPROC_HELPER") != "1" {
		return
	}
	ctx := context.Background()
	db, err := openTestDB(os.Getenv("CRABBOX_TEST_DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if os.Getenv("CRABBOX_MULTIPROC_ROLE") == "reconciler" {
		want := os.Getenv("CRABBOX_MULTIPROC_EXECID")
		claimed, err := store.ClaimExpiredBatch(ctx, "mp-reconciler", 50, 10*time.Minute)
		if err != nil {
			fmt.Println("RESULT=ERR_CLAIM:" + err.Error())
			os.Exit(0)
		}
		for _, c := range claimed {
			if c.ExecutionID == want {
				fmt.Println("CLAIMED=1")
				os.Exit(0)
			}
		}
		fmt.Println("CLAIMED=0")
		os.Exit(0)
	}

	lease := DefaultLeaseDuration
	if ms := os.Getenv("CRABBOX_MULTIPROC_LEASE_MS"); ms != "" {
		if d, err := time.ParseDuration(ms + "ms"); err == nil {
			lease = d
		}
	}
	key := os.Getenv("CRABBOX_MULTIPROC_KEY")
	digest := confDigest("alice", "cap.mp", `{"q":"x"}`)
	acq, err := store.Acquire(ctx, key, "alice", "cap.mp", digest, "", "MUTATION", lease)
	if err != nil {
		fmt.Println("RESULT=ERR:" + err.Error())
		os.Exit(0)
	}
	fmt.Println("RESULT=" + string(acq.Kind))
	if !acq.Acquired() {
		os.Exit(0)
	}
	if err := store.BeginExecution(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		fmt.Println("RESULT=ERR_BEGIN:" + err.Error())
		os.Exit(0)
	}
	if err := store.MarkInFlight(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, "mp-provider", nil); err != nil {
		fmt.Println("RESULT=ERR_INFLIGHT:" + err.Error())
		os.Exit(0)
	}
	if os.Getenv("CRABBOX_MULTIPROC_DIE") == "1" {
		// Die like a power loss mid-flight — no cleanup, lease left
		// for the cluster to expire.
		syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
	}
	if err := store.RecordProviderObservation(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation,
		ProviderObservation{ProviderID: "mp-provider", ProviderStatus: "SUCCEEDED"}); err != nil {
		fmt.Println("RESULT=ERR_OBS:" + err.Error())
		os.Exit(0)
	}
	if err := store.Finalize(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation, StateInFlight,
		confReceipt(acq.Record.ExecutionID, "cap.mp", "alice", digest, "mp-provider", "run-1", StateCommitted)); err != nil {
		fmt.Println("RESULT=ERR_FINALIZE:" + err.Error())
		os.Exit(0)
	}
	fmt.Println("FINALIZED=1")
	os.Exit(0)
}

// spawnWorker launches one helper subprocess. The parent's
// CRABBOX_TEST_DATABASE_URL is inherited.
func spawnWorker(env ...string) (*exec.Cmd, *bytes.Buffer) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMultiProcWorkerHelper")
	cmd.Env = append(os.Environ(), append([]string{"CRABBOX_MULTIPROC_HELPER=1"}, env...)...)
	out := &bytes.Buffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd, out
}

func multiprocSetup(t *testing.T) (*Store, *sql.DB, context.Context) {
	t.Helper()
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping multi-process PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	store, err := NewStore(db)
	if err != nil {
		db.Close()
		t.Fatalf("NewStore: %v", err)
	}
	ctx := context.Background()
	// A leftover recovery gate from an earlier fencing test would
	// poison every worker.
	if _, err := db.ExecContext(ctx,
		`UPDATE cluster_meta SET recovery_required = FALSE WHERE id = 1`); err != nil {
		t.Fatalf("reset recovery mode: %v", err)
	}
	return store, db, ctx
}

// TestLiveMultiProcessSingleKeyDispatch launches 50 independent
// executor processes against one idempotency key on one PostgreSQL
// cluster. Exactly one may acquire, dispatch, and finalize — every
// other process must observe the durable record and stand down:
// cross-process atomicity, not goroutine scheduling luck.
func TestLiveMultiProcessSingleKeyDispatch(t *testing.T) {
	store, db, ctx := multiprocSetup(t)
	defer db.Close()

	key := fmt.Sprintf("mp-single-%d", time.Now().UnixNano())
	const workers = 50
	cmds := make([]*exec.Cmd, workers)
	outs := make([]*bytes.Buffer, workers)
	for i := 0; i < workers; i++ {
		cmds[i], outs[i] = spawnWorker("CRABBOX_MULTIPROC_KEY=" + key)
		if err := cmds[i].Start(); err != nil {
			t.Fatalf("spawn worker %d: %v", i, err)
		}
	}
	acquired, finalized := 0, 0
	for i := range cmds {
		cmds[i].Wait()
		out := outs[i].String()
		if strings.Contains(out, "RESULT=ACQUIRED") || strings.Contains(out, "RESULT=RECLAIMED") {
			acquired++
		}
		if strings.Contains(out, "FINALIZED=1") {
			finalized++
		}
	}
	if acquired != 1 {
		t.Fatalf("acquired = %d, want exactly 1 across 50 processes", acquired)
	}
	if finalized != 1 {
		t.Fatalf("finalized = %d, want exactly 1 — duplicate dispatch is a second external effect", finalized)
	}
	rec, err := store.LookupByKey(ctx, "alice", "cap.mp", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != StateCommitted {
		t.Fatalf("final state = %s, want COMMITTED", rec.State)
	}
}

// TestLiveMultiProcessDistinctKeys launches 20 executor processes
// against 20 distinct keys — independent executions must all commit
// without cross-key interference.
func TestLiveMultiProcessDistinctKeys(t *testing.T) {
	store, db, ctx := multiprocSetup(t)
	defer db.Close()

	base := fmt.Sprintf("mp-distinct-%d", time.Now().UnixNano())
	const workers = 20
	cmds := make([]*exec.Cmd, workers)
	outs := make([]*bytes.Buffer, workers)
	for i := 0; i < workers; i++ {
		cmds[i], outs[i] = spawnWorker(fmt.Sprintf("CRABBOX_MULTIPROC_KEY=%s-%d", base, i))
		if err := cmds[i].Start(); err != nil {
			t.Fatalf("spawn worker %d: %v", i, err)
		}
	}
	finalized := 0
	for i := range cmds {
		cmds[i].Wait()
		out := outs[i].String()
		if strings.Contains(out, "FINALIZED=1") {
			finalized++
		} else if !strings.Contains(out, "RESULT=ACQUIRED") {
			t.Logf("worker %d: %s", i, strings.TrimSpace(out))
		}
	}
	if finalized != workers {
		t.Fatalf("finalized = %d, want %d — every distinct key must commit independently", finalized, workers)
	}
	for i := 0; i < workers; i++ {
		rec, err := store.LookupByKey(ctx, "alice", "cap.mp", fmt.Sprintf("%s-%d", base, i))
		if err != nil {
			t.Fatalf("lookup key %d: %v", i, err)
		}
		if rec.State != StateCommitted {
			t.Fatalf("key %d state = %s, want COMMITTED", i, rec.State)
		}
	}
}

// TestLiveMultiProcessLeaseOwnerKilled covers the distributed failure
// the lease fence exists for: the dispatch owner dies mid-flight, its
// lease expires, and N independent reconciler processes race to claim
// the orphaned record — exactly one wins, and the record transitions
// to UNKNOWN once (never redispatched, never double-claimed).
func TestLiveMultiProcessLeaseOwnerKilled(t *testing.T) {
	store, db, ctx := multiprocSetup(t)
	defer db.Close()

	key := fmt.Sprintf("mp-killed-%d", time.Now().UnixNano())

	// Owner process: acquires with a tiny lease, marks IN_FLIGHT,
	// then SIGKILLs — the orphaned record is the cluster's problem.
	cmd, out := spawnWorker(
		"CRABBOX_MULTIPROC_KEY="+key,
		"CRABBOX_MULTIPROC_DIE=1",
		"CRABBOX_MULTIPROC_LEASE_MS=300",
	)
	if err := cmd.Run(); err == nil {
		t.Fatalf("killed worker should not exit cleanly\n%s", out.String())
	}
	rec, err := store.LookupByKey(ctx, "alice", "cap.mp", key)
	if err != nil {
		t.Fatalf("lookup after kill: %v", err)
	}
	if rec.State != StateInFlight {
		t.Fatalf("post-kill state = %s, want IN_FLIGHT", rec.State)
	}

	// Wait out the dead owner's lease, then race 10 reconciler
	// processes on the same orphaned record.
	time.Sleep(400 * time.Millisecond)
	const racers = 10
	cmds := make([]*exec.Cmd, racers)
	outs := make([]*bytes.Buffer, racers)
	for i := 0; i < racers; i++ {
		cmds[i], outs[i] = spawnWorker(
			"CRABBOX_MULTIPROC_ROLE=reconciler",
			"CRABBOX_MULTIPROC_EXECID="+rec.ExecutionID,
		)
		if err := cmds[i].Start(); err != nil {
			t.Fatalf("spawn reconciler %d: %v", i, err)
		}
	}
	claimed := 0
	for i := range cmds {
		cmds[i].Wait()
		if strings.Contains(outs[i].String(), "CLAIMED=1") {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("reconciliation claims = %d, want exactly 1 across %d processes", claimed, racers)
	}

	// The surviving claim drives the record to UNKNOWN — never
	// blind-redispatched.
	stored, err := store.Lookup(ctx, rec.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnterRecovery(ctx, rec.ExecutionID, StateInFlight, stored.Version); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}
	final, err := store.Lookup(ctx, rec.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != StateUnknown {
		t.Fatalf("final state = %s, want UNKNOWN", final.State)
	}
}
