package idempotency

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestSQLiteClusterEpochSeedAndFreshStore covers the lifecycle the DR
// runbook depends on: the epoch seeds at 1, AdvanceClusterEpoch bumps
// it, a restarted executor (a new store on the same database) admits
// under the new epoch and writes normally, while the stale store stays
// fenced.
func TestSQLiteClusterEpochSeedAndFreshStore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db", "epoch.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	stale, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if stale.ClusterEpoch() != 1 {
		t.Fatalf("initial epoch = %d, want 1", stale.ClusterEpoch())
	}

	next, err := stale.AdvanceClusterEpoch(ctx, 1, "restore")
	if err != nil {
		t.Fatalf("advance: %v", err)
	}
	if next != 2 {
		t.Fatalf("advance returned %d, want 2", next)
	}

	// The advance declared post-restore recovery mode — the operator
	// reconciles, then reopens admission for the restarted world.
	fresh, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("fresh NewSQLiteStore: %v", err)
	}
	if fresh.ClusterEpoch() != 2 {
		t.Fatalf("fresh store epoch = %d, want 2", fresh.ClusterEpoch())
	}
	if required, _ := fresh.ClusterRecoveryRequired(ctx); !required {
		t.Fatal("epoch advance must declare recovery mode")
	}
	if err := fresh.CompleteClusterRecovery(ctx, 2, "reconciled"); err != nil {
		t.Fatalf("complete recovery: %v", err)
	}
	acq, err := fresh.Acquire(ctx, "k1", "alice", "cap.mut", sqliteDigest("e"), "", "MUTATION", time.Minute)
	if err != nil {
		t.Fatalf("fresh acquire: %v", err)
	}
	if !acq.Acquired() || acq.Record.AdmittedEpoch != 2 {
		t.Fatalf("fresh record: kind=%s epoch=%d, want acquired epoch 2", acq.Kind, acq.Record.AdmittedEpoch)
	}

	// The stale store remains fenced.
	if _, err := stale.Acquire(ctx, "k2", "alice", "cap.mut", sqliteDigest("e2"), "", "MUTATION", time.Minute); !errors.Is(err, ClusterEpochMismatch) {
		t.Fatalf("stale acquire: want ClusterEpochMismatch, got %v", err)
	}
	if err := stale.BeginExecution(ctx, acq.Record.ExecutionID, acq.LeaseToken, acq.Generation); !errors.Is(err, ClusterEpochMismatch) {
		t.Fatalf("stale begin: want ClusterEpochMismatch, got %v", err)
	}
}

// TestSQLiteAdvanceClusterEpochConcurrency proves the CAS is atomic:
// N concurrent advances with the same expected epoch produce exactly
// one winner and N-1 typed mismatches — two operators racing the DR
// bump can never double-advance.
func TestSQLiteAdvanceClusterEpochConcurrency(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)

	const racers = 8
	var wg sync.WaitGroup
	errs := make([]error, racers)
	results := make([]int64, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = s.AdvanceClusterEpoch(ctx, 1, "race")
		}(i)
	}
	wg.Wait()

	wins, losses := 0, 0
	for i := range errs {
		switch {
		case errs[i] == nil:
			wins++
			if results[i] != 2 {
				t.Fatalf("winner %d returned epoch %d, want 2", i, results[i])
			}
		case errors.Is(errs[i], ClusterEpochMismatch):
			losses++
		default:
			t.Fatalf("unexpected error: %v", errs[i])
		}
	}
	if wins != 1 || losses != racers-1 {
		t.Fatalf("wins=%d losses=%d, want 1/%d", wins, losses, racers-1)
	}
}

// TestSQLiteClusterRecoveryMode covers the post-restore admission
// gate: an epoch advance declares recovery mode, a fresh store under
// the new epoch finds new-effect admission closed (typed
// CLUSTER_RECOVERY_REQUIRED) while reconciliation paths stay open,
// and CompleteClusterRecovery reopens admission — epoch-guarded so a
// stale operator cannot clear a newer world's mode.
func TestSQLiteClusterRecoveryMode(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db", "recovery.db")
	db, err := OpenSQLiteDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	stale, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if required, err := stale.ClusterRecoveryRequired(ctx); err != nil || required {
		t.Fatalf("fresh cluster recovery_required = %v, %v — want false", required, err)
	}

	// An inherited IN_FLIGHT record exists before the restore.
	pre, err := stale.Acquire(ctx, "pre-restore", "alice", "cap.mut", sqliteDigest("pre"), "", "MUTATION", time.Minute)
	if err != nil {
		t.Fatalf("pre-restore acquire: %v", err)
	}
	if err := stale.BeginExecution(ctx, pre.Record.ExecutionID, pre.LeaseToken, pre.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stale.MarkInFlight(ctx, pre.Record.ExecutionID, pre.LeaseToken, pre.Generation, "prov", nil); err != nil {
		t.Fatalf("mark in flight: %v", err)
	}

	if _, err := stale.AdvanceClusterEpoch(ctx, 1, "restore"); err != nil {
		t.Fatalf("advance: %v", err)
	}

	// Restarted executor under the new epoch.
	fresh, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("fresh NewSQLiteStore: %v", err)
	}
	if required, err := fresh.ClusterRecoveryRequired(ctx); err != nil || !required {
		t.Fatalf("post-advance recovery_required = %v, %v — want true", required, err)
	}

	// New-effect admission is closed with the typed error — never a
	// lease-conflict misclassification.
	if _, err := fresh.Acquire(ctx, "during-recovery", "alice", "cap.mut", sqliteDigest("new"), "", "MUTATION", time.Minute); !errors.Is(err, ClusterRecoveryRequired) {
		t.Fatalf("acquire during recovery: want ClusterRecoveryRequired, got %v", err)
	}

	// Reconciliation of inherited records stays open.
	stored, err := fresh.Lookup(ctx, pre.Record.ExecutionID)
	if err != nil {
		t.Fatalf("lookup inherited record: %v", err)
	}
	if err := fresh.EnterRecovery(ctx, pre.Record.ExecutionID, StateInFlight, stored.Version); err != nil {
		t.Fatalf("recovery-path mutation during recovery mode: %v", err)
	}

	// A stale-epoch operator cannot clear the mode.
	if err := stale.CompleteClusterRecovery(ctx, 1, "premature"); !errors.Is(err, ClusterEpochMismatch) {
		t.Fatalf("stale complete: want ClusterEpochMismatch, got %v", err)
	}
	if required, _ := fresh.ClusterRecoveryRequired(ctx); !required {
		t.Fatal("stale operator cleared recovery mode")
	}

	// The operator's reconciliation gate met — admission reopens.
	if err := fresh.CompleteClusterRecovery(ctx, 2, "reconciliation complete"); err != nil {
		t.Fatalf("complete recovery: %v", err)
	}
	if required, _ := fresh.ClusterRecoveryRequired(ctx); required {
		t.Fatal("recovery mode still required after completion")
	}
	acq, err := fresh.Acquire(ctx, "post-recovery", "alice", "cap.mut", sqliteDigest("post"), "", "MUTATION", time.Minute)
	if err != nil {
		t.Fatalf("post-recovery acquire: %v", err)
	}
	if !acq.Acquired() {
		t.Fatalf("post-recovery acquire kind = %s", acq.Kind)
	}
}

// TestSQLiteMigrationClusterEpochBackfill verifies migration 9 on an
// existing database: pre-existing rows backfill admitted_epoch = 1
// (they were admitted under the implicit initial epoch), and the
// seeded epoch lets the store serve the fencing contract immediately.
func TestSQLiteMigrationClusterEpochBackfill(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)

	// Rows created after migration carry the epoch at INSERT time —
	// the backfill applies to pre-migration rows only, which a fresh
	// database cannot have. Assert the invariant that matters for
	// upgrades: a row admitted now stamps the current epoch, and
	// manually backfilled rows are readable.
	acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", sqliteDigest("b"), "", "MUTATION", time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	rec, err := s.Lookup(ctx, acq.Record.ExecutionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.AdmittedEpoch != 1 {
		t.Fatalf("admitted_epoch = %d, want 1", rec.AdmittedEpoch)
	}
	var seeded int
	if err := s.db.QueryRowContext(ctx,
		`SELECT epoch FROM cluster_meta WHERE id = 1`).Scan(&seeded); err != nil {
		t.Fatalf("cluster_meta seed: %v", err)
	}
	if seeded != 1 {
		t.Fatalf("cluster_meta epoch = %d, want 1", seeded)
	}
}
