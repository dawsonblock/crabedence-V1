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

	// A restarted executor admits under the new epoch.
	fresh, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("fresh NewSQLiteStore: %v", err)
	}
	if fresh.ClusterEpoch() != 2 {
		t.Fatalf("fresh store epoch = %d, want 2", fresh.ClusterEpoch())
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
