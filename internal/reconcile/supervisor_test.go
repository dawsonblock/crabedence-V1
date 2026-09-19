package reconcile

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// stubStore provides the store surface the worker and supervisor touch
// during a cycle, with no real database behind it.
type stubStore struct {
	idempotency.EffectStore
	unknown   []*idempotency.Record
	expired   []*idempotency.Record
	claimErr  error
	backlog   int64
	oldest    *time.Time
	suspended []string
	released  []string
	renewed   []string
}

func (s *stubStore) ClaimUnknownBatch(context.Context, string, int, time.Duration) ([]*idempotency.Record, error) {
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	return s.unknown, nil
}

func (s *stubStore) ClaimExpiredBatch(context.Context, string, int, time.Duration) ([]*idempotency.Record, error) {
	return s.expired, nil
}

func (s *stubStore) ScrubStaleRecoveryLocators(context.Context, time.Duration) (int64, error) {
	return 0, nil
}

func (s *stubStore) ReconciliationBacklog(context.Context) (int64, *time.Time, error) {
	return s.backlog, s.oldest, nil
}

func (s *stubStore) SuspendReconciliation(_ context.Context, executionID string, _ int, _ string) error {
	s.suspended = append(s.suspended, executionID)
	return nil
}

func (s *stubStore) ReleaseReconcileClaim(_ context.Context, executionID string, _ int, _ time.Duration, _ string) error {
	s.released = append(s.released, executionID)
	return nil
}

func (s *stubStore) RenewReconcileClaim(_ context.Context, executionID string, _ int, _ time.Duration) error {
	s.renewed = append(s.renewed, executionID)
	return nil
}

// errorResolver always fails — a provider lookup that could not complete.
type errorResolver struct{}

func (errorResolver) Resolve(context.Context, *idempotency.Record) (idempotency.RecoveryResult, error) {
	return idempotency.RecoveryResult{}, errors.New("provider lookup failed")
}

func TestSupervisorReadinessPolicy(t *testing.T) {
	store := &stubStore{}
	worker := NewWorker(store, NoopResolver{}, time.Minute)
	supervisor := NewSupervisor(worker, store, SupervisorConfig{
		Interval:               time.Minute,
		DegradedAfterCycleAge:  time.Minute,
		NotReadyAfterCycleAge:  time.Hour,
		MaxConsecutiveFailures: 2,
	})

	// Not started: never ready.
	if health := supervisor.Health(context.Background()); health.State != HealthNotReady {
		t.Fatalf("not-started supervisor = %s, want NOT_READY", health.State)
	}

	// A successful cycle makes it ready.
	supervisor.runCycle(context.Background())
	health := supervisor.Health(context.Background())
	if health.State != HealthReady {
		t.Fatalf("after a successful cycle = %s (%v), want READY", health.State, health.Reasons)
	}
	if health.CyclesStarted != 1 || health.CyclesCompleted != 1 || health.CyclesFailed != 0 {
		t.Fatalf("cycle counters = %+v", health)
	}
	if health.LastSuccess.IsZero() {
		t.Fatal("LastSuccess must be recorded")
	}

	// Stale success degrades, then becomes unready.
	stale := NewSupervisor(worker, store, SupervisorConfig{
		Interval:              time.Minute,
		DegradedAfterCycleAge: time.Nanosecond,
		NotReadyAfterCycleAge: time.Hour,
	})
	stale.runCycle(context.Background())
	if health := stale.Health(context.Background()); health.State != HealthDegraded {
		t.Fatalf("stale success = %s (%v), want DEGRADED", health.State, health.Reasons)
	}
	veryStale := NewSupervisor(worker, store, SupervisorConfig{
		Interval:              time.Minute,
		DegradedAfterCycleAge: time.Nanosecond,
		NotReadyAfterCycleAge: time.Nanosecond,
	})
	veryStale.runCycle(context.Background())
	if health := veryStale.Health(context.Background()); health.State != HealthNotReady {
		t.Fatalf("very stale success = %s (%v), want NOT_READY", health.State, health.Reasons)
	}

	// Consecutive failures escalate to not ready.
	failing := &stubStore{claimErr: errors.New("injected claim failure")}
	failingWorker := NewWorker(failing, NoopResolver{}, time.Minute)
	failingSupervisor := NewSupervisor(failingWorker, failing, SupervisorConfig{
		Interval:               time.Minute,
		MaxConsecutiveFailures: 2,
	})
	failingSupervisor.runCycle(context.Background())
	if health := failingSupervisor.Health(context.Background()); health.State == HealthNotReady {
		t.Fatalf("one failure must not be NOT_READY yet: %v", health.Reasons)
	}
	failingSupervisor.runCycle(context.Background())
	health = failingSupervisor.Health(context.Background())
	if health.State != HealthNotReady {
		t.Fatalf("two failures = %s, want NOT_READY", health.State)
	}
	if health.CyclesFailed != 2 {
		t.Fatalf("CyclesFailed = %d, want 2", health.CyclesFailed)
	}
	if health.LastError == "" {
		t.Fatal("LastError must be recorded")
	}
}

func TestSupervisorDegradedOnUnknownBacklogAge(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	store := &stubStore{backlog: 3, oldest: &old}
	worker := NewWorker(store, NoopResolver{}, time.Minute)
	supervisor := NewSupervisor(worker, store, SupervisorConfig{
		Interval:      time.Minute,
		MaxUnknownAge: time.Hour,
	})
	supervisor.runCycle(context.Background())

	health := supervisor.Health(context.Background())
	if health.State != HealthDegraded {
		t.Fatalf("old UNKNOWN backlog = %s (%v), want DEGRADED", health.State, health.Reasons)
	}
	if health.UnknownPending != 3 || health.UnknownOldestAge < time.Hour {
		t.Fatalf("backlog observability = pending %d oldest %s", health.UnknownPending, health.UnknownOldestAge)
	}
}

func TestSupervisorRunLoopObservesCycles(t *testing.T) {
	store := &stubStore{}
	worker := NewWorker(store, NoopResolver{}, time.Minute)
	supervisor := NewSupervisor(worker, store, SupervisorConfig{
		Interval:              10 * time.Millisecond,
		DegradedAfterCycleAge: time.Minute,
		NotReadyAfterCycleAge: time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = supervisor.Run(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if health := supervisor.Health(context.Background()); health.CyclesCompleted >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	health := supervisor.Health(context.Background())
	if health.CyclesCompleted < 2 {
		t.Fatalf("expected at least two observed cycles, got %d", health.CyclesCompleted)
	}
	// After the loop exits the reconciler is stopped — never ready.
	if health.State != HealthNotReady {
		t.Fatalf("stopped supervisor = %s, want NOT_READY", health.State)
	}
	if health.ReconcilerRunning {
		t.Fatal("ReconcilerRunning must be false after the loop exits")
	}
}

func TestWorkerCountersDeadLettersAndResolverFailures(t *testing.T) {
	store := &stubStore{}
	worker := NewWorker(store, errorResolver{}, time.Minute)
	worker.SetMaxAttempts(1)

	// A record past the attempt ceiling is dead-lettered.
	exhausted := &idempotency.Record{
		ExecutionID:      "exec-exhausted",
		State:            idempotency.StateUnknown,
		ReconcileAttempt: 5,
		Version:          1,
	}
	if err := worker.ReconcileOneForTest(context.Background(), exhausted); err != nil {
		t.Fatalf("dead-letter path returned an error: %v", err)
	}
	if metrics := worker.Metrics(); metrics.DeadLetters != 1 {
		t.Fatalf("DeadLetters = %d, want 1", metrics.DeadLetters)
	}
	if len(store.suspended) != 1 || store.suspended[0] != "exec-exhausted" {
		t.Fatalf("suspended = %v", store.suspended)
	}

	// A resolver error is counted and the record keeps its UNKNOWN state.
	pendingWorker := NewWorker(store, errorResolver{}, time.Minute)
	pendingWorker.SetMaxAttempts(3)
	pending := &idempotency.Record{
		ExecutionID:      "exec-pending",
		State:            idempotency.StateUnknown,
		ReconcileAttempt: 1,
		Version:          1,
	}
	if err := pendingWorker.ReconcileOneForTest(context.Background(), pending); err == nil {
		t.Fatal("resolver failure must surface as an error")
	}
	if metrics := pendingWorker.Metrics(); metrics.ResolverFailures != 1 {
		t.Fatalf("ResolverFailures = %d, want 1", metrics.ResolverFailures)
	}
	if len(store.released) != 1 {
		t.Fatalf("released = %v, want the claim released with backoff", store.released)
	}
}
