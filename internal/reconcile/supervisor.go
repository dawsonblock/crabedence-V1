package reconcile

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// Supervisor gives reconciliation first-class operational status: it
// owns the worker's lifecycle, observes every cycle, and evaluates an
// explicit readiness policy. Reconciliation is not a background
// goroutine whose failures are only visible in logs — the process
// knows whether its reconciliation subsystem is healthy.
type Supervisor struct {
	worker *Worker
	store  idempotency.EffectStore
	config SupervisorConfig

	mu                  sync.Mutex
	running             bool
	stopped             bool
	lastCycleStarted    time.Time
	lastCycleCompleted  time.Time
	lastSuccess         time.Time
	consecutiveFailures int64
	lastError           string
	state               string
	statusWriter        func(Health)
}

// SupervisorConfig is the explicit readiness policy. Thresholds are
// configuration, never hard-coded.
type SupervisorConfig struct {
	// Interval is the reconciliation cycle interval.
	Interval time.Duration
	// DegradedAfterCycleAge marks the supervisor DEGRADED when no
	// cycle has succeeded within this window. Default: 3× Interval.
	DegradedAfterCycleAge time.Duration
	// NotReadyAfterCycleAge marks the supervisor NOT READY when no
	// cycle has succeeded within this window. Default: 10× Interval.
	NotReadyAfterCycleAge time.Duration
	// MaxConsecutiveFailures marks the supervisor NOT READY after this
	// many consecutive failed cycles. Zero disables the rule.
	MaxConsecutiveFailures int64
	// MaxUnknownAge marks the supervisor DEGRADED when the oldest
	// pending UNKNOWN record is older than this. Zero disables the rule.
	MaxUnknownAge time.Duration
}

// HealthState is the readiness verdict.
type HealthState string

const (
	HealthReady    HealthState = "READY"
	HealthDegraded HealthState = "DEGRADED"
	HealthNotReady HealthState = "NOT_READY"
)

// Health is the supervisor's readiness snapshot.
type Health struct {
	State HealthState
	// Reasons lists every policy rule currently violated.
	Reasons []string

	ReconcilerRunning   bool
	ReconcilerStopped   bool
	LastCycleStarted    time.Time
	LastCycleCompleted  time.Time
	LastSuccess         time.Time
	ConsecutiveFailures int64
	LastError           string

	// Backlog observability: pending UNKNOWN records and the age of
	// the oldest of them.
	UnknownPending   int64
	UnknownOldestAge time.Duration

	// Worker counters.
	CyclesStarted    int64
	CyclesCompleted  int64
	CyclesFailed     int64
	ResolverFailures int64
	DeadLetters      int64
}

// NewSupervisor creates a supervisor for the given worker.
func NewSupervisor(worker *Worker, store idempotency.EffectStore, config SupervisorConfig) *Supervisor {
	if config.Interval <= 0 {
		config.Interval = 30 * time.Second
	}
	if config.DegradedAfterCycleAge <= 0 {
		config.DegradedAfterCycleAge = 3 * config.Interval
	}
	if config.NotReadyAfterCycleAge <= 0 {
		config.NotReadyAfterCycleAge = 10 * config.Interval
	}
	return &Supervisor{worker: worker, store: store, config: config, state: string(HealthNotReady)}
}

// Run drives the reconciliation loop until the context is cancelled,
// observing every cycle. The supervisor never panics out of the loop:
// a failed cycle is counted and the loop continues, because
// reconciliation being unhealthy must not take the execution service
// down — but it must be visible.
func (s *Supervisor) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.stopped = true
		s.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.runCycle(ctx)
		}
	}
}

func (s *Supervisor) runCycle(ctx context.Context) {
	started := time.Now()
	s.mu.Lock()
	s.lastCycleStarted = started
	s.mu.Unlock()

	err := s.worker.RunCycle(ctx)

	completed := time.Now()
	s.mu.Lock()
	s.lastCycleCompleted = completed
	consecutive := int64(0)
	if err != nil {
		s.consecutiveFailures++
		s.lastError = err.Error()
	} else {
		s.consecutiveFailures = 0
		s.lastSuccess = completed
		s.lastError = ""
	}
	consecutive = s.consecutiveFailures
	s.mu.Unlock()

	if err != nil {
		log.Printf("reconciliation cycle failed (%d consecutive): %v", consecutive, err)
	}

	// Log readiness transitions so an operator sees the subsystem's
	// health change without polling.
	health := s.Health(ctx)
	s.mu.Lock()
	previous := s.state
	s.state = string(health.State)
	s.mu.Unlock()
	if previous != string(health.State) {
		log.Printf("reconciliation readiness: %s -> %s%s", previous, health.State, reasonSuffix(health.Reasons))
	}
	s.writeStatus(health)
}

// SetStatusWriter configures the readiness surface: the supervisor hands
// its health snapshot to the writer on every cycle, so an orchestrator
// (systemd, Kubernetes, a watchdog) can observe reconciliation health
// without reading logs — the degraded state escapes the object graph.
//
// The writer is called synchronously and must be fast; it must never
// panic, and it owns its own error handling (a missing observability
// surface must not take the execution service down).
func (s *Supervisor) SetStatusWriter(write func(Health)) {
	s.mu.Lock()
	s.statusWriter = write
	s.mu.Unlock()
}

// writeStatus publishes the current health snapshot to the configured
// readiness surface, if any.
func (s *Supervisor) writeStatus(health Health) {
	s.mu.Lock()
	write := s.statusWriter
	s.mu.Unlock()
	if write == nil {
		return
	}
	write(health)
}

func reasonSuffix(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return fmt.Sprintf(" (%v)", reasons)
}

// Health evaluates the readiness policy against the supervisor's
// observed state and the store's reconciliation backlog.
func (s *Supervisor) Health(ctx context.Context) Health {
	s.mu.Lock()
	health := Health{
		ReconcilerRunning:   s.running && !s.stopped,
		ReconcilerStopped:   s.stopped,
		LastCycleStarted:    s.lastCycleStarted,
		LastCycleCompleted:  s.lastCycleCompleted,
		LastSuccess:         s.lastSuccess,
		ConsecutiveFailures: s.consecutiveFailures,
		LastError:           s.lastError,
	}
	s.mu.Unlock()

	metrics := s.worker.Metrics()
	health.CyclesStarted = metrics.CyclesStarted
	health.CyclesCompleted = metrics.CyclesCompleted
	health.CyclesFailed = metrics.CyclesFailed
	health.ResolverFailures = metrics.ResolverFailures
	health.DeadLetters = metrics.DeadLetters

	now := time.Now()
	var degraded, notReady []string

	// A reconciler that is not running is never ready — unless cycles
	// have been observed without the loop (a supervisor driven
	// directly, e.g. by tests or a maintenance command): the readiness
	// rules below then apply on their own.
	switch {
	case health.ReconcilerStopped:
		notReady = append(notReady, "reconciler stopped")
	case !health.ReconcilerRunning && health.LastCycleStarted.IsZero():
		notReady = append(notReady, "reconciler not started")
	}

	if !health.LastSuccess.IsZero() {
		age := now.Sub(health.LastSuccess)
		if age > s.config.NotReadyAfterCycleAge {
			notReady = append(notReady, fmt.Sprintf("no successful cycle for %s (limit %s)", age.Round(time.Second), s.config.NotReadyAfterCycleAge))
		} else if age > s.config.DegradedAfterCycleAge {
			degraded = append(degraded, fmt.Sprintf("no successful cycle for %s (limit %s)", age.Round(time.Second), s.config.DegradedAfterCycleAge))
		}
	}
	if s.config.MaxConsecutiveFailures > 0 && health.ConsecutiveFailures >= s.config.MaxConsecutiveFailures {
		notReady = append(notReady, fmt.Sprintf("%d consecutive failed cycles", health.ConsecutiveFailures))
	}

	// Backlog observability is best-effort: a store read failure is a
	// degraded signal, not a reason to guess.
	if s.store != nil {
		pending, oldest, err := s.store.ReconciliationBacklog(ctx)
		if err != nil {
			degraded = append(degraded, fmt.Sprintf("reconciliation backlog unreadable: %v", err))
		} else {
			health.UnknownPending = pending
			if oldest != nil {
				health.UnknownOldestAge = now.Sub(*oldest)
				if s.config.MaxUnknownAge > 0 && health.UnknownOldestAge > s.config.MaxUnknownAge {
					degraded = append(degraded, fmt.Sprintf("oldest UNKNOWN is %s old (limit %s)", health.UnknownOldestAge.Round(time.Second), s.config.MaxUnknownAge))
				}
			}
		}
	}

	switch {
	case len(notReady) > 0:
		health.State = HealthNotReady
		health.Reasons = notReady
	case len(degraded) > 0:
		health.State = HealthDegraded
		health.Reasons = degraded
	default:
		health.State = HealthReady
	}
	return health
}
