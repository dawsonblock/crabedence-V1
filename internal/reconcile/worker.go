// Package reconcile provides reconciliation for UNKNOWN execution states
// and recovery of crashed executions with expired leases.
//
// UNKNOWN means the provider may have executed but the terminal outcome
// cannot be established. This package provides the infrastructure to
// query the provider and resolve UNKNOWN to a definitive state.
//
// Lease expiry means the previous execution holder crashed or stalled.
// Expired-lease records in PREPARED/EXECUTING states need recovery —
// either re-dispatch (if safe) or reconciliation (if the dispatch
// boundary was crossed).
package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// Resolver queries a provider to determine if an operation actually happened.
// This is the legacy interface. New code should use RecoveryResolver.
type Resolver interface {
	// Resolve queries the provider for the terminal state of an execution.
	// Returns CONFIRMED_SUCCEEDED, CONFIRMED_FAILED, or still UNKNOWN.
	Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.State, error)
}

// Worker runs reconciliation for UNKNOWN execution records and recovery
// of crashed executions with expired leases.
type Worker struct {
	store    *idempotency.Store
	resolver Resolver
	interval time.Duration
}

// NewWorker creates a reconciliation worker.
func NewWorker(store *idempotency.Store, resolver Resolver, interval time.Duration) *Worker {
	return &Worker{
		store:    store,
		resolver: resolver,
		interval: interval,
	}
}

// Run starts the reconciliation loop. It runs until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.reconcileAll(ctx); err != nil {
				// Log but continue
				fmt.Printf("reconciliation error: %v\n", err)
			}
		}
	}
}

// reconcileAll finds all records needing attention and attempts recovery.
func (w *Worker) reconcileAll(ctx context.Context) error {
	// Category 1: UNKNOWN records needing provider resolution.
	unknown, err := w.store.ListUnknown(ctx)
	if err != nil {
		return fmt.Errorf("failed to list unknown records: %w", err)
	}
	for _, rec := range unknown {
		if err := w.reconcileOne(ctx, rec); err != nil {
			fmt.Printf("reconciliation failed for %s: %v\n", rec.ExecutionID, err)
		}
	}

	// Category 2: crashed executions with expired leases.
	expired, err := w.store.ListExpiredLeases(ctx)
	if err != nil {
		return fmt.Errorf("failed to list expired leases: %w", err)
	}
	for _, rec := range expired {
		if err := w.recoverCrashed(ctx, rec); err != nil {
			fmt.Printf("crash recovery failed for %s: %v\n", rec.ExecutionID, err)
		}
	}

	return nil
}

// recoverCrashed handles a crashed execution with an expired lease.
//
// The key distinction is the dispatch boundary:
//   - PREPARED (pre-dispatch): no side effect could have occurred.
//     The lease is already reclaimable by the next Acquire() call.
//     No action needed here.
//   - EXECUTING (pre-dispatch): dispatch boundary not crossed.
//     Same as PREPARED — reclaimable.
//   - IN_FLIGHT (post-dispatch): the side effect MAY have occurred.
//     Mark as UNKNOWN for reconciliation. Never blind-retry.
func (w *Worker) recoverCrashed(ctx context.Context, rec *idempotency.Record) error {
	switch rec.State {
	case idempotency.StatePrepared, idempotency.StateExecuting:
		// Pre-dispatch crash — no side effect occurred.
		// The expired lease is automatically reclaimable by the next
		// Acquire() call. Log for observability but take no action.
		fmt.Printf("crash recovery: execution %s crashed in %s (pre-dispatch, safe to reclaim)\n", rec.ExecutionID, rec.State)
		return nil

	case idempotency.StateInFlight:
		// Post-dispatch crash — the side effect MAY have occurred.
		// Mark as UNKNOWN so the reconciliation resolver can determine
		// the actual outcome. Never blind-retry a post-dispatch crash.
		if err := w.store.EnterRecovery(ctx, rec.ExecutionID, idempotency.StateInFlight, rec.Version); err != nil {
			return fmt.Errorf("failed to mark crashed execution as UNKNOWN: %w", err)
		}
		fmt.Printf("crash recovery: execution %s crashed in IN_FLIGHT (post-dispatch, marked UNKNOWN for reconciliation)\n", rec.ExecutionID)
		return nil

	default:
		// Unexpected state for a lease-expired record — log.
		fmt.Printf("crash recovery: execution %s in unexpected state %s with expired lease\n", rec.ExecutionID, rec.State)
		return nil
	}
}

// reconcileOne attempts to reconcile a single UNKNOWN record.
// Uses CAS with expected state=UNKNOWN to prevent overwriting a
// state that changed after it was read.
func (w *Worker) reconcileOne(ctx context.Context, rec *idempotency.Record) error {
	// Query the resolver for the actual outcome.
	state, err := w.resolver.Resolve(ctx, rec)
	if err != nil {
		return fmt.Errorf("resolver error: %w", err)
	}

	// Map the resolved state to a recovery decision.
	var decision idempotency.RecoveryDecision
	switch state {
	case idempotency.StateCommitted:
		decision = idempotency.RecoveryCommitted
	case idempotency.StateFailed:
		decision = idempotency.RecoveryFailed
	case idempotency.StateUnknown:
		// Still unknown — no state change.
		return nil
	default:
		return fmt.Errorf("resolver returned unexpected state: %s", state)
	}

	// Resolve with CAS — expected state is UNKNOWN, expected version is rec.Version.
	result := idempotency.RecoveryResult{
		Decision: decision,
	}
	if err := w.store.ResolveRecovery(ctx, rec.ExecutionID, rec.Version, decision, result); err != nil {
		return fmt.Errorf("failed to resolve recovery: %w", err)
	}

	return nil
}

// NoopResolver is a resolver that always returns UNKNOWN.
// It is used when no provider-specific resolver is available.
// It must not cause retries or terminal rewrites.
type NoopResolver struct{}

// Resolve always returns UNKNOWN (no reconciliation possible).
func (NoopResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.State, error) {
	return idempotency.StateUnknown, nil
}
