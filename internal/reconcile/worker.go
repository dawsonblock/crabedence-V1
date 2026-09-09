// Package reconcile provides reconciliation for UNKNOWN execution states.
//
// UNKNOWN means the provider may have executed but the terminal outcome
// cannot be established. This package provides the infrastructure to
// query the provider and resolve UNKNOWN to a definitive state.
package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// Resolver queries a provider to determine if an operation actually happened.
type Resolver interface {
	// Resolve queries the provider for the terminal state of an execution.
	// Returns CONFIRMED_SUCCEEDED, CONFIRMED_FAILED, or still UNKNOWN.
	Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.State, error)
}

// Worker runs reconciliation for UNKNOWN execution records.
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

// reconcileAll finds all UNKNOWN records and attempts reconciliation.
func (w *Worker) reconcileAll(ctx context.Context) error {
	records, err := w.store.ListUnknown(ctx)
	if err != nil {
		return fmt.Errorf("failed to list unknown records: %w", err)
	}

	for _, rec := range records {
		if err := w.reconcileOne(ctx, rec); err != nil {
			fmt.Printf("reconciliation failed for %s: %v\n", rec.ExecutionID, err)
		}
	}

	return nil
}

// reconcileOne attempts to reconcile a single UNKNOWN record.
func (w *Worker) reconcileOne(ctx context.Context, rec *idempotency.Record) error {
	// Mark as RECONCILIATION_REQUIRED
	if rec.State == idempotency.StateUnknown {
		if err := w.store.SetState(ctx, rec.ExecutionID, idempotency.StateReconciliationRequired, rec.Result, rec.EvidenceDigest); err != nil {
			return fmt.Errorf("failed to mark reconciliation: %w", err)
		}
	}

	// Query the resolver
	state, err := w.resolver.Resolve(ctx, rec)
	if err != nil {
		return fmt.Errorf("resolver error: %w", err)
	}

	// Update the record with the resolved state
	if state != idempotency.StateUnknown && state != idempotency.StateReconciliationRequired {
		if err := w.store.SetState(ctx, rec.ExecutionID, state, rec.Result, rec.EvidenceDigest); err != nil {
			return fmt.Errorf("failed to update state: %w", err)
		}
	}

	return nil
}

// NoopResolver is a resolver that always returns UNKNOWN.
// It is used when no provider-specific resolver is available.
type NoopResolver struct{}

// Resolve always returns UNKNOWN (no reconciliation possible).
func (NoopResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.State, error) {
	return idempotency.StateUnknown, nil
}
