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
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// Worker runs reconciliation for UNKNOWN execution records and recovery
// of crashed executions with expired leases.
//
// The worker uses idempotency.RecoveryResolver, which returns a full
// RecoveryResult (decision, result, evidence, provider identity). This
// is propagated directly to ResolveRecovery, which requires evidence
// for definitive conclusions.
//
// Work distribution: UNKNOWN records are claimed via ClaimUnknownBatch
// (FOR UPDATE SKIP LOCKED), so multiple concurrent workers do not
// process the same records. Failed or unresolved claims are released
// with exponential backoff via ReleaseReconcileClaim.
type Worker struct {
	store         *idempotency.Store
	resolvers     map[string]idempotency.RecoveryResolver // keyed by capability_id
	default_      idempotency.RecoveryResolver
	interval      time.Duration
	workerID      string
	batchSize     int
	claimDuration time.Duration
	// locatorRetention bounds how long a recovery_locator is retained
	// on an UNKNOWN record. Locators may carry operation-identifying
	// data; records unresolved past the retention window are scrubbed.
	locatorRetention time.Duration
	// signer attests definitive CRITICAL recovery decisions. Without
	// it, the worker cannot produce the signed evidence receipt the
	// store requires for CRITICAL — such records stay UNKNOWN.
	signer *evidence.Signer
}

// NewWorker creates a reconciliation worker with a default resolver.
// The default resolver is used when no capability-specific resolver
// is registered.
func NewWorker(store *idempotency.Store, defaultResolver idempotency.RecoveryResolver, interval time.Duration) *Worker {
	return &Worker{
		store:            store,
		resolvers:        make(map[string]idempotency.RecoveryResolver),
		default_:         defaultResolver,
		interval:         interval,
		workerID:         fmt.Sprintf("reconcile-%d", os.Getpid()),
		batchSize:        100,
		claimDuration:    5 * time.Minute,
		locatorRetention: 7 * 24 * time.Hour,
	}
}

// SetWorkerID overrides the default worker identity (pid-based).
// Useful for testing or when a stable identity is needed.
func (w *Worker) SetWorkerID(id string) { w.workerID = id }

// SetBatchSize overrides the default batch size (100).
func (w *Worker) SetBatchSize(n int) { w.batchSize = n }

// SetClaimDuration overrides the default claim duration (5 min).
func (w *Worker) SetClaimDuration(d time.Duration) { w.claimDuration = d }

// SetLocatorRetention overrides the default recovery-locator retention
// (7 days). UNKNOWN records older than the retention have their
// recovery_locator scrubbed — they stay UNKNOWN but stop retaining
// potentially sensitive locator data.
func (w *Worker) SetLocatorRetention(d time.Duration) { w.locatorRetention = d }

// SetEvidenceSigner configures the Ed25519 receipt signer used to
// attest definitive CRITICAL recovery decisions. The signer must be a
// trusted evidence signer on the store (SetTrustedEvidenceSigners) or
// the store will reject the receipts it produces.
func (w *Worker) SetEvidenceSigner(s *evidence.Signer) { w.signer = s }

// RegisterResolver registers a capability-specific recovery resolver.
// When a UNKNOWN record's capability_id matches, this resolver is used
// instead of the default.
func (w *Worker) RegisterResolver(capabilityID string, resolver idempotency.RecoveryResolver) {
	w.resolvers[capabilityID] = resolver
}

// resolve selects the appropriate resolver for a record.
func (w *Worker) resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	if r, ok := w.resolvers[rec.CapabilityID]; ok {
		return r.Resolve(ctx, rec)
	}
	if w.default_ != nil {
		return w.default_.Resolve(ctx, rec)
	}
	// No resolver registered — return UNKNOWN (fail-closed).
	return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
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

// reconcileAll claims a batch of UNKNOWN records and attempts recovery.
// ClaimUnknownBatch uses FOR UPDATE SKIP LOCKED so that multiple
// concurrent workers do not process the same records.
func (w *Worker) reconcileAll(ctx context.Context) error {
	// Category 1: UNKNOWN records needing provider resolution.
	claimed, err := w.store.ClaimUnknownBatch(ctx, w.workerID, w.batchSize, w.claimDuration)
	if err != nil {
		return fmt.Errorf("failed to claim unknown records: %w", err)
	}
	for _, rec := range claimed {
		if err := w.reconcileOne(ctx, rec); err != nil {
			fmt.Printf("reconciliation failed for %s: %v\n", rec.ExecutionID, err)
		}
	}

	// Category 2: crashed executions with expired leases.
	// Uses ClaimExpiredBatch (FOR UPDATE SKIP LOCKED) so multiple
	// concurrent workers do not process the same expired records.
	expired, err := w.store.ClaimExpiredBatch(ctx, w.workerID, w.batchSize, w.claimDuration)
	if err != nil {
		return fmt.Errorf("failed to claim expired leases: %w", err)
	}
	for _, rec := range expired {
		if err := w.recoverCrashed(ctx, rec); err != nil {
			fmt.Printf("crash recovery failed for %s: %v\n", rec.ExecutionID, err)
		}
	}

	// Category 3: retention — scrub recovery locators on UNKNOWN
	// records older than the retention window. Locators may carry
	// operation-identifying data that should not live forever.
	if w.locatorRetention > 0 {
		if n, err := w.store.ScrubStaleRecoveryLocators(ctx, w.locatorRetention); err != nil {
			fmt.Printf("recovery locator scrub failed: %v\n", err)
		} else if n > 0 {
			fmt.Printf("scrubbed recovery locators on %d stale UNKNOWN record(s)\n", n)
		}
	}

	return nil
}

// RecoverCrashedForTest exposes recoverCrashed for cross-package
// integration tests (e.g. provider fault-injection suites that must
// drive the crash-recovery path directly).
func (w *Worker) RecoverCrashedForTest(ctx context.Context, rec *idempotency.Record) error {
	return w.recoverCrashed(ctx, rec)
}

// ReconcileOneForTest exposes reconcileOne for cross-package
// integration tests.
func (w *Worker) ReconcileOneForTest(ctx context.Context, rec *idempotency.Record) error {
	return w.reconcileOne(ctx, rec)
}

// recoverCrashed handles a crashed execution with an expired lease.
// The record was claimed via ClaimExpiredBatch — the reconcile_owner
// claim must be released after processing.
//
// The key distinction is the dispatch boundary:
//   - PREPARED (pre-dispatch): no side effect could have occurred.
//     The lease is already reclaimable by the next Acquire() call.
//     Release the reconcile claim — no action needed.
//   - EXECUTING (pre-dispatch): dispatch boundary not crossed.
//     Same as PREPARED — reclaimable.
//   - IN_FLIGHT (post-dispatch): the side effect MAY have occurred.
//     Mark as UNKNOWN for reconciliation. Never blind-retry.
func (w *Worker) recoverCrashed(ctx context.Context, rec *idempotency.Record) error {
	defer func() {
		// Release the expired-lease claim so the record is not
		// permanently owned by this worker. For IN_FLIGHT → UNKNOWN,
		// EnterRecovery clears the reconcile claim fields itself. For
		// PREPARED/EXECUTING, a successful RecoverExpiredPreDispatch has
		// already cleared the claim (and bumped the version, so this
		// stale-version release harmlessly no-ops); on its failure this
		// still frees the claim.
		if rec.State != idempotency.StateInFlight {
			_ = w.store.ReleaseReconcileClaim(ctx, rec.ExecutionID, rec.Version, 0, "")
		}
	}()

	switch rec.State {
	case idempotency.StatePrepared, idempotency.StateExecuting:
		// Pre-dispatch crash — no side effect occurred. Normalize the
		// record once to a lease-less PREPARED: this clears the expired
		// lease and the reconcile claim in one CAS update, so the record
		// stops being eligible for expired-lease claiming (no per-cycle
		// claim/release churn) and the next Acquire() reacquires it
		// immediately via the lease-less PREPARED path.
		if err := w.store.RecoverExpiredPreDispatch(ctx, rec.ExecutionID, rec.Version); err != nil {
			return fmt.Errorf("failed to normalize expired pre-dispatch execution: %w", err)
		}
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
//
// The full RecoveryResult (including evidence, provider identity,
// and result) is propagated to ResolveRecovery. This is critical:
// ResolveRecovery rejects definitive recovery without proof, so
// the resolver MUST supply evidence for COMMITTED/FAILED decisions.
//
// On failure or continued UNKNOWN, the reconcile claim is released
// with exponential backoff so another worker (or this one later)
// can retry.
func (w *Worker) reconcileOne(ctx context.Context, rec *idempotency.Record) error {
	// Resolver deadline: bounded at 4 claim TTLs — long enough for a
	// legitimately slow resolver whose claim the heartbeat keeps
	// renewing, short enough that a wedged resolver cannot hold the
	// record forever. The deadline is deliberately NOT below one TTL:
	// the heartbeat exists precisely so resolution longer than one
	// claim window remains safe.
	resolveTimeout := w.claimDuration * 4
	if resolveTimeout <= 0 {
		resolveTimeout = 20 * time.Minute
	}
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)

	// Claim heartbeat — renew while the resolver runs. The heartbeat
	// has its own context: it must keep renewing across resolver
	// deadline boundaries so the claim outlives the initial TTL. If
	// renewal fails (claim lost or expired), cancel the resolver
	// context: committing with a lost claim would race another worker.
	hbCtx, hbCancel := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go w.claimHeartbeat(hbCtx, cancel, rec, heartbeatDone)
	// Wait for the heartbeat goroutine AFTER stopping it — the
	// heartbeat exits on hbCtx.Done(), so waiting first would deadlock.
	defer func() { hbCancel(); cancel(); <-heartbeatDone }()

	// Query the resolver for the actual outcome.
	result, err := w.resolve(rctx, rec)
	if err != nil {
		return w.releaseClaim(ctx, rec, fmt.Errorf("resolver error: %w", err))
	}

	// If still UNKNOWN, release the claim with backoff for later retry.
	if result.Decision == idempotency.RecoveryUnknown {
		return w.releaseClaim(ctx, rec, nil)
	}

	// The evidence digest is recomputed from the resolver's evidence
	// ARTIFACT bytes — a resolver-supplied digest is never signed.
	// This is the same boundary the dispatch path enforces: what the
	// trusted signer attests is a digest Crabedence itself computed.
	if len(result.EvidenceArtifact) > 0 {
		sum := sha256.Sum256(result.EvidenceArtifact)
		result.EvidenceDigest = fmt.Sprintf("%x", sum)
		if result.ReceiptVersion == 0 {
			result.ReceiptVersion = 3
		}
	}

	// CRITICAL decisions require a signed evidence receipt attested by
	// a trusted signer. The worker signs on behalf of the verifying
	// path — the receipt binds the resolver's verified outcome to this
	// execution, provider identity, and evidence digest. Without a
	// configured signer or a verifiable evidence artifact the decision
	// cannot be proven; keep the record UNKNOWN rather than silently
	// dropping the requirement.
	if rec.ExecutionClass == "CRITICAL" &&
		(result.Decision == idempotency.RecoveryCommitted || result.Decision == idempotency.RecoveryFailed) {
		if w.signer == nil {
			return w.releaseClaim(ctx, rec, fmt.Errorf("no evidence signer configured — cannot attest CRITICAL recovery"))
		}
		if len(result.EvidenceArtifact) == 0 {
			return w.releaseClaim(ctx, rec, fmt.Errorf("no evidence artifact supplied — cannot attest CRITICAL recovery"))
		}
		signed, signErr := w.signer.Sign(evidence.Binding{
			ExecutionID:    rec.ExecutionID,
			Capability:     rec.CapabilityID,
			Principal:      rec.PrincipalID,
			RequestDigest:  rec.RequestDigest,
			ProviderID:     result.ProviderID,
			ProviderRunID:  result.ProviderRunID,
			Outcome:        recoveryOutcome(result.Decision),
			EvidenceSHA256: result.EvidenceDigest,
		})
		if signErr != nil {
			return w.releaseClaim(ctx, rec, fmt.Errorf("failed to sign recovery evidence receipt: %w", signErr))
		}
		result.EvidenceReceipt = signed
	}

	// Resolve with CAS — expected state is UNKNOWN, expected version
	// is rec.Version. The full RecoveryResult is propagated so
	// ResolveRecovery can validate evidence and build a canonical
	// terminal receipt. On success, ResolveRecovery clears the
	// reconcile claim fields automatically.
	if err := w.store.ResolveRecovery(ctx, rec.ExecutionID, rec.Version, result); err != nil {
		return w.releaseClaim(ctx, rec, fmt.Errorf("failed to resolve recovery: %w", err))
	}

	return nil
}

// claimHeartbeat renews the reconciliation claim while a resolver runs.
// It stops when the context ends, the done channel closes after a
// terminal renewal failure (which also cancels the resolver context),
// or the parent signals completion.
func (w *Worker) claimHeartbeat(ctx context.Context, cancel context.CancelFunc, rec *idempotency.Record, done chan<- struct{}) {
	defer close(done)
	interval := w.claimDuration / 3
	if interval <= 0 {
		interval = time.Minute
	}
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.store.RenewReconcileClaim(ctx, rec.ExecutionID, rec.Version, w.claimDuration); err != nil {
				// Claim lost — the resolver's result can no longer be
				// committed under our claim. Cancel the resolver context.
				cancel()
				return
			}
		}
	}
}

// recoveryOutcome maps a definitive recovery decision to the semantic
// attestation vocabulary: RecoveryCommitted requires COMPLETED proof
// (the effect happened); RecoveryFailed requires NO_EFFECT proof (the
// effect provably did not happen).
func recoveryOutcome(d idempotency.RecoveryDecision) string {
	if d == idempotency.RecoveryCommitted {
		return evidence.OutcomeCompleted
	}
	return evidence.OutcomeNoEffect
}

// releaseClaim releases a reconcile claim back to the pool with
// exponential backoff. The record stays UNKNOWN but gets a
// next_reconcile_at timestamp so it is not immediately reclaimed.
// The backoff duration is passed to the store which computes
// next_reconcile_at using clock_timestamp() — DB-owned time.
func (w *Worker) releaseClaim(ctx context.Context, rec *idempotency.Record, resolveErr error) error {
	// reconcile_attempt is incremented by ClaimUnknownBatch before
	// the record is returned, so attempt=1 is the first retry.
	// Subtract 1 so the first retry gets base backoff (30s), not 1m.
	effectiveAttempt := rec.ReconcileAttempt - 1
	if effectiveAttempt < 0 {
		effectiveAttempt = 0
	}
	backoff := reconcileBackoff(effectiveAttempt)
	errMsg := ""
	if resolveErr != nil {
		errMsg = resolveErr.Error()
	}
	if err := w.store.ReleaseReconcileClaim(ctx, rec.ExecutionID, rec.Version, backoff, errMsg); err != nil {
		return fmt.Errorf("failed to release reconcile claim: %w (original: %v)", err, resolveErr)
	}
	return resolveErr
}

// reconcileBackoff computes exponential backoff for reconciliation
// retries: 30s, 1m, 2m, 4m, 8m, ..., capped at 30m.
// Uses saturating arithmetic — no integer-shift overflow.
func reconcileBackoff(attempt int) time.Duration {
	base := 30 * time.Second
	maxBackoff := 30 * time.Minute
	if attempt < 0 {
		attempt = 0
	}
	// Maximum useful shift: 30s * 2^6 = 32m > 30m cap.
	// Beyond attempt 6, always return maxBackoff.
	if attempt > 6 {
		return maxBackoff
	}
	d := base << uint(attempt)
	if d > maxBackoff || d <= 0 {
		d = maxBackoff
	}
	return d
}

// NoopResolver is a RecoveryResolver that always returns UNKNOWN.
// It is used when no provider-specific resolver is available.
// It must not cause retries or terminal rewrites.
type NoopResolver struct{}

// Resolve always returns UNKNOWN (no reconciliation possible).
func (NoopResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.RecoveryResult, error) {
	return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
}
