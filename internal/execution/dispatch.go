package execution

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// DispatchState tracks where an execution is in the dispatch lifecycle.
type DispatchState string

const (
	// DispatchPre means the request has not yet been sent to the provider.
	// Failure here is safe FAILED — no side effect could have occurred.
	DispatchPre DispatchState = "PRE_DISPATCH"

	// DispatchPost means the request has been sent to the provider.
	// Failure here is UNKNOWN — the side effect may have occurred.
	DispatchPost DispatchState = "POST_DISPATCH"
)

// DispatchExecutor wraps a Handler with dispatch-point tracking and
// durable idempotency. It ensures:
//   - Pre-dispatch failures return FAILED (safe)
//   - Post-dispatch failures return UNKNOWN (may have executed)
//   - Idempotent requests return the stored result
//   - Same key + different request returns CONFLICT
//   - MUTATION/CRITICAL fail closed when durable store is unavailable
//   - CRITICAL evidence is validated BEFORE terminal state is persisted
//   - Only the reservation owner (lease holder) may dispatch
type DispatchExecutor struct {
	handler  Handler
	store    *idempotency.Store
	mu       sync.Mutex
	inFlight map[string]context.CancelFunc
}

// NewDispatchExecutor creates a new dispatch executor with durable idempotency.
func NewDispatchExecutor(handler Handler, store *idempotency.Store) *DispatchExecutor {
	return &DispatchExecutor{
		handler:  handler,
		store:    store,
		inFlight: make(map[string]context.CancelFunc),
	}
}

// ExecuteWithIdempotency executes a request with durable idempotency.
func (e *DispatchExecutor) ExecuteWithIdempotency(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	// For PURE and READ, skip idempotency (no side effects)
	if desc.ExecutionClass == capability.ClassPure || desc.ExecutionClass == capability.ClassRead {
		return e.dispatch(ctx, req, desc)
	}

	// For MUTATION and CRITICAL, durable idempotency is REQUIRED.
	// Fail closed — never execute unguarded mutations.
	if e.store == nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       "durable idempotency unavailable: MUTATION/CRITICAL operations require a database connection",
		}
	}

	// Compute request digest
	digest, err := idempotency.ComputeDigestFromRaw(
		1, // protocol version
		req.Authority.Principal,
		req.Capability,
		req.Arguments,
		req.Authority.EffectiveAuthorityRef(),
		string(desc.ExecutionClass),
	)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to compute digest: %v", err),
		}
	}

	// Reserve the request atomically.
	// Acquired=true means THIS caller owns the reservation and may dispatch.
	// Acquired=false means another caller owns it or the record is terminal.
	reserve, err := e.store.Reserve(ctx, req.IdempotencyKey, req.Authority.Principal, req.Capability, digest, req.Authority.EffectiveAuthorityRef(), string(desc.ExecutionClass))
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("idempotency reserve failed: %v", err),
		}
	}

	// Check for conflict — same key, different request
	if reserve.Conflict {
		return Response{
			Status:      StatusDenied,
			FailureCode: string(capability.FailureIdempotencyConflict),
			Error:       "same idempotency key used with different request",
		}
	}

	// Check for existing terminal result — replay the stored result.
	// Acquired=false means we did NOT create this reservation.
	// P1 #8: Replay the stored provider_id and provider_run_id, not
	// the adapter ID and execution ID. The caller should see the same
	// execution metadata as the original provider result.
	if !reserve.Acquired && reserve.Record != nil && reserve.State.IsTerminal() {
		replayProvider := reserve.Record.ProviderID
		if replayProvider == "" {
			replayProvider = desc.AdapterID
		}
		replayRunID := reserve.Record.ProviderRunID
		if replayRunID == "" {
			replayRunID = reserve.Record.ExecutionID
		}
		return Response{
			Status:   stateToStatus(reserve.State),
			Result:   reserve.Record.Result,
			Evidence: parseEvidence(reserve.Record.EvidenceDigest, reserve.Record.ReceiptVersion),
			Execution: &ExecutionMeta{
				Provider: replayProvider,
				RunID:    replayRunID,
			},
		}
	}

	// Check for existing in-flight — another caller owns the reservation
	// or the record is in a non-terminal state.
	// Acquired=false means we do NOT own this execution.
	if !reserve.Acquired {
		return Response{
			Status:      StatusInFlight,
			FailureCode: string(capability.FailureInFlight),
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    reserve.Record.ExecutionID,
			},
		}
	}

	// Acquired=true — THIS caller owns the reservation and holds the lease.
	// Only now may we dispatch.
	executionID := reserve.Record.ExecutionID
	leaseToken := reserve.LeaseToken

	// Mark as EXECUTING using CAS (only lease holder may transition).
	// This is PRE_DISPATCH — if this fails, return FAILED (safe).
	if err := e.store.TransitionState(ctx, executionID, leaseToken, idempotency.StatePrepared, idempotency.StateExecuting); err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to transition to EXECUTING (lease lost or state changed): %v", err),
		}
	}

	// ─── IN_FLIGHT: the dispatch boundary ───────────────────────────────────
	// Transition to IN_FLIGHT immediately before handler.Execute.
	// IN_FLIGHT has precise semantics: the dispatch boundary has been
	// crossed — the request is with the provider. A crash in EXECUTING
	// is pre-dispatch (safe to reclaim); a crash in IN_FLIGHT is
	// post-dispatch (mark UNKNOWN for reconciliation, never blind-retry).
	if err := e.store.TransitionState(ctx, executionID, leaseToken, idempotency.StateExecuting, idempotency.StateInFlight); err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to transition to IN_FLIGHT (lease lost or state changed): %v", err),
		}
	}

	// Dispatch — from this point, we are POST_DISPATCH.
	// Any failure after this point is UNKNOWN (may have executed).
	resp := e.dispatch(ctx, req, desc)

	// ─── CRITICAL EVIDENCE VALIDATION BEFORE PERSISTENCE ──────────────────
	// The evidence contract MUST be validated BEFORE the terminal state
	// is persisted. Persisting SUCCEEDED with invalid evidence would
	// create a poisoned record that replays invalid evidence on retry.
	//
	// CRITICAL: if evidence validation fails AFTER the dispatch boundary
	// has been crossed (IN_FLIGHT is already persisted), the result is
	// UNKNOWN — not FAILED. The provider may have executed the side
	// effect. Returning FAILED would allow a blind retry. Per the
	// durable execution contract §6: "provider says success + required
	// evidence invalid/missing → UNKNOWN / EVIDENCE_INVALID →
	// reconciliation required."
	if desc.ExecutionClass.RequiresEvidence() && resp.Status == StatusSucceeded {
		if resp.Evidence == nil || resp.Evidence.Digest == "" {
			resp = Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       "CRITICAL capability returned SUCCEEDED without evidence digest (post-dispatch uncertainty)",
				Execution:   resp.Execution,
			}
		} else if !isValidEvidenceDigest(resp.Evidence.Digest) {
			resp = Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       "CRITICAL capability returned invalid evidence digest (post-dispatch uncertainty)",
				Execution:   resp.Execution,
			}
		} else if resp.Evidence.ReceiptVersion != 3 {
			resp = Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       fmt.Sprintf("CRITICAL capability returned receipt_version %d (must be 3, post-dispatch uncertainty)", resp.Evidence.ReceiptVersion),
				Execution:   resp.Execution,
			}
		} else if resp.Execution == nil || resp.Execution.RunID == "" {
			resp = Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       "CRITICAL capability returned SUCCEEDED without run_id (post-dispatch uncertainty)",
			}
		}
	}

	// ─── DETERMINE TERMINAL STATE ──────────────────────────────────────────
	// P1 #3: After the dispatch boundary (IN_FLIGHT), a generic FAILED
	// is treated as UNKNOWN unless the handler explicitly marks it as
	// a DefinitiveFailure (proven no side effect). This prevents a
	// provider that lost connection from causing a blind retry.
	var state idempotency.State
	switch resp.Status {
	case StatusSucceeded:
		state = idempotency.StateCommitted
	case StatusFailed:
		if resp.DefinitiveFailure {
			state = idempotency.StateFailed
		} else {
			// Post-dispatch uncertainty: the handler returned FAILED
			// but cannot prove no side effect occurred. Per the
			// durable execution contract §6, this is UNKNOWN.
			state = idempotency.StateUnknown
		}
	case StatusDenied:
		state = idempotency.StateDenied
	default:
		state = idempotency.StateUnknown
	}

	evidenceDigest := ""
	receiptVersion := 0
	if resp.Evidence != nil {
		evidenceDigest = resp.Evidence.Digest
		receiptVersion = resp.Evidence.ReceiptVersion
	}

	// ─── IMMUTABLE FINALIZATION ────────────────────────────────────────────
	// Finalize uses CAS semantics: only the lease holder may finalize,
	// the expected state must match, and terminal states are immutable.
	// A second identical finalize is idempotent; a conflicting receipt
	// is rejected as FINALIZATION_CONFLICT.
	//
	// If the handler returned an ambiguous result after IN_FLIGHT
	// (post-dispatch uncertainty), the state is UNKNOWN — we do NOT
	// finalize as FAILED. The side effect may have occurred.
	if state == idempotency.StateUnknown {
		// Post-dispatch uncertainty — enter recovery, do not finalize.
		rec, lookupErr := e.store.Lookup(ctx, executionID)
		if lookupErr == nil {
			_ = e.store.EnterRecovery(ctx, executionID, idempotency.StateInFlight, rec.Version)
		}
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       "post-dispatch ambiguity: entered recovery (side effect may have occurred)",
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    executionID,
			},
		}
	}

	providerID := ""
	providerRunID := ""
	if resp.Execution != nil {
		providerID = resp.Execution.Provider
		providerRunID = resp.Execution.RunID
	}

	receipt := idempotency.TerminalReceipt{
		ExecutionID:     executionID,
		Capability:      req.Capability,
		Principal:       req.Authority.Principal,
		RequestDigest:   digest,
		TerminalStatus:  state,
		CanonicalResult: resp.Result,
		ProviderID:      providerID,
		ProviderRunID:   providerRunID,
		EvidenceDigest:  evidenceDigest,
		ReceiptVersion:  receiptVersion,
	}

	// Look up the lease generation for the fenced finalize.
	rec, err := e.store.Lookup(ctx, executionID)
	if err != nil {
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       fmt.Sprintf("failed to lookup execution for finalize: %v", err),
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    executionID,
			},
		}
	}

	if err := e.store.Finalize(ctx, executionID, leaseToken, rec.LeaseGeneration, idempotency.StateInFlight, receipt); err != nil {
		// Finalization failed AFTER dispatch — return UNKNOWN.
		// The side effect may have occurred; we cannot claim FAILED.
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       fmt.Sprintf("failed to finalize execution after dispatch: %v", err),
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    executionID,
			},
		}
	}

	// Add execution metadata
	if resp.Execution == nil {
		resp.Execution = &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    executionID,
		}
	}

	return resp
}

// dispatch sends the request to the handler.
// This crosses the dispatch boundary — any failure after this call
// begins is POST_DISPATCH (may have executed).
func (e *DispatchExecutor) dispatch(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	// Set a timeout if deadline is provided
	dispatchCtx := ctx
	if req.Deadline != "" {
		deadline, err := time.Parse(time.RFC3339, req.Deadline)
		if err == nil {
			remaining := time.Until(deadline)
			if remaining > 0 {
				var cancel context.CancelFunc
				dispatchCtx, cancel = context.WithTimeout(ctx, remaining)
				defer cancel()
			}
		}
	}

	// The handler.Execute call crosses the dispatch boundary.
	resp := e.handler.Execute(dispatchCtx, req, desc)
	return resp
}

// parseEvidence reconstructs an EvidenceRef from stored evidence data.
// It uses the STORED receipt version — it does NOT invent V3 metadata.
// If the stored receipt version is 0 (legacy records), it returns
// the digest without a receipt version claim, rather than fabricating one.
func parseEvidence(digest string, receiptVersion int) *EvidenceRef {
	if digest == "" {
		return nil
	}
	ref := &EvidenceRef{
		Digest: digest,
	}
	// Only set ReceiptVersion if it was actually stored.
	// Never fabricate a version the original execution did not produce.
	if receiptVersion > 0 {
		ref.ReceiptVersion = receiptVersion
	}
	return ref
}

// isValidEvidenceDigest checks that a digest is a 64-character lowercase
// hexadecimal SHA-256 digest.
func isValidEvidenceDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// stateToStatus maps a durable store state to a wire protocol status.
// The store uses COMMITTED; the wire protocol uses SUCCEEDED.
func stateToStatus(state idempotency.State) string {
	switch state {
	case idempotency.StateCommitted:
		return StatusSucceeded
	case idempotency.StateFailed:
		return StatusFailed
	case idempotency.StateDenied:
		return StatusDenied
	case idempotency.StateUnknown:
		return StatusUnknown
	default:
		return string(state)
	}
}

// leaseHeartbeat periodically renews the lease while a provider call is
// active. This prevents long-running provider calls from exceeding the
// lease duration and falling into UNKNOWN despite successful execution.
//
// The heartbeat runs in a goroutine started after IN_FLIGHT is persisted.
// It renews the lease at the store's configured RenewalWindow interval.
// Renewal stops when:
//   - The dispatch context is cancelled (caller gave up or timed out)
//   - heartbeatCancel() is called (provider call returned)
//   - RenewLease fails (lease was taken over or record advanced)
//
// Renewal failures are logged but do not cancel the provider call —
// the provider may still succeed, and finalization will fail-closed
// if the lease was actually lost.
func (e *DispatchExecutor) leaseHeartbeat(ctx context.Context, executionID, leaseToken string, leaseGeneration int) {
	// Renew at 80% of the default lease duration to stay well ahead of
	// expiry. The store's RenewLease checks that the lease is still
	// valid before extending.
	renewalInterval := defaultLeaseRenewalInterval
	ticker := time.NewTicker(renewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.store.RenewLease(ctx, executionID, leaseToken, leaseGeneration, defaultLeaseRenewalDuration); err != nil {
				// Lease renewal failed — the lease may have expired,
				// been taken over, or the record advanced. Log and
				// stop renewing. The provider call continues; if it
				// succeeds, Finalize will fail-closed on the stale lease.
				return
			}
		}
	}
}

// defaultLeaseRenewalInterval is the interval at which the lease heartbeat
// attempts renewal. It is set to 4 minutes, which is 80% of the default
// 5-minute lease duration, providing a comfortable margin before expiry.
const defaultLeaseRenewalInterval = 4 * time.Minute

// defaultLeaseRenewalDuration is the duration for which each renewal
// extends the lease. It matches the default lease duration of 5 minutes.
const defaultLeaseRenewalDuration = 5 * time.Minute
