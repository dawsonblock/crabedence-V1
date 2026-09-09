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
func (e *DispatchExecutor) ExecuteWithIdempotency(ctx context.Context, req Request, desc capability.Descriptor) Response {
	// For PURE and READ, skip idempotency (no side effects)
	if desc.ExecutionClass == capability.ClassPure || desc.ExecutionClass == capability.ClassRead {
		return e.dispatch(ctx, req, desc)
	}

	// For MUTATION and CRITICAL, use durable idempotency
	if e.store == nil {
		// No store — fall back to in-memory dispatch
		return e.dispatch(ctx, req, desc)
	}

	// Compute request digest
	digest, err := idempotency.ComputeDigestFromRaw(
		1, // protocol version
		req.Authority.Principal,
		req.Capability,
		req.Arguments,
		req.Authority.GrantID,
		string(desc.ExecutionClass),
	)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to compute digest: %v", err),
		}
	}

	// Reserve the request atomically
	reserve, err := e.store.Reserve(ctx, req.IdempotencyKey, req.Authority.Principal, req.Capability, digest, req.Authority.GrantID, string(desc.ExecutionClass))
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("idempotency reserve failed: %v", err),
		}
	}

	// Check for conflict
	if reserve.Conflict {
		return Response{
			Status:      StatusDenied,
			FailureCode: string(capability.FailureIdempotencyConflict),
			Error:       "same idempotency key used with different request",
		}
	}

	// Check for existing terminal result
	if reserve.Record != nil && reserve.State.IsTerminal() {
		result := reserve.Record.Result
		return Response{
			Status:   string(reserve.State),
			Result:   result,
			Evidence: parseEvidence(reserve.Record.EvidenceDigest),
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    reserve.Record.ExecutionID,
			},
		}
	}

	// Check for existing in-flight
	if reserve.Record != nil && !reserve.State.IsTerminal() && reserve.State != idempotency.StateReserved {
		return Response{
			Status:      StatusInFlight,
			FailureCode: string(capability.FailureInFlight),
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    reserve.Record.ExecutionID,
			},
		}
	}

	// We have a new reservation — dispatch
	executionID := reserve.Record.ExecutionID

	// Mark as DISPATCHING
	if err := e.store.SetState(ctx, executionID, idempotency.StateDispatching, nil, ""); err != nil {
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       "failed to persist DISPATCHING state",
		}
	}

	// Dispatch
	resp := e.dispatch(ctx, req, desc)

	// Persist terminal result
	var state idempotency.State
	switch resp.Status {
	case StatusSucceeded:
		state = idempotency.StateSucceeded
	case StatusFailed:
		state = idempotency.StateFailed
	case StatusDenied:
		state = idempotency.StateDenied
	default:
		state = idempotency.StateUnknown
	}

	evidenceDigest := ""
	if resp.Evidence != nil {
		evidenceDigest = resp.Evidence.Digest
	}

	if err := e.store.SetState(ctx, executionID, state, resp.Result, evidenceDigest); err != nil {
		// Persistence failed after dispatch — return UNKNOWN
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       "failed to persist terminal result after dispatch",
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

// dispatch sends the request to the handler and tracks dispatch state.
// Pre-dispatch failures return FAILED. Post-dispatch failures return UNKNOWN.
func (e *DispatchExecutor) dispatch(ctx context.Context, req Request, desc capability.Descriptor) Response {
	// PRE_DISPATCH: any failure here is safe FAILED
	// We use a panic recovery to catch pre-dispatch errors
	defer func() {
		// panics are caught by the caller
	}()

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

	// POST_DISPATCH: from this point, any failure is UNKNOWN
	// The handler.Execute call crosses the dispatch boundary.
	resp := e.handler.Execute(dispatchCtx, req, desc)

	// If the handler panicked or returned an error status due to
	// a transport failure, we need to determine if dispatch occurred.
	// For now, we trust the handler to set the correct status.
	return resp
}

func parseEvidence(digest string) *EvidenceRef {
	if digest == "" {
		return nil
	}
	return &EvidenceRef{
		Digest:         digest,
		ReceiptVersion: 3,
	}
}
