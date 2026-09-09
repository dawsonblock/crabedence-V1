package execution

import (
	"context"

	"github.com/openclaw/crabbox/internal/capability"
)

// MultiHandler dispatches to different handlers based on the adapter ID
// in the capability descriptor.
type MultiHandler struct {
	handlers map[string]Handler
}

// NewMultiHandler creates a handler that dispatches based on adapter ID.
func NewMultiHandler(handlers map[string]Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Execute dispatches to the handler registered for the descriptor's adapter ID.
func (h *MultiHandler) Execute(ctx context.Context, req Request, desc capability.Descriptor) Response {
	handler, ok := h.handlers[desc.AdapterID]
	if !ok {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureCapabilityUnimplemented),
			Error:       "no handler registered for adapter: " + desc.AdapterID,
		}
	}
	return handler.Execute(ctx, req, desc)
}

// Execute implements Handler for DispatchExecutor.
// It delegates to ExecuteWithIdempotency which handles durable idempotency
// and dispatch-point semantics.
func (e *DispatchExecutor) Execute(ctx context.Context, req Request, desc capability.Descriptor) Response {
	return e.ExecuteWithIdempotency(ctx, req, desc)
}

// Execute implements Handler for FailClosedHandler.
func (h *FailClosedHandler) Execute(ctx context.Context, req Request, desc capability.Descriptor) Response {
	if desc.ExecutionClass == capability.ClassMutation || desc.ExecutionClass == capability.ClassCritical {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       "durable idempotency unavailable: MUTATION/CRITICAL operations require a database connection",
		}
	}
	return h.inner.Execute(ctx, req, desc)
}
