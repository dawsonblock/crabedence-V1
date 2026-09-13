package execution

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
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
func (h *MultiHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
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

// PrepareRecovery implements idempotency.RecoveryLocatorProvider by
// delegating to the adapter's handler. Handlers that implement the
// contract produce minimal provider-specific locators; handlers that
// don't return (nil, nil) so DispatchExecutor falls back to the generic
// metadata-only locator. An unregistered adapter fails closed — the
// dispatch boundary must not be crossed without recovery coordinates.
func (h *MultiHandler) PrepareRecovery(ctx context.Context, in idempotency.RecoveryLocatorInput) (json.RawMessage, error) {
	handler, ok := h.handlers[in.AdapterID]
	if !ok {
		return nil, fmt.Errorf("no handler registered for adapter: %s", in.AdapterID)
	}
	provider, ok := handler.(idempotency.RecoveryLocatorProvider)
	if !ok {
		return nil, nil
	}
	return provider.PrepareRecovery(ctx, in)
}

// Execute implements Handler for DispatchExecutor.
// It delegates to ExecuteWithIdempotency which handles durable idempotency
// and dispatch-point semantics.
func (e *DispatchExecutor) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	return e.ExecuteWithIdempotency(ctx, req, desc)
}

// Execute implements Handler for FailClosedHandler.
func (h *FailClosedHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	if desc.ExecutionClass == capability.ClassMutation || desc.ExecutionClass == capability.ClassCritical {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       "durable idempotency unavailable: MUTATION/CRITICAL operations require a database connection",
		}
	}
	return h.inner.Execute(ctx, req, desc)
}
