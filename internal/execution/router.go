package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// RouteDispatcher is the trusted route dispatcher. It reads the
// resolved descriptor's execution route — never a caller-supplied
// value — and dispatches accordingly:
//
//	LOCAL       Function Hooks (in-process, PURE only)
//	DIRECT      observational adapters (no durable ledger)
//	CRABEDENCE  the durable execution kernel
//
// The class/route invariant is re-checked at dispatch time as defense
// in depth: registration already rejects MUTATION/CRITICAL on
// non-durable routes, but a dispatcher that trusted the descriptor
// alone would be one registry bug away from executing a mutation
// without durability.
type RouteDispatcher struct {
	local   Handler
	direct  Handler
	durable Handler
}

// NewRouteDispatcher creates a dispatcher whose durable leg is the
// given handler (normally a DispatchExecutor).
func NewRouteDispatcher(durable Handler) *RouteDispatcher {
	return &RouteDispatcher{durable: durable}
}

// SetLocal wires the LOCAL route (Function Hooks).
func (d *RouteDispatcher) SetLocal(local Handler) { d.local = local }

// SetDirect wires the DIRECT route (observational adapters).
func (d *RouteDispatcher) SetDirect(direct Handler) { d.direct = direct }

// Execute implements Handler by dispatching on the descriptor's route.
func (d *RouteDispatcher) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	// Hard invariant, re-checked at the last line before dispatch: a
	// MUTATION or CRITICAL may only execute through the durable route.
	if desc.ExecutionClass.RequiresIdempotencyKey() && desc.ExecutionRoute != capability.RouteCrabedence {
		return Response{
			Status:      StatusDenied,
			FailureCode: string(capability.FailureAdmissionDenied),
			Error: fmt.Sprintf("route %s cannot execute %s capability %s — durable execution is required",
				desc.ExecutionRoute, desc.ExecutionClass, desc.ID),
		}
	}

	switch desc.ExecutionRoute {
	case capability.RouteLocal:
		if d.local == nil {
			return unimplementedRoute(desc)
		}
		return d.local.Execute(ctx, req, desc)
	case capability.RouteDirect:
		if d.direct == nil {
			return unimplementedRoute(desc)
		}
		return d.direct.Execute(ctx, req, desc)
	case capability.RouteCrabedence:
		if d.durable == nil {
			return unimplementedRoute(desc)
		}
		return d.durable.Execute(ctx, req, desc)
	default:
		// An unknown route must never fall through to a dispatch.
		return Response{
			Status:      StatusDenied,
			FailureCode: string(capability.FailureAdmissionDenied),
			Error:       fmt.Sprintf("capability %s declares unknown execution route %q", desc.ID, desc.ExecutionRoute),
		}
	}
}

func unimplementedRoute(desc capability.ResolvedDescriptor) Response {
	return Response{
		Status:      StatusFailed,
		FailureCode: string(capability.FailureCapabilityUnimplemented),
		Error:       fmt.Sprintf("capability %s declares route %s but no dispatcher is wired for it", desc.ID, desc.ExecutionRoute),
	}
}

// ─── Function Hooks (LOCAL route) ─────────────────────────────────────

// HookCall is the read-only context a LOCAL hook receives. It carries
// data only — a hook is never handed a store, dispatcher, or
// effect-fabric client, so a PURE capability cannot produce an
// external effect through dependency injection.
type HookCall struct {
	// Capability is the resolved capability identifier.
	Capability string
	// Principal is the admitted principal.
	Principal string
	// Arguments are the validated request arguments.
	Arguments json.RawMessage
}

// FunctionHook executes a PURE capability in-process.
type FunctionHook interface {
	Execute(ctx context.Context, call HookCall) (json.RawMessage, error)
}

// FunctionHookFunc adapts a function to the FunctionHook interface.
type FunctionHookFunc func(ctx context.Context, call HookCall) (json.RawMessage, error)

// Execute implements FunctionHook.
func (f FunctionHookFunc) Execute(ctx context.Context, call HookCall) (json.RawMessage, error) {
	return f(ctx, call)
}

// defaultHookTimeout bounds a single LOCAL hook execution.
const defaultHookTimeout = 5 * time.Second

// FunctionHookRegistry binds capability IDs to their hook
// implementation and executes them under the LOCAL route contract:
// PURE-only enforcement, input validation, bounded runtime, bounded
// payload, well-formed JSON results, cancellation, and an audit
// record. LOCAL executions have no durable ledger by design — the
// audit record is the attribution surface.
type FunctionHookRegistry struct {
	mu      sync.RWMutex
	hooks   map[string]FunctionHook
	timeout time.Duration
}

// NewFunctionHookRegistry creates an empty hook registry.
func NewFunctionHookRegistry() *FunctionHookRegistry {
	return &FunctionHookRegistry{
		hooks:   make(map[string]FunctionHook),
		timeout: defaultHookTimeout,
	}
}

// Register binds a capability ID to its hook implementation.
func (r *FunctionHookRegistry) Register(capabilityID string, hook FunctionHook) error {
	if capabilityID == "" {
		return errors.New("function hook requires a capability ID")
	}
	if hook == nil {
		return fmt.Errorf("function hook for %s is nil", capabilityID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.hooks[capabilityID]; exists {
		return fmt.Errorf("function hook already registered: %s", capabilityID)
	}
	r.hooks[capabilityID] = hook
	return nil
}

// SetTimeout overrides the per-hook execution budget. Non-positive
// values keep the current budget.
func (r *FunctionHookRegistry) SetTimeout(d time.Duration) {
	if d > 0 {
		r.mu.Lock()
		r.timeout = d
		r.mu.Unlock()
	}
}

// Execute implements Handler for LOCAL capabilities.
func (r *FunctionHookRegistry) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	// The LOCAL route is PURE-only. Registration enforces it and the
	// dispatcher re-checks it; the hook runtime re-checks it once more
	// because this is the last line before in-process execution.
	if desc.ExecutionClass != capability.ClassPure {
		return Response{
			Status:      StatusDenied,
			FailureCode: string(capability.FailureAdmissionDenied),
			Error:       fmt.Sprintf("LOCAL route requires PURE effect class, got %s", desc.ExecutionClass),
		}
	}

	r.mu.RLock()
	hook, ok := r.hooks[req.Capability]
	timeout := r.timeout
	r.mu.RUnlock()
	if !ok {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureCapabilityUnimplemented),
			Error:       "no function hook registered for capability: " + req.Capability,
		}
	}

	// Input validation (defense in depth — admission validates too,
	// but a hook must never run on arguments its contract rejects).
	if len(desc.Schema) > 0 {
		if err := capability.ValidateArguments(desc.Schema, req.Arguments); err != nil {
			return Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureInvalidRequest),
				Error:       fmt.Sprintf("argument schema validation failed: %v", err),
			}
		}
	}

	hookCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	result, err := hook.Execute(hookCtx, HookCall{
		Capability: req.Capability,
		Principal:  req.Authority.Principal,
		Arguments:  req.Arguments,
	})
	duration := time.Since(started)

	runID := fmt.Sprintf("local-%d", started.UnixNano())
	meta := &ExecutionMeta{Provider: desc.AdapterID, RunID: runID}

	if err != nil {
		outcome := "FAILED"
		status := StatusFailed
		failureCode := capability.FailureExecutionFailed
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(hookCtx.Err(), context.DeadlineExceeded) {
			outcome = "TIMEOUT"
			failureCode = capability.FailureExecutionFailed
		} else if errors.Is(err, context.Canceled) {
			outcome = "CANCELED"
		}
		log.Printf("execution audit: route=LOCAL capability=%s principal=%s outcome=%s duration_ms=%d",
			req.Capability, req.Authority.Principal, outcome, duration.Milliseconds())
		return Response{
			Status:      status,
			FailureCode: string(failureCode),
			Error:       fmt.Sprintf("function hook failed: %v", err),
			Execution:   meta,
		}
	}

	// Output contract: a LOCAL result must be well-formed JSON within
	// the durable payload bound — a PURE capability that violates its
	// own result contract has not produced a trustworthy result.
	if len(result) > idempotency.MaxResultBytes {
		log.Printf("execution audit: route=LOCAL capability=%s principal=%s outcome=OVERSIZED duration_ms=%d",
			req.Capability, req.Authority.Principal, duration.Milliseconds())
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureExecutionFailed),
			Error: fmt.Sprintf("function hook result exceeds %d bytes (got %d)",
				idempotency.MaxResultBytes, len(result)),
			Execution: meta,
		}
	}
	if !json.Valid(result) {
		log.Printf("execution audit: route=LOCAL capability=%s principal=%s outcome=INVALID_RESULT duration_ms=%d",
			req.Capability, req.Authority.Principal, duration.Milliseconds())
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureExecutionFailed),
			Error:       "function hook returned a result that is not valid JSON",
			Execution:   meta,
		}
	}

	log.Printf("execution audit: route=LOCAL capability=%s principal=%s outcome=SUCCEEDED duration_ms=%d",
		req.Capability, req.Authority.Principal, duration.Milliseconds())
	return Response{
		Status:    StatusSucceeded,
		Result:    result,
		Execution: meta,
	}
}
