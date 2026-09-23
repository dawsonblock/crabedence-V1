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
//	DIRECT      observational reads (in-process, READ only)
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

// SetDirect wires the DIRECT route (observational reads).
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
		FailureCode: string(capability.FailureCapabilityUnavailable),
		Error:       fmt.Sprintf("capability %s declares route %s but no dispatcher is wired for it", desc.ID, desc.ExecutionRoute),
	}
}

// ─── In-process route runtime ─────────────────────────────────────────

// CallContext is the read-only context an in-process route handler
// receives. LOCAL hooks and DIRECT reads alike receive data only —
// never a store, dispatcher, or effect-fabric client — so PURE and
// READ routes cannot produce an external effect through dependency
// injection.
type CallContext struct {
	// Capability is the resolved capability identifier.
	Capability string
	// Principal is the admitted principal.
	Principal string
	// Arguments are the validated request arguments.
	Arguments json.RawMessage
}

// HookCall is the LOCAL hook view of CallContext.
type HookCall = CallContext

// CallFunc executes one in-process capability invocation.
type CallFunc func(ctx context.Context, call CallContext) (json.RawMessage, error)

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

// routeRuntime executes one route's in-process handlers under a shared
// contract: route/class enforcement, argument re-validation, bounded
// runtime, bounded payload, well-formed JSON results, cancellation,
// and a structured audit record. In-process routes have no durable
// ledger by design — the audit record is the attribution surface.
type routeRuntime struct {
	mu      sync.RWMutex
	route   capability.ExecutionRoute
	class   capability.ExecutionClass
	calls   map[string]CallFunc
	timeout time.Duration
}

func newRouteRuntime(route capability.ExecutionRoute, class capability.ExecutionClass, timeout time.Duration) *routeRuntime {
	return &routeRuntime{
		route:   route,
		class:   class,
		calls:   make(map[string]CallFunc),
		timeout: timeout,
	}
}

func (r *routeRuntime) register(capabilityID string, call CallFunc) error {
	if capabilityID == "" {
		return errors.New("in-process route handler requires a capability ID")
	}
	if call == nil {
		return fmt.Errorf("in-process route handler for %s is nil", capabilityID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.calls[capabilityID]; exists {
		return fmt.Errorf("in-process route handler already registered: %s", capabilityID)
	}
	r.calls[capabilityID] = call
	return nil
}

func (r *routeRuntime) setTimeout(d time.Duration) {
	if d > 0 {
		r.mu.Lock()
		r.timeout = d
		r.mu.Unlock()
	}
}

func (r *routeRuntime) execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	// The class/route pairing is enforced at registration and by the
	// dispatcher; the runtime re-checks it once more because this is
	// the last line before in-process execution.
	if desc.ExecutionClass != r.class || desc.ExecutionRoute != r.route {
		return Response{
			Status:      StatusDenied,
			FailureCode: string(capability.FailureAdmissionDenied),
			Error: fmt.Sprintf("%s route requires %s effect class, got %s/%s",
				r.route, r.class, desc.ExecutionClass, desc.ExecutionRoute),
		}
	}

	r.mu.RLock()
	call, ok := r.calls[req.Capability]
	timeout := r.timeout
	r.mu.RUnlock()
	if !ok {
		if r.route == capability.RouteDirect {
			// A DIRECT read with no registered handler is an adapter
			// this deployment did not configure: a known capability
			// that is currently unavailable, never an unknown one.
			return Response{
				Status:      StatusFailed,
				FailureCode: string(capability.FailureCapabilityUnavailable),
				Error: fmt.Sprintf("capability %s requires adapter %q, which is not configured in this deployment (reason=%s)",
					req.Capability, desc.AdapterID, capability.FailureReasonAdapterNotConfigured),
			}
		}
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureCapabilityUnavailable),
			Error:       fmt.Sprintf("no %s handler registered for capability: %s", r.route, req.Capability),
		}
	}

	// Input validation (defense in depth — admission validates too,
	// but a handler must never run on arguments its contract rejects).
	if len(desc.Schema) > 0 {
		if err := capability.ValidateArguments(desc.Schema, req.Arguments); err != nil {
			return Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureInvalidRequest),
				Error:       fmt.Sprintf("argument schema validation failed: %v", err),
			}
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	// The handler runs in its own goroutine: a route handler that
	// ignores context cancellation would otherwise hold the request —
	// and the connection — open forever. The buffered channel lets a
	// late answer drop without pinning a goroutine on send.
	type callResult struct {
		result json.RawMessage
		err    error
	}
	resultCh := make(chan callResult, 1)
	go func() {
		res, callErr := call(callCtx, CallContext{
			Capability: req.Capability,
			Principal:  req.Authority.Principal,
			Arguments:  req.Arguments,
		})
		resultCh <- callResult{res, callErr}
	}()
	var result json.RawMessage
	var err error
	select {
	case out := <-resultCh:
		result, err = out.result, out.err
	case <-callCtx.Done():
		err = fmt.Errorf("%w: %s handler exceeded its %s execution budget", callCtx.Err(), r.route, timeout)
	}
	duration := time.Since(started)

	runID := fmt.Sprintf("%s-%d", routeRunIDPrefix(r.route), started.UnixNano())
	meta := &ExecutionMeta{Provider: desc.AdapterID, RunID: runID}

	if err != nil {
		outcome := "FAILED"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			outcome = "TIMEOUT"
		} else if errors.Is(err, context.Canceled) {
			outcome = "CANCELED"
		}
		r.audit(req, outcome, duration)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureExecutionFailed),
			Error:       fmt.Sprintf("%s handler failed: %v", r.route, err),
			Execution:   meta,
		}
	}

	// Output contract: an in-process result must be well-formed JSON
	// within the durable payload bound — a handler that violates its
	// own result contract has not produced a trustworthy result.
	if len(result) > idempotency.MaxResultBytes {
		r.audit(req, "OVERSIZED", duration)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureExecutionFailed),
			Error: fmt.Sprintf("%s handler result exceeds %d bytes (got %d)",
				r.route, idempotency.MaxResultBytes, len(result)),
			Execution: meta,
		}
	}
	if !json.Valid(result) {
		r.audit(req, "INVALID_RESULT", duration)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureExecutionFailed),
			Error:       fmt.Sprintf("%s handler returned a result that is not valid JSON", r.route),
			Execution:   meta,
		}
	}

	r.audit(req, "SUCCEEDED", duration)
	return Response{
		Status:    StatusSucceeded,
		Result:    result,
		Execution: meta,
	}
}

// audit writes the structured attribution record for one in-process
// execution. It never includes arguments or results — capability,
// principal, outcome, and duration only.
func (r *routeRuntime) audit(req Request, outcome string, duration time.Duration) {
	log.Printf("execution audit: route=%s capability=%s principal=%s outcome=%s duration_ms=%d",
		r.route, req.Capability, req.Authority.Principal, outcome, duration.Milliseconds())
}

func routeRunIDPrefix(route capability.ExecutionRoute) string {
	switch route {
	case capability.RouteLocal:
		return "local"
	case capability.RouteDirect:
		return "direct"
	default:
		return "route"
	}
}

// ─── Function Hooks (LOCAL route) ─────────────────────────────────────

// defaultHookTimeout bounds a single LOCAL hook execution.
const defaultHookTimeout = 5 * time.Second

// FunctionHookRegistry binds capability IDs to their hook
// implementation and executes them under the LOCAL route contract:
// PURE-only enforcement, input validation, bounded runtime, bounded
// payload, well-formed JSON results, cancellation, and an audit record.
type FunctionHookRegistry struct {
	runtime *routeRuntime
}

// NewFunctionHookRegistry creates an empty hook registry.
func NewFunctionHookRegistry() *FunctionHookRegistry {
	return &FunctionHookRegistry{
		runtime: newRouteRuntime(capability.RouteLocal, capability.ClassPure, defaultHookTimeout),
	}
}

// Register binds a capability ID to its hook implementation.
func (r *FunctionHookRegistry) Register(capabilityID string, hook FunctionHook) error {
	if hook == nil {
		return fmt.Errorf("function hook for %s is nil", capabilityID)
	}
	return r.runtime.register(capabilityID, func(ctx context.Context, call CallContext) (json.RawMessage, error) {
		return hook.Execute(ctx, call)
	})
}

// SetTimeout overrides the per-hook execution budget. Non-positive
// values keep the current budget.
func (r *FunctionHookRegistry) SetTimeout(d time.Duration) { r.runtime.setTimeout(d) }

// Execute implements Handler for LOCAL capabilities.
func (r *FunctionHookRegistry) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	return r.runtime.execute(ctx, req, desc)
}

// ─── Direct reads (DIRECT route) ──────────────────────────────────────

// defaultDirectReadTimeout bounds a single DIRECT read. Reads cross a
// network boundary, so the budget is more generous than a local hook's
// while still bounding a hung provider.
const defaultDirectReadTimeout = 15 * time.Second

// DirectReadFunc performs one observational read. It must not mutate
// provider state — the DIRECT route exists for reads.
type DirectReadFunc func(ctx context.Context, call CallContext) (json.RawMessage, error)

// DirectReadRegistry binds capability IDs to their read implementation
// and executes them under the DIRECT route contract: READ-only
// enforcement, input validation, bounded runtime, bounded payload,
// well-formed JSON results, cancellation, and an audit record.
//
// A DIRECT read has no external effect, so a failure is a safe FAILED
// — never UNKNOWN, and never a durable ledger entry.
type DirectReadRegistry struct {
	runtime *routeRuntime
}

// NewDirectReadRegistry creates an empty direct-read registry.
func NewDirectReadRegistry() *DirectReadRegistry {
	return &DirectReadRegistry{
		runtime: newRouteRuntime(capability.RouteDirect, capability.ClassRead, defaultDirectReadTimeout),
	}
}

// Register binds a capability ID to its read implementation.
func (r *DirectReadRegistry) Register(capabilityID string, read DirectReadFunc) error {
	if read == nil {
		return fmt.Errorf("direct read for %s is nil", capabilityID)
	}
	return r.runtime.register(capabilityID, CallFunc(read))
}

// SetTimeout overrides the per-read execution budget. Non-positive
// values keep the current budget.
func (r *DirectReadRegistry) SetTimeout(d time.Duration) { r.runtime.setTimeout(d) }

// Execute implements Handler for DIRECT capabilities.
func (r *DirectReadRegistry) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	return r.runtime.execute(ctx, req, desc)
}
