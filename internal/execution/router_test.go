package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// recordingHandler records the requests it receives and returns a
// canned response.
type recordingHandler struct {
	calls    []Request
	response Response
}

func (h *recordingHandler) Execute(_ context.Context, req Request, _ capability.ResolvedDescriptor) Response {
	h.calls = append(h.calls, req)
	return h.response
}

func pureLocalDescriptor(id string) capability.ResolvedDescriptor {
	return capability.ResolvedDescriptor{
		ID:               id,
		ExecutionClass:   capability.ClassPure,
		AssuranceProfile: capability.AssuranceNone,
		ExecutionRoute:   capability.RouteLocal,
		AdapterID:        "local",
	}
}

func mutationDurableDescriptor(id string) capability.ResolvedDescriptor {
	return capability.ResolvedDescriptor{
		ID:               id,
		ExecutionClass:   capability.ClassMutation,
		AssuranceProfile: capability.AssuranceDurable,
		ExecutionRoute:   capability.RouteCrabedence,
		AdapterID:        "test-adapter",
	}
}

func readDirectDescriptor(id string) capability.ResolvedDescriptor {
	return capability.ResolvedDescriptor{
		ID:               id,
		ExecutionClass:   capability.ClassRead,
		AssuranceProfile: capability.AssuranceStandard,
		ExecutionRoute:   capability.RouteDirect,
		AdapterID:        "direct-adapter",
	}
}

func testRequest(capabilityID string) Request {
	return Request{
		Capability: capabilityID,
		Arguments:  json.RawMessage(`{"x":1}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}
}

func TestRouteDispatcherRoutesByDescriptorRoute(t *testing.T) {
	durable := &recordingHandler{response: Response{Status: StatusSucceeded, Result: json.RawMessage(`{"durable":true}`)}}
	hooks := NewFunctionHookRegistry()
	if err := hooks.Register("test.pure", FunctionHookFunc(func(_ context.Context, _ HookCall) (json.RawMessage, error) {
		return json.RawMessage(`{"local":true}`), nil
	})); err != nil {
		t.Fatal(err)
	}
	dispatcher := NewRouteDispatcher(durable)
	dispatcher.SetLocal(hooks)

	local := dispatcher.Execute(context.Background(), testRequest("test.pure"), pureLocalDescriptor("test.pure"))
	if local.Status != StatusSucceeded || string(local.Result) != `{"local":true}` {
		t.Fatalf("LOCAL route must execute the function hook, got %s: %s", local.Status, local.Error)
	}
	if len(durable.calls) != 0 {
		t.Fatal("LOCAL route must not reach the durable handler")
	}

	durableDesc := mutationDurableDescriptor("test.mut")
	durableResp := dispatcher.Execute(context.Background(), testRequest("test.mut"), durableDesc)
	if durableResp.Status != StatusSucceeded || string(durableResp.Result) != `{"durable":true}` {
		t.Fatalf("CRABEDENCE route must execute the durable handler, got %s: %s", durableResp.Status, durableResp.Error)
	}
	if len(durable.calls) != 1 {
		t.Fatalf("durable handler calls = %d, want 1", len(durable.calls))
	}

	// DIRECT with no adapter wired fails closed.
	direct := dispatcher.Execute(context.Background(), testRequest("test.read"), readDirectDescriptor("test.read"))
	if direct.Status != StatusFailed || direct.FailureCode != string(capability.FailureCapabilityUnavailable) {
		t.Fatalf("unwired DIRECT route must fail closed, got %s: %s", direct.Status, direct.Error)
	}

	// An unknown route must never fall through to a dispatch.
	unknown := pureLocalDescriptor("test.unknown")
	unknown.ExecutionRoute = "WAT"
	unknownResp := dispatcher.Execute(context.Background(), testRequest("test.unknown"), unknown)
	if unknownResp.Status != StatusDenied {
		t.Fatalf("unknown route must be denied, got %s: %s", unknownResp.Status, unknownResp.Error)
	}
}

func TestRouteDispatcherRefusesMutationOnNonDurableRoute(t *testing.T) {
	durable := &recordingHandler{response: Response{Status: StatusSucceeded}}
	hooks := NewFunctionHookRegistry()
	dispatcher := NewRouteDispatcher(durable)
	dispatcher.SetLocal(hooks)

	// A registry bug that produced this descriptor must not become a
	// mutation executed without durability.
	bad := capability.ResolvedDescriptor{
		ID:               "test.mut",
		ExecutionClass:   capability.ClassMutation,
		AssuranceProfile: capability.AssuranceDurable,
		ExecutionRoute:   capability.RouteLocal,
		AdapterID:        "local",
	}
	response := dispatcher.Execute(context.Background(), testRequest("test.mut"), bad)
	if response.Status != StatusDenied || !strings.Contains(response.Error, "durable execution is required") {
		t.Fatalf("MUTATION on a non-durable route must be denied, got %s: %s", response.Status, response.Error)
	}
	if len(durable.calls) != 0 {
		t.Fatal("denied mutation must not reach any handler")
	}
}

func TestFunctionHookRuntimeContract(t *testing.T) {
	registry := NewFunctionHookRegistry()
	if err := registry.Register("test.pure", FunctionHookFunc(func(_ context.Context, call HookCall) (json.RawMessage, error) {
		if call.Principal != "alice@example.com" {
			return nil, fmt.Errorf("hook did not receive the principal")
		}
		return json.RawMessage(`{"ok":true}`), nil
	})); err != nil {
		t.Fatal(err)
	}
	// Duplicate registration is refused.
	if err := registry.Register("test.pure", FunctionHookFunc(nil)); err == nil {
		t.Fatal("duplicate hook registration must be refused")
	}

	schema := json.RawMessage(`{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}`)
	desc := pureLocalDescriptor("test.pure")
	desc.Schema = schema

	response := registry.Execute(context.Background(), testRequest("test.pure"), desc)
	if response.Status != StatusSucceeded || string(response.Result) != `{"ok":true}` {
		t.Fatalf("hook execution failed: %s: %s", response.Status, response.Error)
	}

	// Non-PURE descriptors never execute in-process.
	mutation := mutationDurableDescriptor("test.pure")
	mutation.Schema = schema
	if response := registry.Execute(context.Background(), testRequest("test.pure"), mutation); response.Status != StatusDenied {
		t.Fatalf("non-PURE descriptor must be denied by the hook runtime, got %s", response.Status)
	}

	// Unregistered capability fails closed.
	missing := registry.Execute(context.Background(), testRequest("test.missing"), pureLocalDescriptor("test.missing"))
	if missing.FailureCode != string(capability.FailureCapabilityUnavailable) {
		t.Fatalf("unregistered capability must be unimplemented, got %s: %s", missing.FailureCode, missing.Error)
	}

	// Invalid arguments are rejected before the hook runs.
	badArgs := Request{Capability: "test.pure", Arguments: json.RawMessage(`{"x":"not-an-integer"}`), Authority: RequestAuthority{Principal: "alice@example.com"}}
	if response := registry.Execute(context.Background(), badArgs, desc); response.Status != StatusDenied {
		t.Fatalf("schema-invalid arguments must be denied, got %s: %s", response.Status, response.Error)
	}
}

func TestFunctionHookRuntimeBoundsAndFailures(t *testing.T) {
	registry := NewFunctionHookRegistry()
	// 100ms is comfortably inside the timeout hook's 2s sleep while
	// leaving headroom for the oversized hook's marshal under a loaded
	// test runner — the hook now runs on its own goroutine, so the
	// budget includes a scheduling hop.
	registry.SetTimeout(100 * time.Millisecond)

	if err := registry.Register("test.error", FunctionHookFunc(func(context.Context, HookCall) (json.RawMessage, error) {
		return nil, errors.New("boom")
	})); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("test.timeout", FunctionHookFunc(func(ctx context.Context, _ HookCall) (json.RawMessage, error) {
		select {
		case <-time.After(2 * time.Second):
			return json.RawMessage(`{}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("test.oversized", FunctionHookFunc(func(context.Context, HookCall) (json.RawMessage, error) {
		oversized := make([]byte, idempotency.MaxResultBytes+1)
		for i := range oversized {
			oversized[i] = 'x'
		}
		return json.RawMessage(fmt.Sprintf("%q", oversized)), nil
	})); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("test.invalid", FunctionHookFunc(func(context.Context, HookCall) (json.RawMessage, error) {
		return json.RawMessage(`not json`), nil
	})); err != nil {
		t.Fatal(err)
	}

	failing := registry.Execute(context.Background(), testRequest("test.error"), pureLocalDescriptor("test.error"))
	if failing.Status != StatusFailed || !strings.Contains(failing.Error, "boom") {
		t.Fatalf("hook error must be FAILED, got %s: %s", failing.Status, failing.Error)
	}

	timedOut := registry.Execute(context.Background(), testRequest("test.timeout"), pureLocalDescriptor("test.timeout"))
	if timedOut.Status != StatusFailed || !strings.Contains(timedOut.Error, "deadline exceeded") {
		t.Fatalf("hook timeout must be FAILED, got %s: %s", timedOut.Status, timedOut.Error)
	}

	oversized := registry.Execute(context.Background(), testRequest("test.oversized"), pureLocalDescriptor("test.oversized"))
	if oversized.Status != StatusFailed || !strings.Contains(oversized.Error, "exceeds") {
		t.Fatalf("oversized result must be FAILED, got %s: %s", oversized.Status, oversized.Error)
	}

	invalid := registry.Execute(context.Background(), testRequest("test.invalid"), pureLocalDescriptor("test.invalid"))
	if invalid.Status != StatusFailed || !strings.Contains(invalid.Error, "not valid JSON") {
		t.Fatalf("invalid JSON result must be FAILED, got %s: %s", invalid.Status, invalid.Error)
	}
}

func TestBuiltInEchoHookExecutesThroughLocalRoute(t *testing.T) {
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	desc, ok := registry.Lookup("system.echo")
	if !ok {
		t.Fatal("system.echo must be registered")
	}
	if desc.ExecutionRoute != capability.RouteLocal {
		t.Fatalf("system.echo route = %s, want LOCAL (PURE + NONE)", desc.ExecutionRoute)
	}

	hooks := NewFunctionHookRegistry()
	if err := RegisterSystemEchoHook(hooks); err != nil {
		t.Fatal(err)
	}
	dispatcher := NewRouteDispatcher(nil)
	dispatcher.SetLocal(hooks)

	response := dispatcher.Execute(context.Background(), Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"hello"}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}, desc)
	if response.Status != StatusSucceeded {
		t.Fatalf("system.echo through the LOCAL route failed: %s: %s", response.Status, response.Error)
	}
	var result map[string]any
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("echo result is not valid JSON: %v", err)
	}
	if result["principal"] != "alice@example.com" {
		t.Fatalf("echo result principal = %v", result["principal"])
	}
}
