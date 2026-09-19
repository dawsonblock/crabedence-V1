package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// EchoHandler implements the system.echo capability.
// This is the first real end-to-end capability: it receives a request,
// admits it through the registry, executes it, and returns a result.
// It does NOT produce evidence or receipts — it's a PURE capability
// for proving the execution boundary works.
type EchoHandler struct{}

// NewEchoHandler creates a handler for system.echo.
func NewEchoHandler() *EchoHandler {
	return &EchoHandler{}
}

// Execute handles a system.echo request by returning the arguments.
func (h *EchoHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	runID := fmt.Sprintf("echo-%d", time.Now().UnixNano())

	result, err := json.Marshal(map[string]any{
		"echo":      req.Arguments,
		"principal": req.Authority.Principal,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to marshal result: %v", err),
			Execution: &ExecutionMeta{
				Provider: "system",
				RunID:    runID,
			},
		}
	}

	return Response{
		Status: StatusSucceeded,
		Result: result,
		Execution: &ExecutionMeta{
			Provider: "system",
			RunID:    runID,
		},
	}
}

// RegisterEchoCapability registers system.echo in the capability registry.
func RegisterEchoCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "system.echo",
		ExecutionClass: capability.ClassPure,
		AdapterID:      "system",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "system.echo",
			GrantRequired: false,
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message": {
					"type": "string",
					"description": "Message to echo back"
				},
				"data": {
					"type": "string",
					"description": "Raw data to echo back (for frame-size tests)"
				}
			},
			"additionalProperties": true
		}`),
	})
}

// systemEchoHook is the LOCAL Function Hook for system.echo. PURE
// capabilities resolve to the LOCAL route (PURE + NONE assurance), so
// the echo capability executes in-process under the hook runtime:
// validated arguments in, bounded JSON out, audit record written.
type systemEchoHook struct{}

// Execute returns the arguments it received, with the admitted
// principal and a timestamp — the same shape the adapter handler
// produced, now behind the LOCAL execution boundary.
func (systemEchoHook) Execute(_ context.Context, call HookCall) (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"echo":      call.Arguments,
		"principal": call.Principal,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// RegisterSystemEchoHook binds system.echo to its LOCAL hook.
func RegisterSystemEchoHook(registry *FunctionHookRegistry) error {
	return registry.Register("system.echo", systemEchoHook{})
}
