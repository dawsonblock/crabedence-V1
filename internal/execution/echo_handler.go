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
	})
}
