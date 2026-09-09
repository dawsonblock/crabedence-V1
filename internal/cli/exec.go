package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"
)

// ExecutionRequest is the wire-format request for the `crabbox exec` command.
type ExecutionRequest struct {
	Capability     string          `json:"capability"`
	Arguments      json.RawMessage `json:"arguments"`
	Authority      ExecutionAuth   `json:"authority"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Deadline       string          `json:"deadline,omitempty"`
	ExecutionClass string          `json:"execution_class,omitempty"`
}

// ExecutionAuth is the authority reference in the wire request.
type ExecutionAuth struct {
	Principal string `json:"principal"`
	GrantID   string `json:"grant_id"`
}

// ExecutionResponse is the wire-format response from `crabbox exec`.
type ExecutionResponse struct {
	Status      string                `json:"status"`
	FailureCode string                `json:"failure_code,omitempty"`
	Result      json.RawMessage       `json:"result,omitempty"`
	Error       string                `json:"error,omitempty"`
	Evidence    *ExecutionEvidenceRef `json:"evidence,omitempty"`
	Execution   *ExecutionMeta        `json:"execution,omitempty"`
}

// ExecutionEvidenceRef is the evidence reference returned to NeMo.
type ExecutionEvidenceRef struct {
	Digest         string `json:"digest"`
	ReceiptVersion int    `json:"receipt_version,omitempty"`
}

// ExecutionMeta is execution metadata returned to NeMo.
type ExecutionMeta struct {
	Provider string `json:"provider"`
	RunID    string `json:"run_id"`
}

// execCommand implements `crabbox exec`: a narrow JSON-in/JSON-out
// execution bridge for NeMo. It reads an ExecutionRequest from stdin,
// validates it through the capability registry, and returns a typed
// response.
//
// Until provider dispatch is fully wired, capabilities without an
// adapter return FAILED with CAPABILITY_UNIMPLEMENTED. This command
// never returns SUCCEEDED for an operation that was not actually
// executed, and never returns UNKNOWN for an operation that was never
// dispatched.
func (a App) execCommand(ctx context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(a.Stderr, "Usage: crabbox exec")
		fmt.Fprintln(a.Stderr, "")
		fmt.Fprintln(a.Stderr, "Reads an ExecutionRequest JSON object from stdin,")
		fmt.Fprintln(a.Stderr, "validates it through the capability registry,")
		fmt.Fprintln(a.Stderr, "dispatches to the configured provider, and writes")
		fmt.Fprintln(a.Stderr, "an ExecutionResponse JSON object to stdout.")
		return nil
	}

	// Read request from stdin
	data, err := io.ReadAll(a.Stdin)
	if err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       fmt.Sprintf("failed to read stdin: %v", err),
		})
	}

	var req ExecutionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       fmt.Sprintf("failed to parse request: %v", err),
		})
	}

	// Build a registry with built-in capabilities
	registry := capability.NewRegistry()
	if err := execution.RegisterEchoCapability(registry); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("registry error: %v", err),
		})
	}
	if err := execution.RegisterCounterCapability(registry); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("registry error: %v", err),
		})
	}

	// Admit the request through the registry
	decision := registry.Admit(capability.AdmissionRequest{
		Capability:     req.Capability,
		Arguments:      req.Arguments,
		Principal:      req.Authority.Principal,
		GrantID:        req.Authority.GrantID,
		ExecutionClass: req.ExecutionClass,
		IdempotencyKey: req.IdempotencyKey,
		Deadline:       req.Deadline,
	})

	if !decision.Allowed {
		status := "DENIED"
		if decision.FailureCode == capability.FailureCapabilityNotFound ||
			decision.FailureCode == capability.FailureCapabilityUnimplemented {
			status = "FAILED"
		}
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      status,
			FailureCode: string(decision.FailureCode),
			Error:       decision.Reason,
		})
	}

	// TODO: For the subprocess bridge, we can't dispatch to the persistent
	// service. The `crabbox serve-execution` command owns the persistent
	// service. The `crabbox exec` command is a simple stdin/stdout bridge
	// that should connect to the persistent service over the Unix socket.
	//
	// For now, return CAPABILITY_UNIMPLEMENTED for all capabilities.
	// The persistent service (crabbox serve-execution) handles real dispatch.
	return writeExecResponse(a.Stdout, ExecutionResponse{
		Status:      "FAILED",
		FailureCode: string(capability.FailureCapabilityUnimplemented),
		Error:       "crabbox exec cannot dispatch; use 'crabbox serve-execution' for the persistent service",
	})
}

// writeExecResponse writes an ExecutionResponse as JSON to the writer.
func writeExecResponse(w io.Writer, resp ExecutionResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	_, err = w.Write(data)
	return err
}
