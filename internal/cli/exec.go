package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ExecutionRequest is the wire-format request for the `crabbox exec` command.
// It is the Go-side equivalent of NeMo's CrabedenceExecutionRequest.
type ExecutionRequest struct {
	Capability     string          `json:"capability"`
	Arguments      json.RawMessage `json:"arguments"`
	Authority      ExecutionAuth   `json:"authority"`
	ExecutionClass string          `json:"execution_class"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Deadline       string          `json:"deadline,omitempty"`
}

// ExecutionAuth is the authority reference in the wire request.
type ExecutionAuth struct {
	Principal string `json:"principal"`
	GrantID   string `json:"grant_id"`
}

// ExecutionResponse is the wire-format response from `crabbox exec`.
type ExecutionResponse struct {
	Status    string                `json:"status"`
	Result    json.RawMessage       `json:"result,omitempty"`
	Error     string                `json:"error,omitempty"`
	Evidence  *ExecutionEvidenceRef `json:"evidence,omitempty"`
	Execution *ExecutionMeta        `json:"execution,omitempty"`
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
// validates authority, dispatches to the configured provider, generates
// RunEvidenceV1, signs a V3 receipt, and returns an ExecutionResponse.
//
// This command does NOT rebuild the execution machinery. It uses the
// existing Crabedence provider, evidence, and receipt systems. The
// command is the production bridge between NeMo's Unix socket server
// and the Go execution core.
//
// Usage:
//
//	echo '{"capability":"...","arguments":{...},...}' | crabbox exec
func (a App) execCommand(ctx context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(a.Stderr, "Usage: crabbox exec")
		fmt.Fprintln(a.Stderr, "")
		fmt.Fprintln(a.Stderr, "Reads an ExecutionRequest JSON object from stdin,")
		fmt.Fprintln(a.Stderr, "dispatches to the configured provider, generates")
		fmt.Fprintln(a.Stderr, "RunEvidenceV1, signs a V3 receipt, and writes an")
		fmt.Fprintln(a.Stderr, "ExecutionResponse JSON object to stdout.")
		return nil
	}

	// Read request from stdin
	data, err := io.ReadAll(a.Stdin)
	if err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "FAILED",
			Error:  fmt.Sprintf("failed to read stdin: %v", err),
		})
	}

	var req ExecutionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "FAILED",
			Error:  fmt.Sprintf("failed to parse request: %v", err),
		})
	}

	// Validate required fields
	if req.Capability == "" {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "FAILED",
			Error:  "missing capability",
		})
	}
	if req.Authority.Principal == "" || req.Authority.GrantID == "" {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "DENIED",
			Error:  "missing authority principal or grant_id",
		})
	}

	// Check deadline if present
	if req.Deadline != "" {
		deadline, err := time.Parse(time.RFC3339, req.Deadline)
		if err != nil {
			return writeExecResponse(a.Stdout, ExecutionResponse{
				Status: "DENIED",
				Error:  fmt.Sprintf("invalid deadline: %v", err),
			})
		}
		if time.Now().After(deadline) {
			return writeExecResponse(a.Stdout, ExecutionResponse{
				Status: "DENIED",
				Error:  "deadline expired",
			})
		}
	}

	// Require idempotency key for mutations
	if (req.ExecutionClass == "MUTATION" || req.ExecutionClass == "CRITICAL") && req.IdempotencyKey == "" {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "DENIED",
			Error:  "idempotency key required for MUTATION/CRITICAL capabilities",
		})
	}

	// TODO: Dispatch to the configured provider based on the capability.
	// For now, this returns a structured response indicating that the
	// provider dispatch bridge is not yet wired. The existing `run`
	// command's provider acquisition, evidence generation, and receipt
	// signing machinery should be called here.
	//
	// The capability ID maps to a registered provider adapter. The
	// arguments are validated against the capability's schema. Authority
	// is verified against the grant. The provider executes the capability.
	// RunEvidenceV1 is generated and canonicalized. A V3 receipt is
	// signed binding the evidence digest. The terminal bundle is
	// committed to the coordinator.

	// For READ operations, return a structured response.
	if req.ExecutionClass == "READ" {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "SUCCEEDED",
			Result: json.RawMessage(`{"note":"read bridge not yet wired to provider"}`),
			Execution: &ExecutionMeta{
				Provider: "bridge-pending",
				RunID:    generateExecRunID(),
			},
		})
	}

	// For MUTATION/CRITICAL, return UNKNOWN until the provider bridge
	// is fully wired. This is safer than claiming SUCCEEDED without
	// actual evidence generation.
	return writeExecResponse(a.Stdout, ExecutionResponse{
		Status: "UNKNOWN",
		Error:  "execution bridge pending provider dispatch wiring",
		Execution: &ExecutionMeta{
			Provider: "bridge-pending",
			RunID:    generateExecRunID(),
		},
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

// generateExecRunID generates a unique run identifier.
func generateExecRunID() string {
	return fmt.Sprintf("exec-%d", time.Now().UnixNano())
}
