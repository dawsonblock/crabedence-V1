package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
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

// GoCapabilityDescriptor is the server-side authoritative capability
// registration. The execution class is pinned here — callers cannot
// self-classify. This is the Go equivalent of NeMo's
// CapabilityDescriptor, but owned by the execution layer, not the
// reasoning layer.
type GoCapabilityDescriptor struct {
	ID              string `json:"id"`
	ExecutionClass  string `json:"execution_class"`
	AuthorityPolicy string `json:"authority_policy"`
	// Schema is the JSON schema for argument validation (future).
	Schema json.RawMessage `json:"schema,omitempty"`
}

// capabilityRegistry is the server-controlled capability catalog.
// Callers (including NeMo) cannot override execution classes here.
// This is the authoritative source — the caller's execution_class
// field is treated as an assertion at most, never as the source of truth.
var capabilityRegistry = map[string]GoCapabilityDescriptor{
	// Capabilities will be registered here as the bridge is wired.
	// Until then, all capabilities are UNIMPLEMENTED.
}

// validExecutionClass returns true if the class is a known value.
func validExecutionClass(class string) bool {
	switch class {
	case "PURE", "READ", "MUTATION", "CRITICAL":
		return true
	}
	return false
}

// hexDigestPattern matches a 64-character lowercase hexadecimal string.
var hexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// execCommand implements `crabbox exec`: a narrow JSON-in/JSON-out
// execution bridge for NeMo. It reads an ExecutionRequest from stdin,
// validates authority, looks up the capability in the server-controlled
// registry, and dispatches to the configured provider.
//
// Until provider dispatch is fully wired, ALL capabilities return
// FAILED with "execution bridge not implemented". This command never
// returns SUCCEEDED or UNKNOWN for an operation that was not actually
// executed — that would be dishonest about side effects.
//
// Usage:
//
//	echo '{"capability":"...","arguments":{...},...}' | crabbox exec
func (a App) execCommand(ctx context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(a.Stderr, "Usage: crabbox exec")
		fmt.Fprintln(a.Stderr, "")
		fmt.Fprintln(a.Stderr, "Reads an ExecutionRequest JSON object from stdin,")
		fmt.Fprintln(a.Stderr, "validates authority and capability, dispatches to the")
		fmt.Fprintln(a.Stderr, "configured provider, generates RunEvidenceV1, signs a")
		fmt.Fprintln(a.Stderr, "V3 receipt, and writes an ExecutionResponse JSON object")
		fmt.Fprintln(a.Stderr, "to stdout.")
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

	// Look up capability in the server-controlled registry.
	// The caller's execution_class is an assertion, not the source of truth.
	desc, known := capabilityRegistry[req.Capability]
	if !known {
		// Unknown capability — check if caller provided a class at least
		if !validExecutionClass(req.ExecutionClass) {
			return writeExecResponse(a.Stdout, ExecutionResponse{
				Status: "FAILED",
				Error:  fmt.Sprintf("unknown capability: %s (no execution class provided)", req.Capability),
			})
		}
		// Capability not registered in server registry.
		// Until the registry is populated, return UNIMPLEMENTED.
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "FAILED",
			Error:  fmt.Sprintf("capability not registered in server registry: %s", req.Capability),
		})
	}

	// The server registry's execution class is authoritative.
	// If the caller supplied a different class, that's a mismatch.
	if req.ExecutionClass != "" && req.ExecutionClass != desc.ExecutionClass {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "DENIED",
			Error: fmt.Sprintf("execution class mismatch: caller asserted %s but capability %s is pinned as %s",
				req.ExecutionClass, req.Capability, desc.ExecutionClass),
		})
	}

	// Use the server-pinned class for all subsequent checks.
	effectiveClass := desc.ExecutionClass

	// Check deadline if present (RFC3339, matching TypeScript Date.parse for ISO strings)
	if req.Deadline != "" {
		deadline, err := time.Parse(time.RFC3339, req.Deadline)
		if err != nil {
			return writeExecResponse(a.Stdout, ExecutionResponse{
				Status: "DENIED",
				Error:  fmt.Sprintf("invalid deadline (expected RFC3339): %v", err),
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
	if (effectiveClass == "MUTATION" || effectiveClass == "CRITICAL") && req.IdempotencyKey == "" {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status: "DENIED",
			Error:  "idempotency key required for MUTATION/CRITICAL capabilities",
		})
	}

	// TODO: Dispatch to the configured provider based on the capability.
	// The existing `run` command's provider acquisition, evidence
	// generation, and receipt signing machinery should be called here.
	//
	// The capability ID maps to a registered provider adapter. The
	// arguments are validated against the capability's schema. Authority
	// is verified against the grant. The provider executes the capability.
	// RunEvidenceV1 is generated and canonicalized. A V3 receipt is
	// signed binding the evidence digest. The terminal bundle is
	// committed to the coordinator.
	//
	// Until provider dispatch is implemented, return FAILED for ALL
	// execution classes. Never return SUCCEEDED (no operation ran) or
	// UNKNOWN (no provider was invoked — UNKNOWN means the operation
	// may have executed, which is not the case here).
	return writeExecResponse(a.Stdout, ExecutionResponse{
		Status: "FAILED",
		Error:  "execution bridge not implemented: provider dispatch not yet wired",
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
