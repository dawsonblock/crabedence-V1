package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"
)

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
// forwards it to the persistent execution service over the Unix
// socket (the same ABI that `crabbox invoke` uses), and writes the
// ExecutionResponse to stdout.
//
// This is the stdin/stdout bridge for subprocess-based planners
// (like the legacy TypeScript bridge.ts). It delegates entirely to
// the persistent execution service — it never dispatches on its own.
//
// Transport failures obey the durable execution contract's dispatch
// boundary: a failure before the request frame is fully transmitted is
// FAILED (the invocation did not happen), while a failure after
// transmission is UNKNOWN — the side effect may have occurred and must
// be reconciled, never reported as a definitive failure.
func (a App) execCommand(ctx context.Context, args []string, timeout time.Duration) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(a.Stderr, "Usage: crabbox exec")
		fmt.Fprintln(a.Stderr, "")
		fmt.Fprintln(a.Stderr, "Reads an ExecutionRequest JSON object from stdin,")
		fmt.Fprintln(a.Stderr, "forwards it to the persistent execution service")
		fmt.Fprintln(a.Stderr, "(crabbox serve-exec) over the Unix socket,")
		fmt.Fprintln(a.Stderr, "and writes an ExecutionResponse JSON object to stdout.")
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

	// The stdin request is parsed under the same strict ABI rules the
	// execution service applies to the socket. A permissive decode here
	// would silently rewrite what the planner sent — dropping unknown
	// fields, keeping the last duplicate key, and losing `authority_ref`
	// in favor of the deprecated `grant_id` alias — so the planner could
	// not tell that its request had been changed.
	req, err := execution.ParseInvocationRequest(data)
	if err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       fmt.Sprintf("invalid request: %v", err),
		})
	}

	// The wire ABI requires arguments to be a JSON object; a request
	// without arguments carries the empty object, never null.
	if len(req.Arguments) == 0 {
		req.Arguments = json.RawMessage(`{}`)
	}

	// Connect to the persistent execution service and send the request
	// through the shared client, which classifies transport failures
	// against the dispatch boundary.
	socketPath := a.defaultExecutionSocketPath()
	client := execution.NewClient(socketPath, execution.ClientOptions{Timeout: timeout})
	resp, err := client.Invoke(ctx, req)
	if err != nil {
		if execution.AmbiguousOutcome(err) {
			// The request was transmitted; the outcome is unknown.
			// Reporting FAILED here would let a caller retry with a
			// different operation or idempotency key while the first
			// invocation may still commit.
			return writeExecResponse(a.Stdout, ExecutionResponse{
				Status:      execution.StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error: fmt.Sprintf(
					"outcome unknown: %v (the request may have been dispatched to the execution service; reconcile before retrying)",
					err,
				),
			})
		}
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       err.Error(),
		})
	}

	return writeExecResponse(a.Stdout, ExecutionResponse{
		Status:      resp.Status,
		FailureCode: resp.FailureCode,
		Result:      resp.Result,
		Error:       resp.Error,
		Evidence:    execEvidenceRef(resp.Evidence),
		Execution:   execExecutionMeta(resp.Execution),
	})
}

func execEvidenceRef(ref *execution.EvidenceRef) *ExecutionEvidenceRef {
	if ref == nil {
		return nil
	}
	return &ExecutionEvidenceRef{Digest: ref.Digest, ReceiptVersion: ref.ReceiptVersion}
}

func execExecutionMeta(meta *execution.ExecutionMeta) *ExecutionMeta {
	if meta == nil {
		return nil
	}
	return &ExecutionMeta{Provider: meta.Provider, RunID: meta.RunID}
}

// defaultExecutionSocketPath returns the canonical execution service
// socket path — the same resolver serve-exec and invoke default
// to, so a default-started service and a default client agree.
func (a App) defaultExecutionSocketPath() string {
	return execution.DefaultSocketPath()
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
