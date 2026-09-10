package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

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
// forwards it to the persistent execution service over the Unix
// socket (the same ABI that `crabbox invoke` uses), and writes the
// ExecutionResponse to stdout.
//
// This is the stdin/stdout bridge for subprocess-based planners
// (like the legacy TypeScript bridge.ts). It delegates entirely to
// the persistent execution service — it never dispatches on its own.
func (a App) execCommand(ctx context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(a.Stderr, "Usage: crabbox exec")
		fmt.Fprintln(a.Stderr, "")
		fmt.Fprintln(a.Stderr, "Reads an ExecutionRequest JSON object from stdin,")
		fmt.Fprintln(a.Stderr, "forwards it to the persistent execution service")
		fmt.Fprintln(a.Stderr, "(crabbox serve-execution) over the Unix socket,")
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

	var req ExecutionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       fmt.Sprintf("failed to parse request: %v", err),
		})
	}

	// Build the execution service request (same wire format as invoke).
	execReq := execution.Request{
		Capability: req.Capability,
		Arguments:  req.Arguments,
		Authority: execution.RequestAuthority{
			Principal:    req.Authority.Principal,
			AuthorityRef: req.Authority.GrantID,
		},
		ExecutionClass: req.ExecutionClass,
		IdempotencyKey: req.IdempotencyKey,
		Deadline:       req.Deadline,
	}

	// Connect to the persistent execution service.
	socketPath := a.defaultExecutionSocketPath()
	conn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to connect to execution service at %s: %v (is 'crabbox serve-execution' running?)", socketPath, err),
		})
	}
	defer conn.Close()

	// Send request (length-prefixed JSON, same ABI as invoke).
	payload, err := json.Marshal(execReq)
	if err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to marshal request: %v", err),
		})
	}

	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(payload) >> 24)
	lenBuf[1] = byte(len(payload) >> 16)
	lenBuf[2] = byte(len(payload) >> 8)
	lenBuf[3] = byte(len(payload))

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(lenBuf); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to send length: %v", err),
		})
	}
	if _, err := conn.Write(payload); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to send request: %v", err),
		})
	}

	// Read response (length-prefixed JSON).
	respLenBuf := make([]byte, 4)
	if _, err := readFull(conn, respLenBuf); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to read response length: %v", err),
		})
	}
	respLen := uint32(respLenBuf[0])<<24 | uint32(respLenBuf[1])<<16 | uint32(respLenBuf[2])<<8 | uint32(respLenBuf[3])
	if respLen > 4*1024*1024 {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("response too large: %d bytes", respLen),
		})
	}

	respBuf := make([]byte, respLen)
	if _, err := readFull(conn, respBuf); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to read response: %v", err),
		})
	}

	// Parse the response and write it to stdout.
	var execResp ExecutionResponse
	if err := json.Unmarshal(respBuf, &execResp); err != nil {
		return writeExecResponse(a.Stdout, ExecutionResponse{
			Status:      "FAILED",
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to parse response: %v", err),
		})
	}

	return writeExecResponse(a.Stdout, execResp)
}

// defaultExecutionSocketPath returns the default execution service
// socket path (same logic as serve.go's defaultSocketPath).
func (a App) defaultExecutionSocketPath() string {
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return xdg + "/crabedence/execution.sock"
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}
	return "/tmp/crabedence-" + user + "/execution.sock"
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
