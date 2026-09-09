package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/openclaw/crabbox/internal/execution"
)

// invokeCommand implements `crabbox invoke`: a planner-agnostic CLI
// client that sends a capability invocation to the execution service
// over the same Unix-socket ABI that any planner would use.
//
// This proves planner independence: the same ABI works for NEMO,
// Hermes, a test client, or any future planner.
//
// Usage:
//   crabbox invoke --capability system.info --principal alice@example.com
//   crabbox invoke --capability test.counter.increment \
//     --principal alice@example.com --authority-ref grant_123 \
//     --idempotency-key key_001 \
//     --arguments '{"counter":"test","by":1}'
func (a App) invokeCommand(ctx context.Context, socketPath, capability, principal, authorityRef, idempotencyKey, argumentsJSON, executionClass, deadline string) error {
	if capability == "" {
		return fmt.Errorf("--capability is required")
	}
	if principal == "" {
		return fmt.Errorf("--principal is required")
	}

	var args json.RawMessage
	if argumentsJSON != "" {
		args = json.RawMessage(argumentsJSON)
	} else {
		args = json.RawMessage(`{}`)
	}

	req := execution.Request{
		Capability:     capability,
		Arguments:      args,
		Authority:      execution.RequestAuthority{Principal: principal, AuthorityRef: authorityRef},
		ExecutionClass: executionClass,
		IdempotencyKey: idempotencyKey,
		Deadline:       deadline,
	}

	conn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to execution service at %s: %w\nIs 'crabbox serve-execution' running?", socketPath, err)
	}
	defer conn.Close()

	// Send request
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(payload) >> 24)
	lenBuf[1] = byte(len(payload) >> 16)
	lenBuf[2] = byte(len(payload) >> 8)
	lenBuf[3] = byte(len(payload))

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to send length: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	respLenBuf := make([]byte, 4)
	if _, err := readFull(conn, respLenBuf); err != nil {
		return fmt.Errorf("failed to read response length: %w", err)
	}
	respLen := uint32(respLenBuf[0])<<24 | uint32(respLenBuf[1])<<16 | uint32(respLenBuf[2])<<8 | uint32(respLenBuf[3])
	if respLen > 4*1024*1024 {
		return fmt.Errorf("response too large: %d bytes", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := readFull(conn, respBuf); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var resp execution.Response
	if err := json.Unmarshal(respBuf, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Print response as JSON
	output, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Fprintf(a.Stdout, "%s\n", output)

	// Exit with non-zero if the request was denied or failed
	switch resp.Status {
	case execution.StatusSucceeded:
		return nil
	case execution.StatusDenied:
		os.Exit(2)
	case execution.StatusFailed:
		os.Exit(1)
	case execution.StatusUnknown:
		os.Exit(3)
	default:
		return fmt.Errorf("unknown status: %s", resp.Status)
	}
	return nil
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
