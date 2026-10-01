package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"
)

// invokeCommand implements `crabbox invoke`: a planner-agnostic CLI
// client that sends a capability invocation to the execution service
// over the same Unix-socket ABI that any planner would use.
//
// This proves planner independence: the same ABI works for NEMO,
// Hermes, a test client, or any future planner.
//
// Transport failures obey the durable execution contract's dispatch
// boundary: a failure before the request frame is fully transmitted is
// an ordinary error (the invocation did not happen), while a failure
// after transmission is printed as a structured UNKNOWN response and
// exits 3 — the side effect may have occurred and must be reconciled,
// never treated as a definitive failure.
//
// Usage:
//
//	crabbox invoke --capability system.info --principal alice@example.com
//	crabbox invoke --capability test.counter.increment \
//	  --principal alice@example.com --idempotency-key key_001 \
//	  --arguments '{"counter":"test","by":1}'
//
// No authority reference travels on argv — process arguments are visible
// to every account on the host. When a deployment's peer map
// authenticates the caller, the service resolves the principal's grant
// itself; when a specific grant must be named anyway, it arrives through
// the CRABEDENCE_AUTHORITY_REF environment variable, which unlike argv
// is not readable by other accounts.
func (a App) invokeCommand(ctx context.Context, socketPath, capabilityName, principal, idempotencyKey, argumentsJSON, executionClass, deadline string, timeout time.Duration) error {
	if capabilityName == "" {
		return fmt.Errorf("--capability is required")
	}
	if principal == "" {
		return fmt.Errorf("--principal is required")
	}
	authorityRef := os.Getenv("CRABEDENCE_AUTHORITY_REF")

	var args json.RawMessage
	if argumentsJSON != "" {
		args = json.RawMessage(argumentsJSON)
	} else {
		args = json.RawMessage(`{}`)
	}

	req := execution.Request{
		Capability:     capabilityName,
		Arguments:      args,
		Authority:      execution.RequestAuthority{Principal: principal, AuthorityRef: authorityRef},
		ExecutionClass: executionClass,
		IdempotencyKey: idempotencyKey,
		Deadline:       deadline,
	}

	client := execution.NewClient(socketPath, execution.ClientOptions{Timeout: timeout})
	resp, err := client.Invoke(ctx, req)
	if err != nil {
		if execution.AmbiguousOutcome(err) {
			// The request was transmitted; the outcome is unknown.
			// Exit 3 matches the UNKNOWN status, so a caller that
			// scripts on the exit code reconciles instead of
			// re-invoking with a fresh idempotency key.
			resp = execution.Response{
				Status:      execution.StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error: fmt.Sprintf(
					"outcome unknown: %v (the request may have been dispatched to the execution service; reconcile before retrying)",
					err,
				),
			}
			a.printInvokeResponse(resp)
			os.Exit(3)
		}
		return fmt.Errorf("failed to invoke %s: %w", capabilityName, err)
	}

	a.printInvokeResponse(resp)

	// Exit with non-zero if the request was denied or failed
	switch resp.Status {
	case execution.StatusSucceeded:
		return nil
	case execution.StatusDenied:
		os.Exit(2)
	case execution.StatusFailed:
		os.Exit(1)
	case execution.StatusUnknown, execution.StatusInFlight:
		// IN_FLIGHT is a valid wire status but not a terminal outcome;
		// the caller's answer is "not yet known", which is exit 3.
		os.Exit(3)
	default:
		return fmt.Errorf("unknown status: %s", resp.Status)
	}
	return nil
}

// printInvokeResponse writes the response as indented JSON to stdout.
func (a App) printInvokeResponse(resp execution.Response) {
	output, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Fprintf(a.Stdout, "%s\n", output)
}
