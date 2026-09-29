package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"
)

// The stdin/stdout bridge must apply the same strict ABI rules the socket
// applies. A permissive decode here silently rewrites what the planner sent —
// dropping unknown fields, keeping the last duplicate key — so the planner
// cannot tell that the request it composed is not the request that ran.

func TestExecRefusesAServerResolvedField(t *testing.T) {
	echoService(t, echoHandler())
	request := `{"capability":"system.echo","arguments":{"message":"hi"},"authority":{"principal":"alice@example.com"},"execution_route":"LOCAL"}`
	resp := runExec(t, request)
	if resp.Status != execution.StatusFailed {
		t.Fatalf("expected FAILED, got %s: %s", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureInvalidRequest) {
		t.Fatalf("expected INVALID_REQUEST, got %s: %s", resp.FailureCode, resp.Error)
	}
	if !strings.Contains(resp.Error, "unknown field") {
		t.Fatalf("the refusal must name the rule, got %q", resp.Error)
	}
}

func TestExecRefusesADuplicateKey(t *testing.T) {
	echoService(t, echoHandler())
	request := `{"capability":"system.echo","capability":"system.echo","arguments":{},"authority":{"principal":"alice@example.com"}}`
	resp := runExec(t, request)
	if resp.FailureCode != string(capability.FailureInvalidRequest) {
		t.Fatalf("expected INVALID_REQUEST, got %s: %s", resp.FailureCode, resp.Error)
	}
	if !strings.Contains(resp.Error, "duplicate key") {
		t.Fatalf("the refusal must name the rule, got %q", resp.Error)
	}
}

func TestExecRefusesTrailingData(t *testing.T) {
	echoService(t, echoHandler())
	request := `{"capability":"system.echo","arguments":{},"authority":{"principal":"alice@example.com"}}{}`
	resp := runExec(t, request)
	if resp.FailureCode != string(capability.FailureInvalidRequest) {
		t.Fatalf("expected INVALID_REQUEST, got %s: %s", resp.FailureCode, resp.Error)
	}
	if !strings.Contains(resp.Error, "trailing data") {
		t.Fatalf("the refusal must name the rule, got %q", resp.Error)
	}
}

// runExec drives the bridge end to end against the harness service and
// returns the decoded response.
func runExec(t *testing.T, request string) ExecutionResponse {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader(request)}
	if err := app.Run(context.Background(), []string{"exec"}); err != nil {
		t.Fatalf("exec: %v (stderr: %s)", err, stderr.String())
	}
	var resp ExecutionResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("exec output is not a response: %v (%q)", err, stdout.String())
	}
	return resp
}
