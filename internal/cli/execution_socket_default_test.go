package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/execution"
)

// The default-to-default contract: `crabbox serve-exec`,
// `crabbox invoke`, and `crabbox exec` must all resolve the same
// socket path with no flags, so starting the documented service and
// calling the documented client actually meet.

// echoService starts a real execution service at the canonical default
// socket path, sandboxed under a private XDG_RUNTIME_DIR — the same
// resolution production uses on Linux. The runtime dir is short on
// purpose: macOS caps Unix socket paths at 104 bytes and t.TempDir()
// embeds the test name.
func echoService(t *testing.T, handler execution.Handler) string {
	t.Helper()
	runtimeDir, err := os.MkdirTemp("", "cbx-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runtimeDir) })
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	socketPath := execution.DefaultSocketPath()
	if socketPath != filepath.Join(runtimeDir, "crabedence", "execution.sock") {
		t.Fatalf("unexpected canonical default %q", socketPath)
	}
	registry := capability.NewRegistry()
	if err := execution.RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := execution.NewService(registry, handler, socketPath)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { service.Stop() })
	return socketPath
}

func echoHandler() execution.Handler {
	return execution.NewMultiHandler(map[string]execution.Handler{
		"system": execution.NewEchoHandler(),
	})
}

func TestServeExecHelpShowsTheCanonicalDefaultSocket(t *testing.T) {
	socketPath := echoService(t, echoHandler())
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader("")}
	if err := app.Run(context.Background(), []string{"serve-exec", "--help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
	// Kong writes help to the configured stdout.
	text := stdout.String() + stderr.String()
	if !strings.Contains(text, socketPath) {
		t.Fatalf("serve-exec help must show the canonical default %q, got:\n%s", socketPath, text)
	}
}

func TestInvokeDefaultSocketReachesTheDefaultService(t *testing.T) {
	echoService(t, echoHandler())
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader("")}
	// No --socket: the command must use the canonical default and find
	// the service the default serve-exec would have started.
	err := app.Run(context.Background(), []string{
		"invoke",
		"--capability", "system.echo",
		"--principal", "alice@example.com",
		"--arguments", `{"message":"default-to-default"}`,
	})
	if err != nil {
		t.Fatalf("invoke: %v (stderr: %s)", err, stderr.String())
	}
	var resp execution.Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("invoke output is not a response: %v (%q)", err, stdout.String())
	}
	if resp.Status != execution.StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}
}

func TestExecDefaultSocketReachesTheDefaultService(t *testing.T) {
	echoService(t, echoHandler())
	request := `{"capability":"system.echo","arguments":{"message":"bridge"},"authority":{"principal":"alice@example.com"}}`
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader(request)}
	// No flags at all: the stdin/stdout bridge must use the canonical
	// default too.
	if err := app.Run(context.Background(), []string{"exec"}); err != nil {
		t.Fatalf("exec: %v (stderr: %s)", err, stderr.String())
	}
	var resp ExecutionResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("exec output is not a response: %v (%q)", err, stdout.String())
	}
	if resp.Status != execution.StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}
}

// stallHandler delays the answer so a client's response wait expires
// mid-flight.
type stallHandler struct {
	inner execution.Handler
	delay time.Duration
}

func (h stallHandler) Execute(ctx context.Context, req execution.Request, desc capability.ResolvedDescriptor) execution.Response {
	time.Sleep(h.delay)
	return h.inner.Execute(ctx, req, desc)
}

// TestExecPostDispatchFailureIsUnknown pins the wire contract for the
// subprocess bridge: after transmission, a lost response is UNKNOWN —
// never FAILED, which a planner could mistake for a definitive failure
// and retry with a fresh idempotency key. The command's wait is
// shortened directly because `exec` is a Kong passthrough command and
// cannot take flags.
func TestExecPostDispatchFailureIsUnknown(t *testing.T) {
	echoService(t, stallHandler{inner: echoHandler(), delay: 2 * time.Second})
	request := `{"capability":"system.echo","arguments":{"message":"slow"},"authority":{"principal":"alice@example.com"}}`
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader(request)}
	if err := app.execCommand(context.Background(), nil, 100*time.Millisecond); err != nil {
		t.Fatalf("exec: %v (stderr: %s)", err, stderr.String())
	}
	var resp ExecutionResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("exec output is not a response: %v (%q)", err, stdout.String())
	}
	if resp.Status != execution.StatusUnknown {
		t.Fatalf("expected UNKNOWN after a post-dispatch wait expiry, got %s: %s", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureExecutionUnknown) {
		t.Fatalf("expected EXECUTION_UNKNOWN, got %s", resp.FailureCode)
	}
	if !strings.Contains(resp.Error, "reconcile before retrying") {
		t.Fatalf("the UNKNOWN response must tell the caller to reconcile, got %q", resp.Error)
	}
}

// TestExecPreDispatchFailureIsFailed is the companion contract: a
// service that is not running is a definitive failure — the invocation
// cannot have happened — so the bridge keeps reporting FAILED.
func TestExecPreDispatchFailureIsFailed(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	request := `{"capability":"system.echo","arguments":{"message":"nobody home"},"authority":{"principal":"alice@example.com"}}`
	var stdout, stderr bytes.Buffer
	app := App{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader(request)}
	if err := app.Run(context.Background(), []string{"exec"}); err != nil {
		t.Fatalf("exec: %v (stderr: %s)", err, stderr.String())
	}
	var resp ExecutionResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("exec output is not a response: %v (%q)", err, stdout.String())
	}
	if resp.Status != "FAILED" {
		t.Fatalf("expected FAILED before dispatch, got %s: %s", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureInternalError) {
		t.Fatalf("expected INTERNAL_ERROR, got %s", resp.FailureCode)
	}
}
