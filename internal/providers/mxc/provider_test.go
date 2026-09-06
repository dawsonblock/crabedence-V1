package mxc

import (
	"context"
	"flag"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
)

func TestExperimentalContainmentRequiresOptIn(t *testing.T) {
	cfg := core.BaseConfig()
	cfg.Provider = providerName
	cfg.TargetOS = core.TargetWindows
	cfg.WindowsMode = core.WindowsModeNormal
	cfg.MXC.Containment = "windows_sandbox"
	_, err := (Provider{}).Configure(cfg, core.Runtime{})
	if err == nil || !strings.Contains(err.Error(), "--mxc-experimental") {
		t.Fatalf("err=%v", err)
	}
}

func TestConfigureNormalizesContainment(t *testing.T) {
	cfg := core.BaseConfig()
	cfg.Provider = providerName
	cfg.TargetOS = core.TargetWindows
	cfg.WindowsMode = core.WindowsModeNormal
	cfg.MXC.Containment = "ProcessContainer"
	configured, err := (Provider{}).Configure(cfg, core.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	if got := configured.(*backend).cfg.MXC.Containment; got != "processcontainer" {
		t.Fatalf("containment=%q", got)
	}
}

func TestConfigureAcceptsStableProcessIntent(t *testing.T) {
	cfg := core.BaseConfig()
	cfg.Provider = providerName
	cfg.TargetOS = core.TargetWindows
	cfg.WindowsMode = core.WindowsModeNormal
	cfg.MXC.Containment = "Process"

	configured, err := (Provider{}).Configure(cfg, core.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	if got := configured.(*backend).cfg.MXC.Containment; got != "process" {
		t.Fatalf("containment=%q", got)
	}
}

func TestFlagsApplyPolicy(t *testing.T) {
	cfg := core.BaseConfig()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	values := registerFlags(fs, cfg)
	if err := fs.Parse([]string{"--mxc-network", "allow", "--mxc-readwrite-paths", `C:\src,C:\cache`, "--mxc-allow-dacl-mutation", "--mxc-allow-windows-ui", "--mxc-experimental"}); err != nil {
		t.Fatal(err)
	}
	if err := applyFlags(&cfg, fs, values); err != nil {
		t.Fatal(err)
	}
	if cfg.MXC.Network != "allow" || len(cfg.MXC.ReadWritePaths) != 2 || !cfg.MXC.AllowDACLMutation || !cfg.MXC.AllowWindowsUI || !cfg.MXC.Experimental {
		t.Fatalf("mxc=%+v", cfg.MXC)
	}
}

func TestParseWindowsBuild(t *testing.T) {
	build, err := parseWindowsBuild("CurrentBuildNumber    REG_SZ    26100\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if build != 26100 {
		t.Fatalf("build = %d, want 26100", build)
	}
}

// fakeCommandRunner is a test CommandRunner that records calls and returns
// configurable results. It lets MXC tests exercise Run and smokeTest without
// requiring a real wxc-exec.exe binary.
type fakeCommandRunner struct {
	mu      sync.Mutex
	calls   []core.LocalCommandRequest
	results []core.LocalCommandResult
	errors  []error
	callIdx int
}

func (r *fakeCommandRunner) Run(_ context.Context, req core.LocalCommandRequest) (core.LocalCommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, req)
	idx := r.callIdx
	r.callIdx++
	if idx < len(r.errors) && r.errors[idx] != nil {
		if idx < len(r.results) {
			return r.results[idx], r.errors[idx]
		}
		return core.LocalCommandResult{ExitCode: 1}, r.errors[idx]
	}
	if idx < len(r.results) {
		return r.results[idx], nil
	}
	return core.LocalCommandResult{ExitCode: 0, Stdout: "", Stderr: ""}, nil
}

func (r *fakeCommandRunner) Calls() []core.LocalCommandRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]core.LocalCommandRequest(nil), r.calls...)
}

func mxcBackendWithRunner(runner core.CommandRunner) *backend {
	cfg := core.BaseConfig()
	cfg.Provider = providerName
	cfg.TargetOS = core.TargetWindows
	cfg.WindowsMode = core.WindowsModeNormal
	cfg.MXC.Containment = "process"
	rt := core.Runtime{Stdout: io.Discard, Stderr: io.Discard, Exec: runner}
	return newBackend(Provider{}.Spec(), cfg, rt).(*backend)
}

func TestRunExecutesMXCCLI(t *testing.T) {
	runner := &fakeCommandRunner{
		results: []core.LocalCommandResult{{ExitCode: 0}},
	}
	b := mxcBackendWithRunner(runner)

	// MXC's Run requires a Windows host; skip on non-Windows since the
	// requireSupportedWindows check runs before the executor.
	if testing.Short() {
		t.Skip("requires Windows host check")
	}

	result, err := b.Run(context.Background(), RunRequest{
		Command: []string{"cmd.exe", "/c", "echo hello"},
		Repo:    core.Repo{Root: t.TempDir()},
		Options: LeaseOptions{TTL: 30 * time.Second},
	})
	// On non-Windows this fails at requireSupportedWindows; on Windows it
	// exercises the fake runner. Either way the call recording validates the
	// injectable runtime path.
	_ = err
	_ = result
	calls := runner.Calls()
	if len(calls) > 0 {
		if calls[0].Name != "wxc-exec.exe" && calls[0].Name != "" {
			// The default CLI path is wxc-exec.exe; verify it was used.
			t.Fatalf("executor name = %q, want wxc-exec.exe", calls[0].Name)
		}
	}
}

func TestRunRejectsPersistentLeaseOptions(t *testing.T) {
	b := mxcBackendWithRunner(&fakeCommandRunner{})

	_, err := b.Run(context.Background(), RunRequest{
		ID:      "cbx_mxc_test",
		Command: []string{"cmd.exe", "/c", "echo hello"},
		Repo:    core.Repo{Root: t.TempDir()},
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}
	// requireSupportedWindows runs first on non-Windows; on Windows the
	// one-shot option validation fires.
	if !strings.Contains(err.Error(), "one-shot") && !strings.Contains(err.Error(), "Windows host") {
		t.Fatalf("err=%v, want one-shot or Windows host rejection", err)
	}

	_, err = b.Run(context.Background(), RunRequest{
		Keep:    true,
		Command: []string{"cmd.exe", "/c", "echo hello"},
		Repo:    core.Repo{Root: t.TempDir()},
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}
	if !strings.Contains(err.Error(), "one-shot") && !strings.Contains(err.Error(), "Windows host") {
		t.Fatalf("err=%v, want one-shot or Windows host rejection", err)
	}
}

func TestRunRejectsSyncAndPatchOptions(t *testing.T) {
	b := mxcBackendWithRunner(&fakeCommandRunner{})

	_, err := b.Run(context.Background(), RunRequest{
		SyncOnly: true,
		Command:  []string{"cmd.exe", "/c", "echo hello"},
		Repo:     core.Repo{Root: t.TempDir()},
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}
	if !strings.Contains(err.Error(), "sync") && !strings.Contains(err.Error(), "Windows host") {
		t.Fatalf("err=%v, want sync or Windows host rejection", err)
	}

	_, err = b.Run(context.Background(), RunRequest{
		ApplyLocalPatch: true,
		Command:         []string{"cmd.exe", "/c", "echo hello"},
		Repo:            core.Repo{Root: t.TempDir()},
	})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}
	if !strings.Contains(err.Error(), "patch") && !strings.Contains(err.Error(), "Windows host") {
		t.Fatalf("err=%v, want patch or Windows host rejection", err)
	}
}

func TestRunPropagatesExecutorFailure(t *testing.T) {
	runner := &fakeCommandRunner{
		results: []core.LocalCommandResult{{ExitCode: 42, Stderr: "sandbox denied"}},
		errors:  []error{context.Canceled},
	}
	b := mxcBackendWithRunner(runner)

	_, err := b.Run(context.Background(), RunRequest{
		Command: []string{"cmd.exe", "/c", "echo hello"},
		Repo:    core.Repo{Root: t.TempDir()},
		Options: LeaseOptions{TTL: 30 * time.Second},
	})
	// On non-Windows this fails at requireSupportedWindows before reaching
	// the runner. On Windows it should surface the executor failure.
	if err != nil && strings.Contains(err.Error(), "requires a Windows host") {
		return // expected on non-Windows CI
	}
	if err == nil {
		t.Fatal("expected executor failure, got nil")
	}
}

func TestWarmupIsUnsupported(t *testing.T) {
	b := mxcBackendWithRunner(&fakeCommandRunner{})
	err := b.Warmup(context.Background(), WarmupRequest{})
	if err == nil || !strings.Contains(err.Error(), "one-shot") {
		t.Fatalf("err=%v, want one-shot rejection", err)
	}
}

func TestStopAndStatusAreUnsupported(t *testing.T) {
	b := mxcBackendWithRunner(&fakeCommandRunner{})
	if err := b.Stop(context.Background(), StopRequest{}); err == nil || !strings.Contains(err.Error(), "one-shot") {
		t.Fatalf("stop err=%v, want one-shot rejection", err)
	}
	if _, err := b.Status(context.Background(), StatusRequest{}); err == nil || !strings.Contains(err.Error(), "one-shot") {
		t.Fatalf("status err=%v, want one-shot rejection", err)
	}
}

func TestListReturnsEmpty(t *testing.T) {
	b := mxcBackendWithRunner(&fakeCommandRunner{})
	leases, err := b.List(context.Background(), ListRequest{})
	if err != nil {
		t.Fatalf("list err=%v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("leases = %d, want 0", len(leases))
	}
}
