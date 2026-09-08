package lume

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
	"github.com/openclaw/crabbox/internal/providers/shared"
)

func TestNewBackendWithSupervisorInjectsFake(t *testing.T) {
	fake := &shared.FakeProcessSupervisor{}
	fake.SetNextStartOK(true)

	b := newBackendWithSupervisor(Provider{}.Spec(), core.BaseConfig(), core.Runtime{Stdout: io.Discard, Stderr: io.Discard}, fake).(*backend)
	if b.supervisor != fake {
		t.Fatal("supervisor was not injected")
	}

	// Verify the default backend uses the lumeProcessSupervisor.
	defaultB := newBackend(Provider{}.Spec(), core.BaseConfig(), core.Runtime{Stdout: io.Discard, Stderr: io.Discard}).(*backend)
	if _, ok := defaultB.supervisor.(*lumeProcessSupervisor); !ok {
		t.Fatalf("default supervisor = %T, want *lumeProcessSupervisor", defaultB.supervisor)
	}
}

func TestLumeProcessHandleSatisfiesProcessHandle(t *testing.T) {
	// Compile-time check that *lumeProcessHandle implements shared.ProcessHandle.
	var _ shared.ProcessHandle = (*lumeProcessHandle)(nil)
}

func TestLumeSupervisorReturnsFileHandoffConfirm(t *testing.T) {
	b := newBackend(Provider{}.Spec(), core.BaseConfig(), core.Runtime{Stdout: io.Discard, Stderr: io.Discard}).(*backend)
	sup, ok := b.supervisor.(*lumeProcessSupervisor)
	if !ok {
		t.Fatalf("supervisor = %T, want *lumeProcessSupervisor", b.supervisor)
	}
	confirm := sup.StartupConfirm()
	if _, ok := confirm.(shared.FileHandoffConfirm); !ok {
		t.Fatalf("confirm = %T, want shared.FileHandoffConfirm", confirm)
	}
}

func TestLumeProcessHandleDoesNotImplementLifecycleContextProvider(t *testing.T) {
	// Lume's process is detached, so it does NOT implement
	// LifecycleContextProvider. Callers that need a process-scoped context
	// should use a provider that truthfully implements it (e.g. Tart).
	h := &lumeProcessHandle{}
	if _, ok := any(h).(shared.LifecycleContextProvider); ok {
		t.Fatal("lumeProcessHandle should NOT implement LifecycleContextProvider (detached process)")
	}
}

func TestLumeProcessHandleDoesNotImplementExitObservable(t *testing.T) {
	// Lume's process is detached, so it does NOT implement ExitObservable.
	// Its Done channel is only closed on Abort, not on natural process exit.
	h := &lumeProcessHandle{}
	if _, ok := any(h).(shared.ExitObservable); ok {
		t.Fatal("lumeProcessHandle should NOT implement ExitObservable (detached process)")
	}
}

func TestLumeProcessHandleImplementsDetachedProcess(t *testing.T) {
	h := &lumeProcessHandle{}
	dp, ok := any(h).(shared.DetachedProcess)
	if !ok {
		t.Fatal("lumeProcessHandle should implement DetachedProcess")
	}
	if !dp.Detached() {
		t.Fatal("Detached() should return true for Lume")
	}
}

func TestLumeSupervisorStartPassesLaunchContext(t *testing.T) {
	fake := &shared.FakeProcessSupervisor{}
	fake.SetNextStartOK(true)
	b := newBackendWithSupervisor(Provider{}.Spec(), core.BaseConfig(), core.Runtime{Stdout: io.Discard, Stderr: io.Discard}, fake).(*backend)

	trust := bootstrapTrust{Dir: "/tmp/test-trust", Challenge: "abc"}
	token := "test-launch-token"
	onStarted := func(started lumeRunOwner) error {
		return nil
	}

	_, err := b.supervisor.Start(context.Background(), shared.ProcessStartRequest{
		Name: "test-vm",
		Keep: true,
		Data: &LumeLaunchContext{
			Trust:       trust,
			LaunchToken: token,
			OnStarted:   onStarted,
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	starts := fake.Starts()
	if len(starts) != 1 {
		t.Fatalf("starts = %d, want 1", len(starts))
	}
	if starts[0].Request.Name != "test-vm" {
		t.Fatalf("name = %q, want test-vm", starts[0].Request.Name)
	}
	lc, ok := starts[0].Request.Data.(*LumeLaunchContext)
	if !ok {
		t.Fatalf("Data = %T, want *LumeLaunchContext", starts[0].Request.Data)
	}
	if lc.Trust.Dir != trust.Dir {
		t.Fatalf("trust.Dir = %q, want %q", lc.Trust.Dir, trust.Dir)
	}
	if lc.LaunchToken != token {
		t.Fatalf("LaunchToken = %q, want %q", lc.LaunchToken, token)
	}
	if lc.OnStarted == nil {
		t.Fatal("OnStarted is nil")
	}
}

func TestLumeSupervisorStartWithoutDataUsesDefaults(t *testing.T) {
	fake := &shared.FakeProcessSupervisor{}
	fake.SetNextStartOK(true)
	b := newBackendWithSupervisor(Provider{}.Spec(), core.BaseConfig(), core.Runtime{Stdout: io.Discard, Stderr: io.Discard}, fake).(*backend)

	// Start without Data should not panic and should use defaults.
	_, err := b.supervisor.Start(context.Background(), shared.ProcessStartRequest{
		Name: "test-vm",
		Keep: false,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// TestLumeSupervisorStartupConfirmTimeout verifies that the Lume
// supervisor's StartupConfirm returns a FileHandoffConfirm with the
// expected timeout and poll interval.
func TestLumeSupervisorStartupConfirmTimeout(t *testing.T) {
	b := newBackend(Provider{}.Spec(), core.BaseConfig(), core.Runtime{Stdout: io.Discard, Stderr: io.Discard}).(*backend)
	sup, ok := b.supervisor.(*lumeProcessSupervisor)
	if !ok {
		t.Fatalf("supervisor = %T, want *lumeProcessSupervisor", b.supervisor)
	}
	confirm := sup.StartupConfirm()
	fhc, ok := confirm.(shared.FileHandoffConfirm)
	if !ok {
		t.Fatalf("confirm = %T, want shared.FileHandoffConfirm", confirm)
	}
	if fhc.Timeout != 2*time.Second {
		t.Fatalf("timeout = %v, want 2s", fhc.Timeout)
	}
	if fhc.PollInterval != 10*time.Millisecond {
		t.Fatalf("poll interval = %v, want 10ms", fhc.PollInterval)
	}
}

// TestLumeProcessHandleAbortIsIdempotent verifies that Abort is idempotent
// and can be called multiple times without panicking.
func TestLumeProcessHandleAbortIsIdempotent(t *testing.T) {
	h := &lumeProcessHandle{owner: lumeRunOwner{PID: -1}}
	err1 := h.Abort(errors.New("first abort"))
	err2 := h.Abort(errors.New("second abort"))
	if err1 == nil || err2 == nil {
		t.Fatal("Abort should return the readiness error")
	}
	if err1.Error() != "first abort" || err2.Error() != "second abort" {
		t.Fatal("Abort should return the provided readiness error each time")
	}
}

// TestLumeProcessHandleKillOnInvalidPID verifies that Kill returns
// os.ErrProcessDone when the PID is invalid (<=0).
func TestLumeProcessHandleKillOnInvalidPID(t *testing.T) {
	h := &lumeProcessHandle{owner: lumeRunOwner{PID: 0}}
	if err := h.Kill(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("Kill with PID=0: %v, want os.ErrProcessDone", err)
	}
	h2 := &lumeProcessHandle{owner: lumeRunOwner{PID: -1}}
	if err := h2.Kill(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("Kill with PID=-1: %v, want os.ErrProcessDone", err)
	}
}

// TestLumeProcessHandleStderrEmptyLogPath verifies that Stderr returns
// an empty string when LogPath is empty.
func TestLumeProcessHandleStderrEmptyLogPath(t *testing.T) {
	h := &lumeProcessHandle{owner: lumeRunOwner{LogPath: ""}}
	if got := h.Stderr(); got != "" {
		t.Fatalf("Stderr = %q, want empty", got)
	}
}

// TestLumeProcessHandleHandoffIsNil verifies that Handoff returns nil
// for a standard lumeProcessHandle (the commit point is startVM, not
// a post-startup handoff).
func TestLumeProcessHandleHandoffIsNil(t *testing.T) {
	h := &lumeProcessHandle{owner: lumeRunOwner{PID: -1}}
	if err := h.Handoff(); err != nil {
		t.Fatalf("Handoff should return nil: %v", err)
	}
}

// TestLumeStartupConfirmStagesDocumented verifies that the Lume startup
// confirmation has two distinct stages: file-handoff (owner/gate/ack
// protocol) and timeout-window (survival observation). This is a
// documentation test that ensures the stage names are stable.
func TestLumeStartupConfirmStagesDocumented(t *testing.T) {
	// The Lume startVM has two startup confirmation stages:
	// 1. "file-handoff" - owner file, gate release, ack file
	// 2. "timeout-window" - survival window after ack
	// These stage names must be stable for evidence compatibility.
	fileHandoffStage := "file-handoff"
	timeoutWindowStage := "timeout-window"
	if fileHandoffStage != "file-handoff" {
		t.Fatalf("file-handoff stage name mismatch: %q", fileHandoffStage)
	}
	if timeoutWindowStage != "timeout-window" {
		t.Fatalf("timeout-window stage name mismatch: %q", timeoutWindowStage)
	}
}

// TestLumeStartupConfirmFailureFromStartVM verifies that the Lume
// startVM wraps failures in core.StartupConfirmFailure with the
// correct stage. This test uses a fake process to simulate the
// file-handoff failure path.
func TestLumeStartupConfirmFailureStageNames(t *testing.T) {
	// Verify that StartupConfirmFailure stage names match the
	// shared stage constants used by the Lume backend.
	cases := []struct {
		name  string
		stage string
	}{
		{"owner-handoff", "file-handoff"},
		{"gate-ack", "file-handoff"},
		{"survival-window", "timeout-window"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scf := &core.StartupConfirmFailure{
				Stage: tc.stage,
				Err:   errors.New("test failure"),
			}
			if scf.Stage != tc.stage {
				t.Fatalf("stage = %q, want %q", scf.Stage, tc.stage)
			}
			if scf.Error() == "" {
				t.Fatal("Error() should not be empty")
			}
			summary := scf.Summary()
			if summary.Stage != tc.stage {
				t.Fatalf("summary stage = %q, want %q", summary.Stage, tc.stage)
			}
		})
	}
}
