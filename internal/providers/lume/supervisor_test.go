package lume

import (
	"context"
	"io"
	"testing"

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
