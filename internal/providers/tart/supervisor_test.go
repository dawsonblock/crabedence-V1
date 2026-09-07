package tart

import (
	"context"
	"testing"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
	"github.com/openclaw/crabbox/internal/providers/shared"
)

func TestNewBackendWithSupervisorInjectsFake(t *testing.T) {
	fake := &shared.FakeProcessSupervisor{}
	fake.SetNextStartOK(true)

	b := newBackendWithSupervisor(Provider{}.Spec(), core.BaseConfig(), core.Runtime{}, fake).(*backend)
	if b.supervisor != fake {
		t.Fatal("supervisor was not injected")
	}

	// Verify the default backend uses the tartProcessSupervisor.
	defaultB := newBackend(Provider{}.Spec(), core.BaseConfig(), core.Runtime{}).(*backend)
	if _, ok := defaultB.supervisor.(*tartProcessSupervisor); !ok {
		t.Fatalf("default supervisor = %T, want *tartProcessSupervisor", defaultB.supervisor)
	}
}

func TestStartSupervisedVMUsesInjectedSupervisor(t *testing.T) {
	fake := &shared.FakeProcessSupervisor{}
	fake.SetNextStartOK(true)

	b := newBackendWithSupervisor(Provider{}.Spec(), core.BaseConfig(), core.Runtime{}, fake).(*backend)

	handle, err := b.startSupervisedVM(context.Background(), "test-vm", false)
	if err != nil {
		t.Fatalf("startSupervisedVM: %v", err)
	}
	if handle == nil {
		t.Fatal("handle is nil")
	}

	starts := fake.Starts()
	if len(starts) != 1 {
		t.Fatalf("starts = %d, want 1", len(starts))
	}
	if starts[0].Request.Name != "test-vm" {
		t.Fatalf("name = %q, want test-vm", starts[0].Request.Name)
	}
	if starts[0].Request.Keep {
		t.Fatal("keep = true, want false")
	}
}

func TestStartupProcessSatisfiesFullProcessHandle(t *testing.T) {
	// Compile-time check that *startupProcess implements shared.FullProcessHandle
	// (ProcessHandle + ProcessKiller + ProcessHandoff + ProcessStderr +
	// ExitObservable + LifecycleContextProvider). Tart owns its child's
	// lifecycle and can truthfully implement all capabilities.
	var _ shared.FullProcessHandle = (*startupProcess)(nil)
}

func TestStartupProcessImplementsExitObservable(t *testing.T) {
	// Tart's startupProcess implements ExitObservable because it can
	// truthfully observe process exit (Done is closed when the process
	// exits and is reaped).
	var _ shared.ExitObservable = (*startupProcess)(nil)
}

func TestStartupProcessImplementsLifecycleContextProvider(t *testing.T) {
	// Tart's startupProcess implements LifecycleContextProvider because it
	// exposes a process-scoped lifecycle context.
	var _ shared.LifecycleContextProvider = (*startupProcess)(nil)
}

func TestStartupProcessDoesNotImplementDetachedProcess(t *testing.T) {
	// Tart's startupProcess does NOT implement DetachedProcess because
	// Tart owns its child's lifecycle.
	p := &startupProcess{}
	if _, ok := any(p).(shared.DetachedProcess); ok {
		t.Fatal("startupProcess should NOT implement DetachedProcess (Tart owns lifecycle)")
	}
}

func TestStartupProcessContextReturnsLifecycleContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &startupProcess{ctx: ctx}
	if p.Context() != ctx {
		t.Fatal("Context() did not return the lifecycle context")
	}
	cancel()
	if err := p.Context().Err(); err == nil {
		t.Fatal("Context() should be cancelled after cancel")
	}
}

func TestStartSupervisedVMReturnsProcessHandle(t *testing.T) {
	fake := &shared.FakeProcessSupervisor{}
	fake.SetNextStartOK(true)
	b := newBackendWithSupervisor(Provider{}.Spec(), core.BaseConfig(), core.Runtime{}, fake).(*backend)
	handle, err := b.startSupervisedVM(context.Background(), "test-vm", false)
	if err != nil {
		t.Fatalf("startSupervisedVM: %v", err)
	}
	if handle == nil {
		t.Fatal("handle is nil")
	}
	// The fake handle implements FullProcessHandle, which includes
	// LifecycleContextProvider. Verify via type assertion.
	lcp, ok := handle.(shared.LifecycleContextProvider)
	if !ok {
		t.Fatal("handle does not implement LifecycleContextProvider")
	}
	if lcp.Context() == nil {
		t.Fatal("Context() returned nil")
	}
}

func TestTartSupervisorReturnsTimeoutWindowConfirm(t *testing.T) {
	b := newBackend(Provider{}.Spec(), core.BaseConfig(), core.Runtime{}).(*backend)
	sup, ok := b.supervisor.(*tartProcessSupervisor)
	if !ok {
		t.Fatalf("supervisor = %T, want *tartProcessSupervisor", b.supervisor)
	}
	confirm := sup.StartupConfirm()
	if _, ok := confirm.(shared.TimeoutWindowConfirm); !ok {
		t.Fatalf("confirm = %T, want shared.TimeoutWindowConfirm", confirm)
	}
}

func TestConfirmStartupUsesSharedStrategy(t *testing.T) {
	// Verify that confirmStartup delegates to TimeoutWindowConfirm by
	// checking that a process exit during the window is detected via
	// the exitedErr channel (the shared strategy's input).
	p := &startupProcess{
		exitedErr: make(chan error, 1),
		ctx:       context.Background(),
		done:      make(chan struct{}),
	}
	// Simulate process exit before the timeout window elapses.
	exitErr := core.Exit(2, "tart run test-vm failed during startup: boom")
	p.exitedErr <- exitErr
	err := p.confirmStartup(context.Background(), time.Hour)
	if err == nil {
		t.Fatal("confirmStartup should fail when process exits during window")
	}
}
