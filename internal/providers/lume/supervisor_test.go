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

func TestLumeProcessHandleContextReturnsBackground(t *testing.T) {
	h := &lumeProcessHandle{}
	if h.Context() == nil {
		t.Fatal("Context() returned nil")
	}
	// Lume's context should never be cancelled (background) since Lume
	// manages its lifecycle internally.
	if err := h.Context().Err(); err != nil {
		t.Fatalf("Context() = %v, want background", err)
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
