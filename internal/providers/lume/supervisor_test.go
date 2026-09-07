package lume

import (
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
