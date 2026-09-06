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
