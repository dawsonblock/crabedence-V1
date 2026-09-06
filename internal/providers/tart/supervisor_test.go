package tart

import (
	"context"
	"testing"

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

func TestStartupProcessSatisfiesProcessHandle(t *testing.T) {
	// Compile-time check that *startupProcess implements shared.ProcessHandle.
	var _ shared.ProcessHandle = (*startupProcess)(nil)
}
