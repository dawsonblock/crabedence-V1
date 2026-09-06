package tart

import (
	"context"

	"github.com/openclaw/crabbox/internal/providers/shared"
)

// tartProcessSupervisor adapts the backend's existing startVM/stopVM logic to
// the shared.ProcessSupervisor interface. It is the default supervisor for
// Tart; tests may inject a fake via newBackendWithSupervisor.
//
// Startup confirmation uses TimeoutWindowConfirm semantics: a Tart VM that
// survives the startup observe window without exiting is presumed booted.
// The kqueue-based reaper in startupProcess.go handles exit observation
// natively; the shared interface is satisfied by exporting the existing
// abort/handoff/kill methods.
type tartProcessSupervisor struct {
	backend *backend
}

// StartupConfirm returns the shared.ProcessStartupConfirm that matches
// Tart's startup observation behavior. Tests and external callers can use
// this to understand or override the readiness strategy.
func (s *tartProcessSupervisor) StartupConfirm() shared.ProcessStartupConfirm {
	return shared.TimeoutWindowConfirm{Timeout: s.backend.startupObserveTimeout}
}

func (s *tartProcessSupervisor) Start(ctx context.Context, req shared.ProcessStartRequest) (shared.ProcessHandle, error) {
	// Tart's startVM already encapsulates spawn, stderr capture, startup
	// observation (TimeoutWindowConfirm semantics), and the abort path.
	// The returned *startupProcess satisfies shared.ProcessHandle.
	return s.backend.startVM(ctx, req.Name, req.Keep)
}

// Compile-time check that *startupProcess satisfies shared.ProcessHandle.
var _ shared.ProcessHandle = (*startupProcess)(nil)

// Compile-time check that *tartProcessSupervisor satisfies shared.ProcessSupervisor.
var _ shared.ProcessSupervisor = (*tartProcessSupervisor)(nil)
