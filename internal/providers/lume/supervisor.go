package lume

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/providers/shared"
)

// lumeProcessSupervisor adapts the backend's existing startVM/stopVM logic to
// the shared.ProcessSupervisor interface. It is the default supervisor for
// Lume; tests may inject a fake via newBackendWithSupervisor.
//
// Startup confirmation uses FileHandoffConfirm semantics: Lume's wrapper
// script writes a PID file, waits for a gate file, then writes an ack file.
// The startVM implementation handles this protocol internally; the supervisor
// exposes the strategy via StartupConfirm for documentation and testing.
type lumeProcessSupervisor struct {
	backend *backend
}

// StartupConfirm returns the shared.ProcessStartupConfirm that matches
// Lume's startup observation behavior.
func (s *lumeProcessSupervisor) StartupConfirm() shared.ProcessStartupConfirm {
	return shared.FileHandoffConfirm{
		Timeout:      2 * time.Second,
		PollInterval: 10 * time.Millisecond,
	}
}

func (s *lumeProcessSupervisor) Start(ctx context.Context, req shared.ProcessStartRequest) (shared.ProcessHandle, error) {
	owner, err := s.backend.startVM(ctx, s.backend.configForRun(), req.Name, bootstrapTrust{}, "", func(started lumeRunOwner) error {
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &lumeProcessHandle{owner: owner, backend: s.backend}, nil
}

// lumeProcessHandle wraps a lumeRunOwner and the backend's stop logic to
// satisfy shared.ProcessHandle. Because Lume's startVM spawns a detached
// process that the CLI does not directly wait on, Done() and Context()
// have weaker semantics than Tart's startupProcess:
//   - Done() is closed when Abort() is called (not on natural child exit,
//     since the CLI does not own the child's lifecycle after handoff).
//   - Context() returns context.Background() because Lume does not expose
//     a process-scoped context.
//   - Abort() is idempotent and signals the process but does not wait for
//     reaping (the process is detached).
//
// These semantics are intentionally weaker than Tart's. Callers that need
// process-exit observation should use Tart or a provider that owns its
// child's lifecycle. See docs/plan/portable-coordinator.md for details.
type lumeProcessHandle struct {
	owner     lumeRunOwner
	backend   *backend
	mu        sync.Mutex
	aborted   bool
	done      chan struct{}
	doneOnce  sync.Once
	abortOnce sync.Once
}

func (h *lumeProcessHandle) ensureDone() chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done == nil {
		h.done = make(chan struct{})
	}
	return h.done
}

func (h *lumeProcessHandle) PID() int { return h.owner.PID }

func (h *lumeProcessHandle) Kill() error {
	if h.owner.PID <= 0 {
		return os.ErrProcessDone
	}
	if !ownerProcessMatches(h.owner) {
		return os.ErrProcessDone
	}
	return signalProcessInterrupt(h.owner.PID)
}

// Abort is idempotent. It signals the process and closes Done. It does not
// wait for the process to actually exit because Lume's process is detached.
func (h *lumeProcessHandle) Abort(readinessErr error) error {
	h.abortOnce.Do(func() {
		_ = h.Kill()
	})
	h.doneOnce.Do(func() {
		close(h.ensureDone())
	})
	return readinessErr
}

func (h *lumeProcessHandle) Handoff() error {
	// Lume's commit point is the successful return from startVM; the owner
	// record is persisted by the onStarted callback. No additional context
	// watcher is needed because Lume's stop path uses identity-fenced signals.
	return nil
}

func (h *lumeProcessHandle) Stderr() string {
	if h.owner.LogPath == "" {
		return ""
	}
	data, err := os.ReadFile(h.owner.LogPath)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h *lumeProcessHandle) Done() <-chan struct{} {
	return h.ensureDone()
}

// Context returns context.Background() because Lume does not expose a
// process-scoped lifecycle context. Callers should use their own context
// for post-startup operations.
func (h *lumeProcessHandle) Context() context.Context {
	return context.Background()
}

// Compile-time checks.
var _ shared.ProcessSupervisor = (*lumeProcessSupervisor)(nil)
var _ shared.ProcessHandle = (*lumeProcessHandle)(nil)
