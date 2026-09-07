package shared

import (
	"context"
	"sync"
	"time"
)

// ProcessSupervisor manages the lifecycle of a long-running provider process
// (for example a Tart VM or a Lume VM). Provider backends receive one at
// construction time so tests can substitute a fake without spawning real
// processes. The supervisor owns spawn, startup observation, stderr capture,
// stop/kill, exit observation, and the acquisition handoff.
type ProcessSupervisor interface {
	// Start spawns the process and observes startup. On startup failure the
	// process is reaped and the log is closed before returning the error.
	Start(ctx context.Context, req ProcessStartRequest) (ProcessHandle, error)
}

// ProcessStartRequest configures a supervised process launch.
type ProcessStartRequest struct {
	// Name is the VM/instance name for diagnostics.
	Name string
	// Command is the executable and arguments.
	Command []string
	// Env is the child environment.
	Env []string
	// Keep survives caller context cancellation after a successful handoff.
	Keep bool
	// LogPath is the stderr capture path. Empty uses a temporary file.
	LogPath string
	// Detached sets a new session (setsid) for the child on POSIX.
	Detached bool
	// ObserveTimeout is the startup observation window after the process
	// starts. If StartupConfirm is nil, the process is considered ready if
	// it survives this window without exiting.
	ObserveTimeout time.Duration
	// StartupConfirm waits for readiness. nil uses the timeout window.
	StartupConfirm ProcessStartupConfirm
}

// ProcessStartupConfirm waits for the process to become ready. It returns nil
// when the process is ready, or an error if it exits or the context is
// cancelled before readiness.
type ProcessStartupConfirm interface {
	Wait(ctx context.Context, handle ProcessHandle, exited <-chan error) error
}

// ProcessHandle controls a started process. It is returned by Start and is
// the sole interface for lifecycle control after spawn.
type ProcessHandle interface {
	// PID returns the operating-system process ID.
	PID() int
	// Kill sends SIGKILL (or equivalent) to the process. Returns
	// os.ErrProcessDone if the process has already exited.
	Kill() error
	// Abort snapshots diagnostics, cancels readiness, kills the process if
	// still running, reaps it, and closes the log. Returns the joined error.
	Abort(readinessErr error) error
	// Handoff is the acquisition commit point. It closes the log, detaches
	// the startup context, and (for non-keep) installs a caller-context
	// watcher that kills the process when the caller is cancelled.
	Handoff() error
	// Stderr returns captured startup diagnostics (valid after Abort).
	Stderr() string
	// Done is closed when the process has exited and been reaped.
	Done() <-chan struct{}
	// Context returns the process's lifecycle context. It is cancelled when
	// the process exits, so callers can use it for operations that should
	// abort if the process dies (e.g. waitForIP). After Handoff, the context
	// is detached from the caller and may or may not remain live depending
	// on the provider.
	Context() context.Context
}

// FakeProcessSupervisor is a test-only ProcessSupervisor that never spawns
// real processes. It records Start calls and returns configurable handles.
type FakeProcessSupervisor struct {
	mu          sync.Mutex
	starts      []FakeProcessStart
	handles     []*fakeProcessHandle
	nextStartOK bool
}

// FakeProcessStart records one Start invocation.
type FakeProcessStart struct {
	Request ProcessStartRequest
}

// SetNextStartOK configures whether the next Start call succeeds or fails.
func (s *FakeProcessSupervisor) SetNextStartOK(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStartOK = ok
}

// Starts returns a snapshot of recorded Start calls.
func (s *FakeProcessSupervisor) Starts() []FakeProcessStart {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FakeProcessStart, len(s.starts))
	copy(out, s.starts)
	return out
}

// Handles returns the handles created by Start (in creation order).
func (s *FakeProcessSupervisor) Handles() []ProcessHandle {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ProcessHandle, len(s.handles))
	for i, h := range s.handles {
		out[i] = h
	}
	return out
}

// Start implements ProcessSupervisor. It records the request and returns a
// fake handle. The handle's PID increments per call to avoid collisions.
func (s *FakeProcessSupervisor) Start(_ context.Context, req ProcessStartRequest) (ProcessHandle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts = append(s.starts, FakeProcessStart{Request: req})
	if !s.nextStartOK && len(s.handles) > 0 {
		return nil, context.Canceled
	}
	h := &fakeProcessHandle{
		pid:     len(s.handles) + 1000,
		done:    make(chan struct{}),
		aborted: make(chan struct{}),
	}
	s.handles = append(s.handles, h)
	return h, nil
}

type fakeProcessHandle struct {
	pid     int
	done    chan struct{}
	aborted chan struct{}
	handed  bool
	killed  bool
}

func (h *fakeProcessHandle) PID() int              { return h.pid }
func (h *fakeProcessHandle) Kill() error           { h.killed = true; return nil }
func (h *fakeProcessHandle) Stderr() string        { return "" }
func (h *fakeProcessHandle) Done() <-chan struct{} { return h.done }
func (h *fakeProcessHandle) Context() context.Context {
	return context.Background()
}

func (h *fakeProcessHandle) Abort(readinessErr error) error {
	close(h.aborted)
	close(h.done)
	return readinessErr
}

func (h *fakeProcessHandle) Handoff() error {
	h.handed = true
	return nil
}

// Aborted is a test helper that returns whether Abort was called.
func (h *fakeProcessHandle) Aborted() bool {
	select {
	case <-h.aborted:
		return true
	default:
		return false
	}
}

// HandedOff is a test helper that returns whether Handoff was called.
func (h *fakeProcessHandle) HandedOff() bool { return h.handed }
