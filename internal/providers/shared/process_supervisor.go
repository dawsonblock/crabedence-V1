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

// ProcessStartRequest configures a supervised process launch. Name, Keep,
// and ObserveTimeout are consumed by all supervisors. Data carries
// provider-specific launch context (e.g. Lume's bootstrap trust, launch
// token, and owner callback) that the provider's supervisor type-asserts.
// This is not aspirational — it is the minimal escape hatch for context
// that is genuinely provider-specific and cannot be generalized.
type ProcessStartRequest struct {
	// Name is the VM/instance name for diagnostics.
	Name string
	// Keep survives caller context cancellation after a successful handoff.
	Keep bool
	// ObserveTimeout is the startup observation window after the process
	// starts.
	ObserveTimeout time.Duration
	// Data carries provider-specific launch context. Each provider's
	// supervisor type-asserts this to its own concrete type. nil is
	// valid and means "use defaults" (used by tests and the generic path).
	Data any
}

// ProcessStartupConfirm waits for the process to become ready. It returns a
// StartupConfirmResult and an error: the result is populated even on failure,
// so callers can record startup evidence (stage, duration, outcome) for
// provider qualification.
//
// The Wait signature no longer takes a ProcessHandle parameter. The
// strategies only need the caller's context and the process-exit error
// channel (exited). The exit channel is provided by the supervisor, which
// derives it from the process's exit observation (if available). This
// change ensures startup confirmation strategies request only the
// capabilities they actually require.
type ProcessStartupConfirm interface {
	Wait(ctx context.Context, exited <-chan error) (StartupConfirmResult, error)
}

// StartupConfirmResult captures the outcome of a startup confirmation wait.
// It is populated even when Wait returns an error, so callers can record
// structured startup evidence for provider qualification.
type StartupConfirmResult struct {
	// Stage identifies the confirmation strategy: "timeout-window",
	// "file-handoff", or "process-exit".
	Stage string
	// Duration is the elapsed time from Wait start to outcome.
	Duration time.Duration
	// Ready is true if the process was confirmed ready.
	Ready bool
	// ProcessExited is true if the process exited during confirmation
	// (distinguishing exit-based failures from timeout/cancellation).
	ProcessExited bool
	// Retryable is true if the failure is likely to succeed on retry
	// (e.g. timeout, transient file error). False for process exits and
	// persistent I/O errors.
	Retryable bool
}

// ProcessHandle is now defined in process_capabilities.go as a narrow
// interface with only PID() and Abort(). The previous monolithic interface
// that included Kill, Handoff, Stderr, Done, and Context has been split
// into capability interfaces (ProcessKiller, ProcessHandoff, ProcessStderr,
// ExitObservable, LifecycleContextProvider, DetachedProcess).
// FullProcessHandle is the backward-compatible superset.

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
// If SetNextStartOK(false) has been called, Start returns context.Canceled.
func (s *FakeProcessSupervisor) Start(_ context.Context, req ProcessStartRequest) (ProcessHandle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts = append(s.starts, FakeProcessStart{Request: req})
	if !s.nextStartOK {
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
	pid       int
	done      chan struct{}
	aborted   chan struct{}
	handed    bool
	killed    bool
	abortOnce sync.Once
	doneOnce  sync.Once
}

func (h *fakeProcessHandle) PID() int              { return h.pid }
func (h *fakeProcessHandle) Kill() error           { h.killed = true; return nil }
func (h *fakeProcessHandle) Stderr() string        { return "" }
func (h *fakeProcessHandle) Done() <-chan struct{} { return h.done }
func (h *fakeProcessHandle) Context() context.Context {
	return context.Background()
}

func (h *fakeProcessHandle) Abort(readinessErr error) error {
	h.abortOnce.Do(func() {
		close(h.aborted)
	})
	h.doneOnce.Do(func() {
		close(h.done)
	})
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

// Compile-time check that *fakeProcessHandle satisfies FullProcessHandle.
var _ FullProcessHandle = (*fakeProcessHandle)(nil)
