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

// LumeLaunchContext carries the provider-specific data that Lume's Acquire
// passes through the supervisor to startVM. It is carried in
// ProcessStartRequest.Data and type-asserted by lumeProcessSupervisor.Start.
type LumeLaunchContext struct {
	Trust       bootstrapTrust
	LaunchToken string
	OnStarted   func(lumeRunOwner) error
}

// LumeHandle is a ProcessHandle that also exposes Lume's run-owner identity.
// The Lume supervisor returns handles that satisfy this interface; Acquire
// uses it to extract provider-specific context (owner PID, boot identity,
// log path) without reaching into a concrete struct. Tests may substitute
// any handle implementing both shared.ProcessHandle and Owner().
type LumeHandle interface {
	shared.ProcessHandle
	Owner() lumeRunOwner
}

// Owner returns the underlying lumeRunOwner. This is used by Acquire after
// a successful supervisor Start to access the owner identity for label
// persistence and recovery.
func (h *lumeProcessHandle) Owner() lumeRunOwner { return h.owner }

func (s *lumeProcessSupervisor) Start(ctx context.Context, req shared.ProcessStartRequest) (shared.ProcessHandle, error) {
	trust := bootstrapTrust{}
	launchToken := ""
	var onStarted func(lumeRunOwner) error
	if lc, ok := req.Data.(*LumeLaunchContext); ok && lc != nil {
		trust = lc.Trust
		launchToken = lc.LaunchToken
		onStarted = lc.OnStarted
	}
	owner, err := s.backend.startVM(ctx, s.backend.configForRun(), req.Name, trust, launchToken, onStarted)
	if err != nil {
		return nil, err
	}
	return &lumeProcessHandle{owner: owner, backend: s.backend}, nil
}

// lumeProcessHandle wraps a lumeRunOwner and the backend's stop logic to
// satisfy shared.ProcessHandle. Because Lume's startVM spawns a detached
// process that the CLI does not directly wait on, this handle implements
// shared.ProcessHandle, shared.ProcessKiller, shared.ProcessHandoff,
// shared.ProcessStderr, and shared.DetachedProcess — but NOT
// shared.ExitObservable, shared.ReapableProcess, or
// shared.LifecycleContextProvider.
//
// The previous monolithic ProcessHandle forced Lume to implement Done() and
// Context() with weaker semantics that did not truthfully represent the
// process's lifecycle. With the capability split, Lume explicitly advertises
// that it is detached, and callers that need exit observation or
// process-scoped context must use a provider that truthfully implements
// those interfaces (e.g. Tart).
//
// Abort() is idempotent and signals the process but does not wait for
// reaping (the process is detached).
type lumeProcessHandle struct {
	owner     lumeRunOwner
	backend   *backend
	mu        sync.Mutex
	aborted   bool
	done      chan struct{}
	doneOnce  sync.Once
	abortOnce sync.Once
}

// Detached returns true because Lume's process is detached from the CLI's
// lifecycle. The CLI does not own the child process after handoff.
func (h *lumeProcessHandle) Detached() bool { return true }

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

// ensureDone and the Done method are retained as internal infrastructure
// for Abort's signaling, but Done() is NOT exported as part of the
// ExitObservable interface. Lume does not implement ExitObservable because
// its Done channel is only closed on Abort, not on natural process exit.
func (h *lumeProcessHandle) ensureDone() chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done == nil {
		h.done = make(chan struct{})
	}
	return h.done
}

// Compile-time checks. Lume implements ProcessHandle (PID + Abort),
// ProcessKiller, ProcessHandoff, ProcessStderr, and DetachedProcess.
// It does NOT implement ExitObservable, ReapableProcess, or
// LifecycleContextProvider because its process is detached.
var _ shared.ProcessSupervisor = (*lumeProcessSupervisor)(nil)
var _ shared.ProcessHandle = (*lumeProcessHandle)(nil)
var _ shared.ProcessKiller = (*lumeProcessHandle)(nil)
var _ shared.ProcessHandoff = (*lumeProcessHandle)(nil)
var _ shared.ProcessStderr = (*lumeProcessHandle)(nil)
var _ shared.DetachedProcess = (*lumeProcessHandle)(nil)
var _ LumeHandle = (*lumeProcessHandle)(nil)
