package shared

import "context"

// ProcessHandle is the minimal interface every provider process must implement.
// It exposes only the capabilities that are universally available across all
// provider types (Tart, Lume, etc.).
//
// Providers that offer additional capabilities implement the optional
// capability interfaces (ExitObservable, ReapableProcess,
// LifecycleContextProvider, DetachedProcess) in addition to this base.
// Callers type-assert to those interfaces only when they need the
// capability and can gracefully degrade when it is absent.
//
// This split replaces the previous monolithic ProcessHandle which advertised
// Done(), Context(), and other methods that some providers (e.g. Lume) cannot
// truthfully implement. A detached process that the CLI does not own cannot
// truthfully expose exit observation or a process-scoped lifecycle context.
type ProcessHandle interface {
	// PID returns the operating-system process ID.
	PID() int
	// Abort snapshots diagnostics, cancels readiness, kills the process if
	// still running, reaps it (if reaping is supported), and closes the log.
	// Returns the joined error. The readinessErr is the error that caused
	// the abort (e.g. startup failure, context cancellation); it is joined
	// with any cleanup errors and returned.
	Abort(readinessErr error) error
}

// ExitObservable is implemented by providers that can observe process exit.
// Done is closed when the process has exited and been reaped (if reaping
// applies). Providers with detached processes (e.g. Lume) do NOT implement
// this interface — their Done channel is only closed on Abort, not on
// natural process exit, so it does not truthfully represent exit observation.
//
// Callers that need exit observation should type-assert:
//
//	if obs, ok := handle.(ExitObservable); ok { <-obs.Done() }
type ExitObservable interface {
	Done() <-chan struct{}
}

// ReapableProcess is implemented by providers that can wait for and reap
// the process. Wait blocks until the process has exited and returns its
// exit error. Providers with detached processes do NOT implement this
// interface.
type ReapableProcess interface {
	Wait() error
}

// LifecycleContextProvider is implemented by providers that expose a
// process-scoped lifecycle context. The context is cancelled when the
// process exits, so callers can use it for operations that should abort
// if the process dies (e.g. waitForIP). Providers with detached processes
// do NOT implement this interface — they return context.Background() which
// does not reflect the process's actual lifecycle.
type LifecycleContextProvider interface {
	Context() context.Context
}

// DetachedProcess is implemented by providers whose process is detached
// from the CLI's lifecycle. Detached returns true when the CLI does not
// own the child process's lifecycle after handoff. This means:
//   - The process may outlive the CLI.
//   - Exit cannot be observed (Done is only closed on Abort).
//   - The process cannot be reaped (Wait is not available).
//   - There is no process-scoped lifecycle context.
//
// Callers should check this before attempting to use ExitObservable,
// ReapableProcess, or LifecycleContextProvider:
//
//	if _, detached := handle.(DetachedProcess); detached && handle.(DetachedProcess).Detached() {
//	    // Cannot observe exit, reap, or use process-scoped context.
//	}
type DetachedProcess interface {
	Detached() bool
}

// ProcessKiller is implemented by providers that can send a kill signal
// (SIGKILL or equivalent) to the process. This is separated from the base
// ProcessHandle because some providers may only support Abort (which
// includes kill as part of cleanup) but not standalone Kill.
type ProcessKiller interface {
	Kill() error
}

// ProcessHandoff is the acquisition commit point. It closes the log,
// detaches the startup context, and (for non-keep) installs a caller-context
// watcher that kills the process when the caller is cancelled. This is
// separated from the base ProcessHandle because the handoff semantics are
// provider-specific (e.g. Lume's commit point is the successful return from
// startVM, not an explicit Handoff call).
type ProcessHandoff interface {
	Handoff() error
}

// ProcessStderr returns captured startup diagnostics. This is valid after
// Abort. Separated from the base ProcessHandle because not all providers
// capture stderr.
type ProcessStderr interface {
	Stderr() string
}

// FullProcessHandle is the legacy superset interface that includes all
// capabilities. It is retained for backward compatibility with existing
// code that expects the full interface. New code should use the individual
// capability interfaces and type-assert only what it needs.
//
// Tart's startupProcess implements this fully. Lume's lumeProcessHandle
// implements ProcessHandle, ProcessKiller, ProcessHandoff, ProcessStderr,
// and DetachedProcess, but NOT ExitObservable, ReapableProcess, or
// LifecycleContextProvider (because its process is detached).
type FullProcessHandle interface {
	ProcessHandle
	ProcessKiller
	ProcessHandoff
	ProcessStderr
	ExitObservable
	LifecycleContextProvider
}
