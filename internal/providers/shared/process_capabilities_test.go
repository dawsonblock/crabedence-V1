package shared

import (
	"context"
	"testing"
)

// mockDetachedHandle simulates a detached process (like Lume) that does NOT
// implement ExitObservable, ReapableProcess, or LifecycleContextProvider.
type mockDetachedHandle struct {
	pid int
}

func (h *mockDetachedHandle) PID() int                       { return h.pid }
func (h *mockDetachedHandle) Abort(readinessErr error) error { return nil }
func (h *mockDetachedHandle) Kill() error                    { return nil }
func (h *mockDetachedHandle) Handoff() error                 { return nil }
func (h *mockDetachedHandle) Stderr() string                 { return "" }
func (h *mockDetachedHandle) Detached() bool                 { return true }

// mockOwnedHandle simulates an owned process (like Tart) that DOES implement
// ExitObservable and LifecycleContextProvider.
type mockOwnedHandle struct {
	pid    int
	doneCh chan struct{}
	ctx    context.Context
}

func (h *mockOwnedHandle) PID() int                       { return h.pid }
func (h *mockOwnedHandle) Abort(readinessErr error) error { close(h.doneCh); return nil }
func (h *mockOwnedHandle) Kill() error                    { return nil }
func (h *mockOwnedHandle) Handoff() error                 { return nil }
func (h *mockOwnedHandle) Stderr() string                 { return "" }
func (h *mockOwnedHandle) Done() <-chan struct{}          { return h.doneCh }
func (h *mockOwnedHandle) Context() context.Context       { return h.ctx }

// Compile-time assertions.
var _ ProcessHandle = (*mockDetachedHandle)(nil)
var _ ProcessKiller = (*mockDetachedHandle)(nil)
var _ ProcessHandoff = (*mockDetachedHandle)(nil)
var _ ProcessStderr = (*mockDetachedHandle)(nil)
var _ DetachedProcess = (*mockDetachedHandle)(nil)

var _ ProcessHandle = (*mockOwnedHandle)(nil)
var _ ProcessKiller = (*mockOwnedHandle)(nil)
var _ ProcessHandoff = (*mockOwnedHandle)(nil)
var _ ProcessStderr = (*mockOwnedHandle)(nil)
var _ ExitObservable = (*mockOwnedHandle)(nil)
var _ LifecycleContextProvider = (*mockOwnedHandle)(nil)
var _ FullProcessHandle = (*mockOwnedHandle)(nil)

// TestDetachedHandleDoesNotExposeExitObservation verifies that a detached
// process handle (like Lume) does NOT implement ExitObservable. This is
// critical because a detached process's Done() channel would only close on
// Abort, not on natural process exit, which would be a false claim of exit
// observation.
func TestDetachedHandleDoesNotExposeExitObservation(t *testing.T) {
	var h ProcessHandle = &mockDetachedHandle{pid: 1234}
	if _, ok := h.(ExitObservable); ok {
		t.Fatal("detached handle should NOT implement ExitObservable")
	}
	if _, ok := h.(ReapableProcess); ok {
		t.Fatal("detached handle should NOT implement ReapableProcess")
	}
	if _, ok := h.(LifecycleContextProvider); ok {
		t.Fatal("detached handle should NOT implement LifecycleContextProvider")
	}
	// But it SHOULD implement DetachedProcess.
	dp, ok := h.(DetachedProcess)
	if !ok {
		t.Fatal("detached handle should implement DetachedProcess")
	}
	if !dp.Detached() {
		t.Fatal("Detached() should return true")
	}
}

// TestOwnedHandleExposesExitObservation verifies that an owned process handle
// (like Tart) DOES implement ExitObservable and LifecycleContextProvider.
func TestOwnedHandleExposesExitObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var h ProcessHandle = &mockOwnedHandle{
		pid:    5678,
		doneCh: make(chan struct{}),
		ctx:    ctx,
	}
	if obs, ok := h.(ExitObservable); !ok {
		t.Fatal("owned handle should implement ExitObservable")
	} else {
		// Done() should return the channel.
		if obs.Done() == nil {
			t.Fatal("Done() should return a non-nil channel")
		}
	}
	if lcp, ok := h.(LifecycleContextProvider); !ok {
		t.Fatal("owned handle should implement LifecycleContextProvider")
	} else {
		if lcp.Context() == nil {
			t.Fatal("Context() should return a non-nil context")
		}
	}
	// It should NOT implement DetachedProcess.
	if dp, ok := h.(DetachedProcess); ok {
		if dp.Detached() {
			t.Fatal("owned handle should not be detached")
		}
	}
}

// TestDetachedHandleImplementsBaseProcessHandle verifies that a detached
// handle still satisfies the base ProcessHandle interface (PID + Abort).
func TestDetachedHandleImplementsBaseProcessHandle(t *testing.T) {
	h := &mockDetachedHandle{pid: 1234}
	if h.PID() != 1234 {
		t.Fatalf("PID: got %d, want 1234", h.PID())
	}
	if err := h.Abort(nil); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}

// TestStartupConfirmDoesNotRequireProcessHandle verifies that the
// ProcessStartupConfirm strategies only need the context and exit channel,
// not a full ProcessHandle. This is verified by the interface signature
// itself: Wait(ctx, exited) does not take a ProcessHandle parameter.
func TestStartupConfirmDoesNotRequireProcessHandle(t *testing.T) {
	// This test is a compile-time check: if the interface required a
	// ProcessHandle, the strategies would need one. The fact that we can
	// call Wait with just a context and an exit channel proves the
	// interface is minimal.
	confirm := TimeoutWindowConfirm{Timeout: 10}
	exited := make(chan error, 1)
	result, err := confirm.Wait(context.Background(), exited)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !result.Ready {
		t.Fatal("should be ready")
	}
}
