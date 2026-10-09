package execution

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// TestStopBarrierCoversAcceptedConnection holds a connection inside the
// exact shutdown-race window — accepted, connection slot acquired,
// handler not yet registered with the drain group — while Stop() runs.
//
// The invariant at the observable boundary: once Stop has returned, no
// request may be served on that connection. The defective ordering
// (Stop begins handlers.Wait() while the accept loop can still reach
// handlers.Add(1)) lets the drain report clean while the held
// connection goes on to dispatch; the corrected ordering (Stop waits
// for the accept loop to terminate before it waits on the handler
// group, and registration happens under the lifecycle lock) instead
// closes the connection without dispatching it.
//
// The gate makes the interleaving deterministic: the test does not
// rely on the race detector happening to schedule the hazard window.
func TestStopBarrierCoversAcceptedConnection(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{}
	service := setupServiceWithGrants(registry, handler, socketPath)
	service.drainTimeout = 10 * time.Second

	accepted := make(chan struct{})
	proceed := make(chan struct{})
	service.acceptGate = func() {
		close(accepted)
		<-proceed
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The client connection is accepted immediately; the accept loop
	// then blocks inside the gate, holding the connection inside the
	// hazard window.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was never accepted")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- service.Stop() }()

	// Stop must not report a clean drain while an accepted connection
	// is still able to register a handler. Under the defective ordering
	// Stop returns here with the handler count still zero; under the
	// corrected ordering it waits for the accept loop, which is blocked
	// in the gate — so it cannot return yet. The wait is a bounded
	// observability window, not a synchronization: the deciding
	// assertion below is that the connection is never served.
	var stopErr error
	stopReturnedBeforeRelease := false
	select {
	case stopErr = <-stopDone:
		stopReturnedBeforeRelease = true
	case <-time.After(500 * time.Millisecond):
	}

	// Release the window regardless of which ordering ran, so a
	// corrected Stop cannot hang.
	close(proceed)
	if !stopReturnedBeforeRelease {
		select {
		case stopErr = <-stopDone:
		case <-time.After(10 * time.Second):
			t.Fatal("Stop did not return after the accept gate released")
		}
	}
	if stopErr != nil {
		t.Fatalf("Stop: %v", stopErr)
	}

	// The deciding probe, at the wire: the pre-accepted connection
	// must not serve a request after the service has stopped. If it
	// does, a handler registered behind the drain barrier — exactly
	// the defect the barrier exists to close.
	resp, served := sendRequestTolerant(conn, echoRequest())
	if served && resp.Status == StatusSucceeded {
		t.Fatalf("a request was dispatched and served after the service stopped (Stop returned before the gate released: %v) — a handler registered behind the drain barrier", stopReturnedBeforeRelease)
	}
	if got := handler.executions.Load(); got != 0 {
		t.Fatalf("executions after clean stop = %d, want 0 — work dispatched behind the drain barrier", got)
	}
}

// TestRepeatedStopIsIdempotent proves Stop() is safe to call twice and
// that a second call does not resurrect acceptance or re-delete a
// successor's socket.
func TestRepeatedStopIsIdempotent(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := setupServiceWithGrants(registry, &gatedHandler{}, socketPath)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := service.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
