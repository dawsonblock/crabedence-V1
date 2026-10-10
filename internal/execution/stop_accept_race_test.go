package execution

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
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

// TestStopRefusesConnectionAcceptedAtBoundary proves a connection that
// was accepted before the stop but never admitted is refused
// explicitly — a definitive pre-dispatch denial at the wire — rather
// than dispatched or silently abandoned.
func TestStopRefusesConnectionAcceptedAtBoundary(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{}
	service := setupServiceWithGrants(registry, handler, socketPath)

	accepted := make(chan struct{})
	proceed := make(chan struct{})
	service.acceptGate = func() {
		close(accepted)
		<-proceed
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

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
	// Let the stop transition land before releasing the window.
	time.Sleep(200 * time.Millisecond)
	close(proceed)

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return after the accept gate released")
	}

	// The boundary connection gets an explicit definitive refusal, not
	// a dispatch and not a silent hang: the client can distinguish "the
	// service rejected this request" from "the socket died".
	resp, served := sendRequestTolerant(conn, echoRequest())
	if served && resp.Status == StatusSucceeded {
		t.Fatalf("a request was dispatched after the service stopped: %+v", resp)
	}
	if served && (!resp.DefinitiveFailure || resp.Status != StatusFailed) {
		t.Fatalf("boundary refusal = %+v, want a definitive FAILED refusal", resp)
	}
	if got := handler.executions.Load(); got != 0 {
		t.Fatalf("executions after clean stop = %d, want 0", got)
	}
}

// TestConcurrentStopIdempotent runs many concurrent Stop calls: they
// converge on one terminal result — one closed listener, one drained
// handler group, one consistent error value — instead of racing each
// other's drain observation.
func TestConcurrentStopIdempotent(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{started: make(chan struct{}), release: make(chan struct{})}
	service := setupServiceWithGrants(registry, handler, socketPath)
	service.drainTimeout = 10 * time.Second

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// An in-flight handler makes the drain real: every stopper waits
	// on the same drain rather than observing the group at zero.
	go func() {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return
		}
		defer conn.Close()
		sendRequestTolerant(conn, echoRequest())
	}()
	select {
	case <-handler.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started")
	}

	const stoppers = 20
	var wg sync.WaitGroup
	errs := make([]error, stoppers)
	for i := 0; i < stoppers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = service.Stop()
		}(i)
	}
	// Let the stops converge on the shared transition, then release
	// the handler so the drain can finish.
	time.Sleep(100 * time.Millisecond)
	close(handler.release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Stop call %d returned %v — concurrent stops must converge on one result", i, err)
		}
	}
	if got := service.LifecycleState(); got != StateStopped {
		t.Fatalf("lifecycle state after concurrent stops = %v, want StateStopped", got)
	}
	// And a trailing Stop still returns the same terminal result.
	if err := service.Stop(); err != nil {
		t.Fatalf("a trailing Stop after concurrent stops returned %v", err)
	}
}

// TestStopTimeoutNotClean proves a drain that cannot finish inside the
// deadline is reported as a typed timeout — never as a successful stop
// — and that the service remains observably STOPPING until a retried
// Stop finishes the drain.
func TestStopTimeoutNotClean(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{started: make(chan struct{}), release: make(chan struct{})}
	service := setupServiceWithGrants(registry, handler, socketPath)
	service.drainTimeout = 250 * time.Millisecond

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	go func() {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return
		}
		defer conn.Close()
		sendRequestTolerant(conn, echoRequest())
	}()
	select {
	case <-handler.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started")
	}

	err := service.Stop()
	if !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Stop with a blocked handler = %v, want ErrShutdownTimeout", err)
	}
	if got := service.LifecycleState(); got != StateStopping {
		t.Fatalf("lifecycle state after a timed-out stop = %v, want StateStopping (degraded, never clean)", got)
	}

	// Once the handler finishes, a retried Stop completes the drain —
	// retry semantics are documented: the same shared deadline is
	// re-waited, and a completed drain returns immediately.
	close(handler.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = service.Stop()
		if err == nil {
			break
		}
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("retried Stop returned %v, want nil or ErrShutdownTimeout", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("a retried Stop never completed the finished drain")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := service.LifecycleState(); got != StateStopped {
		t.Fatalf("lifecycle state after the retried stop = %v, want StateStopped", got)
	}
}

// TestRestartAfterCleanStop proves a stopped service can start a fresh
// lifecycle: a new accept-done channel, a new drain group, a new
// socket — nothing from the previous lifecycle leaks into the next.
func TestRestartAfterCleanStop(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{}
	service := setupServiceWithGrants(registry, handler, socketPath)

	for cycle := 1; cycle <= 2; cycle++ {
		if err := service.Start(context.Background()); err != nil {
			t.Fatalf("cycle %d Start: %v", cycle, err)
		}
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatalf("cycle %d dial: %v", cycle, err)
		}
		resp, ok := sendRequestTolerant(conn, echoRequest())
		conn.Close()
		if !ok || resp.Status != StatusSucceeded {
			t.Fatalf("cycle %d request = %+v (served %v), want SUCCEEDED", cycle, resp, ok)
		}
		if err := service.Stop(); err != nil {
			t.Fatalf("cycle %d Stop: %v", cycle, err)
		}
		if got := service.LifecycleState(); got != StateStopped {
			t.Fatalf("cycle %d lifecycle state = %v, want StateStopped", cycle, got)
		}
	}
	if got := handler.executions.Load(); got != 2 {
		t.Fatalf("executions across two lifecycles = %d, want 2", got)
	}
}

// TestStopDuringHandshake proves a connection parked in the
// unauthenticated phase does not block the lifecycle transition: the
// drain accounts for it as one admitted handler, and the service
// refuses to call the drain clean while it is held. Once the client
// goes away the handler unblocks and the drain completes — no new
// mutation ever happened on that connection.
func TestStopDuringHandshake(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{}
	service := setupServiceWithGrants(registry, handler, socketPath)
	service.drainTimeout = 250 * time.Millisecond

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A client that connects and stays silent: its handler is admitted
	// and parked in the header read — the unauthenticated phase.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(service.connSlots) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	err = service.Stop()
	if !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Stop with a parked handshake = %v, want ErrShutdownTimeout", err)
	}
	if got := handler.executions.Load(); got != 0 {
		t.Fatalf("a parked handshake dispatched work: %d executions", got)
	}

	// The client going away unblocks the handler's read; a retried
	// Stop then completes the drain.
	conn.Close()
	deadline = time.Now().Add(5 * time.Second)
	for {
		err = service.Stop()
		if err == nil {
			break
		}
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("retried Stop returned %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("Stop never finished once the parked handshake went away")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := service.LifecycleState(); got != StateStopped {
		t.Fatalf("final lifecycle state = %v, want StateStopped", got)
	}
}

// TestStopWithUnknownExternalEffect proves the shutdown path never
// collapses an in-flight dispatch into a failure: a handler whose work
// outlives the drain deadline keeps its own outcome — Stop reports the
// timeout, the handler's definitive answer is still delivered, and
// nothing preemptively marks the effect failed. The durable UNKNOWN
// semantics below the handler are pinned by the dispatch-crash suites;
// this test pins the service's own ordering around them.
func TestStopWithUnknownExternalEffect(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{started: make(chan struct{}), release: make(chan struct{})}
	service := setupServiceWithGrants(registry, handler, socketPath)
	service.drainTimeout = 250 * time.Millisecond

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	respCh := make(chan Response, 1)
	go func() {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return
		}
		defer conn.Close()
		if resp, ok := sendRequestTolerant(conn, echoRequest()); ok {
			respCh <- resp
		}
	}()
	select {
	case <-handler.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started")
	}

	// The drain deadline expires while the dispatch is still in
	// flight: the stop is a typed timeout, not a synthetic failure of
	// the in-flight effect.
	if err := service.Stop(); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Stop over an in-flight dispatch = %v, want ErrShutdownTimeout", err)
	}

	close(handler.release)
	select {
	case resp := <-respCh:
		if resp.Status != StatusSucceeded {
			t.Fatalf("the in-flight dispatch received %+v — its own outcome, not a stop-invented failure", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight dispatch never delivered its response")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := service.Stop()
		if err == nil {
			break
		}
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("retried Stop returned %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("Stop never finished after the in-flight dispatch completed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStopRandomizedSchedules fuzzes start/stop/admission interleavings
// against the lifecycle invariants: no handler ever dispatches after a
// Stop that reported success, concurrent stoppers agree, and a
// timed-out stop always finishes on retry once its blocker goes away.
// The schedule count is bounded so the campaign stays cheap under
// -race; CRABEDENCE_STOP_SCHEDULES raises it for dedicated runs.
func TestStopRandomizedSchedules(t *testing.T) {
	schedules := 1000
	if n, err := strconv.Atoi(os.Getenv("CRABEDENCE_STOP_SCHEDULES")); err == nil && n > 0 {
		schedules = n
	}
	rng := rand.New(rand.NewSource(20261009))

	for i := 0; i < schedules; i++ {
		socketPath := testSocketPath(t)
		registry := capability.NewRegistry()
		if err := RegisterEchoCapability(registry); err != nil {
			t.Fatal(err)
		}
		handler := &gatedHandler{}
		service := setupServiceWithGrants(registry, handler, socketPath)
		service.drainTimeout = 2 * time.Second

		// A gate the schedule may hold a connection inside — the exact
		// hazard window — released from the stop path.
		var gateRelease chan struct{}
		if rng.Intn(3) == 0 {
			gateRelease = make(chan struct{})
			release := gateRelease
			service.acceptGate = func() { <-release }
		}

		if err := service.Start(context.Background()); err != nil {
			t.Fatalf("schedule %d: Start: %v", i, err)
		}

		clients := rng.Intn(3)
		conns := make([]net.Conn, 0, clients)
		for c := 0; c < clients; c++ {
			conn, err := net.Dial("unix", socketPath)
			if err == nil {
				conns = append(conns, conn)
			}
		}

		stoppers := 1 + rng.Intn(4)
		var wg sync.WaitGroup
		errs := make([]error, stoppers)
		for s := 0; s < stoppers; s++ {
			wg.Add(1)
			go func(s int) {
				defer wg.Done()
				errs[s] = service.Stop()
			}(s)
		}

		if gateRelease != nil {
			// Release the window mid-stop; the boundary connection must
			// be refused, never admitted.
			time.Sleep(time.Duration(rng.Intn(5)) * time.Millisecond)
			close(gateRelease)
		}
		// Close every client connection the schedule opened: a conn
		// that never spoke parks its handler in the header read for
		// the whole header timeout, and the point of this campaign is
		// the lifecycle interleavings, not the parked-read path (which
		// TestStopDuringHandshake covers deterministically). Closing
		// unblocks those handlers so the drain finishes inside the
		// shared deadline and the campaign stays cheap.
		for _, conn := range conns {
			conn.Close()
		}
		wg.Wait()

		// Retried stops converge: any timeout still finishes once the
		// blockers are gone — here the gate is already released and
		// the conns are closed.
		deadline := time.Now().Add(5 * time.Second)
		finalErr := error(nil)
		for s := range errs {
			for errors.Is(errs[s], ErrShutdownTimeout) && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
				errs[s] = service.Stop()
			}
			finalErr = errs[s]
		}
		if finalErr != nil {
			t.Fatalf("schedule %d: a Stop never converged: %v", i, finalErr)
		}
		if got := service.LifecycleState(); got != StateStopped {
			t.Fatalf("schedule %d: lifecycle state = %v, want StateStopped", i, got)
		}

		// The post-stop probe: nothing may serve — a fresh dial fails
		// against a removed socket, and anything that answers must not
		// report a served dispatch.
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			resp, served := sendRequestTolerant(conn, echoRequest())
			conn.Close()
			if served && resp.Status == StatusSucceeded {
				t.Fatalf("schedule %d: a request was served after a clean stop", i)
			}
		}
	}
}
