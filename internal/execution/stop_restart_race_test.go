package execution

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// The stop/restart lifecycle tests in this file pin finding F-013: a
// successful Stop() must mean the OLD lifecycle's owned-socket cleanup
// is finished — never that a drain observation escaped ahead of it —
// and an old stop finalizer must never be able to remove a socket a
// later lifecycle bound. The hazard the tests hold open is the window
// between the handler drain completing and the bound socket's removal:
// historically Stop() published StateStopped before cleaning up, so a
// racing Start() could bind a successor and replace the identity the
// old finalizer was about to consult.
//
// The gate (stopCleanupGate) makes the interleaving deterministic: the
// test does not rely on the scheduler or the race detector happening to
// land inside the window.

// socketIdentityAt returns the dev+inode identity of the socket bound at
// path, or nil when the path does not name a socket on this platform.
func socketIdentityAt(t *testing.T, path string) *socketFileID {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil
	}
	return socketFileIdentity(info)
}

// newEchoService builds a grant-wired echo service on a private socket
// path — the same fixture the other lifecycle tests use.
func newEchoService(t *testing.T, socketPath string) (*Service, *gatedHandler) {
	t.Helper()
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := &gatedHandler{}
	return setupServiceWithGrants(registry, handler, socketPath), handler
}

// TestStopRestartCleanupInterleaving holds a Stop inside the exact
// pre-cleanup window — the drain has finished but the bound socket has
// not yet been resolved — and calls Start() concurrently.
//
// Required behavior: Start() must refuse while cleanup is pending (the
// service is still STOPPING; LC-1 forbids binding a successor until the
// previous lifecycle finalized). Once the held Stop completes, a later
// Start() binds a fresh socket that survives the old finalizer and
// serves authorized requests.
//
// Defective behavior this catches: StateStopped published before
// cleanup lets the racing Start() bind; the old finalizer then resolves
// the path against the successor's (mutable) identity and unlinks the
// NEW socket.
func TestStopRestartCleanupInterleaving(t *testing.T) {
	socketPath := testSocketPath(t)
	service, _ := newEchoService(t, socketPath)
	service.drainTimeout = 10 * time.Second

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var gateOnce sync.Once
	var entries atomic.Int64
	service.stopCleanupGate = func() {
		entries.Add(1)
		gateOnce.Do(func() {
			close(entered)
			<-proceed
		})
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	boundIdent := socketIdentityAt(t, socketPath)
	if boundIdent == nil {
		t.Fatal("the bound socket has no filesystem identity on this platform")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- service.Stop() }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop never reached the pre-cleanup window")
	}

	// The held Stop has drained but has not finished owned-socket
	// cleanup: a successor must not bind yet.
	if startErr := service.Start(context.Background()); startErr == nil {
		t.Fatal("Start succeeded while the previous lifecycle's socket cleanup was still pending — a successor bound ahead of finalization")
	}

	close(proceed)
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop never returned after the cleanup gate released")
	}
	if got := service.LifecycleState(); got != StateStopped {
		t.Fatalf("lifecycle state after stop = %v, want StateStopped", got)
	}
	// The completed Stop removed its own socket: nothing may be left
	// at the path from the old lifecycle.
	if ident := socketIdentityAt(t, socketPath); ident != nil {
		t.Fatalf("the old lifecycle's socket survived a clean stop (ident %+v)", *ident)
	}
	if got := entries.Load(); got != 1 {
		t.Fatalf("owned-socket cleanup ran %d times for the first lifecycle, want exactly 1", got)
	}

	// A fresh lifecycle now binds — and its socket must survive the
	// old finalizer.
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start after a clean stop: %v", err)
	}
	newIdent := socketIdentityAt(t, socketPath)
	if newIdent == nil || *newIdent == *boundIdent {
		t.Fatalf("the restarted socket identity = %+v, want a fresh object distinct from %+v", newIdent, boundIdent)
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial the restarted socket: %v", err)
	}
	resp, ok := sendRequestTolerant(conn, echoRequest())
	conn.Close()
	if !ok || resp.Status != StatusSucceeded {
		t.Fatalf("the restarted service did not serve an authorized request: %+v (served %v)", resp, ok)
	}
	if err := service.Stop(); err != nil {
		t.Fatalf("final Stop: %v", err)
	}
}

// TestDoubleStopSingleCleanup runs many concurrent Stop callers:
// exactly one cleanup attempt finalizes the lifecycle, every caller
// observes the same truthful result, and no caller can unlink another
// caller's successor socket.
func TestDoubleStopSingleCleanup(t *testing.T) {
	socketPath := testSocketPath(t)
	service, _ := newEchoService(t, socketPath)
	service.drainTimeout = 10 * time.Second

	var cleanups atomic.Int64
	var gateOnce sync.Once
	gateRelease := make(chan struct{})
	service.stopCleanupGate = func() {
		cleanups.Add(1)
		gateOnce.Do(func() { <-gateRelease })
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	const stoppers = 50
	var wg sync.WaitGroup
	errs := make([]error, stoppers)
	for i := 0; i < stoppers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = service.Stop()
		}(i)
	}
	// Let the stoppers converge on the single cleanup attempt, then
	// release it.
	deadline := time.Now().Add(5 * time.Second)
	for cleanups.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	close(gateRelease)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Stop call %d returned %v — concurrent stops must converge on one result", i, err)
		}
	}
	if got := cleanups.Load(); got != 1 {
		t.Fatalf("owned-socket cleanup ran %d times for %d stoppers, want exactly 1", got, stoppers)
	}
	if got := service.LifecycleState(); got != StateStopped {
		t.Fatalf("lifecycle state after concurrent stops = %v, want StateStopped", got)
	}
}

// TestStopTimeoutThenRetry proves a drain timeout is a typed failure
// that never claims a clean drain, that a retried Stop finalizes the
// SAME generation (never borrowing a later one's identity), and that a
// restart after the retry gets a fresh socket the old generation cannot
// reach.
func TestStopTimeoutThenRetry(t *testing.T) {
	socketPath := testSocketPath(t)
	handler := &gatedHandler{started: make(chan struct{}), release: make(chan struct{})}
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := setupServiceWithGrants(registry, handler, socketPath)
	service.drainTimeout = 250 * time.Millisecond

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	boundIdent := socketIdentityAt(t, socketPath)

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
		t.Fatalf("a timed-out stop reported %v, want StateStopping — timeouts never claim a clean drain", got)
	}
	// While the drain is unresolved, restart stays refused.
	if startErr := service.Start(context.Background()); startErr == nil {
		t.Fatal("Start succeeded while a timed-out stop was still draining")
	}

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
	if ident := socketIdentityAt(t, socketPath); ident != nil {
		t.Fatalf("the timed-out-then-retried lifecycle left its socket behind (ident %+v)", *ident)
	}

	// The restart binds a genuinely new object — the retried finalizer
	// removed the ORIGINAL generation's socket, not a successor's.
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start after timeout+retry: %v", err)
	}
	newIdent := socketIdentityAt(t, socketPath)
	if newIdent == nil || (boundIdent != nil && *newIdent == *boundIdent) {
		t.Fatalf("the restarted socket identity = %+v, want a fresh object", newIdent)
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial after timeout+retry+restart: %v", err)
	}
	conn.Close()
	if err := service.Stop(); err != nil {
		t.Fatalf("final Stop: %v", err)
	}
}

// TestForeignSocketReplacement replaces the bound socket's path with a
// foreign object while a Stop is held in the pre-cleanup window. The
// finalizer must never unlink an object the lifecycle did not bind, the
// stop must surface an observable failure rather than a clean result,
// and an operator clearing the occupant recovers the lifecycle to
// Stopped on retry.
func TestForeignSocketReplacement(t *testing.T) {
	socketPath := testSocketPath(t)
	service, _ := newEchoService(t, socketPath)
	service.drainTimeout = 10 * time.Second

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var gateOnce sync.Once
	service.stopCleanupGate = func() {
		gateOnce.Do(func() {
			close(entered)
			<-proceed
		})
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopDone := make(chan error, 1)
	go func() { stopDone <- service.Stop() }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop never reached the pre-cleanup window")
	}

	// Inside the window the drain is done. Whatever the path still
	// names — the bound socket (when cleanup owns the unlink) or
	// nothing (when listener close already unlinked it) — replace it
	// with a foreign regular file: a successor, an attacker, or an
	// accident; the finalizer cannot tell which and must never unlink
	// it.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clear the socket path for the replacement: %v", err)
	}
	if err := os.WriteFile(socketPath, []byte("foreign occupant\n"), 0o600); err != nil {
		t.Fatalf("plant foreign file: %v", err)
	}
	close(proceed)

	var stopErr error
	select {
	case stopErr = <-stopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop never returned after the cleanup gate released")
	}
	if stopErr == nil {
		t.Fatal("Stop reported success while the socket path named a foreign object — an unresolved path is never a clean stop")
	}
	if got := service.LifecycleState(); got == StateStopped {
		t.Fatal("the lifecycle published StateStopped with the socket path unresolved")
	}

	// The foreign object is untouched — the identity check refused
	// the unlink rather than deleting somebody else's bytes.
	data, err := os.ReadFile(socketPath)
	if err != nil || string(data) != "foreign occupant\n" {
		t.Fatalf("the foreign occupant was modified or removed (data=%q, err=%v)", data, err)
	}

	// Recovery: the operator resolves the occupant and retries — the
	// same Stop call path completes the finalization.
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("operator clears the occupant: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := service.Stop()
		if err == nil {
			break
		}
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("recovery Stop returned %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery Stop never completed: last err %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := service.LifecycleState(); got != StateStopped {
		t.Fatalf("lifecycle state after recovery = %v, want StateStopped", got)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start after recovery: %v", err)
	}
	if err := service.Stop(); err != nil {
		t.Fatalf("final Stop: %v", err)
	}
}

// TestForeignSocketSuccessor proves the reciprocal of the same
// invariant: when the path names a DIFFERENT socket (a successor or a
// foreign service's live socket), the old finalizer refuses to unlink
// it even though it is a socket owned by the same user.
func TestForeignSocketSuccessor(t *testing.T) {
	socketPath := testSocketPath(t)
	service, _ := newEchoService(t, socketPath)
	service.drainTimeout = 10 * time.Second

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var gateOnce sync.Once
	service.stopCleanupGate = func() {
		gateOnce.Do(func() {
			close(entered)
			<-proceed
		})
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopDone := make(chan error, 1)
	go func() { stopDone <- service.Stop() }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop never reached the pre-cleanup window")
	}

	// Replace the bound socket with a different live socket bound by
	// this test — same owner, same directory, different object. The
	// path may already be free when the listener's own close unlinked
	// it.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clear the socket path: %v", err)
	}
	foreign, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("bind the foreign socket: %v", err)
	}
	defer foreign.Close()
	foreignIdent := socketIdentityAt(t, socketPath)
	close(proceed)

	var stopErr error
	select {
	case stopErr = <-stopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop never returned after the cleanup gate released")
	}
	if stopErr == nil {
		t.Fatal("Stop reported success while the socket path named a foreign socket")
	}
	// The foreign socket survives — the finalizer refused the unlink.
	if ident := socketIdentityAt(t, socketPath); ident == nil || (foreignIdent != nil && *ident != *foreignIdent) {
		t.Fatal("the old lifecycle's finalizer removed or replaced a socket it did not bind")
	}
	// And the foreign socket still accepts: it was never unlinked.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("the foreign socket was unlinked: %v", err)
	}
	conn.Close()
	// The service stays recoverable: clearing the foreign socket lets a
	// retried Stop finish.
	foreign.Close()
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("operator clears the foreign socket: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := service.Stop()
		if err == nil {
			break
		}
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("recovery Stop returned %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery Stop never completed: last err %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := service.LifecycleState(); got != StateStopped {
		t.Fatalf("lifecycle state after recovery = %v, want StateStopped", got)
	}
}

// TestRapidLifecycleStress runs bounded randomized start/stop/dial
// schedules against the lifecycle invariants: a successful Stop always
// ends with the owned socket resolved, a Start during stopping is
// refused, a restart gets a distinct socket, and no schedule leaves the
// path naming an object the wrong lifecycle bound. The default count
// keeps the campaign cheap under -race; CRABEDENCE_RESTART_CYCLES
// raises it for dedicated runs (nightly qualification targets 10k+).
func TestRapidLifecycleStress(t *testing.T) {
	cycles := 200
	if n, err := strconv.Atoi(os.Getenv("CRABEDENCE_RESTART_CYCLES")); err == nil && n > 0 {
		cycles = n
	}
	rng := rand.New(rand.NewSource(20261010))

	for i := 0; i < cycles; i++ {
		socketPath := testSocketPath(t)
		service, _ := newEchoService(t, socketPath)
		service.drainTimeout = 2 * time.Second

		if err := service.Start(context.Background()); err != nil {
			t.Fatalf("cycle %d: Start: %v", i, err)
		}
		boundIdent := socketIdentityAt(t, socketPath)

		stoppers := 1 + rng.Intn(4)
		errs := make([]error, stoppers)
		var wg sync.WaitGroup
		for s := 0; s < stoppers; s++ {
			wg.Add(1)
			go func(s int) {
				defer wg.Done()
				errs[s] = service.Stop()
			}(s)
		}
		// Some schedules also race a restart into the stop.
		var restartErr error
		restartScheduled := rng.Intn(3) == 0
		if restartScheduled {
			restartErr = service.Start(context.Background())
		}
		wg.Wait()

		// Every stopper agrees on one result; a restart during the stop
		// is refused or lands only after finalization — never inside it.
		finalErr := error(nil)
		for s := range errs {
			for errors.Is(errs[s], ErrShutdownTimeout) {
				time.Sleep(5 * time.Millisecond)
				errs[s] = service.Stop()
			}
			if errs[s] != nil && finalErr == nil {
				finalErr = errs[s]
			}
			if errs[s] != finalErr {
				t.Fatalf("cycle %d: stopper %d saw %v, another saw %v — concurrent stops must converge", i, s, errs[s], finalErr)
			}
		}
		if finalErr != nil {
			t.Fatalf("cycle %d: Stop never converged: %v", i, finalErr)
		}
		if restartScheduled && restartErr == nil {
			// The restart could only succeed after the stop finalized:
			// a fresh socket now serves.
			if ident := socketIdentityAt(t, socketPath); ident == nil || (boundIdent != nil && *ident == *boundIdent) {
				t.Fatalf("cycle %d: post-restart socket identity is not fresh", i)
			}
			conn, err := net.Dial("unix", socketPath)
			if err != nil {
				t.Fatalf("cycle %d: the post-restart socket does not accept: %v", i, err)
			}
			resp, ok := sendRequestTolerant(conn, echoRequest())
			conn.Close()
			if !ok || resp.Status != StatusSucceeded {
				t.Fatalf("cycle %d: the post-restart service does not serve: %+v", i, resp)
			}
		}
		if got := service.LifecycleState(); got == StateStopping {
			t.Fatalf("cycle %d: lifecycle still stopping after every stopper converged", i)
		}
		if err := service.Stop(); err != nil {
			t.Fatalf("cycle %d: trailing Stop: %v", i, err)
		}
		if ident := socketIdentityAt(t, socketPath); ident != nil {
			t.Fatalf("cycle %d: a socket remains after the final stop", i)
		}
	}
}
