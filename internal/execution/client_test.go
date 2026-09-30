package execution

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// The client's dispatch boundary is the contract these tests pin: a
// failure before the request frame is fully transmitted is PRE_DISPATCH
// (safe to retry), and every failure after that is ambiguous — an
// UNKNOWN outcome that must never be reported as FAILED.

func clientRequest() Request {
	return Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"hello"}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}
}

func TestClientInvokeSucceeds(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := setupServiceWithGrants(registry, NewMultiHandler(map[string]Handler{
		"system": NewEchoHandler(),
	}), socketPath)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	client := NewClient(socketPath, ClientOptions{Timeout: 5 * time.Second})
	resp, err := client.Invoke(context.Background(), clientRequest())
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}
}

func TestClientDialFailureIsPreDispatch(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "missing.sock"), ClientOptions{Timeout: time.Second})
	_, err := client.Invoke(context.Background(), clientRequest())
	var transport *TransportError
	if !errors.As(err, &transport) {
		t.Fatalf("expected *TransportError, got %v", err)
	}
	if transport.Kind != TransportPreDispatch {
		t.Fatalf("expected PRE_DISPATCH, got %s", transport.Kind)
	}
	if AmbiguousOutcome(err) {
		t.Fatal("a connection that never carried a frame is not an ambiguous outcome")
	}
}

// fakeService runs one scripted exchange on a fresh Unix socket. The
// handler always reads the client's complete request frame first, so
// every scripted failure is provably post-transmission.
func fakeService(t *testing.T, handle func(conn net.Conn)) string {
	t.Helper()
	socketPath := filepath.Join(shortSocketDir(t), "execution.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handle(conn)
	}()
	return socketPath
}

func readRequestFrame(conn net.Conn) error {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return err
	}
	payload := make([]byte, binary.BigEndian.Uint32(lenBuf))
	_, err := io.ReadFull(conn, payload)
	return err
}

func writeFrameBytes(conn net.Conn, payload []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func TestClientConnectionLostAfterTransmissionIsPostDispatch(t *testing.T) {
	socketPath := fakeService(t, func(conn net.Conn) {
		if err := readRequestFrame(conn); err != nil {
			return
		}
		// The service closes without a response: the invocation may
		// have run.
	})
	client := NewClient(socketPath, ClientOptions{Timeout: 5 * time.Second})
	_, err := client.Invoke(context.Background(), clientRequest())
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportPostDispatch {
		t.Fatalf("expected POST_DISPATCH, got %v", err)
	}
	if !AmbiguousOutcome(err) {
		t.Fatal("a lost response after transmission must be ambiguous")
	}
}

func TestClientWaitExpiryAfterTransmissionIsPostDispatch(t *testing.T) {
	socketPath := fakeService(t, func(conn net.Conn) {
		if err := readRequestFrame(conn); err != nil {
			return
		}
		// Hold the connection past the client's wait without answering.
		time.Sleep(2 * time.Second)
	})
	client := NewClient(socketPath, ClientOptions{Timeout: 100 * time.Millisecond})
	_, err := client.Invoke(context.Background(), clientRequest())
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportPostDispatch {
		t.Fatalf("expected POST_DISPATCH, got %v", err)
	}
	if !AmbiguousOutcome(err) {
		t.Fatal("an expired wait after transmission must be ambiguous")
	}
}

func TestClientMalformedResponseIsProtocol(t *testing.T) {
	socketPath := fakeService(t, func(conn net.Conn) {
		if err := readRequestFrame(conn); err != nil {
			return
		}
		_ = writeFrameBytes(conn, []byte("not json"))
	})
	client := NewClient(socketPath, ClientOptions{Timeout: 5 * time.Second})
	_, err := client.Invoke(context.Background(), clientRequest())
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportProtocol {
		t.Fatalf("expected PROTOCOL, got %v", err)
	}
	if !AmbiguousOutcome(err) {
		t.Fatal("an unreadable response is as ambiguous as a lost one")
	}
}

func TestClientOversizedResponseFrameIsProtocol(t *testing.T) {
	socketPath := fakeService(t, func(conn net.Conn) {
		if err := readRequestFrame(conn); err != nil {
			return
		}
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, maxMessageBytes+1)
		_, _ = conn.Write(header)
	})
	client := NewClient(socketPath, ClientOptions{Timeout: 5 * time.Second})
	_, err := client.Invoke(context.Background(), clientRequest())
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportProtocol {
		t.Fatalf("expected PROTOCOL, got %v", err)
	}
}

func TestClientUnknownWireStatusIsProtocol(t *testing.T) {
	socketPath := fakeService(t, func(conn net.Conn) {
		if err := readRequestFrame(conn); err != nil {
			return
		}
		_ = writeFrameBytes(conn, []byte(`{"status":"PROBABLY_FINE"}`))
	})
	client := NewClient(socketPath, ClientOptions{Timeout: 5 * time.Second})
	_, err := client.Invoke(context.Background(), clientRequest())
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportProtocol {
		t.Fatalf("expected PROTOCOL, got %v", err)
	}
}

func TestClientOversizedRequestIsPreDispatch(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "missing.sock"), ClientOptions{Timeout: time.Second})
	req := clientRequest()
	req.Arguments = json.RawMessage(fmt.Sprintf(`{"message":%q}`, make([]byte, maxMessageBytes)))
	_, err := client.Invoke(context.Background(), req)
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportPreDispatch {
		t.Fatalf("expected PRE_DISPATCH, got %v", err)
	}
}

// partialConn accepts a bounded number of bytes, then fails — the
// write boundary a real short write would produce.
type partialConn struct {
	net.Conn
	accept int
}

func (c *partialConn) Write(p []byte) (int, error) {
	if c.accept <= 0 {
		return 0, io.ErrClosedPipe
	}
	n := min(len(p), c.accept)
	c.accept -= n
	if n < len(p) {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

// TestWriteFrameReportsExactWriteBoundary pins the classification
// input: the number of bytes the kernel accepted, so a frame that was
// not fully written is provably pre-dispatch.
func TestWriteFrameReportsExactWriteBoundary(t *testing.T) {
	frame := []byte("0123456789")
	for _, tc := range []struct {
		name    string
		accept  int
		written int
		failed  bool
	}{
		{name: "nothing accepted", accept: 0, written: 0, failed: true},
		{name: "partially accepted", accept: 4, written: 4, failed: true},
		{name: "fully accepted", accept: 10, written: 10, failed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			written, err := writeFrame(&partialConn{accept: tc.accept}, frame)
			if written != tc.written {
				t.Fatalf("expected %d bytes accepted, got %d", tc.written, written)
			}
			if failed := err != nil; failed != tc.failed {
				t.Fatalf("expected failed=%v, got err=%v", tc.failed, err)
			}
			// The dispatch boundary: only a fully written frame can
			// have been dispatched.
			if got := written < len(frame); got != tc.failed {
				t.Fatalf("frame-complete classification disagreed with the write result")
			}
		})
	}
}

func TestClientRequestMarshalFailureIsPreDispatch(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "missing.sock"), ClientOptions{Timeout: time.Second})
	req := clientRequest()
	req.Arguments = json.RawMessage(`{"broken":`)
	_, err := client.Invoke(context.Background(), req)
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportPreDispatch {
		t.Fatalf("expected PRE_DISPATCH, got %v", err)
	}
}

// ─── Durable post-dispatch semantics ─────────────────────────────────

// slowHandler delays the provider answer, so a client's response wait
// can expire while the service keeps working toward the durable
// terminal outcome.
type slowHandler struct {
	inner Handler
	delay time.Duration
}

func (h slowHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	time.Sleep(h.delay)
	return h.inner.Execute(ctx, req, desc)
}

// mutationService wires a durable dispatch executor behind a real
// service for the post-dispatch timeout tests.
func mutationService(t *testing.T, socketPath string, delay time.Duration) *idempotency.SQLiteStore {
	t.Helper()
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}
	inner := NewMultiHandler(map[string]Handler{"test-counter": NewCounterHandler()})
	executor := NewDispatchExecutor(slowHandler{inner: inner, delay: delay}, store)
	service := setupServiceWithGrants(registry, executor, socketPath)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { service.Stop() })
	return store
}

func awaitDurableCommit(t *testing.T, store *idempotency.SQLiteStore, key string, wait time.Duration) {
	t.Helper()
	deadline := time.Now().Add(wait)
	var lastState idempotency.State
	var lastErr error
	for time.Now().Before(deadline) {
		rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.counter.increment", key)
		if err == nil {
			lastState, lastErr = rec.State, nil
			if rec.State == idempotency.StateCommitted {
				return
			}
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the invocation never reached its durable terminal outcome: state=%s err=%v", lastState, lastErr)
}

// TestClientWaitExpiryLeavesTheMutationCommitting is the fast
// regression for the post-dispatch contract: the client stops waiting
// and reports an ambiguous failure, while the service — which never
// learned the client left — drives the invocation to its durable
// terminal outcome. Reporting FAILED at the client would invite a
// retry while the first mutation may still commit.
func TestClientWaitExpiryLeavesTheMutationCommitting(t *testing.T) {
	socketPath := testSocketPath(t)
	store := mutationService(t, socketPath, 750*time.Millisecond)

	key := fmt.Sprintf("post-dispatch-%d", time.Now().UnixNano())
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"pd","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: key,
	}
	client := NewClient(socketPath, ClientOptions{Timeout: 100 * time.Millisecond})
	_, err := client.Invoke(context.Background(), req)
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportPostDispatch {
		t.Fatalf("expected POST_DISPATCH, got %v", err)
	}
	if !AmbiguousOutcome(err) {
		t.Fatal("an expired wait must be an ambiguous outcome")
	}

	awaitDurableCommit(t, store, key, 10*time.Second)
}

// TestLateResponseAfterConnectionLifetime pins the property that makes
// a longer client wait meaningful: the service's connection lifetime
// bounds the request READ, not the response write. writeResponse sets
// its own write deadline, so an invocation that finishes after the
// 60-second connection lifetime still delivers its definitive answer
// instead of stranding the caller with an ambiguity it did not have.
// Skipped unless explicitly requested: the provider deliberately
// outlives the connection lifetime.
func TestLateResponseAfterConnectionLifetime(t *testing.T) {
	if os.Getenv("CRABBOX_QUALIFICATION_POST_DISPATCH") != "1" {
		t.Skip("set CRABBOX_QUALIFICATION_POST_DISPATCH=1 to run the late-response qualification")
	}
	socketPath := testSocketPath(t)
	// The provider finishes past the service's 60-second connection
	// lifetime.
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := setupServiceWithGrants(registry, slowHandler{
		inner: NewMultiHandler(map[string]Handler{"system": NewEchoHandler()}),
		delay: connectionLifetime + 5*time.Second,
	}, socketPath)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	client := NewClient(socketPath, ClientOptions{Timeout: connectionLifetime + 30*time.Second})
	resp, err := client.Invoke(context.Background(), Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"late"}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	})
	if err != nil {
		t.Fatalf("a response after the connection lifetime was lost: %v", err)
	}
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}
}

// TestPostDispatchTimeoutQualification is the >30-second
// qualification: it uses the production default client wait against a
// mutation that outlives it, and proves the client returns an
// ambiguous failure while the service still reaches its durable
// terminal outcome. Skipped unless explicitly requested, because it
// deliberately waits out the real 30-second default.
func TestPostDispatchTimeoutQualification(t *testing.T) {
	if os.Getenv("CRABBOX_QUALIFICATION_POST_DISPATCH") != "1" {
		t.Skip("set CRABBOX_QUALIFICATION_POST_DISPATCH=1 to run the >30s post-dispatch qualification")
	}
	socketPath := testSocketPath(t)
	// The provider outlives the client's 30-second default wait.
	store := mutationService(t, socketPath, DefaultClientTimeout+2*time.Second)

	key := fmt.Sprintf("post-dispatch-qual-%d", time.Now().UnixNano())
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"qual","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: key,
	}
	client := NewClient(socketPath, ClientOptions{})
	started := time.Now()
	_, err := client.Invoke(context.Background(), req)
	if elapsed := time.Since(started); elapsed < DefaultClientTimeout {
		t.Fatalf("the client returned before its %s wait expired (%s)", DefaultClientTimeout, elapsed)
	}
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportPostDispatch {
		t.Fatalf("expected POST_DISPATCH, got %v", err)
	}
	if !AmbiguousOutcome(err) {
		t.Fatal("a wait expiry past the production default must be ambiguous")
	}

	awaitDurableCommit(t, store, key, DefaultClientTimeout)
}

// TestClientCancellationIsClassifiedNotSwallowed pins that a cancelled
// caller unblocks the client instead of waiting out the socket
// deadline, and that the resulting failure keeps its dispatch
// classification.
func TestClientCancellationIsClassifiedNotSwallowed(t *testing.T) {
	socketPath := fakeService(t, func(conn net.Conn) {
		if err := readRequestFrame(conn); err != nil {
			return
		}
		// Hold the connection open: the cancellation, not the server,
		// must end this exchange.
		time.Sleep(2 * time.Second)
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	client := NewClient(socketPath, ClientOptions{Timeout: 10 * time.Second})
	started := time.Now()
	_, err := client.Invoke(ctx, clientRequest())
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancellation did not unblock the client (%s)", elapsed)
	}
	var transport *TransportError
	if !errors.As(err, &transport) || transport.Kind != TransportPostDispatch {
		t.Fatalf("expected POST_DISPATCH after transmission, got %v", err)
	}
}
