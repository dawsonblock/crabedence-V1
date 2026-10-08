package execution

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// gatedHandler counts dispatched executions and can block inside
// Execute so a test can hold a dispatch in flight.
type gatedHandler struct {
	executions atomic.Int64
	started    chan struct{}
	release    chan struct{}
	startOnce  sync.Once
}

func (h *gatedHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	h.executions.Add(1)
	if h.started != nil {
		h.startOnce.Do(func() { close(h.started) })
	}
	if h.release != nil {
		<-h.release
	}
	return Response{Status: StatusSucceeded, Result: json.RawMessage(`{"ok":true}`)}
}

// sendRequestTolerant writes one request frame and reads one response,
// reporting whether a response arrived. A write failure means the
// service closed the connection before the frame completed — a
// pre-dispatch refusal, which the client classifies as a definitive
// failure with no effect.
func sendRequestTolerant(conn net.Conn, req Request) (Response, bool) {
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, false
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		return Response{}, false
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return Response{}, false
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n > maxMessageBytes {
		return Response{}, false
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return Response{}, false
	}
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		return Response{}, false
	}
	return resp, true
}

func admissionTestService(t *testing.T, handler Handler, connections, handshakes int) *Service {
	t.Helper()
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := NewService(registry, handler, socketPath)
	service.SetAdmissionLimits(connections, handshakes)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { service.Stop() })
	return service
}

func echoRequest() Request {
	return Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"hello"}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}
}

// TestAdmissionLimitSlots proves the ceiling primitives refuse rather
// than wait, and that a released slot is reusable.
func TestAdmissionLimitSlots(t *testing.T) {
	service := NewService(capability.NewRegistry(), succeedHandler{}, testSocketPath(t))
	service.SetAdmissionLimits(1, 1)

	if !service.tryAcquireConnection() {
		t.Fatal("the first connection slot must be granted")
	}
	if service.tryAcquireConnection() {
		t.Fatal("a connection slot beyond the ceiling must be refused, not queued")
	}
	service.releaseConnection()
	if !service.tryAcquireConnection() {
		t.Fatal("a released connection slot must be reusable")
	}
	service.releaseConnection()

	if !service.tryAcquireHandshake() {
		t.Fatal("the first handshake slot must be granted")
	}
	if service.tryAcquireHandshake() {
		t.Fatal("a handshake slot beyond the ceiling must be refused, not queued")
	}
	service.releaseHandshake()
	if !service.tryAcquireHandshake() {
		t.Fatal("a released handshake slot must be reusable")
	}
	service.releaseHandshake()
}

// TestConnectionCeilingRefusesBeforeDispatch proves a connection at the
// ceiling is refused definitively — never dispatched — and that the
// ceiling is transient: once a slot frees, the same request succeeds.
func TestConnectionCeilingRefusesBeforeDispatch(t *testing.T) {
	handler := &gatedHandler{}
	service := admissionTestService(t, handler, 1, 4)

	// Hold the only connection slot with a silent connection. The
	// service accepts it before any later connection (the accept queue
	// is ordered), so the slot is provably taken.
	held, err := net.Dial("unix", service.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	conn, err := net.Dial("unix", service.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The refusal writes a BUSY frame and closes; a client whose frame
	// write races the close sees a pre-dispatch failure instead. Both
	// are refusals — the property under test is that nothing dispatched.
	if resp, gotResponse := sendRequestTolerant(conn, echoRequest()); gotResponse {
		if resp.Status != StatusFailed ||
			resp.FailureCode != string(capability.FailureServiceBusy) ||
			!resp.DefinitiveFailure {
			t.Fatalf("refusal = %+v, want FAILED/%s/definitive", resp, capability.FailureServiceBusy)
		}
	}
	if got := handler.executions.Load(); got != 0 {
		t.Fatalf("the refused request was dispatched: %d executions", got)
	}

	// Free the slot: the ceiling must be transient.
	held.Close()
	deadline := time.Now().Add(5 * time.Second)
	succeeded := false
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", service.socketPath)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		resp, gotResponse := sendRequestTolerant(conn, echoRequest())
		conn.Close()
		if gotResponse {
			if resp.Status == StatusSucceeded {
				succeeded = true
				break
			}
			if resp.FailureCode != string(capability.FailureServiceBusy) {
				t.Fatalf("unexpected response after the ceiling: %+v", resp)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !succeeded {
		t.Fatal("a request after the ceiling was freed never succeeded")
	}
	if got := handler.executions.Load(); got != 1 {
		t.Fatalf("executions = %d, want exactly 1 (only the admitted request)", got)
	}
}

// TestHandshakeCeilingRefusesBeforeAuthentication proves the
// unauthenticated phase is bounded separately: with the handshake
// ceiling reached, a challenge is refused with an explicit busy error
// instead of doing the work, and once a slot frees the handshake
// proceeds.
func TestHandshakeCeilingRefusesBeforeAuthentication(t *testing.T) {
	handler := &gatedHandler{}
	service := admissionTestService(t, handler, 4, 1)
	service.SetAttestation(AttestationPolicy{Required: true, Relaxed: true})

	// Occupy the single handshake slot, as a slow handshake would.
	if !service.tryAcquireHandshake() {
		t.Fatal("failed to occupy the handshake slot")
	}

	conn, err := net.Dial("unix", service.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFrame(conn, map[string]string{"type": attestChallengeType})
	var refused attestResponse
	readJSONFrame(t, conn, &refused)
	conn.Close()
	if refused.Status != "error" || refused.Error == "" {
		t.Fatalf("a handshake at the ceiling must be refused explicitly, got %+v", refused)
	}

	// Release the slot: the handshake must proceed.
	service.releaseHandshake()
	conn, err = net.Dial("unix", service.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writeJSONFrame(conn, map[string]string{"type": attestChallengeType})
	var challenge challengeResponse
	readJSONFrame(t, conn, &challenge)
	if challenge.SessionID == "" || challenge.Nonce == "" {
		t.Fatalf("challenge after the ceiling was freed is incomplete: %+v", challenge)
	}
}

// TestHeaderTimeoutDropsSilentConnections proves a connection that
// never sends its length prefix is dropped within the short header
// bound, not held for the full request lifetime.
func TestHeaderTimeoutDropsSilentConnections(t *testing.T) {
	service := admissionTestService(t, &gatedHandler{}, DefaultMaxConnections, DefaultMaxHandshakeConnections)

	conn, err := net.Dial("unix", service.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(headerReadTimeout + 4*time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("a silent connection produced data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("the service held a silent connection for %s — the header must be dropped within %s", time.Since(start), headerReadTimeout)
	}
	if elapsed := time.Since(start); elapsed > headerReadTimeout+3*time.Second {
		t.Fatalf("silent connection dropped after %s, want within %s", elapsed, headerReadTimeout+3*time.Second)
	}
}

// TestStopDrainsInFlightHandlers proves Stop waits for an admitted
// dispatch to finish rather than abandoning it mid-flight.
func TestStopDrainsInFlightHandlers(t *testing.T) {
	handler := &gatedHandler{started: make(chan struct{}), release: make(chan struct{})}
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := NewService(registry, handler, socketPath)
	service.SetAdmissionLimits(4, 4)
	service.drainTimeout = 10 * time.Second
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

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

	stopCh := make(chan error, 1)
	go func() { stopCh <- service.Stop() }()
	select {
	case err := <-stopCh:
		t.Fatalf("Stop returned (%v) while a handler was in flight", err)
	case <-time.After(250 * time.Millisecond):
	}

	close(handler.release)
	select {
	case err := <-stopCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after the in-flight handler finished")
	}

	select {
	case resp := <-respCh:
		if resp.Status != StatusSucceeded {
			t.Fatalf("the in-flight request received %+v, want its definitive answer", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the in-flight request received no response")
	}
}

// TestAdmissionLimitsFromConfig proves the ceilings resolve from the
// validated deployment configuration, with malformed values refused.
func TestAdmissionLimitsFromConfig(t *testing.T) {
	clearServiceEnv(t)
	cfg, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConnections != DefaultMaxConnections || cfg.MaxHandshakeConnections != DefaultMaxHandshakeConnections {
		t.Fatalf("defaults = %d/%d, want %d/%d", cfg.MaxConnections, cfg.MaxHandshakeConnections,
			DefaultMaxConnections, DefaultMaxHandshakeConnections)
	}

	t.Setenv("CRABEDENCE_MAX_CONNECTIONS", "8")
	t.Setenv("CRABEDENCE_MAX_HANDSHAKES", "2")
	cfg, err = LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConnections != 8 || cfg.MaxHandshakeConnections != 2 {
		t.Fatalf("declared ceilings = %d/%d, want 8/2", cfg.MaxConnections, cfg.MaxHandshakeConnections)
	}

	for _, bad := range []string{"0", "-1", "many"} {
		t.Setenv("CRABEDENCE_MAX_CONNECTIONS", bad)
		if _, err := LoadServiceConfig(ServeOptions{}); err == nil {
			t.Fatalf("CRABEDENCE_MAX_CONNECTIONS=%q must refuse startup", bad)
		}
	}
}
