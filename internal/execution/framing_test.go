package execution

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// byteAtATimeWriter accepts exactly one byte per Write call — the
// pathological short-write case a Unix stream can produce.
type byteAtATimeWriter struct {
	buf []byte
}

func (w *byteAtATimeWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.buf = append(w.buf, p[0])
	return 1, nil
}

// stalledWriter accepts nothing and reports no error — the case that
// must become a hard error rather than an infinite loop.
type stalledWriter struct{}

func (stalledWriter) Write([]byte) (int, error) { return 0, nil }

// failingWriter always errors.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("injected write failure") }

func TestWriteFullHandlesShortWrites(t *testing.T) {
	payload := []byte("framed-transport-payload")
	writer := &byteAtATimeWriter{}
	if err := writeFull(writer, payload); err != nil {
		t.Fatalf("writeFull: %v", err)
	}
	if string(writer.buf) != string(payload) {
		t.Fatalf("wrote %q, want %q", writer.buf, payload)
	}
}

func TestWriteFullFailsClosed(t *testing.T) {
	if err := writeFull(stalledWriter{}, []byte("x")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("zero-byte write must fail with ErrUnexpectedEOF, got %v", err)
	}
	if err := writeFull(failingWriter{}, []byte("x")); err == nil {
		t.Fatal("write errors must propagate")
	}
}

// readFrame reads one length-prefixed frame from conn.
func readFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := binary.BigEndian.Uint32(header)
	if length > maxMessageBytes {
		t.Fatalf("frame length %d exceeds the bound", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read frame payload: %v", err)
	}
	return payload
}

func TestWriteResponseFramesAndBounds(t *testing.T) {
	t.Run("normal response round-trips", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		service := &Service{}
		go service.writeResponse(server, Response{
			Status: StatusSucceeded,
			Result: json.RawMessage(`{"ok":true}`),
		}, capability.ClassRead)

		var response Response
		if err := json.Unmarshal(readFrame(t, client), &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.Status != StatusSucceeded || string(response.Result) != `{"ok":true}` {
			t.Fatalf("response = %+v", response)
		}
	})

	// A response that cannot be framed is replaced by a parseable one —
	// but the substitute must tell the truth about the execution. A READ
	// can prove no effect occurred, so FAILED stays definitive; a
	// MUTATION may already have taken effect, so it becomes UNKNOWN.
	oversized := json.RawMessage(`"` + strings.Repeat("x", maxMessageBytes+1) + `"`)
	for _, tc := range []struct {
		name          string
		executedClass capability.ExecutionClass
		wantStatus    string
		wantCode      string
	}{
		{name: "read", executedClass: capability.ClassRead, wantStatus: StatusFailed, wantCode: string(capability.FailureInternalError)},
		{name: "mutation", executedClass: capability.ClassMutation, wantStatus: StatusUnknown, wantCode: string(capability.FailureExecutionUnknown)},
		{name: "critical", executedClass: capability.ClassCritical, wantStatus: StatusUnknown, wantCode: string(capability.FailureExecutionUnknown)},
		{name: "before admission", executedClass: "", wantStatus: StatusFailed, wantCode: string(capability.FailureInternalError)},
	} {
		t.Run("oversized response is replaced by an error frame ("+tc.name+")", func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			service := &Service{}
			go service.writeResponse(server, Response{Status: StatusSucceeded, Result: oversized}, tc.executedClass)

			frame := readFrame(t, client)
			if len(frame) > maxMessageBytes {
				t.Fatalf("frame length %d exceeds the bound", len(frame))
			}
			var response Response
			if err := json.Unmarshal(frame, &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.Status != tc.wantStatus || response.FailureCode != tc.wantCode {
				t.Fatalf("oversized response must be replaced truthfully, got %+v", response)
			}
			if !strings.Contains(response.Error, "frame bound") {
				t.Fatalf("the substitute must name the frame bound, got %+v", response)
			}
		})
	}
}

// TestOversizedMutationResponseIsUnknownNotFailed proves the caller-facing
// contract for a side-effectful execution whose response cannot be framed:
// the mutation may already have taken effect, so the substitute must be an
// ambiguity the caller reconciles — never a definitive FAILED.
func TestOversizedMutationResponseIsUnknownNotFailed(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := oversizedResultHandler{}
	service := setupServiceWithGrants(registry, handler, socketPath)
	if err := service.Start(t.Context()); err != nil {
		t.Fatalf("start service: %v", err)
	}
	defer service.Stop()

	client := NewClient(socketPath, ClientOptions{Timeout: 10 * time.Second})
	resp, err := client.Invoke(t.Context(), Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"oversized","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: "oversized-response-1",
	})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if resp.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN for an unframeable mutation result, got %s: %s", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureExecutionUnknown) {
		t.Fatalf("expected EXECUTION_UNKNOWN, got %s", resp.FailureCode)
	}
}

// oversizedResultHandler succeeds with a result the wire cannot carry.
type oversizedResultHandler struct{}

func (oversizedResultHandler) Execute(context.Context, Request, capability.ResolvedDescriptor) Response {
	return Response{
		Status: StatusSucceeded,
		Result: json.RawMessage(`"` + strings.Repeat("x", maxMessageBytes+1) + `"`),
	}
}

// TestOversizedRequestFrameIsRejected proves the service refuses an
// oversized length prefix before allocating the body.
func TestOversizedRequestFrameIsRejected(t *testing.T) {
	registry := capability.NewRegistry()
	dispatcher := NewRouteDispatcher(nil)
	socketPath := testSocketPath(t)
	service := NewService(registry, dispatcher, socketPath)
	if err := service.Start(t.Context()); err != nil {
		t.Fatalf("start service: %v", err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, maxMessageBytes+1)
	if _, err := conn.Write(header); err != nil {
		t.Fatal(err)
	}

	var response Response
	if err := json.Unmarshal(readFrame(t, conn), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != StatusFailed || !strings.Contains(response.Error, "too large") {
		t.Fatalf("oversized frame must be rejected, got %+v", response)
	}
}
