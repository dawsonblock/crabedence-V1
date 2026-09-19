package execution

import (
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
		})

		var response Response
		if err := json.Unmarshal(readFrame(t, client), &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.Status != StatusSucceeded || string(response.Result) != `{"ok":true}` {
			t.Fatalf("response = %+v", response)
		}
	})

	t.Run("oversized response is replaced by an error frame", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		oversized := json.RawMessage(`"` + strings.Repeat("x", maxMessageBytes+1) + `"`)
		service := &Service{}
		go service.writeResponse(server, Response{Status: StatusSucceeded, Result: oversized})

		frame := readFrame(t, client)
		if len(frame) > maxMessageBytes {
			t.Fatalf("frame length %d exceeds the bound", len(frame))
		}
		var response Response
		if err := json.Unmarshal(frame, &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.Status != StatusFailed || !strings.Contains(response.Error, "frame bound") {
			t.Fatalf("oversized response must be replaced by an error frame, got %+v", response)
		}
	})
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
