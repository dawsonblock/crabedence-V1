package execution

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

func TestExecutionServiceEcho(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"system": NewEchoHandler(),
	})

	service := NewService(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"hello"}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}
	if resp.Execution == nil || resp.Execution.Provider != "system" {
		t.Fatalf("expected provider=system, got %+v", resp.Execution)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	echo, ok := result["echo"].(map[string]any)
	if !ok {
		t.Fatalf("expected echo object, got %v", result["echo"])
	}
	if echo["message"] != "hello" {
		t.Fatalf("expected echo.message=hello, got %v", echo["message"])
	}
}

func TestExecutionServiceCounterIncrement(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	counter := NewCounterHandler()
	handler := NewMultiHandler(map[string]Handler{
		"test-counter": counter,
	})

	service := NewService(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"test","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", GrantID: "grant_123"},
		IdempotencyKey: "key_001",
	}
	resp := sendRequest(t, conn, req)
	conn.Close()

	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}
	if counter.GetCount("test") != 1 {
		t.Fatalf("expected count=1, got %d", counter.GetCount("test"))
	}
}

func TestExecutionServiceUnknownCapability(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	handler := NewMultiHandler(map[string]Handler{})

	service := NewService(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := Request{
		Capability: "nonexistent.capability",
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != "DENIED" {
		t.Fatalf("expected DENIED, got %s", resp.Status)
	}
	if resp.FailureCode != string(capability.FailureCapabilityNotFound) {
		t.Fatalf("expected CAPABILITY_NOT_FOUND, got %s", resp.FailureCode)
	}
}

func TestExecutionServiceMissingIdempotencyKey(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})

	service := NewService(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := Request{
		Capability: "test.counter.increment",
		Arguments:  json.RawMessage(`{"counter":"test"}`),
		Authority:  RequestAuthority{Principal: "alice@example.com", GrantID: "grant_123"},
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != "DENIED" {
		t.Fatalf("expected DENIED, got %s", resp.Status)
	}
	if resp.FailureCode != string(capability.FailureAdmissionDenied) {
		t.Fatalf("expected ADMISSION_DENIED, got %s", resp.FailureCode)
	}
}

func TestExecutionServiceExecutionClassMismatch(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})

	service := NewService(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", GrantID: "grant_123"},
		IdempotencyKey: "key_001",
		ExecutionClass: "READ",
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != "DENIED" {
		t.Fatalf("expected DENIED, got %s", resp.Status)
	}
	if resp.FailureCode != string(capability.FailureAdmissionDenied) {
		t.Fatalf("expected ADMISSION_DENIED, got %s", resp.FailureCode)
	}
}

func TestExecutionServiceOversizedMessage(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	handler := NewMultiHandler(map[string]Handler{})

	service := NewService(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	lenBuf := make([]byte, 4)
	lenBuf[0] = 0x01
	conn.Write(lenBuf)

	resp := readResponse(t, conn)
	if resp.Status != "FAILED" {
		t.Fatalf("expected FAILED for oversized message, got %s", resp.Status)
	}
}

func TestExecutionServiceMissingAuthority(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})

	service := NewService(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{}`),
		IdempotencyKey: "key_001",
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != "DENIED" {
		t.Fatalf("expected DENIED, got %s", resp.Status)
	}
	if resp.FailureCode != string(capability.FailureUnauthorized) {
		t.Fatalf("expected UNAUTHORIZED, got %s", resp.FailureCode)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────

func testSocketPath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "crabedence-exec-test-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	return path
}

func sendRequest(t *testing.T, conn net.Conn, req Request) Response {
	t.Helper()
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(payload) >> 24)
	lenBuf[1] = byte(len(payload) >> 16)
	lenBuf[2] = byte(len(payload) >> 8)
	lenBuf[3] = byte(len(payload))

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(lenBuf); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	return readResponse(t, conn)
}

func readResponse(t *testing.T, conn net.Conn) Response {
	t.Helper()
	respLenBuf := make([]byte, 4)
	if _, err := readFull(conn, respLenBuf); err != nil {
		t.Fatal(err)
	}

	respLen := uint32(respLenBuf[0])<<24 | uint32(respLenBuf[1])<<16 | uint32(respLenBuf[2])<<8 | uint32(respLenBuf[3])
	if respLen > 4*1024*1024 {
		t.Fatalf("response too large: %d", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := readFull(conn, respBuf); err != nil {
		t.Fatal(err)
	}

	var resp Response
	if err := json.Unmarshal(respBuf, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
