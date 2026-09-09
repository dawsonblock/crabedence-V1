package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// TestConcurrentIdenticalMutations verifies that 100 concurrent
// mutation requests without durable idempotency ALL fail closed.
// This is the fail-closed guarantee: no unguarded mutations.
//
// When a PostgreSQL store is wired in (via DispatchExecutor), a
// separate test should verify that 100 concurrent identical mutations
// result in exactly ONE mutation (count == 1). That test requires
// a live PostgreSQL connection and belongs in the integration test suite.
func TestConcurrentIdenticalMutations(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	counter := NewCounterHandler()
	handler := NewMultiHandler(map[string]Handler{
		"test-counter": counter,
	})

	// No store → FailClosedHandler → MUTATION/CRITICAL fail closed
	failClosed := NewFailClosedHandler(handler)
	service := NewService(registry, failClosed, socketPath)
	service.SetGrantResolver(testGrantResolver())

	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)

	var failCount, successCount int64
	var mu sync.Mutex

	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			conn, err := net.Dial("unix", socketPath)
			if err != nil {
				t.Errorf("dial error: %v", err)
				return
			}
			defer conn.Close()

			req := Request{
				Capability:     "test.counter.increment",
				Arguments:      json.RawMessage(`{"counter":"concurrent","by":1}`),
				Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
				IdempotencyKey: "concurrent_key_001",
			}
			resp := sendRequest(t, conn, req)
			mu.Lock()
			if resp.Status == StatusFailed {
				failCount++
			} else if resp.Status == StatusSucceeded {
				successCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// ALL 100 must fail closed — no unguarded mutations
	if failCount != N {
		t.Errorf("expected %d failures (fail closed), got %d failures, %d successes", N, failCount, successCount)
	}
	if successCount != 0 {
		t.Errorf("expected 0 successes (no durable idempotency), got %d", successCount)
	}

	// Counter must be 0 — no mutations executed
	count := counter.GetCount("concurrent")
	if count != 0 {
		t.Errorf("expected count=0 (fail closed), got %d", count)
	}
}

// TestUnicodePayload verifies that Unicode arguments are handled correctly.
func TestUnicodePayload(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"system": NewEchoHandler(),
	})

	service := setupServiceWithGrants(registry, handler, socketPath)
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

	// Unicode payload with multi-byte characters
	req := Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"こんにちは世界🦀","emoji":"🎉"}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	echo, ok := result["echo"].(map[string]any)
	if !ok {
		t.Fatalf("expected echo object, got %v", result["echo"])
	}
	if echo["message"] != "こんにちは世界🦀" {
		t.Fatalf("unicode mismatch: got %v", echo["message"])
	}
}

// TestMaxFrameSize verifies that a message at the maximum size boundary
// is handled (not rejected as oversized).
func TestMaxFrameSize(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"system": NewEchoHandler(),
	})

	service := setupServiceWithGrants(registry, handler, socketPath)
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

	// Create a payload just under the 4 MiB limit
	// The JSON envelope adds some overhead, so we use ~3.5 MiB of data
	largeData := make([]byte, 3*1024*1024)
	for i := range largeData {
		largeData[i] = 'x'
	}
	req := Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(fmt.Sprintf(`{"data":"%s"}`, string(largeData))),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}

	// This should succeed (under the limit)
	resp := sendRequest(t, conn, req)
	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED for large payload, got %s: %s", resp.Status, resp.Error)
	}
}

// TestSocketCloseBeforeResponse verifies that closing the socket
// before receiving a response is handled gracefully.
func TestSocketCloseBeforeResponse(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	handler := NewMultiHandler(map[string]Handler{})

	service := setupServiceWithGrants(registry, handler, socketPath)
	ctx := context.Background()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	// Send a partial frame (just the length prefix, no body)
	lenBuf := make([]byte, 4)
	lenBuf[0] = 0x00
	lenBuf[1] = 0x00
	lenBuf[2] = 0x00
	lenBuf[3] = 0x10 // 16 bytes expected
	conn.Write(lenBuf)

	// Close immediately — server should handle this gracefully
	conn.Close()

	// Give the server a moment to process
	time.Sleep(100 * time.Millisecond)

	// Service should still be running
	service.mu.Lock()
	running := service.running
	service.mu.Unlock()
	if !running {
		t.Fatal("service should still be running after client disconnect")
	}
}

// TestExpiredDeadline verifies that an expired deadline is rejected.
func TestExpiredDeadline(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"system": NewEchoHandler(),
	})

	service := setupServiceWithGrants(registry, handler, socketPath)
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

	// Deadline in the past
	req := Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
		Deadline:   "2020-01-01T00:00:00Z",
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != "DENIED" {
		t.Fatalf("expected DENIED for expired deadline, got %s", resp.Status)
	}
	if resp.FailureCode != string(capability.FailureAdmissionDenied) {
		t.Fatalf("expected ADMISSION_DENIED, got %s", resp.FailureCode)
	}
}

// TestInvalidDeadline verifies that a malformed deadline is rejected.
func TestInvalidDeadline(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"system": NewEchoHandler(),
	})

	service := setupServiceWithGrants(registry, handler, socketPath)
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

	// Invalid deadline format (not RFC3339)
	req := Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
		Deadline:   "not-a-date",
	}
	resp := sendRequest(t, conn, req)

	if resp.Status != "DENIED" {
		t.Fatalf("expected DENIED for invalid deadline, got %s", resp.Status)
	}
}

// TestMalformedJSON verifies that malformed JSON in the request is rejected.
func TestMalformedJSON(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	handler := NewMultiHandler(map[string]Handler{})

	service := setupServiceWithGrants(registry, handler, socketPath)
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

	// Send malformed JSON
	payload := []byte(`{"capability": "system.echo", invalid}`)
	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(payload) >> 24)
	lenBuf[1] = byte(len(payload) >> 16)
	lenBuf[2] = byte(len(payload) >> 8)
	lenBuf[3] = byte(len(payload))

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(lenBuf)
	conn.Write(payload)

	resp := readResponse(t, conn)
	if resp.Status != "FAILED" {
		t.Fatalf("expected FAILED for malformed JSON, got %s", resp.Status)
	}
	if resp.FailureCode != string(capability.FailureInvalidRequest) {
		t.Fatalf("expected INVALID_REQUEST, got %s", resp.FailureCode)
	}
}
