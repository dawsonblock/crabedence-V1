package execution

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// TestEndToEndSystemInfo verifies the full execution path:
// client → Unix socket → Service → admission → authority → handler → response
//
// This is the closest test to the real NEMO → Go path without
// requiring a TypeScript runtime. It uses system.info (READ class)
// which goes through the remote execution port.
func TestEndToEndSystemInfo(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	if err := RegisterSystemInfoCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"system":      NewEchoHandler(),
		"system-info": NewSystemInfoHandler(),
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

	// system.info is a READ capability — goes through the remote port
	req := Request{
		Capability: "system.info",
		Arguments:  json.RawMessage(`{}`),
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

	if result["go_version"] == nil {
		t.Error("expected go_version in result")
	}
	if result["os"] == nil {
		t.Error("expected os in result")
	}
	if result["principal"] != "alice@example.com" {
		t.Errorf("expected principal=alice@example.com, got %v", result["principal"])
	}
	if result["capability"] != "system.info" {
		t.Errorf("expected capability=system.info, got %v", result["capability"])
	}

	if resp.Execution == nil {
		t.Fatal("expected execution metadata")
	}
	if resp.Execution.Provider != "system-info" {
		t.Errorf("expected provider=system-info, got %s", resp.Execution.Provider)
	}
	if resp.Execution.RunID == "" {
		t.Error("expected non-empty run_id")
	}
}

// TestEndToEndEcho verifies the echo capability through the full path.
func TestEndToEndEcho(t *testing.T) {
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

	req := Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"hello"}`),
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
	if echo["message"] != "hello" {
		t.Errorf("expected message=hello, got %v", echo["message"])
	}
}

// TestEndToEndAuthorityRejection verifies that a request without
// a valid grant is rejected by the authority verification layer.
func TestEndToEndAuthorityRejection(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})

	service := NewService(registry, handler, socketPath) // No grant resolver — uses NoopGrantResolver
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

	// test.counter.increment requires a grant — NoopGrantResolver returns nil
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"test","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", GrantID: "grant_123"},
		IdempotencyKey: "key_001",
	}

	resp := sendRequest(t, conn, req)
	if resp.Status != StatusDenied {
		t.Fatalf("expected DENIED, got %s: %s", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureUnauthorized) {
		t.Errorf("expected UNAUTHORIZED, got %s", resp.FailureCode)
	}
}

// TestEndToEndExpiredGrant verifies that an expired grant is rejected.
func TestEndToEndExpiredGrant(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})

	service := NewService(registry, handler, socketPath)
	resolver := capability.NewInMemoryGrantResolver()
	resolver.AddGrant(&capability.Grant{
		ID:           "expired_grant",
		Principal:    "alice@example.com",
		Capabilities: []string{"*"},
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
	})
	service.SetGrantResolver(resolver)

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
		Arguments:      json.RawMessage(`{"counter":"test","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", GrantID: "expired_grant"},
		IdempotencyKey: "key_001",
	}

	resp := sendRequest(t, conn, req)
	if resp.Status != StatusDenied {
		t.Fatalf("expected DENIED, got %s: %s", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureUnauthorized) {
		t.Errorf("expected UNAUTHORIZED, got %s", resp.FailureCode)
	}
}

// TestEndToEndWrongPrincipal verifies that a grant issued to one principal
// cannot be used by another.
func TestEndToEndWrongPrincipal(t *testing.T) {
	socketPath := testSocketPath(t)

	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	handler := NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	})

	service := NewService(registry, handler, socketPath)
	resolver := capability.NewInMemoryGrantResolver()
	resolver.AddGrant(&capability.Grant{
		ID:           "grant_alice",
		Principal:    "alice@example.com",
		Capabilities: []string{"*"},
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	service.SetGrantResolver(resolver)

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

	// Bob tries to use Alice's grant
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"test","by":1}`),
		Authority:      RequestAuthority{Principal: "bob@example.com", GrantID: "grant_alice"},
		IdempotencyKey: "key_001",
	}

	resp := sendRequest(t, conn, req)
	if resp.Status != StatusDenied {
		t.Fatalf("expected DENIED, got %s: %s", resp.Status, resp.Error)
	}
	if resp.FailureCode != string(capability.FailureUnauthorized) {
		t.Errorf("expected UNAUTHORIZED, got %s", resp.FailureCode)
	}
}
