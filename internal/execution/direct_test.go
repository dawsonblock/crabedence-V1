package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
)

func githubReadsRegistry(t *testing.T, baseURL, token string) (*capability.Registry, *DirectReadRegistry) {
	t.Helper()
	registry := capability.NewRegistry()
	if err := RegisterGitHubReadCapabilities(registry); err != nil {
		t.Fatalf("register github.issue.get: %v", err)
	}
	reads := NewDirectReadRegistry()
	if err := RegisterGitHubReads(reads, NewGitHubReads(baseURL, token)); err != nil {
		t.Fatalf("register github reads: %v", err)
	}
	return registry, reads
}

func TestGitHubIssueGetDirectRead(t *testing.T) {
	var gotAuth string
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"number": 42,
			"title": "Crash on startup",
			"state": "open",
			"html_url": "https://github.com/example-org/my-app/issues/42",
			"created_at": "2026-09-01T10:00:00Z",
			"updated_at": "2026-09-02T11:00:00Z",
			"user": {"login": "alice"},
			"body": "SECRET-INTERNAL-NOTES",
			"labels": [{"name": "bug"}]
		}`)
	}))
	defer server.Close()

	registry, reads := githubReadsRegistry(t, server.URL, "test-token")
	desc, ok := registry.Lookup("github.issue.get")
	if !ok {
		t.Fatal("github.issue.get must be registered")
	}
	if desc.ExecutionRoute != capability.RouteDirect {
		t.Fatalf("route = %s, want DIRECT", desc.ExecutionRoute)
	}

	dispatcher := NewRouteDispatcher(nil)
	dispatcher.SetDirect(reads)
	response := dispatcher.Execute(context.Background(), Request{
		Capability: "github.issue.get",
		Arguments:  json.RawMessage(`{"repo":"example-org/my-app","number":42}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}, desc)

	if response.Status != StatusSucceeded {
		t.Fatalf("direct read failed: %s: %s", response.Status, response.Error)
	}
	if gotPath != "/repos/example-org/my-app/issues/42" {
		t.Fatalf("request path = %s", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("authorization header = %q", gotAuth)
	}

	var result map[string]any
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if result["title"] != "Crash on startup" || result["author"] != "alice" {
		t.Fatalf("projected result = %v", result)
	}
	// The projection must not pass provider payloads through.
	if _, present := result["body"]; present {
		t.Fatal("direct read must project a bounded field set, not return the raw provider payload")
	}
	if _, present := result["labels"]; present {
		t.Fatal("direct read must not return undeclared provider fields")
	}
	if response.Execution == nil || response.Execution.Provider != "github" {
		t.Fatalf("execution metadata = %+v", response.Execution)
	}
}

func TestGitHubIssueGetFailuresAreSafe(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}))
	defer notFound.Close()

	registry, reads := githubReadsRegistry(t, notFound.URL, "")
	desc, _ := registry.Lookup("github.issue.get")
	dispatcher := NewRouteDispatcher(nil)
	dispatcher.SetDirect(reads)

	response := dispatcher.Execute(context.Background(), Request{
		Capability: "github.issue.get",
		Arguments:  json.RawMessage(`{"repo":"example-org/my-app","number":7}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}, desc)

	if response.Status != StatusFailed {
		t.Fatalf("a failed read is a safe FAILED, got %s", response.Status)
	}
	if !strings.Contains(response.Error, "not found") {
		t.Fatalf("error = %s", response.Error)
	}
}

func TestGitHubIssueGetBoundsResponseBody(t *testing.T) {
	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("x", 64*1024)
		for i := 0; i < (maxDirectReadBytes/len(chunk))+2; i++ {
			fmt.Fprint(w, chunk)
		}
	}))
	defer oversized.Close()

	registry, reads := githubReadsRegistry(t, oversized.URL, "")
	desc, _ := registry.Lookup("github.issue.get")
	dispatcher := NewRouteDispatcher(nil)
	dispatcher.SetDirect(reads)

	response := dispatcher.Execute(context.Background(), Request{
		Capability: "github.issue.get",
		Arguments:  json.RawMessage(`{"repo":"example-org/my-app","number":7}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}, desc)

	if response.Status != StatusFailed || !strings.Contains(response.Error, "exceeds") {
		t.Fatalf("oversized provider response must fail closed, got %s: %s", response.Status, response.Error)
	}
}

func TestDirectRegistryEnforcesRouteAndClass(t *testing.T) {
	reads := NewDirectReadRegistry()
	if err := reads.Register("test.read", func(context.Context, CallContext) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}); err != nil {
		t.Fatal(err)
	}

	// A MUTATION descriptor must never execute in the read runtime.
	mutation := mutationDurableDescriptor("test.read")
	mutation.ExecutionRoute = capability.RouteDirect
	if response := reads.Execute(context.Background(), testRequest("test.read"), mutation); response.Status != StatusDenied {
		t.Fatalf("MUTATION on the DIRECT runtime must be denied, got %s", response.Status)
	}

	// A READ descriptor on the durable route is not a DIRECT read.
	durableRead := readDirectDescriptor("test.read")
	durableRead.ExecutionRoute = capability.RouteCrabedence
	if response := reads.Execute(context.Background(), testRequest("test.read"), durableRead); response.Status != StatusDenied {
		t.Fatalf("READ on the CRABEDENCE route must not execute in the DIRECT runtime, got %s", response.Status)
	}

	// Unregistered reads fail closed.
	missing := reads.Execute(context.Background(), testRequest("test.missing"), readDirectDescriptor("test.missing"))
	if missing.FailureCode != string(capability.FailureCapabilityUnimplemented) {
		t.Fatalf("unregistered DIRECT capability must be unimplemented, got %s", missing.FailureCode)
	}
}

func TestSystemInfoDirectReadThroughDispatcher(t *testing.T) {
	registry := capability.NewRegistry()
	if err := RegisterSystemInfoCapability(registry); err != nil {
		t.Fatal(err)
	}
	desc, ok := registry.Lookup("system.info")
	if !ok {
		t.Fatal("system.info must be registered")
	}
	if desc.ExecutionRoute != capability.RouteDirect {
		t.Fatalf("system.info route = %s, want DIRECT (READ + STANDARD)", desc.ExecutionRoute)
	}

	reads := NewDirectReadRegistry()
	if err := RegisterSystemInfoRead(reads, NewSystemInfoHandler()); err != nil {
		t.Fatal(err)
	}
	dispatcher := NewRouteDispatcher(nil)
	dispatcher.SetDirect(reads)

	response := dispatcher.Execute(context.Background(), Request{
		Capability: "system.info",
		Arguments:  json.RawMessage(`{}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	}, desc)
	if response.Status != StatusSucceeded {
		t.Fatalf("system.info direct read failed: %s: %s", response.Status, response.Error)
	}
	var result map[string]any
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if result["go_version"] == nil || result["principal"] != "alice@example.com" {
		t.Fatalf("system.info result = %v", result)
	}
}

// TestDirectReadEndToEndOverSocket proves the full DIRECT path through
// the service: socket → admission → schema validation → route
// dispatcher → read adapter → projected result, with no durable ledger.
func TestDirectReadEndToEndOverSocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"number": 9, "title": "Flaky test", "state": "closed", "html_url": "https://example.test/9", "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z", "user": {"login": "bob"}}`)
	}))
	defer server.Close()

	registry := capability.NewRegistry()
	for _, register := range []func(*capability.Registry) error{
		RegisterEchoCapability,
		RegisterSystemInfoCapability,
		RegisterGitHubReadCapabilities,
	} {
		if err := register(registry); err != nil {
			t.Fatal(err)
		}
	}

	hooks := NewFunctionHookRegistry()
	if err := RegisterSystemEchoHook(hooks); err != nil {
		t.Fatal(err)
	}
	reads := NewDirectReadRegistry()
	if err := RegisterSystemInfoRead(reads, NewSystemInfoHandler()); err != nil {
		t.Fatal(err)
	}
	if err := RegisterGitHubReads(reads, NewGitHubReads(server.URL, "token")); err != nil {
		t.Fatal(err)
	}
	dispatcher := NewRouteDispatcher(nil)
	dispatcher.SetLocal(hooks)
	dispatcher.SetDirect(reads)

	socketPath := testSocketPath(t)
	service := NewService(registry, dispatcher, socketPath)
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("start service: %v", err)
	}
	defer service.Stop()

	// The service handles one request per connection.
	send := func(req Request) Response {
		t.Helper()
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return sendRequest(t, conn, req)
	}

	response := send(Request{
		Capability: "github.issue.get",
		Arguments:  json.RawMessage(`{"repo":"example-org/my-app","number":9}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	})
	if response.Status != StatusSucceeded {
		t.Fatalf("github.issue.get over the socket failed: %s: %s", response.Status, response.Error)
	}
	var result map[string]any
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if result["title"] != "Flaky test" || result["author"] != "bob" {
		t.Fatalf("projected result = %v", result)
	}

	// A READ with an invalid argument shape is rejected at admission.
	denied := send(Request{
		Capability: "github.issue.get",
		Arguments:  json.RawMessage(`{"repo":"example-org/my-app","number":0}`),
		Authority:  RequestAuthority{Principal: "alice@example.com"},
	})
	if denied.Status != StatusDenied {
		t.Fatalf("invalid read arguments must be denied, got %s: %s", denied.Status, denied.Error)
	}
}
