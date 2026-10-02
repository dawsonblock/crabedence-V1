package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

func TestGitHubCommentCommitsWithMarkerAndEvidence(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id": 9001, "html_url": "https://github.test/issues/7#issuecomment-9001"}`)
	}))
	defer srv.Close()

	h := NewGitHubCommentHandler(srv.URL, "tok")
	ctx := context.WithValue(context.Background(), externalTokenKey{}, "gh-comment-exec-1")
	resp := h.Execute(ctx, Request{
		Capability: "github.issue.comment",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","number":7,"body":"confirmed"}`),
	}, testCounterDescriptor())

	if resp.Status != StatusSucceeded {
		t.Fatalf("comment commit failed: %s: %s", resp.Status, resp.Error)
	}
	if gotPath != "/repos/octo/repo/issues/7/comments" {
		t.Fatalf("request path = %s", gotPath)
	}
	var posted struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(gotBody), &posted); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	if !strings.Contains(posted.Body, "confirmed") || !strings.Contains(posted.Body, opMarker("gh-comment-exec-1")) {
		t.Fatalf("comment body must carry the operation marker: %s", posted.Body)
	}
	if resp.Execution.RunID != "https://github.test/issues/7#issuecomment-9001" {
		t.Fatalf("run ID = %q, want the provider's comment URL", resp.Execution.RunID)
	}
	if len(resp.EvidenceArtifact) == 0 {
		t.Fatal("the raw provider response must be bound as the evidence artifact")
	}
}

func TestGitHubCommentArgsValidationIsDefinitive(t *testing.T) {
	h := NewGitHubCommentHandler("http://github.invalid", "tok")
	cases := []struct {
		name string
		args string
	}{
		{"bad repo", `{"repo":"noslash","number":1,"body":"x"}`},
		{"nonpositive number", `{"repo":"octo/repo","number":0,"body":"x"}`},
		{"empty body", `{"repo":"octo/repo","number":1,"body":"  "}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.Execute(context.Background(), Request{
				Capability: "github.issue.comment",
				Arguments:  json.RawMessage(tc.args),
			}, testCounterDescriptor())
			if resp.Status != StatusFailed || !resp.DefinitiveFailure {
				t.Fatalf("invalid args must fail definitively — the request never left: %+v", resp)
			}
		})
	}
}

func TestGitHubCommentTransportAmbiguity(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		definitive bool
	}{
		{"conn_reset_after_send", &net.OpError{Op: "write", Err: syscall.ECONNRESET}, false},
		{"conn_refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"dns_failure", &net.DNSError{IsNotFound: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewGitHubCommentHandler("http://github.invalid", "tok")
			h.SetHTTPClient(&http.Client{Transport: errRoundTripper{err: tc.err}})
			resp := h.Execute(context.Background(), Request{
				Capability: "github.issue.comment",
				Arguments:  json.RawMessage(`{"repo":"octo/repo","number":3,"body":"x"}`),
			}, testCounterDescriptor())
			if resp.DefinitiveFailure != tc.definitive {
				t.Errorf("DefinitiveFailure=%v, want %v", resp.DefinitiveFailure, tc.definitive)
			}
		})
	}
}

func TestGitHubCommentRecoveryLocator(t *testing.T) {
	h := NewGitHubCommentHandler("http://github.invalid", "tok")
	loc, err := h.PrepareRecovery(context.Background(), idempotency.RecoveryLocatorInput{
		ExecutionID:   "exec-1",
		CapabilityID:  "github.issue.comment",
		RequestDigest: "digest-1",
		Arguments:     json.RawMessage(`{"repo":"octo/repo","number":9,"body":"secret body never persisted"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if loc.ResourceRef != "repos/octo/repo/issues/9/comments" {
		t.Fatalf("resource ref = %q", loc.ResourceRef)
	}
	if loc.ExternalToken == "" || loc.Strategy != "external-token" {
		t.Fatalf("locator must carry the external token strategy: %+v", loc)
	}
	if strings.Contains(string(loc.Extensions), "secret body") || strings.Contains(loc.ResourceRef, "secret") {
		t.Fatal("the locator must never carry the comment body")
	}
}

func TestGitHubCommentResolverMarkerScan(t *testing.T) {
	var requests int32
	marker := opMarker("gh-comment-exec-p2")
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "page=2") {
			fmt.Fprintf(w, `[{"id":2,"html_url":"https://github.test/issues/5#issuecomment-2","body":"note\n\n%s"}]`, marker)
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/octo/repo/issues/5/comments?per_page=100&page=2>; rel="next"`, srvURL(r)))
		fmt.Fprint(w, `[{"id":1,"html_url":"https://github.test/issues/5#issuecomment-1","body":"unrelated"}]`)
	}))
	defer srv.Close()

	h := NewGitHubCommentHandler(srv.URL, "tok")
	res, err := h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-comment-exec-p2","resource_ref":"repos/octo/repo/issues/5/comments"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("page-2 marker must resolve COMMITTED, got %s", res.Decision)
	}
	if res.ProviderRunID != "https://github.test/issues/5#issuecomment-2" {
		t.Errorf("expected the original comment URL, got %q", res.ProviderRunID)
	}
	if atomic.LoadInt32(&requests) < 2 {
		t.Errorf("the comment resolver must paginate — %d request(s)", requests)
	}

	// Exhausted listing without the marker is UNKNOWN, never FAILED:
	// absence of positive evidence is not proof of no effect.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	}))
	defer empty.Close()
	h2 := NewGitHubCommentHandler(empty.URL, "tok")
	res, err = h2.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-comment-absent","resource_ref":"repos/octo/repo/issues/5/comments"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryUnknown {
		t.Fatalf("marker-absent must stay UNKNOWN, got %s", res.Decision)
	}
}

func TestGitHubAdapterMuxRoutesAndFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id": 1, "html_url": "https://github.test/x#issuecomment-1"}`)
	}))
	defer srv.Close()

	mux := &githubAdapter{
		issue:   NewGitHubIssueHandler(srv.URL, "tok"),
		comment: NewGitHubCommentHandler(srv.URL, "tok"),
	}
	descFor := func(id string) capability.ResolvedDescriptor {
		d := testCounterDescriptor()
		d.ID = id
		d.AdapterID = "github"
		return d
	}

	// A capability the adapter does not carry fails closed — it never
	// falls through to a sibling handler.
	resp := mux.Execute(context.Background(), Request{
		Capability: "github.unknown",
		Arguments:  json.RawMessage(`{}`),
	}, descFor("github.unknown"))
	if resp.Status != StatusFailed || !resp.DefinitiveFailure {
		t.Fatalf("an unknown capability under the adapter must fail definitively: %+v", resp)
	}

	// The comment capability reaches the comment handler.
	resp = mux.Execute(context.Background(), Request{
		Capability: "github.issue.comment",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","number":5,"body":"hi"}`),
	}, descFor("github.issue.comment"))
	if resp.Status != StatusSucceeded {
		t.Fatalf("mux must route github.issue.comment to the comment handler: %v", resp.Error)
	}

	// PrepareRecovery routes by capability ID too.
	loc, err := mux.PrepareRecovery(context.Background(), idempotency.RecoveryLocatorInput{
		ExecutionID:   "e1",
		CapabilityID:  "github.issue.comment",
		RequestDigest: "d1",
		Arguments:     json.RawMessage(`{"repo":"octo/repo","number":5,"body":"x"}`),
	})
	if err != nil || loc == nil {
		t.Fatalf("mux PrepareRecovery must route: %v", err)
	}
	if loc.ResourceRef != "repos/octo/repo/issues/5/comments" {
		t.Fatalf("locator resource ref = %q", loc.ResourceRef)
	}
	if _, err := mux.PrepareRecovery(context.Background(), idempotency.RecoveryLocatorInput{
		CapabilityID: "github.unknown",
	}); err == nil {
		t.Fatal("PrepareRecovery on an unknown capability must fail closed")
	}
}

// testCounterDescriptor stands in for a resolved descriptor where the
// handler only reads Arguments/Capability — the dispatch contract tests
// do not depend on a real registration.
