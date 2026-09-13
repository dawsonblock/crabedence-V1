package execution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// errRoundTripper injects a transport error for every request.
type errRoundTripper struct{ err error }

func (rt errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, rt.err
}

// TestGitHubConnResetIsAmbiguous verifies the post-send safety rule:
// a TCP reset is NOT proof of no effect — the request may have been
// fully received and the issue created before the connection dropped.
// Only failures provably before request transmission (ECONNREFUSED,
// DNS failure) are definitive.
func TestGitHubConnResetIsAmbiguous(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		definitive bool
	}{
		{"conn_reset_after_send", &net.OpError{Op: "write", Err: syscall.ECONNRESET}, false},
		{"conn_refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"dns_failure", &net.DNSError{IsNotFound: true}, true},
		{"timeout", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewGitHubIssueHandler("http://github.invalid", "tok")
			h.SetHTTPClient(&http.Client{Transport: errRoundTripper{err: tc.err}})
			resp := h.Execute(context.Background(), Request{
				Capability: "github.issue.create",
				Arguments:  json.RawMessage(`{"repo":"octo/repo","title":"t"}`),
			}, testCounterDescriptor())
			if resp.DefinitiveFailure != tc.definitive {
				t.Errorf("%s: DefinitiveFailure=%v, want %v (err=%v)",
					tc.name, resp.DefinitiveFailure, tc.definitive, tc.err)
			}
		})
	}
}

// TestGitHubResolverPaginates verifies recovery follows Link rel="next"
// through the complete issue listing — a marker on page 2 must still
// resolve COMMITTED. A first-page miss is not proof of absence.
func TestGitHubResolverPaginates(t *testing.T) {
	var requests int32
	marker := opMarker("gh-issue-exec-p2")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "page=2") {
			fmt.Fprintf(w, `[{"number":2,"html_url":"https://github.test/issues/2","body":"real issue\n\n%s"}]`, marker)
			return
		}
		// Page 1: no marker, but there IS a next page.
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/octo/repo/issues?state=all&per_page=100&page=2>; rel="next"`, srvURL(r)))
		fmt.Fprint(w, `[{"number":1,"html_url":"https://github.test/issues/1","body":"unrelated"}]`)
	}))
	defer srv.Close()

	h := NewGitHubIssueHandler(srv.URL, "tok")
	res, err := h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-issue-exec-p2","resource_ref":"repos/octo/repo/issues"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("page-2 marker must resolve COMMITTED, got %s", res.Decision)
	}
	if res.ProviderRunID != "https://github.test/issues/2" {
		t.Errorf("expected original provider run ID, got %q", res.ProviderRunID)
	}
	if len(res.EvidenceArtifact) == 0 {
		t.Error("resolver must return the raw provider object as evidence artifact")
	}
	if atomic.LoadInt32(&requests) < 2 {
		t.Errorf("resolver must paginate — only %d request(s) made", requests)
	}
}

// srvURL returns the base URL the request arrived on, so fake Link
// headers point back at the test server.
func srvURL(r *http.Request) string {
	return "http://" + r.Host
}

// TestGitHubResolverMarkerAbsentIsUnknown verifies the negative-read
// rule: an exhausted listing with no marker is absence of positive
// evidence, not proof of no effect — the record stays UNKNOWN and
// reconcilable rather than terminally FAILED.
func TestGitHubResolverMarkerAbsentIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"number":1,"html_url":"https://github.test/issues/1","body":"unrelated"}]`)
	}))
	defer srv.Close()

	h := NewGitHubIssueHandler(srv.URL, "tok")
	res, err := h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-issue-exec-absent","resource_ref":"repos/octo/repo/issues"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == idempotency.RecoveryFailed {
		t.Error("marker absent must NOT be RecoveryFailed — absence of evidence is not proof of no effect")
	}
	if res.Decision != idempotency.RecoveryUnknown {
		t.Errorf("expected RecoveryUnknown, got %s", res.Decision)
	}
}

// fakeEvidenceHandler supplies a FORGED evidence digest alongside a
// real artifact — the audit's fabricated-digest probe. The dispatcher
// must attest only the recomputed artifact digest.
type fakeEvidenceHandler struct{}

func (fakeEvidenceHandler) Execute(_ context.Context, _ Request, _ capability.ResolvedDescriptor) Response {
	return Response{
		Status: StatusSucceeded,
		Result: json.RawMessage(`{"ok":true}`),
		Evidence: &EvidenceRef{
			Digest:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ReceiptVersion: 3,
		},
		EvidenceArtifact: []byte(`{"provider":"truth","op":"did-happen"}`),
		Execution:        &ExecutionMeta{Provider: "fake", RunID: "run-fake-1"},
	}
}

// TestLiveEvidenceDigestRecomputedFromArtifact verifies the evidence
// boundary: a handler-supplied digest is never persisted or attested —
// the durable evidence_digest is sha256 of the artifact bytes.
func TestLiveEvidenceDigestRecomputedFromArtifact(t *testing.T) {
	if os.Getenv("CRABBOX_TEST_DATABASE_URL") == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	store, db := liveStore(t, 5*time.Second)
	defer db.Close()

	exec := NewDispatchExecutor(NewMultiHandler(map[string]Handler{
		"fake": fakeEvidenceHandler{},
	}), store)
	artifact := []byte(`{"provider":"truth","op":"did-happen"}`)
	want := fmt.Sprintf("%x", sha256.Sum256(artifact))

	key := fmt.Sprintf("test-artifact-%d", time.Now().UnixNano())
	defer db.ExecContext(context.Background(),
		`DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	resp := exec.ExecuteWithIdempotency(context.Background(), Request{
		Capability:     "github.issue.create",
		Arguments:      json.RawMessage(`{"repo":"octo/repo","title":"t"}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_f"},
		IdempotencyKey: key,
	}, capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "fake",
	})
	if resp.Status != StatusSucceeded {
		t.Fatalf("dispatch failed: %s %s", resp.Status, resp.Error)
	}
	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "github.issue.create", key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.EvidenceDigest != want {
		t.Errorf("stored evidence_digest must be sha256(artifact)=%s, got %s — handler-supplied digest leaked", want, rec.EvidenceDigest)
	}
	if strings.Contains(rec.EvidenceDigest, "aaaa") {
		t.Error("forged handler digest was persisted")
	}
}

// TestRealGitHubAPI is the real-provider qualification: it exercises
// the adapter against GitHub itself (not the httptest simulation) when
// CRABBOX_GITHUB_TEST_TOKEN/GITHUB_TOKEN and CRABBOX_GITHUB_TEST_REPO
// are configured. Proves the marker survives a real round trip and the
// resolver finds it via the live API.
func TestRealGitHubAPI(t *testing.T) {
	token := os.Getenv("CRABBOX_GITHUB_TEST_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	repo := os.Getenv("CRABBOX_GITHUB_TEST_REPO")
	if token == "" || repo == "" {
		t.Skip("CRABBOX_GITHUB_TEST_TOKEN/CRABBOX_GITHUB_TEST_REPO not configured; skipping real GitHub test")
	}

	h := NewGitHubIssueHandler("https://api.github.com", token)
	ctx := context.Background()

	execToken := fmt.Sprintf("gh-issue-real-%d", time.Now().UnixNano())
	args := fmt.Sprintf(`{"repo":%q,"title":"crabedence fabric qualification %d","body":"at-most-once qualification"}`, repo, time.Now().UnixNano())

	dispatchCtx := context.WithValue(ctx, externalTokenKey{}, execToken)
	resp := h.Execute(dispatchCtx, Request{
		Capability: "github.issue.create",
		Arguments:  json.RawMessage(args),
	}, testCounterDescriptor())
	if resp.Status != StatusSucceeded {
		t.Fatalf("real issue create failed: %s %s", resp.Status, resp.Error)
	}
	if len(resp.EvidenceArtifact) == 0 {
		t.Fatal("Execute must return the provider response as evidence artifact")
	}

	// The resolver must find the marker via the real API and return
	// the ORIGINAL provider run ID — the issue URL GitHub assigned.
	res, err := h.Resolve(ctx, &idempotency.Record{
		RecoveryLocator: json.RawMessage(fmt.Sprintf(
			`{"external_token":%q,"resource_ref":"repos/%s/issues"}`, execToken, repo)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("real recovery must resolve COMMITTED, got %s", res.Decision)
	}
	if res.ProviderRunID != resp.Execution.RunID {
		t.Errorf("recovery must return the original provider run ID %q, got %q",
			resp.Execution.RunID, res.ProviderRunID)
	}
}
