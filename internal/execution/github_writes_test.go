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
	"syscall"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

func TestGitHubIssueCloseCommitsWithEvidence(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"number": 7, "state": "closed", "html_url": "https://github.test/issues/7"}`)
	}))
	defer srv.Close()

	h := NewGitHubIssueCloseHandler(srv.URL, "tok")
	resp := h.Execute(context.Background(), Request{
		Capability: "github.issue.close",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","number":7,"state_reason":"completed"}`),
	}, testCounterDescriptor())

	if resp.Status != StatusSucceeded {
		t.Fatalf("close failed: %s: %s", resp.Status, resp.Error)
	}
	if gotMethod != http.MethodPatch || gotPath != "/repos/octo/repo/issues/7" {
		t.Fatalf("request = %s %s, want PATCH /repos/octo/repo/issues/7", gotMethod, gotPath)
	}
	var sent map[string]string
	if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	if sent["state"] != "closed" || sent["state_reason"] != "completed" {
		t.Fatalf("payload = %v, want state=closed + state_reason", sent)
	}
	if resp.Execution.RunID != "https://github.test/issues/7" {
		t.Fatalf("run ID = %q, want the issue URL", resp.Execution.RunID)
	}
	if len(resp.EvidenceArtifact) == 0 {
		t.Fatal("the raw provider response must be bound as the evidence artifact")
	}
}

func TestGitHubIssueCloseArgsValidationIsDefinitive(t *testing.T) {
	h := NewGitHubIssueCloseHandler("http://github.invalid", "tok")
	cases := []struct {
		name string
		args string
	}{
		{"bad repo", `{"repo":"noslash","number":1}`},
		{"nonpositive number", `{"repo":"octo/repo","number":0}`},
		{"bad state_reason", `{"repo":"octo/repo","number":1,"state_reason":"wontfix"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.Execute(context.Background(), Request{
				Capability: "github.issue.close",
				Arguments:  json.RawMessage(tc.args),
			}, testCounterDescriptor())
			if resp.Status != StatusFailed || !resp.DefinitiveFailure {
				t.Fatalf("invalid args must fail definitively — the request never left: %+v", resp)
			}
		})
	}
}

func TestGitHubIssueCloseResolverObservesState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/issues/7") {
			fmt.Fprint(w, `{"number": 7, "state": "closed", "html_url": "https://github.test/issues/7"}`)
			return
		}
		fmt.Fprint(w, `{"number": 8, "state": "open", "html_url": "https://github.test/issues/8"}`)
	}))
	defer srv.Close()

	h := NewGitHubIssueCloseHandler(srv.URL, "tok")
	res, err := h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-close-1","resource_ref":"repos/octo/repo/issues/7"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("a closed issue must resolve COMMITTED, got %s", res.Decision)
	}
	if res.ProviderRunID != "https://github.test/issues/7" {
		t.Errorf("expected the issue URL as run ID, got %q", res.ProviderRunID)
	}

	res, err = h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-close-2","resource_ref":"repos/octo/repo/issues/8"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryUnknown {
		t.Fatalf("an open issue must stay UNKNOWN, got %s", res.Decision)
	}
}

func TestGitHubIssueUpdateCommitsProvidedFieldsOnly(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"number": 3, "html_url": "https://github.test/issues/3"}`)
	}))
	defer srv.Close()

	h := NewGitHubIssueUpdateHandler(srv.URL, "tok")
	resp := h.Execute(context.Background(), Request{
		Capability: "github.issue.update",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","number":3,"title":"new title","labels":["bug"," p0 ","bug"]}`),
	}, testCounterDescriptor())
	if resp.Status != StatusSucceeded {
		t.Fatalf("update failed: %s: %s", resp.Status, resp.Error)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	if sent["title"] != "new title" {
		t.Fatalf("title = %v", sent["title"])
	}
	// Labels are canonicalized — trimmed and deduplicated.
	labels, _ := sent["labels"].([]any)
	if len(labels) != 2 {
		t.Fatalf("labels = %v, want canonicalized [bug p0]", sent["labels"])
	}
	if _, present := sent["body"]; present {
		t.Fatal("an absent field must not appear in the payload — absence is not a clear")
	}
	if _, present := sent["assignees"]; present {
		t.Fatal("an absent field must not appear in the payload")
	}
}

func TestGitHubIssueUpdateRequiresOneFieldAndLocatorHoldsDigests(t *testing.T) {
	h := NewGitHubIssueUpdateHandler("http://github.invalid", "tok")
	resp := h.Execute(context.Background(), Request{
		Capability: "github.issue.update",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","number":3}`),
	}, testCounterDescriptor())
	if resp.Status != StatusFailed || !resp.DefinitiveFailure {
		t.Fatalf("an update with no fields must fail definitively: %+v", resp)
	}

	loc, err := h.PrepareRecovery(context.Background(), idempotency.RecoveryLocatorInput{
		ExecutionID:   "exec-1",
		CapabilityID:  "github.issue.update",
		RequestDigest: "digest-1",
		Arguments:     json.RawMessage(`{"repo":"octo/repo","number":3,"title":"secret title never persisted"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if loc.Strategy != "state-observation" {
		t.Fatalf("strategy = %q, want state-observation", loc.Strategy)
	}
	if strings.Contains(string(loc.Extensions), "secret title") {
		t.Fatal("the locator must carry the desired-state digest, never the raw title")
	}
	if !strings.Contains(string(loc.Extensions), "title_sha256") {
		t.Fatalf("locator must carry the desired-state digest: %s", loc.Extensions)
	}
}

func TestGitHubIssueUpdateResolverDigestsObservedState(t *testing.T) {
	// title_sha256("new title") computed through the same canonical form
	// the locator uses.
	want := sha256Hex("new title")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"number": 3, "title": "new title", "html_url": "https://github.test/issues/3", "labels": [], "assignees": []}`)
	}))
	defer srv.Close()

	h := NewGitHubIssueUpdateHandler(srv.URL, "tok")
	ext, _ := json.Marshal(map[string]any{
		"repo": "octo/repo", "number": 3, "title_sha256": want,
	})
	res, err := h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(fmt.Sprintf(
			`{"external_token":"gh-upd-1","resource_ref":"repos/octo/repo/issues/3","extensions":%s}`, ext)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("matching desired state must resolve COMMITTED, got %s", res.Decision)
	}

	// A field the update never applied (or a later actor overwrote)
	// stays UNKNOWN — never a fabricated COMMITTED.
	ext, _ = json.Marshal(map[string]any{
		"repo": "octo/repo", "number": 3, "title_sha256": sha256Hex("other title"),
	})
	res, err = h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(fmt.Sprintf(
			`{"external_token":"gh-upd-2","resource_ref":"repos/octo/repo/issues/3","extensions":%s}`, ext)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryUnknown {
		t.Fatalf("a field mismatch must stay UNKNOWN, got %s", res.Decision)
	}
	if !strings.Contains(string(res.Result), "title") {
		t.Fatalf("the mismatch report must name the field, not its value: %s", res.Result)
	}
}

func TestGitHubPullCreateCommitsWithMarkerAndEvidence(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"number": 42, "html_url": "https://github.test/pulls/42"}`)
	}))
	defer srv.Close()

	h := NewGitHubPullCreateHandler(srv.URL, "tok")
	ctx := context.WithValue(context.Background(), externalTokenKey{}, "gh-pr-exec-1")
	resp := h.Execute(ctx, Request{
		Capability: "github.pr.create",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","title":"feat","head":"topic","base":"main","body":"adds x"}`),
	}, testCounterDescriptor())

	if resp.Status != StatusSucceeded {
		t.Fatalf("pr create failed: %s: %s", resp.Status, resp.Error)
	}
	if gotPath != "/repos/octo/repo/pulls" {
		t.Fatalf("request path = %s", gotPath)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	body, _ := sent["body"].(string)
	if !strings.Contains(body, "adds x") || !strings.Contains(body, opMarker("gh-pr-exec-1")) {
		t.Fatalf("PR body must carry the operation marker: %s", body)
	}
	if sent["head"] != "topic" || sent["base"] != "main" {
		t.Fatalf("head/base = %v/%v", sent["head"], sent["base"])
	}
	if resp.Execution.RunID != "https://github.test/pulls/42" {
		t.Fatalf("run ID = %q, want the PR URL", resp.Execution.RunID)
	}
}

func TestGitHubPullCreateArgsValidationIsDefinitive(t *testing.T) {
	h := NewGitHubPullCreateHandler("http://github.invalid", "tok")
	cases := []struct {
		name string
		args string
	}{
		{"missing head", `{"repo":"octo/repo","title":"t","base":"main"}`},
		{"missing base", `{"repo":"octo/repo","title":"t","head":"b"}`},
		{"empty title", `{"repo":"octo/repo","title":" ","head":"a","base":"main"}`},
		{"bad ref", `{"repo":"octo/repo","title":"t","head":"a..b","base":"main"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.Execute(context.Background(), Request{
				Capability: "github.pr.create",
				Arguments:  json.RawMessage(tc.args),
			}, testCounterDescriptor())
			if resp.Status != StatusFailed || !resp.DefinitiveFailure {
				t.Fatalf("invalid args must fail definitively: %+v", resp)
			}
		})
	}
}

func TestGitHubPullCreateAcceptsDottedRefs(t *testing.T) {
	// A single dot is legal in a git ref (release-1.2, dependabot
	// heads) — only the ".." sequence is forbidden.
	for _, head := range []string{"release-1.2", "dependabot/npm/foo-4.17.21", "v1.0.x"} {
		if _, err := normalizeGitHubPullCreateArgs(json.RawMessage(fmt.Sprintf(
			`{"repo":"octo/repo","title":"t","head":%q,"base":"main"}`, head))); err != nil {
			t.Fatalf("head %q must be accepted: %v", head, err)
		}
	}
	if _, err := normalizeGitHubPullCreateArgs(json.RawMessage(
		`{"repo":"octo/repo","title":"t","head":"a..b","base":"main"}`)); err == nil {
		t.Fatal("a double-dot sequence must still be rejected")
	}
}

func TestGitHubPullCreateResolverMarkerScan(t *testing.T) {
	marker := opMarker("gh-pr-exec-p2")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[{"number":42,"html_url":"https://github.test/pulls/42","body":"desc\n\n%s"}]`, marker)
	}))
	defer srv.Close()

	h := NewGitHubPullCreateHandler(srv.URL, "tok")
	res, err := h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-pr-exec-p2","resource_ref":"repos/octo/repo/pulls"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted {
		t.Fatalf("a PR body carrying the marker must resolve COMMITTED, got %s", res.Decision)
	}
	if res.ProviderRunID != "https://github.test/pulls/42" {
		t.Errorf("expected the PR URL, got %q", res.ProviderRunID)
	}
}

func TestGitHubPullMergeCommits(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sha":"abc123","merged":true,"message":"Pull Request successfully merged"}`)
	}))
	defer srv.Close()

	h := NewGitHubPullMergeHandler(srv.URL, "tok")
	resp := h.Execute(context.Background(), Request{
		Capability: "github.pr.merge",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","number":42,"merge_method":"squash"}`),
	}, testCounterDescriptor())
	if resp.Status != StatusSucceeded {
		t.Fatalf("merge failed: %s: %s", resp.Status, resp.Error)
	}
	if gotMethod != http.MethodPut || gotPath != "/repos/octo/repo/pulls/42/merge" {
		t.Fatalf("request = %s %s, want PUT /repos/octo/repo/pulls/42/merge", gotMethod, gotPath)
	}
	if resp.Execution.RunID != "abc123" {
		t.Fatalf("run ID = %q, want the merge commit SHA", resp.Execution.RunID)
	}
}

func TestGitHubPullMergeDeclinedIsDefinitive(t *testing.T) {
	// A 200 carrying merged=false is the provider's own report that no
	// effect occurred — a no-effect proof, not ambiguity.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sha":null,"merged":false,"message":"Not mergeable"}`)
	}))
	defer srv.Close()

	h := NewGitHubPullMergeHandler(srv.URL, "tok")
	resp := h.Execute(context.Background(), Request{
		Capability: "github.pr.merge",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","number":42}`),
	}, testCounterDescriptor())
	if resp.Status != StatusFailed || !resp.DefinitiveFailure {
		t.Fatalf("merged=false on 200 must fail definitively: %+v", resp)
	}
}

func TestGitHubPullMergeResolverObservesMergedFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/pulls/42") {
			fmt.Fprint(w, `{"number":42,"merged":true,"merge_commit_sha":"abc123","html_url":"https://github.test/pulls/42"}`)
			return
		}
		fmt.Fprint(w, `{"number":43,"merged":false,"state":"open","html_url":"https://github.test/pulls/43"}`)
	}))
	defer srv.Close()

	h := NewGitHubPullMergeHandler(srv.URL, "tok")
	res, err := h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-merge-1","resource_ref":"repos/octo/repo/pulls/42"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryCommitted || res.ProviderRunID != "abc123" {
		t.Fatalf("a merged PR must resolve COMMITTED with the merge SHA: %+v", res)
	}

	res, err = h.Resolve(context.Background(), &idempotency.Record{
		RecoveryLocator: json.RawMessage(
			`{"external_token":"gh-merge-2","resource_ref":"repos/octo/repo/pulls/43"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != idempotency.RecoveryUnknown {
		t.Fatalf("an unmerged PR must stay UNKNOWN, got %s", res.Decision)
	}
}

// testClientHandler is the common shape of the github write adapters —
// an Execute plus the test seam for a short-timeout or error-injecting
// HTTP client.
type testClientHandler interface {
	Execute(context.Context, Request, capability.ResolvedDescriptor) Response
	SetHTTPClient(*http.Client)
}

func TestGitHubWritesTransportAmbiguity(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		definitive bool
	}{
		{"conn_reset_after_send", &net.OpError{Op: "write", Err: syscall.ECONNRESET}, false},
		{"conn_refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"dns_failure", &net.DNSError{IsNotFound: true}, true},
	}
	handlers := map[string]struct {
		newHandler func(string, string) testClientHandler
		args       string
	}{
		"github.issue.close":  {func(u, tok string) testClientHandler { return NewGitHubIssueCloseHandler(u, tok) }, `{"repo":"octo/repo","number":3}`},
		"github.issue.update": {func(u, tok string) testClientHandler { return NewGitHubIssueUpdateHandler(u, tok) }, `{"repo":"octo/repo","number":3,"title":"t"}`},
		"github.pr.create":    {func(u, tok string) testClientHandler { return NewGitHubPullCreateHandler(u, tok) }, `{"repo":"octo/repo","title":"t","head":"a","base":"main"}`},
		"github.pr.merge":     {func(u, tok string) testClientHandler { return NewGitHubPullMergeHandler(u, tok) }, `{"repo":"octo/repo","number":3}`},
	}
	for capID, cfg := range handlers {
		for _, tc := range cases {
			t.Run(capID+"/"+tc.name, func(t *testing.T) {
				h := cfg.newHandler("http://github.invalid", "tok")
				h.SetHTTPClient(&http.Client{Transport: errRoundTripper{err: tc.err}})
				resp := h.Execute(context.Background(), Request{
					Capability: capID,
					Arguments:  json.RawMessage(cfg.args),
				}, testCounterDescriptor())
				if resp.DefinitiveFailure != tc.definitive {
					t.Errorf("DefinitiveFailure=%v, want %v", resp.DefinitiveFailure, tc.definitive)
				}
			})
		}
	}
}

func TestGitHubAdapterMuxRoutesWriteCapabilities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"number": 7, "state": "closed", "merged": true, "sha": "abc", "html_url": "https://github.test/x"}`)
	}))
	defer srv.Close()

	mux := &githubAdapter{
		issue:       NewGitHubIssueHandler(srv.URL, "tok"),
		comment:     NewGitHubCommentHandler(srv.URL, "tok"),
		issueClose:  NewGitHubIssueCloseHandler(srv.URL, "tok"),
		issueUpdate: NewGitHubIssueUpdateHandler(srv.URL, "tok"),
		pullCreate:  NewGitHubPullCreateHandler(srv.URL, "tok"),
		pullMerge:   NewGitHubPullMergeHandler(srv.URL, "tok"),
	}
	descFor := func(id string) capability.ResolvedDescriptor {
		d := testCounterDescriptor()
		d.ID = id
		d.AdapterID = "github"
		return d
	}

	for _, tc := range []struct {
		capability string
		args       string
	}{
		{"github.issue.close", `{"repo":"octo/repo","number":7}`},
		{"github.issue.update", `{"repo":"octo/repo","number":7,"title":"t"}`},
		{"github.pr.create", `{"repo":"octo/repo","title":"t","head":"a","base":"main"}`},
		{"github.pr.merge", `{"repo":"octo/repo","number":7}`},
	} {
		resp := mux.Execute(context.Background(), Request{
			Capability: tc.capability,
			Arguments:  json.RawMessage(tc.args),
		}, descFor(tc.capability))
		if resp.Status != StatusSucceeded {
			t.Fatalf("mux must route %s to its handler: %v", tc.capability, resp.Error)
		}
		loc, err := mux.PrepareRecovery(context.Background(), idempotency.RecoveryLocatorInput{
			ExecutionID: "e1", CapabilityID: tc.capability, RequestDigest: "d1",
			Arguments: json.RawMessage(tc.args),
		})
		if err != nil || loc == nil {
			t.Fatalf("mux PrepareRecovery must route %s: %v", tc.capability, err)
		}
	}
}
