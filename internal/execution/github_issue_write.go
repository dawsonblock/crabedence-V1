package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/providertransport"
)

// State-observation recovery: a PATCHed field carries no free-form
// marker slot, so these mutations cannot bind an external token to the
// provider object the way issue.create binds its body marker. The
// locator instead records the resource coordinate plus digests of the
// desired state, and Resolve observes the provider object — the desired
// state present → COMMITTED, absent → UNKNOWN (an interleaved change by
// another actor is indistinguishable from non-application, and absence
// of positive evidence is not proof of no effect). The locator carries
// digests, never the raw field values.

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// canonicalStringSet normalizes a string list to its sorted, deduplicated
// form — the canonical identity a desired-state digest covers.
func canonicalStringSet(values []string) []string {
	set := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		set = append(set, v)
	}
	sort.Strings(set)
	return set
}

// digestStringSet returns the canonical digest of a string set — the
// same value whether computed from request arguments or an observed
// provider object.
func digestStringSet(values []string) string {
	return sha256Hex(strings.Join(canonicalStringSet(values), "\x00"))
}

// GitHubIssueCloseHandler implements the github.issue.close capability —
// closing an issue is a durable MUTATION with the same exactly-once
// contract as issue.create, but recovery observes the target state
// instead of scanning for a body marker:
//
//   - PrepareRecovery persists a minimal locator carrying the external
//     operation token (sent as X-Crabex-Operation for tracing), the
//     repo coordinate, and the issue number.
//   - Resolve GETs the issue — strictly observational. state=closed →
//     COMMITTED (the desired postcondition holds); otherwise → UNKNOWN.
type GitHubIssueCloseHandler struct {
	transport    *providertransport.Transport
	transportErr error
}

// NewGitHubIssueCloseHandler creates the close adapter against the same
// provider identity as the issue adapter.
func NewGitHubIssueCloseHandler(baseURL, token string) *GitHubIssueCloseHandler {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	h := &GitHubIssueCloseHandler{}
	h.transport, h.transportErr = newGitHubTransport(baseURL, token)
	return h
}

// SetTransport installs the shared trusted transport — the production
// wiring path.
func (h *GitHubIssueCloseHandler) SetTransport(t *providertransport.Transport) {
	h.transport, h.transportErr = t, nil
}

// SetHTTPClient overrides the transport's HTTP client (tests use
// short timeouts and injected round-trippers).
func (h *GitHubIssueCloseHandler) SetHTTPClient(c *http.Client) {
	if h.transport != nil {
		h.transport.SetHTTPClient(c)
	}
}

// transportFailure renders a transport-construction failure as a
// definite no-effect — nothing was ever dispatched.
func (h *GitHubIssueCloseHandler) transportFailure() (Response, bool) {
	if h.transportErr == nil {
		return Response{}, false
	}
	return Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureInternalError),
		Error:             fmt.Sprintf("github transport unavailable: %v", h.transportErr),
		DefinitiveFailure: true,
		Execution:         &ExecutionMeta{Provider: "github"},
	}, true
}

// issueCloseStateReasons is the closed set the schema's enum must match
// — the adapter re-validates semantically, always.
var issueCloseStateReasons = map[string]bool{
	"completed":   true,
	"not_planned": true,
}

type githubIssueCloseArgs struct {
	Repo        string `json:"repo"`
	Number      int    `json:"number"`
	StateReason string `json:"state_reason"`
}

func normalizeGitHubIssueCloseArgs(raw json.RawMessage) (githubIssueCloseArgs, error) {
	var args githubIssueCloseArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, err
	}
	args.Repo = strings.TrimSpace(args.Repo)
	args.StateReason = strings.TrimSpace(args.StateReason)
	if _, _, err := githubRepoParts(args.Repo); err != nil {
		return args, err
	}
	if args.Number < 1 {
		return args, fmt.Errorf("number must be a positive issue number, got %d", args.Number)
	}
	if args.StateReason != "" && !issueCloseStateReasons[args.StateReason] {
		return args, fmt.Errorf("state_reason must be one of completed, not_planned, got %q", args.StateReason)
	}
	return args, nil
}

// PrepareRecovery implements idempotency.RecoveryLocatorProvider. The
// locator is minimal provider lookup material: the external token
// (uniform operation identity, carried to the provider as a trace
// header), the repo coordinate, and the issue number.
func (h *GitHubIssueCloseHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	args, err := normalizeGitHubIssueCloseArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	ext, _ := json.Marshal(map[string]any{
		"repo":         args.Repo,
		"number":       args.Number,
		"state_reason": args.StateReason,
	})
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "github",
		Strategy:       "state-observation",
		ExternalToken:  idempotency.ProviderIdempotencyKey(in.ExecutionID, in.RequestDigest, "github"),
		ResourceRef:    fmt.Sprintf("repos/%s/issues/%d", args.Repo, args.Number),
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
		Extensions:     ext,
	}, nil
}

// Execute closes the issue via PATCH. Closing an already-closed issue is
// a provider-side no-op that still returns 200 — the desired
// postcondition is what the operation asserts.
func (h *GitHubIssueCloseHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	args, err := normalizeGitHubIssueCloseArgs(req.Arguments)
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             fmt.Sprintf("invalid arguments: %v", err),
			DefinitiveFailure: true, // request never sent — no effect
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}

	if fail, bad := h.transportFailure(); bad {
		return fail
	}
	payload := map[string]string{"state": "closed"}
	if args.StateReason != "" {
		payload["state_reason"] = args.StateReason
	}
	body, _ := json.Marshal(payload)

	owner, name, _ := githubRepoParts(args.Repo)
	token := ExternalTokenFromContext(ctx)
	httpResp, err := h.transport.Do(ctx, providertransport.ProviderHTTPRequest{
		Method: http.MethodPatch,
		URL: fmt.Sprintf("/repos/%s/%s/issues/%d",
			url.PathEscape(owner), url.PathEscape(name), args.Number),
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/vnd.github+json",
		},
		Body:    body,
		Context: githubRequestContext(req, "github.issue.close", desc, fmt.Sprintf("repos/%s/issues/%d", args.Repo, args.Number), token),
	})
	if err != nil {
		return githubFailure(err)
	}
	respBody := httpResp.Body

	if httpResp.StatusCode == http.StatusOK {
		var issue struct {
			Number  int    `json:"number"`
			State   string `json:"state"`
			HTMLURL string `json:"html_url"`
		}
		if err := json.Unmarshal(respBody, &issue); err != nil {
			// 2xx with an unparseable body — the close may have applied.
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       fmt.Sprintf("github returned %d with unparseable body: %v", httpResp.StatusCode, err),
				Execution:   &ExecutionMeta{Provider: "github"},
				Dispatch:    githubProvenance(httpResp.Trace, httpResp.StatusCode),
			}
		}
		runID := issue.HTMLURL
		if runID == "" {
			runID = fmt.Sprintf("gh:%s#%d", args.Repo, issue.Number)
		}
		result, _ := json.Marshal(map[string]any{
			"issue_number": issue.Number,
			"issue_url":    runID,
			"repo":         args.Repo,
			"state":        issue.State,
		})
		return Response{
			Status:           StatusSucceeded,
			Result:           result,
			Evidence:         &EvidenceRef{ReceiptVersion: 3},
			EvidenceArtifact: respBody, // raw provider response — digest is recomputed upstream
			Execution:        &ExecutionMeta{Provider: "github", RunID: runID},
			Dispatch:         githubProvenance(httpResp.Trace, httpResp.StatusCode),
		}
	}

	// 4xx is definitive — GitHub rejected the request without changing
	// state. 5xx and redirects are ambiguous post-dispatch: UNKNOWN.
	definitive := httpResp.StatusCode >= 400 && httpResp.StatusCode < 500
	return Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureExecutionFailed),
		Error:             fmt.Sprintf("github returned %d: %s", httpResp.StatusCode, truncate(string(respBody), 512)),
		DefinitiveFailure: definitive,
		EvidenceArtifact:  respBody, // provider's rejection body — artifact for NO_EFFECT proof
		Execution:         &ExecutionMeta{Provider: "github"},
		Dispatch:          githubProvenance(httpResp.Trace, httpResp.StatusCode),
	}
}

// Resolve implements idempotency.RecoveryResolver by observing the
// issue's current state — strictly observational (a single GET), so a
// duplicate or racing resolver is harmless. state=closed → COMMITTED
// with the issue URL; any other observed state → UNKNOWN.
func (h *GitHubIssueCloseHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	var loc idempotency.RecoveryLocator
	if len(rec.RecoveryLocator) > 0 {
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("unparseable recovery locator: %w", err)
		}
	}
	repo, number := locatorRepoNumber(loc, "issues")
	if repo == "" || number == 0 {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	owner, name, err := githubRepoParts(repo)
	if err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}

	if h.transportErr != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github transport unavailable: %w", h.transportErr)
	}
	httpResp, err := h.transport.Do(ctx, providertransport.ProviderHTTPRequest{
		Method: http.MethodGet,
		URL: fmt.Sprintf("/repos/%s/%s/issues/%d",
			url.PathEscape(owner), url.PathEscape(name), number),
		Headers: map[string]string{"Accept": "application/vnd.github+json"},
		Context: providertransport.RequestContext{
			Capability: "github.issue.close",
			Resource:   fmt.Sprintf("repos/%s/issues/%d", repo, number),
		},
	})
	if err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue get failed: %w", err)
	}
	respBody := httpResp.Body
	status := httpResp.StatusCode
	if status != http.StatusOK {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue get returned %d", status)
	}

	var issue struct {
		Number      int    `json:"number"`
		State       string `json:"state"`
		HTMLURL     string `json:"html_url"`
		ClosedAt    string `json:"closed_at"`
		StateReason string `json:"state_reason"`
	}
	if err := json.Unmarshal(respBody, &issue); err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue get unparseable: %w", err)
	}
	// The locator carries the reason this execution requested. A closed
	// issue whose recorded reason differs was closed by another actor's
	// operation — not this one's postcondition — however its timestamp
	// lands. An empty request constraint accepts any closed reason.
	var ext struct {
		StateReason string `json:"state_reason"`
	}
	if len(loc.Extensions) > 0 {
		_ = json.Unmarshal(loc.Extensions, &ext)
	}
	reasonMatches := ext.StateReason == "" || issue.StateReason == ext.StateReason
	if issue.State == "closed" && reasonMatches && transitionWithinExecution(issue.ClosedAt, rec) {
		result, _ := json.Marshal(map[string]any{
			"issue_number": issue.Number,
			"issue_url":    issue.HTMLURL,
			"repo":         repo,
			"state":        issue.State,
			"closed_at":    issue.ClosedAt,
			"state_reason": issue.StateReason,
		})
		return idempotency.RecoveryResult{
			Decision:         idempotency.RecoveryCommitted,
			Result:           result,
			ReceiptVersion:   3,
			ProviderID:       "github",
			ProviderRunID:    issue.HTMLURL,
			EvidenceArtifact: respBody,
		}, nil
	}
	return idempotency.RecoveryResult{
		Decision:   idempotency.RecoveryUnknown,
		ProviderID: "github",
		Result: json.RawMessage(fmt.Sprintf(
			`{"repo":%q,"issue":%d,"state_observed":%q,"closed_at":%q,"state_reason_observed":%q}`,
			repo, number, issue.State, issue.ClosedAt, issue.StateReason)),
	}, nil
}

// locatorRepoNumber extracts the repo coordinate and object number from
// a recovery locator — Extensions first, then the ResourceRef shape
// "repos/{owner}/{name}/{kind}/{number}" as a fallback.
func locatorRepoNumber(loc idempotency.RecoveryLocator, kind string) (string, int) {
	var ext struct {
		Repo   string `json:"repo"`
		Number int    `json:"number"`
	}
	repo, number := "", 0
	if len(loc.Extensions) > 0 {
		_ = json.Unmarshal(loc.Extensions, &ext)
		repo, number = ext.Repo, ext.Number
	}
	if (repo == "" || number == 0) && loc.ResourceRef != "" {
		parts := strings.Split(strings.TrimPrefix(loc.ResourceRef, "repos/"), "/")
		if len(parts) == 4 && parts[2] == kind {
			if repo == "" {
				repo = parts[0] + "/" + parts[1]
			}
			if number == 0 {
				fmt.Sscanf(parts[3], "%d", &number)
			}
		}
	}
	return repo, number
}

// providerSkewTolerance bounds the clock disagreement tolerated between
// this host and the provider when a transition timestamp is compared
// against the record's creation time.
const providerSkewTolerance = 30 * time.Second

// transitionWithinExecution reports whether a provider-reported transition
// timestamp can belong to this execution. Observing shared current state
// alone proves nothing about which invocation caused it — a transition
// that predates the record is conclusively *not* this execution's effect,
// while one inside the window is the strongest attribution the provider's
// plain resource API offers. A same-window concurrent actor remains
// indistinguishable, which is why these resolvers stay observational:
// ambiguous evidence resolves Unknown, never Committed.
func transitionWithinExecution(transition string, rec *idempotency.Record) bool {
	if transition == "" || rec == nil || rec.CreatedAt.IsZero() {
		return false
	}
	at, err := time.Parse(time.RFC3339, transition)
	if err != nil {
		return false
	}
	return !at.Before(rec.CreatedAt.Add(-providerSkewTolerance))
}

// GitHubIssueUpdateHandler implements the github.issue.update
// capability — a durable MUTATION that PATCHes an issue's title, body,
// labels, or assignees. Recovery is desired-state observation by
// digest: the locator stores a SHA-256 of each provided field's
// canonical form, and Resolve commits when every provided field's
// digest matches the observed object.
type GitHubIssueUpdateHandler struct {
	transport    *providertransport.Transport
	transportErr error
}

// NewGitHubIssueUpdateHandler creates the update adapter against the
// same provider identity as the issue adapter.
func NewGitHubIssueUpdateHandler(baseURL, token string) *GitHubIssueUpdateHandler {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	h := &GitHubIssueUpdateHandler{}
	h.transport, h.transportErr = newGitHubTransport(baseURL, token)
	return h
}

// SetTransport installs the shared trusted transport — the production
// wiring path.
func (h *GitHubIssueUpdateHandler) SetTransport(t *providertransport.Transport) {
	h.transport, h.transportErr = t, nil
}

// SetHTTPClient overrides the transport's HTTP client (tests use
// short timeouts and injected round-trippers).
func (h *GitHubIssueUpdateHandler) SetHTTPClient(c *http.Client) {
	if h.transport != nil {
		h.transport.SetHTTPClient(c)
	}
}

// transportFailure renders a transport-construction failure as a
// definite no-effect — nothing was ever dispatched.
func (h *GitHubIssueUpdateHandler) transportFailure() (Response, bool) {
	if h.transportErr == nil {
		return Response{}, false
	}
	return Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureInternalError),
		Error:             fmt.Sprintf("github transport unavailable: %v", h.transportErr),
		DefinitiveFailure: true,
		Execution:         &ExecutionMeta{Provider: "github"},
	}, true
}

type githubIssueUpdateArgs struct {
	Repo      string    `json:"repo"`
	Number    int       `json:"number"`
	Title     *string   `json:"title"`
	Body      *string   `json:"body"`
	Labels    *[]string `json:"labels"`
	Assignees *[]string `json:"assignees"`
}

// provided reports which fields carry an update — pointer presence
// distinguishes "absent" from "explicitly empty" (an empty labels array
// is a clear-all, not a no-op).
func (a githubIssueUpdateArgs) provided() []string {
	var fields []string
	if a.Title != nil {
		fields = append(fields, "title")
	}
	if a.Body != nil {
		fields = append(fields, "body")
	}
	if a.Labels != nil {
		fields = append(fields, "labels")
	}
	if a.Assignees != nil {
		fields = append(fields, "assignees")
	}
	return fields
}

func normalizeGitHubIssueUpdateArgs(raw json.RawMessage) (githubIssueUpdateArgs, error) {
	var args githubIssueUpdateArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, err
	}
	args.Repo = strings.TrimSpace(args.Repo)
	if _, _, err := githubRepoParts(args.Repo); err != nil {
		return args, err
	}
	if args.Number < 1 {
		return args, fmt.Errorf("number must be a positive issue number, got %d", args.Number)
	}
	if len(args.provided()) == 0 {
		return args, fmt.Errorf("at least one of title, body, labels, assignees is required")
	}
	if args.Title != nil {
		title := strings.TrimSpace(*args.Title)
		if title == "" {
			return args, fmt.Errorf("title must not be empty when provided")
		}
		args.Title = &title
	}
	if args.Labels != nil {
		if len(*args.Labels) > 100 {
			return args, fmt.Errorf("labels accepts at most 100 entries, got %d", len(*args.Labels))
		}
		labels := canonicalStringSet(*args.Labels)
		for _, l := range labels {
			if len(l) > 50 {
				return args, fmt.Errorf("label %q exceeds 50 characters", truncate(l, 24))
			}
		}
		args.Labels = &labels
	}
	if args.Assignees != nil {
		if len(*args.Assignees) > 10 {
			return args, fmt.Errorf("assignees accepts at most 10 entries, got %d", len(*args.Assignees))
		}
		assignees := canonicalStringSet(*args.Assignees)
		for _, a := range assignees {
			if len(a) > 39 {
				return args, fmt.Errorf("assignee %q exceeds 39 characters", truncate(a, 24))
			}
		}
		args.Assignees = &assignees
	}
	return args, nil
}

// desiredStateDigests computes the canonical digest of each provided
// field — the values the recovery locator stores so Resolve can compare
// observed state without persisting raw arguments.
func (a githubIssueUpdateArgs) desiredStateDigests() map[string]string {
	digests := make(map[string]string, 4)
	if a.Title != nil {
		digests["title_sha256"] = sha256Hex(*a.Title)
	}
	if a.Body != nil {
		digests["body_sha256"] = sha256Hex(*a.Body)
	}
	if a.Labels != nil {
		digests["labels_sha256"] = digestStringSet(*a.Labels)
	}
	if a.Assignees != nil {
		digests["assignees_sha256"] = digestStringSet(*a.Assignees)
	}
	return digests
}

// PrepareRecovery persists the minimal locator: operation token, repo
// coordinate, issue number, and the desired-state digests — never the
// field values themselves.
func (h *GitHubIssueUpdateHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	args, err := normalizeGitHubIssueUpdateArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	ext := map[string]any{"repo": args.Repo, "number": args.Number}
	for k, v := range args.desiredStateDigests() {
		ext[k] = v
	}
	extJSON, _ := json.Marshal(ext)
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "github",
		Strategy:       "state-observation",
		ExternalToken:  idempotency.ProviderIdempotencyKey(in.ExecutionID, in.RequestDigest, "github"),
		ResourceRef:    fmt.Sprintf("repos/%s/issues/%d", args.Repo, args.Number),
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
		Extensions:     extJSON,
	}, nil
}

// Execute PATCHes the issue with exactly the provided fields.
func (h *GitHubIssueUpdateHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	args, err := normalizeGitHubIssueUpdateArgs(req.Arguments)
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             fmt.Sprintf("invalid arguments: %v", err),
			DefinitiveFailure: true, // request never sent — no effect
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}

	payload := map[string]any{}
	if args.Title != nil {
		payload["title"] = *args.Title
	}
	if args.Body != nil {
		payload["body"] = *args.Body
	}
	if args.Labels != nil {
		payload["labels"] = *args.Labels
	}
	if args.Assignees != nil {
		payload["assignees"] = *args.Assignees
	}
	body, _ := json.Marshal(payload)

	if fail, bad := h.transportFailure(); bad {
		return fail
	}
	owner, name, _ := githubRepoParts(args.Repo)
	token := ExternalTokenFromContext(ctx)
	httpResp, err := h.transport.Do(ctx, providertransport.ProviderHTTPRequest{
		Method: http.MethodPatch,
		URL: fmt.Sprintf("/repos/%s/%s/issues/%d",
			url.PathEscape(owner), url.PathEscape(name), args.Number),
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/vnd.github+json",
		},
		Body:    body,
		Context: githubRequestContext(req, "github.issue.update", desc, fmt.Sprintf("repos/%s/issues/%d", args.Repo, args.Number), token),
	})
	if err != nil {
		return githubFailure(err)
	}
	respBody := httpResp.Body

	if httpResp.StatusCode == http.StatusOK {
		var issue struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
		}
		if err := json.Unmarshal(respBody, &issue); err != nil {
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       fmt.Sprintf("github returned %d with unparseable body: %v", httpResp.StatusCode, err),
				Execution:   &ExecutionMeta{Provider: "github"},
				Dispatch:    githubProvenance(httpResp.Trace, httpResp.StatusCode),
			}
		}
		runID := issue.HTMLURL
		if runID == "" {
			runID = fmt.Sprintf("gh:%s#%d", args.Repo, issue.Number)
		}
		result, _ := json.Marshal(map[string]any{
			"issue_number": issue.Number,
			"issue_url":    runID,
			"repo":         args.Repo,
			"fields":       args.provided(),
		})
		return Response{
			Status:           StatusSucceeded,
			Result:           result,
			Evidence:         &EvidenceRef{ReceiptVersion: 3},
			EvidenceArtifact: respBody,
			Execution:        &ExecutionMeta{Provider: "github", RunID: runID},
			Dispatch:         githubProvenance(httpResp.Trace, httpResp.StatusCode),
		}
	}

	definitive := httpResp.StatusCode >= 400 && httpResp.StatusCode < 500
	return Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureExecutionFailed),
		Error:             fmt.Sprintf("github returned %d: %s", httpResp.StatusCode, truncate(string(respBody), 512)),
		DefinitiveFailure: definitive,
		EvidenceArtifact:  respBody,
		Execution:         &ExecutionMeta{Provider: "github"},
		Dispatch:          githubProvenance(httpResp.Trace, httpResp.StatusCode),
	}
}

// Resolve observes the issue and digests each provided field from the
// provider's response under the same canonicalization the locator used.
// Every provided field matching → COMMITTED; any mismatch → UNKNOWN.
func (h *GitHubIssueUpdateHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	var loc idempotency.RecoveryLocator
	if len(rec.RecoveryLocator) > 0 {
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("unparseable recovery locator: %w", err)
		}
	}
	repo, number := locatorRepoNumber(loc, "issues")
	if repo == "" || number == 0 || len(loc.Extensions) == 0 {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	var ext map[string]any
	if err := json.Unmarshal(loc.Extensions, &ext); err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("unparseable locator extensions: %w", err)
	}
	want := map[string]string{}
	for _, field := range []string{"title", "body", "labels", "assignees"} {
		if digest, ok := ext[field+"_sha256"].(string); ok && digest != "" {
			want[field] = digest
		}
	}
	if len(want) == 0 {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	owner, name, err := githubRepoParts(repo)
	if err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}

	if h.transportErr != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github transport unavailable: %w", h.transportErr)
	}
	httpResp, err := h.transport.Do(ctx, providertransport.ProviderHTTPRequest{
		Method: http.MethodGet,
		URL: fmt.Sprintf("/repos/%s/%s/issues/%d",
			url.PathEscape(owner), url.PathEscape(name), number),
		Headers: map[string]string{"Accept": "application/vnd.github+json"},
		Context: providertransport.RequestContext{
			Capability: "github.issue.update",
			Resource:   fmt.Sprintf("repos/%s/issues/%d", repo, number),
		},
	})
	if err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue get failed: %w", err)
	}
	respBody := httpResp.Body
	status := httpResp.StatusCode
	if status != http.StatusOK {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue get returned %d", status)
	}

	var issue struct {
		Number    int    `json:"number"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		HTMLURL   string `json:"html_url"`
		UpdatedAt string `json:"updated_at"`
		Labels    []struct {
			Name string `json:"name"`
		} `json:"labels"`
		Assignees []struct {
			Login string `json:"login"`
		} `json:"assignees"`
	}
	if err := json.Unmarshal(respBody, &issue); err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue get unparseable: %w", err)
	}

	observed := map[string]string{}
	if _, ok := want["title"]; ok {
		observed["title"] = sha256Hex(issue.Title)
	}
	if _, ok := want["body"]; ok {
		observed["body"] = sha256Hex(issue.Body)
	}
	if _, ok := want["labels"]; ok {
		names := make([]string, 0, len(issue.Labels))
		for _, l := range issue.Labels {
			names = append(names, l.Name)
		}
		observed["labels"] = digestStringSet(names)
	}
	if _, ok := want["assignees"]; ok {
		logins := make([]string, 0, len(issue.Assignees))
		for _, a := range issue.Assignees {
			logins = append(logins, a.Login)
		}
		observed["assignees"] = digestStringSet(logins)
	}
	var mismatched []string
	for field, digest := range want {
		if observed[field] != digest {
			mismatched = append(mismatched, field)
		}
	}
	// Matching content alone does not show *this* execution made it so —
	// the issue may already have carried exactly those values. The provider
	// timestamp has to place the last transition inside this record's
	// lifetime before the observed state can be called ours.
	if len(mismatched) == 0 && transitionWithinExecution(issue.UpdatedAt, rec) {
		result, _ := json.Marshal(map[string]any{
			"issue_number": issue.Number,
			"issue_url":    issue.HTMLURL,
			"repo":         repo,
			"fields":       sortedKeys(want),
			"updated_at":   issue.UpdatedAt,
		})
		return idempotency.RecoveryResult{
			Decision:         idempotency.RecoveryCommitted,
			Result:           result,
			ReceiptVersion:   3,
			ProviderID:       "github",
			ProviderRunID:    issue.HTMLURL,
			EvidenceArtifact: respBody,
		}, nil
	}
	sort.Strings(mismatched)
	return idempotency.RecoveryResult{
		Decision:   idempotency.RecoveryUnknown,
		ProviderID: "github",
		Result: json.RawMessage(fmt.Sprintf(
			`{"repo":%q,"issue":%d,"fields_mismatched":%s,"updated_at":%q}`,
			repo, number, mustJSON(mismatched), issue.UpdatedAt)),
	}, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// RegisterGitHubIssueCloseCapability registers github.issue.close.
func RegisterGitHubIssueCloseCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "github.issue.close",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "github",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "github.issue",
			GrantRequired: true,
			ResourceArguments: map[string]string{
				"repo": "repo",
			},
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"required": ["repo", "number"],
			"properties": {
				"repo":         {"type": "string", "description": "owner/name"},
				"number":       {"type": "integer", "minimum": 1, "description": "Issue number"},
				"state_reason": {"type": "string", "enum": ["completed", "not_planned"]}
			},
			"additionalProperties": false
		}`),
	})
}

// RegisterGitHubIssueUpdateCapability registers github.issue.update.
// At least one of title, body, labels, assignees must be provided —
// the schema subset cannot express anyOf, so the adapter enforces the
// requirement semantically.
func RegisterGitHubIssueUpdateCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "github.issue.update",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "github",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "github.issue",
			GrantRequired: true,
			ResourceArguments: map[string]string{
				"repo": "repo",
			},
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"required": ["repo", "number"],
			"properties": {
				"repo":      {"type": "string", "description": "owner/name"},
				"number":    {"type": "integer", "minimum": 1, "description": "Issue number"},
				"title":     {"type": "string", "minLength": 1, "maxLength": 256},
				"body":      {"type": "string", "maxLength": 65536},
				"labels":    {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 50}},
				"assignees": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 39}}
			},
			"additionalProperties": false
		}`),
	})
}
