package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// GitHubPullCreateHandler implements the github.pr.create capability —
// opening a pull request is a durable MUTATION with the same marker-based
// exactly-once contract as issue.create: the external operation token is
// embedded in the PR body as a hidden marker, and Resolve scans the
// repo's pull listing for it.
type GitHubPullCreateHandler struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewGitHubPullCreateHandler creates the adapter against the same
// provider identity as the issue adapter.
func NewGitHubPullCreateHandler(baseURL, token string) *GitHubPullCreateHandler {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &GitHubPullCreateHandler{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// SetHTTPClient overrides the HTTP client (tests use short timeouts).
func (h *GitHubPullCreateHandler) SetHTTPClient(c *http.Client) { h.client = c }

type githubPullCreateArgs struct {
	Repo  string `json:"repo"`  // "owner/name"
	Title string `json:"title"` // PR title
	Head  string `json:"head"`  // source branch ("branch" or "owner:branch")
	Base  string `json:"base"`  // target branch
	Body  string `json:"body"`  // PR body
	Draft bool   `json:"draft"` // create as draft
}

// normalizeGitHubPullCreateArgs applies provider semantic normalization
// — validation and trimming — distinct from JSON canonicalization.
func normalizeGitHubPullCreateArgs(raw json.RawMessage) (githubPullCreateArgs, error) {
	var args githubPullCreateArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, err
	}
	args.Repo = strings.TrimSpace(args.Repo)
	args.Title = strings.TrimSpace(args.Title)
	args.Head = strings.TrimSpace(args.Head)
	args.Base = strings.TrimSpace(args.Base)
	if _, _, err := githubRepoParts(args.Repo); err != nil {
		return args, err
	}
	if args.Title == "" {
		return args, fmt.Errorf("title is required")
	}
	for _, ref := range []struct{ name, value string }{{"head", args.Head}, {"base", args.Base}} {
		if ref.value == "" {
			return args, fmt.Errorf("%s is required", ref.name)
		}
		if strings.ContainsAny(ref.value, " \t\r\n") || strings.Contains(ref.value, "..") {
			return args, fmt.Errorf("%s %q is not a valid git ref", ref.name, ref.value)
		}
	}
	return args, nil
}

// PrepareRecovery implements idempotency.RecoveryLocatorProvider. The
// locator is minimal provider lookup material: the external token the
// PR body marker will carry, the repo coordinate, and the head/base
// refs. The PR title and body are never stored.
func (h *GitHubPullCreateHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	args, err := normalizeGitHubPullCreateArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	ext, _ := json.Marshal(map[string]any{"repo": args.Repo, "head": args.Head, "base": args.Base})
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "github",
		Strategy:       "external-token",
		ExternalToken:  idempotency.ProviderIdempotencyKey(in.ExecutionID, in.RequestDigest, "github"),
		ResourceRef:    "repos/" + args.Repo + "/pulls",
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
		Extensions:     ext,
	}, nil
}

// Execute creates the pull request, embedding the hidden marker in the
// body so the durable ledger and the external object share one
// operation identity.
func (h *GitHubPullCreateHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	args, err := normalizeGitHubPullCreateArgs(req.Arguments)
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             fmt.Sprintf("invalid arguments: %v", err),
			DefinitiveFailure: true, // request never sent — no effect
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}

	token := ExternalTokenFromContext(ctx)
	body := args.Body
	if token != "" {
		body = strings.TrimSpace(body + "\n\n" + opMarker(token))
	}
	payload, _ := json.Marshal(map[string]any{
		"title": args.Title,
		"head":  args.Head,
		"base":  args.Base,
		"body":  body,
		"draft": args.Draft,
	})

	owner, name, _ := githubRepoParts(args.Repo)
	endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls",
		h.baseURL, url.PathEscape(owner), url.PathEscape(name))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInternalError),
			Error:             err.Error(),
			DefinitiveFailure: true,
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	if h.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+h.token)
	}
	if token != "" {
		httpReq.Header.Set("X-Crabex-Operation", token)
	}

	httpResp, err := h.client.Do(httpReq)
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureExecutionFailed),
			Error:             fmt.Sprintf("github request failed: %v", err),
			DefinitiveFailure: githubTransportDefinitive(err),
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}
	defer httpResp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))

	if httpResp.StatusCode == http.StatusCreated || httpResp.StatusCode == http.StatusOK {
		var pr struct {
			Number  int    `json:"number"`
			ID      int64  `json:"id"`
			HTMLURL string `json:"html_url"`
		}
		if err := json.Unmarshal(respBody, &pr); err != nil {
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       fmt.Sprintf("github returned %d with unparseable body: %v", httpResp.StatusCode, err),
				Execution:   &ExecutionMeta{Provider: "github"},
			}
		}
		runID := pr.HTMLURL
		if runID == "" {
			runID = fmt.Sprintf("gh:%s#%d", args.Repo, pr.Number)
		}
		result, _ := json.Marshal(map[string]any{
			"pr_number": pr.Number,
			"pr_url":    runID,
			"repo":      args.Repo,
			"head":      args.Head,
			"base":      args.Base,
		})
		return Response{
			Status:           StatusSucceeded,
			Result:           result,
			Evidence:         &EvidenceRef{ReceiptVersion: 3},
			EvidenceArtifact: respBody,
			Execution:        &ExecutionMeta{Provider: "github", RunID: runID},
		}
	}

	// 4xx is definitive — GitHub rejected the request without creating
	// the PR (including 422 "pull request already exists"). 5xx and
	// redirects are ambiguous post-dispatch: UNKNOWN.
	definitive := httpResp.StatusCode >= 400 && httpResp.StatusCode < 500
	return Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureExecutionFailed),
		Error:             fmt.Sprintf("github returned %d: %s", httpResp.StatusCode, truncate(string(respBody), 512)),
		DefinitiveFailure: definitive,
		EvidenceArtifact:  respBody,
		Execution:         &ExecutionMeta{Provider: "github"},
	}
}

// Resolve scans the repo's pull listing for the body marker —
// strictly observational (GET only), paginated to exhaustion with
// same-origin next links. Marker-found → COMMITTED with the original PR
// URL; exhausted → UNKNOWN.
func (h *GitHubPullCreateHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	var loc idempotency.RecoveryLocator
	if len(rec.RecoveryLocator) > 0 {
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("unparseable recovery locator: %w", err)
		}
	}
	repo := ""
	var ext struct {
		Repo string `json:"repo"`
	}
	if len(loc.Extensions) > 0 {
		_ = json.Unmarshal(loc.Extensions, &ext)
		repo = ext.Repo
	}
	if repo == "" && loc.ResourceRef != "" {
		repo = strings.TrimSuffix(strings.TrimPrefix(loc.ResourceRef, "repos/"), "/pulls")
	}
	if loc.ExternalToken == "" || repo == "" {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}

	marker := opMarker(loc.ExternalToken)
	owner, name, err := githubRepoParts(repo)
	if err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	truncated := false
	seen := map[string]bool{}
	nextURL := fmt.Sprintf("%s/repos/%s/%s/pulls?state=all&per_page=100",
		h.baseURL, url.PathEscape(owner), url.PathEscape(name))
	for nextURL != "" {
		if seen[nextURL] {
			truncated = true
			break
		}
		seen[nextURL] = true
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return idempotency.RecoveryResult{}, err
		}
		httpReq.Header.Set("Accept", "application/vnd.github+json")
		if h.token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+h.token)
		}
		httpResp, err := h.client.Do(httpReq)
		if err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("github pull list failed: %w", err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4<<20))
		linkHeader := httpResp.Header.Get("Link")
		status := httpResp.StatusCode
		httpResp.Body.Close()
		if status != http.StatusOK {
			return idempotency.RecoveryResult{}, fmt.Errorf("github pull list returned %d", status)
		}

		var rawPulls []json.RawMessage
		if err := json.Unmarshal(respBody, &rawPulls); err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("github pull list unparseable: %w", err)
		}
		for _, rawPR := range rawPulls {
			var pr struct {
				Number  int    `json:"number"`
				HTMLURL string `json:"html_url"`
				Body    string `json:"body"`
			}
			if err := json.Unmarshal(rawPR, &pr); err != nil {
				continue
			}
			if strings.Contains(pr.Body, marker) {
				result, _ := json.Marshal(map[string]any{
					"pr_number": pr.Number,
					"pr_url":    pr.HTMLURL,
					"repo":      repo,
				})
				return idempotency.RecoveryResult{
					Decision:         idempotency.RecoveryCommitted,
					Result:           result,
					ReceiptVersion:   3,
					ProviderID:       "github",
					ProviderRunID:    pr.HTMLURL,
					EvidenceArtifact: rawPR,
				}, nil
			}
		}
		candidate := nextLinkURL(linkHeader)
		if candidate != "" && !sameOrigin(h.baseURL, candidate) {
			truncated = true
			candidate = ""
		}
		nextURL = candidate
	}

	extra := ""
	if truncated {
		extra = `,"pagination_truncated":true`
	}
	return idempotency.RecoveryResult{
		Decision:   idempotency.RecoveryUnknown,
		ProviderID: "github",
		Result:     json.RawMessage(fmt.Sprintf(`{"repo":%q,"marker_absent":true%s}`, repo, extra)),
	}, nil
}

// GitHubPullMergeHandler implements the github.pr.merge capability — a
// durable MUTATION that merges a pull request. Recovery is
// target-state observation: Resolve GETs the pull and commits when
// merged=true is observed.
type GitHubPullMergeHandler struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewGitHubPullMergeHandler creates the merge adapter against the same
// provider identity as the issue adapter.
func NewGitHubPullMergeHandler(baseURL, token string) *GitHubPullMergeHandler {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &GitHubPullMergeHandler{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// SetHTTPClient overrides the HTTP client (tests use short timeouts).
func (h *GitHubPullMergeHandler) SetHTTPClient(c *http.Client) { h.client = c }

// pullMergeMethods is the closed set the schema's enum must match.
var pullMergeMethods = map[string]bool{
	"merge":  true,
	"squash": true,
	"rebase": true,
}

type githubPullMergeArgs struct {
	Repo        string `json:"repo"`
	Number      int    `json:"number"`
	MergeMethod string `json:"merge_method"`
}

func normalizeGitHubPullMergeArgs(raw json.RawMessage) (githubPullMergeArgs, error) {
	var args githubPullMergeArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, err
	}
	args.Repo = strings.TrimSpace(args.Repo)
	args.MergeMethod = strings.TrimSpace(args.MergeMethod)
	if _, _, err := githubRepoParts(args.Repo); err != nil {
		return args, err
	}
	if args.Number < 1 {
		return args, fmt.Errorf("number must be a positive pull request number, got %d", args.Number)
	}
	if args.MergeMethod != "" && !pullMergeMethods[args.MergeMethod] {
		return args, fmt.Errorf("merge_method must be one of merge, squash, rebase, got %q", args.MergeMethod)
	}
	return args, nil
}

// PrepareRecovery persists the minimal locator: operation token, repo
// coordinate, and the pull request number.
func (h *GitHubPullMergeHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	args, err := normalizeGitHubPullMergeArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	ext, _ := json.Marshal(map[string]any{"repo": args.Repo, "number": args.Number})
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "github",
		Strategy:       "state-observation",
		ExternalToken:  idempotency.ProviderIdempotencyKey(in.ExecutionID, in.RequestDigest, "github"),
		ResourceRef:    fmt.Sprintf("repos/%s/pulls/%d", args.Repo, args.Number),
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
		Extensions:     ext,
	}, nil
}

// Execute merges the pull request via PUT .../merge.
func (h *GitHubPullMergeHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	args, err := normalizeGitHubPullMergeArgs(req.Arguments)
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             fmt.Sprintf("invalid arguments: %v", err),
			DefinitiveFailure: true, // request never sent — no effect
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}

	payload := map[string]string{}
	if args.MergeMethod != "" {
		payload["merge_method"] = args.MergeMethod
	}
	body, _ := json.Marshal(payload)

	owner, name, _ := githubRepoParts(args.Repo)
	endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/merge",
		h.baseURL, url.PathEscape(owner), url.PathEscape(name), args.Number)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInternalError),
			Error:             err.Error(),
			DefinitiveFailure: true,
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	if h.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+h.token)
	}
	if token := ExternalTokenFromContext(ctx); token != "" {
		httpReq.Header.Set("X-Crabex-Operation", token)
	}

	httpResp, err := h.client.Do(httpReq)
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureExecutionFailed),
			Error:             fmt.Sprintf("github request failed: %v", err),
			DefinitiveFailure: githubTransportDefinitive(err),
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}
	defer httpResp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))

	if httpResp.StatusCode == http.StatusOK {
		var merge struct {
			SHA     string `json:"sha"`
			Merged  bool   `json:"merged"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &merge); err != nil {
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       fmt.Sprintf("github returned %d with unparseable body: %v", httpResp.StatusCode, err),
				Execution:   &ExecutionMeta{Provider: "github"},
			}
		}
		// A 200 with merged=false means GitHub declined the merge in the
		// response body — the provider's own report that no effect
		// occurred is a definitive no-effect proof.
		if !merge.Merged {
			return Response{
				Status:            StatusFailed,
				FailureCode:       string(capability.FailureExecutionFailed),
				Error:             fmt.Sprintf("github reports the merge did not occur: %s", merge.Message),
				DefinitiveFailure: true,
				EvidenceArtifact:  respBody,
				Execution:         &ExecutionMeta{Provider: "github"},
			}
		}
		runID := merge.SHA
		if runID == "" {
			runID = fmt.Sprintf("gh:%s#%d merge", args.Repo, args.Number)
		}
		result, _ := json.Marshal(map[string]any{
			"pr_number":        args.Number,
			"repo":             args.Repo,
			"merged":           true,
			"merge_commit_sha": merge.SHA,
		})
		return Response{
			Status:           StatusSucceeded,
			Result:           result,
			Evidence:         &EvidenceRef{ReceiptVersion: 3},
			EvidenceArtifact: respBody,
			Execution:        &ExecutionMeta{Provider: "github", RunID: runID},
		}
	}

	// 4xx is definitive — 405 (not mergeable), 404 (missing), 409
	// (head moved/conflict) all mean no merge commit was produced.
	// 5xx is ambiguous post-dispatch: UNKNOWN.
	definitive := httpResp.StatusCode >= 400 && httpResp.StatusCode < 500
	return Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureExecutionFailed),
		Error:             fmt.Sprintf("github returned %d: %s", httpResp.StatusCode, truncate(string(respBody), 512)),
		DefinitiveFailure: definitive,
		EvidenceArtifact:  respBody,
		Execution:         &ExecutionMeta{Provider: "github"},
	}
}

// Resolve observes the pull request's merged flag — strictly
// observational (a single GET). merged=true → COMMITTED with the merge
// commit SHA; otherwise → UNKNOWN.
func (h *GitHubPullMergeHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	var loc idempotency.RecoveryLocator
	if len(rec.RecoveryLocator) > 0 {
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("unparseable recovery locator: %w", err)
		}
	}
	repo, number := locatorRepoNumber(loc, "pulls")
	if repo == "" || number == 0 {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	owner, name, err := githubRepoParts(repo)
	if err != nil {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls/%d",
		h.baseURL, url.PathEscape(owner), url.PathEscape(name), number)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return idempotency.RecoveryResult{}, err
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	if h.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+h.token)
	}
	httpResp, err := h.client.Do(httpReq)
	if err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github pull get failed: %w", err)
	}
	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	status := httpResp.StatusCode
	httpResp.Body.Close()
	if status != http.StatusOK {
		return idempotency.RecoveryResult{}, fmt.Errorf("github pull get returned %d", status)
	}

	var pr struct {
		Number         int    `json:"number"`
		Merged         bool   `json:"merged"`
		State          string `json:"state"`
		MergeCommitSHA string `json:"merge_commit_sha"`
		HTMLURL        string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &pr); err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github pull get unparseable: %w", err)
	}
	if pr.Merged {
		runID := pr.MergeCommitSHA
		if runID == "" {
			runID = pr.HTMLURL
		}
		result, _ := json.Marshal(map[string]any{
			"pr_number":        pr.Number,
			"pr_url":           pr.HTMLURL,
			"repo":             repo,
			"merged":           true,
			"merge_commit_sha": pr.MergeCommitSHA,
		})
		return idempotency.RecoveryResult{
			Decision:         idempotency.RecoveryCommitted,
			Result:           result,
			ReceiptVersion:   3,
			ProviderID:       "github",
			ProviderRunID:    runID,
			EvidenceArtifact: respBody,
		}, nil
	}
	return idempotency.RecoveryResult{
		Decision:   idempotency.RecoveryUnknown,
		ProviderID: "github",
		Result: json.RawMessage(fmt.Sprintf(
			`{"repo":%q,"pull":%d,"merged":false,"state_observed":%q}`, repo, number, pr.State)),
	}, nil
}

// RegisterGitHubPullCreateCapability registers github.pr.create.
func RegisterGitHubPullCreateCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "github.pr.create",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "github",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "github.pr",
			GrantRequired: true,
			// Least-privilege resource scope: a grant constrained to
			// repo=[owner/name] admits PR creation only in those
			// repositories, and a base=[branch] constraint further
			// restricts which branches PRs may target.
			ResourceArguments: map[string]string{
				"repo": "repo",
				"base": "base",
			},
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"required": ["repo", "title", "head", "base"],
			"properties": {
				"repo":  {"type": "string", "description": "owner/name"},
				"title": {"type": "string", "minLength": 1, "maxLength": 256},
				"head":  {"type": "string", "minLength": 1, "maxLength": 256, "description": "source branch (\"branch\" or \"owner:branch\")"},
				"base":  {"type": "string", "minLength": 1, "maxLength": 256, "description": "target branch"},
				"body":  {"type": "string", "maxLength": 65536},
				"draft": {"type": "boolean"}
			},
			"additionalProperties": false
		}`),
	})
}

// RegisterGitHubPullMergeCapability registers github.pr.merge.
func RegisterGitHubPullMergeCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "github.pr.merge",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "github",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "github.pr",
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
				"number":       {"type": "integer", "minimum": 1, "description": "Pull request number"},
				"merge_method": {"type": "string", "enum": ["merge", "squash", "rebase"]}
			},
			"additionalProperties": false
		}`),
	})
}
