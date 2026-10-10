package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/providertransport"
)

// GitHubCommentHandler implements the github.issue.comment capability —
// posting a comment on an existing issue is a durable MUTATION with the
// same exactly-once contract as issue.create:
//
//   - PrepareRecovery persists a minimal locator carrying the stable
//     external operation token; Execute embeds the SAME token in the
//     comment body as a hidden marker, so the ledger and the provider
//     object share one operation identity.
//   - Resolve scans the issue's comment listing for the marker —
//     strictly observational, never a write. Found → COMMITTED with the
//     original provider run ID (the comment URL); exhausted → UNKNOWN,
//     because comment listing is eventually consistent and absence of
//     positive evidence is not proof of no effect.
type GitHubCommentHandler struct {
	transport    *providertransport.Transport
	transportErr error
}

// NewGitHubCommentHandler creates the comment adapter against the same
// provider identity as the issue adapter.
func NewGitHubCommentHandler(baseURL, token string) *GitHubCommentHandler {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	h := &GitHubCommentHandler{}
	h.transport, h.transportErr = newGitHubTransport(baseURL, token)
	return h
}

// SetTransport installs the shared trusted transport — the production
// wiring path.
func (h *GitHubCommentHandler) SetTransport(t *providertransport.Transport) {
	h.transport, h.transportErr = t, nil
}

// SetHTTPClient overrides the transport's HTTP client (tests use
// short timeouts and injected round-trippers).
func (h *GitHubCommentHandler) SetHTTPClient(c *http.Client) {
	if h.transport != nil {
		h.transport.SetHTTPClient(c)
	}
}

// transportFailure renders a transport-construction failure as a
// definite no-effect — nothing was ever dispatched.
func (h *GitHubCommentHandler) transportFailure() (Response, bool) {
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

type githubCommentArgs struct {
	Repo   string `json:"repo"`   // "owner/name"
	Number int    `json:"number"` // issue number
	Body   string `json:"body"`   // comment body
}

// normalizeGitHubCommentArgs applies provider semantic normalization —
// validation and trimming — distinct from JSON canonicalization.
func normalizeGitHubCommentArgs(raw json.RawMessage) (githubCommentArgs, error) {
	var args githubCommentArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, err
	}
	args.Repo = strings.TrimSpace(args.Repo)
	args.Body = strings.TrimSpace(args.Body)
	owner, name, ok := strings.Cut(args.Repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return args, fmt.Errorf("repo must be \"owner/name\", got %q", args.Repo)
	}
	if args.Number < 1 {
		return args, fmt.Errorf("number must be a positive issue number, got %d", args.Number)
	}
	if args.Body == "" {
		return args, fmt.Errorf("body is required")
	}
	return args, nil
}

// PrepareRecovery implements idempotency.RecoveryLocatorProvider. The
// locator is minimal provider lookup material: the external token (which
// the comment body marker will carry), the repo coordinate, and the
// issue number. The comment body is never stored.
func (h *GitHubCommentHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	args, err := normalizeGitHubCommentArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	ext, _ := json.Marshal(map[string]any{"repo": args.Repo, "number": args.Number})
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "github",
		Strategy:       "external-token",
		ExternalToken:  idempotency.ProviderIdempotencyKey(in.ExecutionID, in.RequestDigest, "github"),
		ResourceRef:    fmt.Sprintf("repos/%s/issues/%d/comments", args.Repo, args.Number),
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
		Extensions:     ext,
	}, nil
}

// Execute posts the comment. The request body embeds the hidden marker
// carrying the SAME external token persisted in the recovery locator —
// the durable execution and the external object share one operation
// identity.
func (h *GitHubCommentHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	args, err := normalizeGitHubCommentArgs(req.Arguments)
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
	token := ExternalTokenFromContext(ctx)
	body := args.Body
	if token != "" {
		body = strings.TrimSpace(body + "\n\n" + opMarker(token))
	}
	payload, _ := json.Marshal(map[string]string{"body": body})

	owner, name, _ := strings.Cut(args.Repo, "/")
	httpResp, err := h.transport.Do(ctx, providertransport.ProviderHTTPRequest{
		Method: http.MethodPost,
		URL: fmt.Sprintf("/repos/%s/%s/issues/%d/comments",
			url.PathEscape(owner), url.PathEscape(name), args.Number),
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/vnd.github+json",
		},
		Body:    payload,
		Context: githubRequestContext(req, "github.issue.comment", desc, fmt.Sprintf("repos/%s/issues/%d/comments", args.Repo, args.Number), token),
	})
	if err != nil {
		return githubFailure(err)
	}
	respBody := httpResp.Body

	if httpResp.StatusCode == http.StatusCreated || httpResp.StatusCode == http.StatusOK {
		var comment struct {
			ID      int64  `json:"id"`
			NodeID  string `json:"node_id"`
			HTMLURL string `json:"html_url"`
		}
		if err := json.Unmarshal(respBody, &comment); err != nil {
			// 2xx with an unparseable body — the comment may exist.
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       fmt.Sprintf("github returned %d with unparseable body: %v", httpResp.StatusCode, err),
				Execution:   &ExecutionMeta{Provider: "github"},
				Dispatch:    githubProvenance(httpResp.Trace, httpResp.StatusCode),
			}
		}
		runID := comment.HTMLURL
		if runID == "" {
			runID = fmt.Sprintf("gh:%s#%d comment %d", args.Repo, args.Number, comment.ID)
		}
		result, _ := json.Marshal(map[string]any{
			"comment_id":  comment.ID,
			"comment_url": runID,
			"repo":        args.Repo,
			"issue":       args.Number,
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

	// 4xx validation/auth failures are definitive — GitHub rejected the
	// request without creating the comment. 5xx and redirects are
	// ambiguous post-dispatch: UNKNOWN.
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

// Resolve implements idempotency.RecoveryResolver for the comment's
// listing endpoint — strictly observational (GET only), paginated to
// exhaustion with same-origin next links, marker-found → COMMITTED with
// the original comment URL, marker-absent → UNKNOWN.
func (h *GitHubCommentHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	var loc idempotency.RecoveryLocator
	if len(rec.RecoveryLocator) > 0 {
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("unparseable recovery locator: %w", err)
		}
	}
	repo := ""
	number := 0
	var ext struct {
		Repo   string `json:"repo"`
		Number int    `json:"number"`
	}
	if len(loc.Extensions) > 0 {
		_ = json.Unmarshal(loc.Extensions, &ext)
		repo = ext.Repo
		number = ext.Number
	}
	if (repo == "" || number == 0) && loc.ResourceRef != "" {
		// ResourceRef is "repos/{repo}/issues/{number}/comments".
		parts := strings.Split(strings.TrimPrefix(loc.ResourceRef, "repos/"), "/")
		if len(parts) == 5 && parts[2] == "issues" && parts[4] == "comments" {
			if repo == "" {
				repo = parts[0] + "/" + parts[1]
			}
			if number == 0 {
				fmt.Sscanf(parts[3], "%d", &number)
			}
		}
	}
	if loc.ExternalToken == "" || repo == "" || number == 0 {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}

	marker := opMarker(loc.ExternalToken)
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}
	// Paginate completely — a fixed cap would make effects on later
	// pages permanently unreachable; termination is guaranteed by the
	// resolver deadline and visited-URL cycle detection, and a next link
	// is only followed on the API origin so the bearer never leaks.
	truncated := false
	seen := map[string]bool{}
	nextURL := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100",
		url.PathEscape(owner), url.PathEscape(name), number)
	for nextURL != "" {
		if seen[nextURL] {
			truncated = true
			break
		}
		seen[nextURL] = true
		httpResp, err := h.transport.Do(ctx, providertransport.ProviderHTTPRequest{
			Method:  http.MethodGet,
			URL:     nextURL,
			Headers: map[string]string{"Accept": "application/vnd.github+json"},
			Context: providertransport.RequestContext{
				Capability: "github.issue.comment",
				Resource:   fmt.Sprintf("repos/%s/issues/%d/comments", repo, number),
			},
		})
		if err != nil {
			var policyErr *providertransport.PolicyError
			if errors.As(err, &policyErr) && !policyErr.DLP {
				truncated = true
				break
			}
			return idempotency.RecoveryResult{}, fmt.Errorf("github comment list failed: %w", err)
		}
		respBody := httpResp.Body
		linkHeader := httpResp.Header.Get("Link")
		status := httpResp.StatusCode
		if status != http.StatusOK {
			return idempotency.RecoveryResult{}, fmt.Errorf("github comment list returned %d", status)
		}

		var rawComments []json.RawMessage
		if err := json.Unmarshal(respBody, &rawComments); err != nil {
			return idempotency.RecoveryResult{}, fmt.Errorf("github comment list unparseable: %w", err)
		}
		for _, rawComment := range rawComments {
			var comment struct {
				ID      int64  `json:"id"`
				HTMLURL string `json:"html_url"`
				Body    string `json:"body"`
			}
			if err := json.Unmarshal(rawComment, &comment); err != nil {
				continue
			}
			if strings.Contains(comment.Body, marker) {
				result, _ := json.Marshal(map[string]any{
					"comment_id":  comment.ID,
					"comment_url": comment.HTMLURL,
					"repo":        repo,
					"issue":       number,
				})
				return idempotency.RecoveryResult{
					Decision:         idempotency.RecoveryCommitted,
					Result:           result,
					ReceiptVersion:   3,
					ProviderID:       "github",
					ProviderRunID:    comment.HTMLURL, // original provider run ID
					EvidenceArtifact: rawComment,      // raw provider object — digest recomputed by attestor
				}, nil
			}
		}
		candidate := nextLinkURL(linkHeader)
		if candidate == "" {
			nextURL = ""
			continue
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
		Result:     json.RawMessage(fmt.Sprintf(`{"repo":%q,"issue":%d,"marker_absent":true%s}`, repo, number, extra)),
	}, nil
}

// RegisterGitHubCommentCapability registers github.issue.comment — a
// MUTATION, so it resolves to the durable CRABEDENCE route by default.
func RegisterGitHubCommentCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "github.issue.comment",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "github",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "github.issue",
			GrantRequired: true,
			// The grant's repo constraint scopes which repositories a
			// comment can land in; the issue number is an integer, so it
			// cannot carry a resource dimension (constraints bind string
			// arguments only) — repo is the least-privilege scope.
			ResourceArguments: map[string]string{
				"repo": "repo",
			},
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"required": ["repo", "number", "body"],
			"properties": {
				"repo":   {"type": "string", "description": "owner/name"},
				"number": {"type": "integer", "minimum": 1, "description": "Issue number"},
				"body":   {"type": "string", "minLength": 1, "maxLength": 65473}
			},
			"additionalProperties": false
		}`),
	})
}

// githubAdapter routes the github adapter's durable capabilities to their
// per-capability handlers. MultiHandler dispatches on the descriptor's
// adapter ID, so one adapter carrying several capabilities needs its own
// dispatch — and a capability the adapter does not know fails closed
// rather than falling through to whichever handler answered first.
type githubAdapter struct {
	issue       *GitHubIssueHandler
	comment     *GitHubCommentHandler
	issueClose  *GitHubIssueCloseHandler
	issueUpdate *GitHubIssueUpdateHandler
	pullCreate  *GitHubPullCreateHandler
	pullMerge   *GitHubPullMergeHandler
}

func (a *githubAdapter) handlerFor(capabilityID string) (Handler, error) {
	switch capabilityID {
	case "github.issue.create":
		return a.issue, nil
	case "github.issue.comment":
		return a.comment, nil
	case "github.issue.close":
		return a.issueClose, nil
	case "github.issue.update":
		return a.issueUpdate, nil
	case "github.pr.create":
		return a.pullCreate, nil
	case "github.pr.merge":
		return a.pullMerge, nil
	default:
		return nil, fmt.Errorf("adapter github has no handler for capability %q", capabilityID)
	}
}

func (a *githubAdapter) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	handler, err := a.handlerFor(desc.ID)
	if err != nil {
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInternalError),
			Error:             err.Error(),
			DefinitiveFailure: true, // never reached the provider — no effect
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}
	return handler.Execute(ctx, req, desc)
}

// PrepareRecovery implements the executor's recoveryPreparer contract by
// routing to the per-capability locator provider.
func (a *githubAdapter) PrepareRecovery(ctx context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	handler, err := a.handlerFor(in.CapabilityID)
	if err != nil {
		return nil, err
	}
	provider, ok := handler.(idempotency.RecoveryLocatorProvider)
	if !ok {
		return nil, nil
	}
	return provider.PrepareRecovery(ctx, in)
}
