package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// GitHubIssueHandler implements the github.issue.create capability —
// the first real external-effect provider for the Effect Fabric.
//
// Exactly-once model:
//   - PrepareRecovery generates a stable external operation token
//     (gh-issue-<execution_id>) persisted in the typed recovery locator.
//     The same token is injected into the dispatch context and embedded
//     in the issue body as a hidden marker (<!-- crabex-op:... -->), so
//     the locator and the external request carry the SAME identity.
//   - Resolve lists the repo's issues and looks for the marker. Found
//     → the effect provably happened under this execution's token
//     (COMMITTED with the original provider run ID — the issue URL).
//     The marker binds provider operation identity to durable
//     execution identity rather than reconstructing it after a crash.
//   - Resolve is strictly observational: it only reads (GET), never
//     writes — a duplicate or racing resolver is harmless.
type GitHubIssueHandler struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewGitHubIssueHandler creates the adapter. baseURL points at the
// GitHub API root (or a test server); token is the API token sent as a
// Bearer credential.
func NewGitHubIssueHandler(baseURL, token string) *GitHubIssueHandler {
	return &GitHubIssueHandler{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// SetHTTPClient overrides the HTTP client (tests use short timeouts).
func (h *GitHubIssueHandler) SetHTTPClient(c *http.Client) { h.client = c }

// opMarker returns the hidden issue-body marker binding the issue to
// the stable external operation token.
func opMarker(externalToken string) string {
	return "<!-- crabex-op:" + externalToken + " -->"
}

type githubIssueArgs struct {
	Repo  string `json:"repo"`  // "owner/name"
	Title string `json:"title"` // issue title
	Body  string `json:"body"`  // issue body
}

// normalizeGitHubIssueArgs applies provider semantic normalization —
// validation and trimming — distinct from JSON canonicalization.
func normalizeGitHubIssueArgs(raw json.RawMessage) (githubIssueArgs, error) {
	var args githubIssueArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, err
	}
	args.Repo = strings.TrimSpace(args.Repo)
	args.Title = strings.TrimSpace(args.Title)
	parts := strings.SplitN(args.Repo, "/", 3)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return args, fmt.Errorf("repo must be \"owner/name\", got %q", args.Repo)
	}
	if args.Title == "" {
		return args, fmt.Errorf("title is required")
	}
	return args, nil
}

// PrepareRecovery implements idempotency.RecoveryLocatorProvider. The
// locator is minimal provider lookup material: the external token
// (which the issue body marker will carry) and the repo coordinate.
// The full request body is never stored.
func (h *GitHubIssueHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	args, err := normalizeGitHubIssueArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	ext, _ := json.Marshal(map[string]any{"repo": args.Repo})
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "github",
		Strategy:       "external-token",
		ExternalToken:  "gh-issue-" + in.ExecutionID,
		ResourceRef:    "repos/" + args.Repo + "/issues",
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
		Extensions:     ext,
	}, nil
}

// Execute creates the GitHub issue. The request body embeds the hidden
// marker carrying the SAME external token persisted in the recovery
// locator — the durable execution and the external object share one
// operation identity.
func (h *GitHubIssueHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	args, err := normalizeGitHubIssueArgs(req.Arguments)
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
	payload, _ := json.Marshal(map[string]string{"title": args.Title, "body": body})

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.baseURL+"/repos/"+args.Repo+"/issues", bytes.NewReader(payload))
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
		// Connection refused / DNS failures happen before any bytes
		// were written — the provider never saw the request, so no
		// effect is provable. Timeouts and mid-request drops are
		// ambiguous: the request may have reached the provider.
		definitive := errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, context.DeadlineExceeded)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			definitive = false // timeout — may have executed
		}
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureExecutionFailed),
			Error:             fmt.Sprintf("github request failed: %v", err),
			DefinitiveFailure: definitive,
			Execution:         &ExecutionMeta{Provider: "github"},
		}
	}
	defer httpResp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))

	if httpResp.StatusCode == http.StatusCreated || httpResp.StatusCode == http.StatusOK {
		var issue struct {
			Number  int    `json:"number"`
			ID      int64  `json:"id"`
			NodeID  string `json:"node_id"`
			HTMLURL string `json:"html_url"`
		}
		if err := json.Unmarshal(respBody, &issue); err != nil {
			// 2xx with an unparseable body — the issue may exist.
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       fmt.Sprintf("github returned %d with unparseable body: %v", httpResp.StatusCode, err),
				Execution:   &ExecutionMeta{Provider: "github"},
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
		})
		sum := sha256.Sum256(result)
		return Response{
			Status: StatusSucceeded,
			Result: result,
			Evidence: &EvidenceRef{
				Digest:         fmt.Sprintf("%x", sum),
				ReceiptVersion: 3,
			},
			Execution: &ExecutionMeta{Provider: "github", RunID: runID},
		}
	}

	// 4xx validation/auth failures are definitive — GitHub rejected the
	// request without creating the issue. 5xx and redirects are
	// ambiguous post-dispatch: UNKNOWN.
	definitive := httpResp.StatusCode >= 400 && httpResp.StatusCode < 500
	return Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureExecutionFailed),
		Error:             fmt.Sprintf("github returned %d: %s", httpResp.StatusCode, truncate(string(respBody), 512)),
		DefinitiveFailure: definitive,
		Execution:         &ExecutionMeta{Provider: "github"},
	}
}

// Resolve implements idempotency.RecoveryResolver. It is strictly
// observational — a read-only marker scan, never a write — so duplicate
// or racing resolvers are harmless. Marker found → COMMITTED with the
// ORIGINAL provider run ID (the issue URL), never a fabricated one.
// Marker absent after a successful authoritative listing → FAILED
// (no-effect proof for this exercise).
func (h *GitHubIssueHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
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
		repo = strings.TrimSuffix(strings.TrimPrefix(loc.ResourceRef, "repos/"), "/issues")
	}
	if loc.ExternalToken == "" || repo == "" {
		return idempotency.RecoveryResult{Decision: idempotency.RecoveryUnknown}, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		h.baseURL+"/repos/"+repo+"/issues?state=all&per_page=100", nil)
	if err != nil {
		return idempotency.RecoveryResult{}, err
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	if h.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+h.token)
	}
	httpResp, err := h.client.Do(httpReq)
	if err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue list failed: %w", err)
	}
	defer httpResp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4<<20))
	if httpResp.StatusCode != http.StatusOK {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue list returned %d", httpResp.StatusCode)
	}

	var issues []struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal(respBody, &issues); err != nil {
		return idempotency.RecoveryResult{}, fmt.Errorf("github issue list unparseable: %w", err)
	}

	marker := opMarker(loc.ExternalToken)
	for _, issue := range issues {
		if strings.Contains(issue.Body, marker) {
			result, _ := json.Marshal(map[string]any{
				"issue_number": issue.Number,
				"issue_url":    issue.HTMLURL,
				"repo":         repo,
			})
			sum := sha256.Sum256(result)
			return idempotency.RecoveryResult{
				Decision:       idempotency.RecoveryCommitted,
				Result:         result,
				EvidenceDigest: fmt.Sprintf("%x", sum),
				ReceiptVersion: 3,
				ProviderID:     "github",
				ProviderRunID:  issue.HTMLURL, // original provider run ID
			}, nil
		}
	}
	// Authoritative listing succeeded and no issue carries the token —
	// the effect provably did not happen under this execution.
	result, _ := json.Marshal(map[string]any{"repo": repo, "marker_absent": true})
	sum := sha256.Sum256(result)
	return idempotency.RecoveryResult{
		Decision:       idempotency.RecoveryFailed,
		Result:         result,
		EvidenceDigest: fmt.Sprintf("%x", sum),
		ReceiptVersion: 3,
		ProviderID:     "github",
		ProviderRunID:  "none",
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// RegisterGitHubIssueCapability registers github.issue.create.
func RegisterGitHubIssueCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "github.issue.create",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "github",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "github.issue",
			GrantRequired: true,
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"required": ["repo", "title"],
			"properties": {
				"repo":  {"type": "string", "description": "owner/name"},
				"title": {"type": "string", "minLength": 1, "maxLength": 256},
				"body":  {"type": "string", "maxLength": 65536}
			},
			"additionalProperties": false
		}`),
	})
}
