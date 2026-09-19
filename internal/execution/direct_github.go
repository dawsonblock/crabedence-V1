package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// GitHubReads implements the observational GitHub read capabilities on
// the DIRECT route: external reads with admission, schema validation,
// authority, timeouts, and audit — without the durable mutation
// ledger. A read has no external effect, so a failure is a safe FAILED,
// never UNKNOWN.
//
// Every read projects a bounded field set. The DIRECT route must not
// become a proxy that returns arbitrary provider payloads: the caller
// gets exactly the fields the capability declares, and the adapter
// never logs or returns credentials.
type GitHubReads struct {
	baseURL string
	token   string
	client  *http.Client
}

// maxDirectReadBytes bounds the provider response body a DIRECT read
// will consume — a bounded projection, never an unbounded passthrough.
const maxDirectReadBytes = 256 * 1024

// NewGitHubReads creates the GitHub read adapter.
func NewGitHubReads(baseURL, token string) *GitHubReads {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &GitHubReads{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 20 * time.Second},
	}
}

// RegisterGitHubReadCapabilities registers the DIRECT read capabilities.
func RegisterGitHubReadCapabilities(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "github.issue.get",
		ExecutionClass: capability.ClassRead,
		AdapterID:      "github",
		AuthorityPolicy: capability.AuthorityPolicy{
			// Observational public read: no authority material required.
			// Policy is per-capability — a private-repository read would
			// pin GrantRequired: true instead.
			ID:            "github.read",
			GrantRequired: false,
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"required": ["repo", "number"],
			"properties": {
				"repo":   {
					"type": "string",
					"minLength": 3,
					"maxLength": 200,
					"description": "Repository as owner/name"
				},
				"number": {
					"type": "integer",
					"minimum": 1,
					"description": "Issue number"
				}
			},
			"additionalProperties": false
		}`),
	})
}

// RegisterGitHubReads binds the GitHub read implementations.
func RegisterGitHubReads(registry *DirectReadRegistry, reads *GitHubReads) error {
	return registry.Register("github.issue.get", reads.IssueGet)
}

// IssueGet reads one issue: GET /repos/{owner}/{repo}/issues/{number}.
// The result is a bounded projection — number, title, state, URL,
// author, timestamps — never the raw provider payload.
func (g *GitHubReads) IssueGet(ctx context.Context, call CallContext) (json.RawMessage, error) {
	var args struct {
		Repo   string `json:"repo"`
		Number int    `json:"number"`
	}
	if err := json.Unmarshal(call.Arguments, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	owner, name, ok := strings.Cut(args.Repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") || args.Number < 1 {
		return nil, errors.New("repo must be owner/name and number must be a positive issue number")
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues/%d",
		g.baseURL, url.PathEscape(owner), url.PathEscape(name), args.Number)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build github request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.token != "" {
		request.Header.Set("Authorization", "Bearer "+g.token)
	}

	response, err := g.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("github read failed: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxDirectReadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read github response: %w", err)
	}
	if len(body) > maxDirectReadBytes {
		return nil, fmt.Errorf("github response exceeds %d bytes", maxDirectReadBytes)
	}

	switch response.StatusCode {
	case http.StatusOK:
		// Fall through to the projection.
	case http.StatusNotFound:
		return nil, fmt.Errorf("issue %s#%d not found", args.Repo, args.Number)
	case http.StatusUnauthorized, http.StatusForbidden:
		// Never echo the response body — it can carry credential hints.
		return nil, fmt.Errorf("github denied the read (HTTP %d)", response.StatusCode)
	default:
		return nil, fmt.Errorf("github returned HTTP %d", response.StatusCode)
	}

	var issue struct {
		Number    int    `json:"number"`
		Title     string `json:"title"`
		State     string `json:"state"`
		HTMLURL   string `json:"html_url"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		User      struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &issue); err != nil {
		return nil, fmt.Errorf("github response was not a JSON object: %w", err)
	}

	return json.Marshal(map[string]any{
		"number":     issue.Number,
		"title":      issue.Title,
		"state":      issue.State,
		"html_url":   issue.HTMLURL,
		"author":     issue.User.Login,
		"created_at": issue.CreatedAt,
		"updated_at": issue.UpdatedAt,
	})
}
