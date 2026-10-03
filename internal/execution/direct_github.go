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
	"github.com/openclaw/crabbox/internal/providertransport"
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
	transport    *providertransport.Transport
	transportErr error
}

// maxDirectReadBytes bounds the provider response body a DIRECT read
// will consume — a bounded projection, never an unbounded passthrough.
const maxDirectReadBytes = 256 * 1024

// NewGitHubReads creates the GitHub read adapter.
func NewGitHubReads(baseURL, token string) *GitHubReads {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	g := &GitHubReads{}
	g.transport, g.transportErr = newGitHubTransport(baseURL, token)
	return g
}

// SetTransport installs the shared trusted transport — the production
// wiring path.
func (g *GitHubReads) SetTransport(t *providertransport.Transport) {
	g.transport, g.transportErr = t, nil
}

// githubReadAuthority is the authority policy every GitHub DIRECT read
// shares: the adapter always attaches the configured GitHub token, so a
// read can see whatever the service credential can — including private
// repositories. It is therefore NOT a public read: it requires a grant
// like the mutation leg, scoped to repositories through the repo
// constraint.
func githubReadAuthority() capability.AuthorityPolicy {
	return capability.AuthorityPolicy{
		ID:            "github.read",
		GrantRequired: true,
		ResourceArguments: map[string]string{
			"repo": "repo",
		},
	}
}

// RegisterGitHubReadCapabilities registers the DIRECT read capabilities.
func RegisterGitHubReadCapabilities(reg *capability.Registry) error {
	for _, desc := range []capability.CapabilityDescriptor{
		{
			ID:              "github.issue.get",
			ExecutionClass:  capability.ClassRead,
			AdapterID:       "github",
			AuthorityPolicy: githubReadAuthority(),
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
		},
		{
			ID:              "github.issue.list",
			ExecutionClass:  capability.ClassRead,
			AdapterID:       "github",
			AuthorityPolicy: githubReadAuthority(),
			Schema: json.RawMessage(`{
				"type": "object",
				"required": ["repo"],
				"properties": {
					"repo":  {
						"type": "string",
						"minLength": 3,
						"maxLength": 200,
						"description": "Repository as owner/name"
					},
					"state": {
						"type": "string",
						"enum": ["open", "closed", "all"],
						"description": "Issue state filter (default open)"
					},
					"limit": {
						"type": "integer",
						"minimum": 1,
						"maximum": 50,
						"description": "Maximum issues returned (default 30, capped at 50)"
					}
				},
				"additionalProperties": false
			}`),
		},
	} {
		if err := reg.Register(desc); err != nil {
			return err
		}
	}
	return nil
}

// RegisterGitHubReads binds the GitHub read implementations.
func RegisterGitHubReads(registry *DirectReadRegistry, reads *GitHubReads) error {
	if err := registry.Register("github.issue.get", reads.IssueGet); err != nil {
		return err
	}
	return registry.Register("github.issue.list", reads.IssueList)
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

	if g.transportErr != nil {
		return nil, fmt.Errorf("github transport unavailable: %w", g.transportErr)
	}
	response, err := g.transport.Do(ctx, providertransport.ProviderHTTPRequest{
		Method: http.MethodGet,
		URL: fmt.Sprintf("/repos/%s/%s/issues/%d",
			url.PathEscape(owner), url.PathEscape(name), args.Number),
		Headers: map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		},
		Context: providertransport.RequestContext{
			Capability:     "github.issue.get",
			Principal:      call.Principal,
			ExecutionClass: "READ",
			Resource:       fmt.Sprintf("repos/%s/issues/%d", args.Repo, args.Number),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("github read failed: %w", err)
	}

	body := response.Body
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

// maxIssueListResults is the server-side ceiling on the projected issue
// list — the schema already bounds `limit` to 50, and the adapter never
// exceeds the schema's own contract.
const maxIssueListResults = 50

// issueListItemBytes bounds one raw issue entry on the provider page.
// GitHub caps an issue body near 64 KiB and each entry also carries the
// author, labels, milestone, and reaction envelope around it, so a page
// holding even a few large bodies can exceed the fixed DIRECT bound while
// the projected result stays small — the raw read bound has to scale with
// the page, not sit at it.
const issueListItemBytes = 96 * 1024

// IssueList lists a repository's issues: GET /repos/{owner}/{repo}/issues
// with the caller's state filter and a bounded page size. The result is
// the same bounded projection as a single get, capped by the caller's
// limit — never the raw provider page.
func (g *GitHubReads) IssueList(ctx context.Context, call CallContext) (json.RawMessage, error) {
	var args struct {
		Repo  string `json:"repo"`
		State string `json:"state"`
		Limit int    `json:"limit"`
	}
	if err := json.Unmarshal(call.Arguments, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	owner, name, ok := strings.Cut(args.Repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return nil, errors.New("repo must be owner/name")
	}
	state := args.State
	if state == "" {
		state = "open"
	}
	if state != "open" && state != "closed" && state != "all" {
		return nil, fmt.Errorf("state must be open, closed, or all — got %q", args.State)
	}
	limit := args.Limit
	if limit == 0 {
		limit = 30
	}
	if limit < 1 || limit > maxIssueListResults {
		return nil, fmt.Errorf("limit must be 1..%d, got %d", maxIssueListResults, args.Limit)
	}

	readBound := int64(limit) * issueListItemBytes
	if readBound < maxDirectReadBytes {
		readBound = maxDirectReadBytes
	}
	if g.transportErr != nil {
		return nil, fmt.Errorf("github transport unavailable: %w", g.transportErr)
	}
	response, err := g.transport.Do(ctx, providertransport.ProviderHTTPRequest{
		Method: http.MethodGet,
		URL: fmt.Sprintf("/repos/%s/%s/issues?state=%s&per_page=%d",
			url.PathEscape(owner), url.PathEscape(name), state, limit),
		Headers: map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		},
		MaxResponseBytes: readBound,
		Context: providertransport.RequestContext{
			Capability:     "github.issue.list",
			Principal:      call.Principal,
			ExecutionClass: "READ",
			Resource:       fmt.Sprintf("repos/%s/issues", args.Repo),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("github read failed: %w", err)
	}

	body := response.Body
	if int64(len(body)) > readBound {
		return nil, fmt.Errorf("github response exceeds %d bytes", readBound)
	}

	switch response.StatusCode {
	case http.StatusOK:
		// Fall through to the projection.
	case http.StatusNotFound:
		return nil, fmt.Errorf("repository %s not found", args.Repo)
	case http.StatusUnauthorized, http.StatusForbidden:
		// Never echo the response body — it can carry credential hints.
		return nil, fmt.Errorf("github denied the read (HTTP %d)", response.StatusCode)
	default:
		return nil, fmt.Errorf("github returned HTTP %d", response.StatusCode)
	}

	var issues []struct {
		Number    int    `json:"number"`
		Title     string `json:"title"`
		State     string `json:"state"`
		HTMLURL   string `json:"html_url"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		// The repository-issues API returns pull requests interleaved with
		// issues; this discriminator is the only thing telling them apart.
		PullRequest *struct{} `json:"pull_request"`
		User        struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &issues); err != nil {
		return nil, fmt.Errorf("github response was not a JSON array: %w", err)
	}

	projected := make([]map[string]any, 0, len(issues))
	for _, issue := range issues {
		// A pull request in this listing is not an issue — the capability
		// enumerates issues, and a PR projected as one would carry a number
		// that collides with the issue namespace it is not part of.
		if issue.PullRequest != nil {
			continue
		}
		projected = append(projected, map[string]any{
			"number":     issue.Number,
			"title":      issue.Title,
			"state":      issue.State,
			"html_url":   issue.HTMLURL,
			"author":     issue.User.Login,
			"created_at": issue.CreatedAt,
			"updated_at": issue.UpdatedAt,
		})
	}
	return json.Marshal(map[string]any{
		"repo":   args.Repo,
		"state":  state,
		"issues": projected,
		"count":  len(projected),
	})
}
