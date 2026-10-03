package execution

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/providertransport"
)

// GitHub transport wiring. Every GitHub adapter handler — mutations,
// reads, and resolvers — dispatches through one trusted transport:
// handlers specify method, path, and payload; the transport owns the
// pinned origin, outbound DLP, credential attachment, TLS and redirect
// policy, and dispatch provenance. No GitHub code path constructs an
// Authorization header or chooses a destination.

// insecureTestProviderOriginEnv is the explicit development/test
// exception permitting a plaintext loopback provider origin. It is
// refused in production mode — a production deployment can never be
// coaxed into sending the bearer token over plaintext.
const insecureTestProviderOriginEnv = "CRABBOX_ALLOW_INSECURE_TEST_PROVIDER_ORIGIN"

// githubOriginOptions resolves the origin policy the deployment may
// use. Production admits HTTPS origins only; development additionally
// admits plaintext loopback under the explicit test exception. The
// deployment mode is the validated startup snapshot's, not a re-read
// of the process environment.
func githubOriginOptions(production bool) (providertransport.OriginOptions, error) {
	insecure := strings.EqualFold(strings.TrimSpace(os.Getenv(insecureTestProviderOriginEnv)), "true") ||
		strings.TrimSpace(os.Getenv(insecureTestProviderOriginEnv)) == "1"
	if insecure && production {
		return providertransport.OriginOptions{}, fmt.Errorf(
			"%s permits plaintext provider origins and is unavailable in production mode", insecureTestProviderOriginEnv)
	}
	return providertransport.OriginOptions{AllowLoopbackPlaintext: insecure}, nil
}

// newGitHubTransport builds the github provider transport for a raw
// base URL. The strict production path goes through
// newGitHubTransportForService — this permissive-origin variant exists
// for the handler constructors' test surface (loopback test servers
// and synthetic hosts) and is never how production wiring decides
// where credentials may go.
func newGitHubTransport(baseURL, token string) (*providertransport.Transport, error) {
	origin, err := providertransport.ParseOrigin(baseURL, providertransport.OriginOptions{
		AllowPlaintext: true, // test-only constructor path; production validates strictly
	})
	if err != nil {
		return nil, err
	}
	return providertransport.New(githubTransportConfig(origin, token, providertransport.DefaultLimits(), nil))
}

// newGitHubTransportForService builds the production github transport
// from the validated service configuration: the declared API URL must
// be a canonical HTTPS origin, plaintext needs the explicit test
// exception (refused in production), and the deployment token becomes
// both the transport-owned credential and a DLP-protected value.
func newGitHubTransportForService(cfg *ServiceConfig, audit providertransport.AuditSink) (*providertransport.Transport, error) {
	opts, err := githubOriginOptions(cfg.Production())
	if err != nil {
		return nil, err
	}
	base := cfg.GitHubAPIURL
	if base == "" {
		base = "https://api.github.com"
	}
	origin, err := providertransport.ParseOrigin(base, opts)
	if err != nil {
		return nil, fmt.Errorf("CRABBOX_GITHUB_API_URL: %w", err)
	}
	return providertransport.New(githubTransportConfig(origin, cfg.GitHubToken, providertransport.DefaultLimits(), audit))
}

// githubTransportConfig assembles one transport: pinned origin,
// bearer credential attached only post-policy, the outbound DLP
// chain, and the production dispatch bounds.
func githubTransportConfig(origin providertransport.ProviderOrigin, token string, limits providertransport.Limits, audit providertransport.AuditSink) providertransport.Config {
	return providertransport.Config{
		ProviderID: "github",
		Origin:     origin,
		Credential: providertransport.BearerToken(token),
		DLP:        githubOutboundDLP(token),
		Limits:     limits,
		Timeout:    60 * time.Second,
		AuditSink:  audit,
	}
}

// githubOutboundDLP is the enforced order for every github payload:
// the registered runtime secrets first (the strongest check — actual
// values must never leave), then credential-shape detection, then the
// capability field policy that fails unknown mutation capabilities
// closed.
func githubOutboundDLP(token string) providertransport.OutboundDLP {
	protected := providertransport.NewProtectedValues()
	protected.Protect("github provider credential", token)
	return providertransport.ChainDLP{
		protected,
		providertransport.SecretPatterns{},
		&providertransport.CapabilityFieldPolicy{
			Policies:                githubFieldPolicies,
			RequirePolicyForClasses: map[string]bool{"MUTATION": true, "CRITICAL": true},
		},
	}
}

// githubFieldPolicies name the exact canonical payload fields each
// github capability may emit. A mutation capability without a declared
// policy fails closed rather than shipping an unevaluated projection.
var githubFieldPolicies = map[string]providertransport.FieldPolicy{
	"github.issue.create":  {AllowedFields: fieldSet("title", "body")},
	"github.issue.comment": {AllowedFields: fieldSet("body")},
	"github.issue.close":   {AllowedFields: fieldSet("state", "state_reason")},
	"github.issue.update":  {AllowedFields: fieldSet("title", "body", "labels", "assignees")},
	"github.pr.create":     {AllowedFields: fieldSet("title", "head", "base", "body", "draft")},
	"github.pr.merge":      {AllowedFields: fieldSet("merge_method")},
	// Reads and resolvers dispatch GETs with no body; the policy
	// admits them explicitly so a malformed adapter cannot smuggle a
	// payload out on a read-shaped capability.
	"github.issue.get":  {AllowedFields: fieldSet()},
	"github.issue.list": {AllowedFields: fieldSet()},
}

func fieldSet(fields ...string) map[string]bool {
	set := make(map[string]bool, len(fields))
	for _, f := range fields {
		set[f] = true
	}
	return set
}

// providerAuditSink emits the outbound audit stream as a non-secret
// structured log line — the record exists by construction contains no
// credential material, only identities, digests, and outcomes.
func providerAuditSink(ev providertransport.AuditEvent) {
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	log.Printf("provider-transport %s", line)
}

// githubRequestContext assembles the non-secret invocation identity
// DLP and audit consume. payloadCapability is the adapter's own
// capability identity — the outbound field policy binds to the
// payload this handler constructs, which is invariant under whatever
// capability alias invoked it. The authority reference itself is
// never passed — it is a credential, not context.
func githubRequestContext(req Request, payloadCapability string, desc capability.ResolvedDescriptor, resource, externalToken string) providertransport.RequestContext {
	return providertransport.RequestContext{
		Principal:      req.Authority.Principal,
		Capability:     payloadCapability,
		ExecutionClass: string(desc.ExecutionClass),
		Resource:       resource,
		ExternalToken:  externalToken,
	}
}

// githubFailure translates a transport refusal into the handler's
// response contract. A PolicyError or a dispatch failure whose trace
// proves no request bytes left is a definite no-effect; anything at or
// past the request-written milestone stays ambiguous — the durable
// executor converges it to UNKNOWN and reconciliation decides.
// The dispatch trace rides the response so the ambiguity is recorded
// with its provenance rather than as a bare UNKNOWN.
func githubFailure(err error) Response {
	resp := Response{
		Status:    StatusFailed,
		Execution: &ExecutionMeta{Provider: "github"},
	}
	if providertransport.NoEffectProof(err) {
		resp.DefinitiveFailure = true
		resp.FailureCode = string(capability.FailureExecutionFailed)
		resp.Error = fmt.Sprintf("github request refused before dispatch: %v", err)
	} else {
		resp.FailureCode = string(capability.FailureExecutionFailed)
		resp.Error = fmt.Sprintf("github request failed after dispatch: %v", err)
	}
	trace := providertransport.TraceOf(err)
	resp.Dispatch = &DispatchProvenance{
		Milestone: string(trace.Milestone),
		Cause:     string(trace.Cause),
	}
	return resp
}

// githubProvenance converts a completed dispatch's transport trace
// into the durable provenance persisted with the observation. The
// milestone records how far the request observably got (normally
// response_complete); the cause classifies a provider answer that
// could not confirm the outcome — a 5xx is provider-side ambiguity,
// so provider-health accounting attributes it correctly rather than
// inferring causality from the bare UNKNOWN.
func githubProvenance(trace providertransport.DispatchTrace, statusCode int) *DispatchProvenance {
	cause := trace.Cause
	if cause == "" && statusCode >= 500 {
		cause = providertransport.CauseProviderUnavailable
	}
	return &DispatchProvenance{
		Milestone: string(trace.Milestone),
		Cause:     string(cause),
	}
}
