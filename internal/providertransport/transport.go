package providertransport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// DispatchMilestone records how far an outbound request actually got.
// The durable-execution contract needs the difference between "the
// provider provably never saw this" and "the request may have been
// executed": a milestone below MilestoneRequestWritten is a no-effect
// proof, anything at or above it is potential post-dispatch ambiguity.
type DispatchMilestone string

const (
	MilestoneNone             DispatchMilestone = "none"              // nothing attempted
	MilestonePolicyRefused    DispatchMilestone = "policy_refused"    // refused before any I/O
	MilestoneConnected        DispatchMilestone = "connected"         // transport up, request not written
	MilestoneRequestWritten   DispatchMilestone = "request_written"   // request bytes left the process
	MilestoneResponseBegan    DispatchMilestone = "response_began"    // first response byte received
	MilestoneResponseComplete DispatchMilestone = "response_complete" // full response consumed
)

// reached reports whether m is at or past threshold — the ordered
// boundary the ambiguity contract keys on.
func (m DispatchMilestone) reached(threshold DispatchMilestone) bool {
	order := map[DispatchMilestone]int{
		MilestoneNone:             0,
		MilestonePolicyRefused:    0,
		MilestoneConnected:        1,
		MilestoneRequestWritten:   2,
		MilestoneResponseBegan:    3,
		MilestoneResponseComplete: 4,
	}
	return order[m] >= order[threshold]
}

// RequestSent reports whether request bytes may have left the process —
// the post-dispatch boundary. False is a no-effect proof: nothing was
// transmitted, so the provider cannot have applied an effect.
func (m DispatchMilestone) RequestSent() bool {
	return m.reached(MilestoneRequestWritten)
}

// AmbiguityCause names why an outbound call's outcome cannot be
// determined. Provider-side causes (the provider or the path to it
// failed) must be distinguishable from local causes (this process
// stopped waiting) so provider-health accounting never has to guess.
type AmbiguityCause string

const (
	CauseProviderTimeout           AmbiguityCause = "PROVIDER_TIMEOUT"
	CauseProviderTransportFailure  AmbiguityCause = "PROVIDER_TRANSPORT_FAILURE"
	CauseProviderConnectionReset   AmbiguityCause = "PROVIDER_CONNECTION_RESET"
	CauseProviderProtocolAmbiguity AmbiguityCause = "PROVIDER_PROTOCOL_AMBIGUITY"
	// CauseProviderUnavailable is a well-formed provider answer that
	// could not confirm the outcome — 5xx, throttle wall, half-open
	// maintenance window. The request provably arrived; the provider
	// failed to produce a definitive answer.
	CauseProviderUnavailable      AmbiguityCause = "PROVIDER_UNAVAILABLE"
	CauseLocalExecutorCancel      AmbiguityCause = "LOCAL_EXECUTOR_CANCEL"
	CauseLocalDeadlinePreDispatch AmbiguityCause = "LOCAL_DEADLINE_BEFORE_DISPATCH"
	CauseDLPPolicyRefusal         AmbiguityCause = "LOCAL_DLP_POLICY_REFUSAL"
	CauseUnknown                  AmbiguityCause = "UNKNOWN_CAUSE"
)

// ProviderSide reports whether the cause is attributable to the
// provider or the path to it — the only causes that may degrade
// provider health. Local causes (executor cancellation, a deadline
// that fired before dispatch, a DLP refusal) say nothing about
// provider health.
func (c AmbiguityCause) ProviderSide() bool {
	switch c {
	case CauseProviderTimeout,
		CauseProviderTransportFailure,
		CauseProviderConnectionReset,
		CauseProviderProtocolAmbiguity,
		CauseProviderUnavailable:
		return true
	default:
		return false
	}
}

// DispatchTrace is the provenance one outbound call produces: how far
// it got, and — when it failed — the classified cause.
type DispatchTrace struct {
	// Milestone is the furthest dispatch milestone reached.
	Milestone DispatchMilestone `json:"milestone"`
	// Cause classifies a failed dispatch; empty on success.
	Cause AmbiguityCause `json:"cause,omitempty"`
	// Redirects counts the same-origin redirects followed.
	Redirects int `json:"redirects,omitempty"`
	// Origin is the canonical destination the request went to.
	Origin string `json:"origin,omitempty"`
}

// RequestContext carries the invocation identity DLP and audit need.
// It never carries credentials — the transport owns those.
type RequestContext struct {
	Principal      string `json:"principal,omitempty"`
	Capability     string `json:"capability,omitempty"`
	ExecutionClass string `json:"execution_class,omitempty"`
	Resource       string `json:"resource,omitempty"`
	AuthorityID    string `json:"authority_id,omitempty"`
	ExecutionID    string `json:"execution_id,omitempty"`
	ExternalToken  string `json:"external_token,omitempty"`
}

// ProviderHTTPRequest is what a handler may specify — the operation
// and the payload. Destination, credentials, TLS, and policy are the
// transport's, not the handler's.
type ProviderHTTPRequest struct {
	Method string
	// URL is an origin-relative path (preferred) or an absolute URL
	// that must resolve to the trusted origin exactly.
	URL string
	// Headers are non-secret request headers. Credential-shaped names
	// (Authorization, Proxy-Authorization, X-Api-Key, and anything in
	// the transport's credential set) are refused — credentials are
	// attached by the transport, never by the handler.
	Headers map[string]string
	// Body is the canonical outbound payload — exactly the bytes the
	// provider receives and the bytes DLP and the request digest cover.
	Body []byte
	// MaxResponseBytes optionally tightens the inbound body bound for
	// this request; zero uses the transport limit.
	MaxResponseBytes int64
	// Context is the invocation identity for DLP and audit.
	Context RequestContext
}

// ProviderHTTPResponse is the bounded provider answer.
type ProviderHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Trace      DispatchTrace
}

// Limits bound what may leave and what may come back.
type Limits struct {
	// MaxRequestBytes bounds the outbound body.
	MaxRequestBytes int64
	// MaxResponseBytes bounds the inbound body.
	MaxResponseBytes int64
	// MaxRedirects bounds same-origin redirect hops.
	MaxRedirects int
	// HeaderTimeout bounds waiting for response headers after write.
	HeaderTimeout time.Duration
}

// DefaultLimits are the production bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxRequestBytes:  1 << 20,
		MaxResponseBytes: 4 << 20,
		MaxRedirects:     3,
		HeaderTimeout:    30 * time.Second,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxRequestBytes <= 0 {
		l.MaxRequestBytes = d.MaxRequestBytes
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = d.MaxResponseBytes
	}
	if l.MaxRedirects <= 0 {
		l.MaxRedirects = d.MaxRedirects
	}
	if l.HeaderTimeout <= 0 {
		l.HeaderTimeout = d.HeaderTimeout
	}
	return l
}

// CredentialAttachment injects the request's authentication. The
// transport calls it exactly once per dispatch, only after destination
// policy and DLP have passed — the credential is never assembled into
// a request that could be refused onward or inspected by anything that
// should not see it.
type CredentialAttachment interface {
	// Attach adds the credential to req.
	Attach(req *http.Request)
	// Profile returns the non-secret identity of the credential for
	// audit (e.g. "bearer" — never the credential value).
	Profile() string
}

// BearerToken attaches Authorization: Bearer <token>.
type BearerToken string

// Attach implements CredentialAttachment.
func (b BearerToken) Attach(req *http.Request) {
	if b != "" {
		req.Header.Set("Authorization", "Bearer "+string(b))
	}
}

// Profile implements CredentialAttachment.
func (b BearerToken) Profile() string {
	if b == "" {
		return "none"
	}
	return "bearer"
}

// AuditEvent is the non-secret record of one outbound operation.
type AuditEvent struct {
	Provider          string            `json:"provider"`
	Origin            string            `json:"origin"`
	Method            string            `json:"method"`
	EndpointClass     string            `json:"endpoint_class"`
	RequestDigest     string            `json:"request_digest"`
	DLPDecision       string            `json:"dlp_decision"`
	DLPPolicyDigest   string            `json:"dlp_policy_digest,omitempty"`
	CredentialProfile string            `json:"credential_profile"`
	RedirectCount     int               `json:"redirect_count"`
	ResultCategory    string            `json:"result_category"`
	DispatchMilestone DispatchMilestone `json:"dispatch_milestone"`
	AmbiguityCause    AmbiguityCause    `json:"ambiguity_cause,omitempty"`
	Capability        string            `json:"capability,omitempty"`
	Principal         string            `json:"principal,omitempty"`
	ExecutionID       string            `json:"execution_id,omitempty"`
	LatencyMillis     int64             `json:"latency_ms"`
}

// AuditSink consumes the non-secret outbound audit stream.
type AuditSink func(AuditEvent)

// Config assembles one provider's trusted transport.
type Config struct {
	// ProviderID is the audit identity ("github").
	ProviderID string
	// Origin is the sole destination this transport may reach.
	Origin ProviderOrigin
	// Credential is attached after policy checks; nil sends unsigned
	// requests (still subject to destination and DLP policy).
	Credential CredentialAttachment
	// DLP evaluates the canonical payload before credential attachment
	// and dispatch. nil means "no DLP" — only acceptable where the
	// deployment configuration has decided that, never by omission in
	// production paths that construct via NewForProvider.
	DLP OutboundDLP
	// Limits bounds request, response, and redirect shape.
	Limits Limits
	// HTTPClient optionally supplies the underlying client (tests use
	// short timeouts); the transport still owns redirect policy.
	HTTPClient *http.Client
	// Timeout bounds a single dispatch including redirects.
	Timeout time.Duration
	// AuditSink receives the non-secret audit stream; nil discards.
	AuditSink AuditSink
}

// Transport is the single authenticated outbound boundary for one
// provider. Handlers build requests; the transport decides if and how
// they reach the wire.
type Transport struct {
	cfg    Config
	origin ProviderOrigin
	client *http.Client
	limits Limits
}

// New validates the configuration and builds the transport.
func New(cfg Config) (*Transport, error) {
	if cfg.ProviderID == "" {
		return nil, fmt.Errorf("providertransport: ProviderID is required")
	}
	if cfg.Origin.Scheme == "" || cfg.Origin.Host == "" {
		return nil, fmt.Errorf("providertransport %s: a validated ProviderOrigin is required", cfg.ProviderID)
	}
	limits := cfg.Limits.withDefaults()
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		}
	}
	if client.Timeout <= 0 && cfg.Timeout > 0 {
		client.Timeout = cfg.Timeout
	}
	// The redirect policy belongs to the transport boundary: the
	// default Go policy forwards sensitive headers within subdomains,
	// which is not the contract. Redirects are handled explicitly in
	// Do — same-origin only, bounded, loop-detected — so the client's
	// own following is disabled entirely.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Transport{cfg: cfg, origin: cfg.Origin, client: client, limits: limits}, nil
}

// Origin returns the trusted destination identity.
func (t *Transport) Origin() ProviderOrigin { return t.origin }

// SetHTTPClient replaces the underlying client. The transport still
// owns redirect policy — the client's CheckRedirect is overwritten.
// Tests use this for short timeouts and injected round-trippers.
func (t *Transport) SetHTTPClient(c *http.Client) {
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	t.client = c
}

// credentialHeaderNames are the header names a handler may never set —
// credential material is the transport's to attach.
var credentialHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"cookie":              true,
	"set-cookie":          true,
}

// Do executes one provider request through the full trusted path:
//
//	destination policy → request limits → DLP → credential attachment
//	→ bounded same-origin redirects → bounded response read → audit.
//
// A non-nil *PolicyError return means the request was provably never
// dispatched — a definite no-effect. A non-nil *DispatchError carries
// the milestone and classified cause for the ambiguity contract.
func (t *Transport) Do(ctx context.Context, req ProviderHTTPRequest) (*ProviderHTTPResponse, error) {
	started := time.Now()
	trace := DispatchTrace{Milestone: MilestoneNone, Origin: t.origin.String()}
	var decision DLPDecision

	respond := func(resp *ProviderHTTPResponse, callErr error, category string, cause AmbiguityCause) (*ProviderHTTPResponse, error) {
		trace.Cause = cause
		if resp != nil {
			resp.Trace = trace
		}
		if callErr != nil {
			var de *DispatchError
			if errors.As(callErr, &de) {
				de.Trace = trace
			}
		}
		t.emit(req, trace, decision, category, started)
		return resp, callErr
	}

	// ── destination policy ───────────────────────────────────────
	target, err := t.origin.resolveURL(req.URL)
	if err != nil {
		trace.Milestone = MilestonePolicyRefused
		return respond(nil, &PolicyError{Reason: err.Error(), Cause: CauseLocalExecutorCancel}, "policy_refusal", CauseLocalExecutorCancel)
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		trace.Milestone = MilestonePolicyRefused
		return respond(nil, &PolicyError{Reason: "http method is required", Cause: CauseLocalExecutorCancel}, "policy_refusal", CauseLocalExecutorCancel)
	}
	if int64(len(req.Body)) > t.limits.MaxRequestBytes {
		trace.Milestone = MilestonePolicyRefused
		return respond(nil, &PolicyError{
			Reason: fmt.Sprintf("request body %d bytes exceeds the %d-byte bound", len(req.Body), t.limits.MaxRequestBytes),
			Cause:  CauseLocalExecutorCancel,
		}, "request_too_large", CauseLocalExecutorCancel)
	}
	for name := range req.Headers {
		if credentialHeaderNames[strings.ToLower(name)] {
			trace.Milestone = MilestonePolicyRefused
			return respond(nil, &PolicyError{
				Reason: fmt.Sprintf("handler may not set credential header %q — credentials are transport-owned", name),
				Cause:  CauseLocalExecutorCancel,
			}, "policy_refusal", CauseLocalExecutorCancel)
		}
	}

	// ── outbound DLP — before any credential exists on the request ──
	body := req.Body
	if t.cfg.DLP != nil {
		decision, err = t.cfg.DLP.Evaluate(ctx, DLPInput{
			Principal:      req.Context.Principal,
			Capability:     req.Context.Capability,
			ExecutionClass: req.Context.ExecutionClass,
			Provider:       t.cfg.ProviderID,
			Origin:         t.origin.String(),
			Resource:       req.Context.Resource,
			AuthorityID:    req.Context.AuthorityID,
			ExecutionID:    req.Context.ExecutionID,
			Method:         method,
			Path:           target.Path,
			Headers:        req.Headers,
			Body:           body,
			ContentType:    req.Headers["Content-Type"],
		})
		if err != nil {
			// A DLP that cannot answer fails closed — never dispatch a
			// payload the policy could not evaluate.
			trace.Milestone = MilestonePolicyRefused
			return respond(nil, &PolicyError{
				Reason: fmt.Sprintf("outbound DLP evaluation failed closed: %v", err),
				Cause:  CauseDLPPolicyRefusal,
			}, "dlp_error", CauseDLPPolicyRefusal)
		}
		switch decision.Kind {
		case DecisionAllow:
		case DecisionTransform:
			body = decision.TransformedBody
			if int64(len(body)) > t.limits.MaxRequestBytes {
				trace.Milestone = MilestonePolicyRefused
				return respond(nil, &PolicyError{
					Reason: fmt.Sprintf("DLP-transformed body %d bytes exceeds the %d-byte bound", len(body), t.limits.MaxRequestBytes),
					Cause:  CauseDLPPolicyRefusal,
				}, "request_too_large", CauseDLPPolicyRefusal)
			}
		case DecisionBlock:
			trace.Milestone = MilestonePolicyRefused
			return respond(nil, &PolicyError{
				Reason: fmt.Sprintf("outbound DLP blocked the request: %s", decision.Reason),
				Cause:  CauseDLPPolicyRefusal,
				DLP:    true,
			}, "dlp_block", CauseDLPPolicyRefusal)
		case DecisionRequireApproval:
			trace.Milestone = MilestonePolicyRefused
			return respond(nil, &PolicyError{
				Reason:         fmt.Sprintf("outbound DLP requires approval: %s", decision.Reason),
				Cause:          CauseDLPPolicyRefusal,
				DLP:            true,
				ApprovalNeeded: true,
			}, "dlp_approval_required", CauseDLPPolicyRefusal)
		default:
			trace.Milestone = MilestonePolicyRefused
			return respond(nil, &PolicyError{
				Reason: fmt.Sprintf("outbound DLP returned an unrecognized decision %d — failing closed", decision.Kind),
				Cause:  CauseDLPPolicyRefusal,
			}, "dlp_error", CauseDLPPolicyRefusal)
		}
	}

	// ── dispatch with bounded same-origin redirects ────────────────
	current := target
	currentBody := body
	currentMethod := method
	for hop := 0; ; hop++ {
		if hop > t.limits.MaxRedirects {
			trace.Milestone = maxMilestone(trace.Milestone, MilestoneResponseBegan)
			return respond(nil, &DispatchError{
				Cause: CauseProviderProtocolAmbiguity,
				Err:   fmt.Errorf("redirect depth exceeds %d hops", t.limits.MaxRedirects),
				Trace: trace,
			}, "redirect_depth", CauseProviderProtocolAmbiguity)
		}
		resp, redirectTo, callErr := t.dispatchOnce(ctx, req, currentMethod, current, currentBody, &trace)
		if callErr != nil {
			return respond(nil, callErr, resultCategoryOfError(callErr), causeOfError(callErr, trace))
		}
		if redirectTo == "" {
			trace.Milestone = MilestoneResponseComplete
			resp.Trace = trace
			return respond(resp, nil, resultCategoryOfStatus(resp.StatusCode), "")
		}
		// A redirect is a provider answer — the request arrived — so
		// following it can never leak credentials cross-origin:
		// same-origin is enforced before the next hop, HTTPS→HTTP is
		// refused, and loops/depth fail above.
		next, err := url.Parse(redirectTo)
		if err != nil {
			return respond(nil, &DispatchError{
				Cause: CauseProviderProtocolAmbiguity,
				Err:   fmt.Errorf("unparseable redirect location %q", redirectTo),
				Trace: trace,
			}, "redirect_protocol", CauseProviderProtocolAmbiguity)
		}
		next = current.ResolveReference(next)
		if !t.origin.SameOrigin(next) {
			return respond(nil, &DispatchError{
				Cause: CauseProviderProtocolAmbiguity,
				Err:   fmt.Errorf("cross-origin redirect to %s refused — credentials never leave the trusted origin", next.Redacted()),
				Trace: trace,
			}, "redirect_refused", CauseProviderProtocolAmbiguity)
		}
		if next.Scheme == "http" && current.Scheme == "https" {
			return respond(nil, &DispatchError{
				Cause: CauseProviderProtocolAmbiguity,
				Err:   errors.New("https→http downgrade redirect refused"),
				Trace: trace,
			}, "redirect_refused", CauseProviderProtocolAmbiguity)
		}
		resp.Body = nil // release the redirect body; it is not the answer
		trace.Redirects++
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
			// 301/302/303 conventionally downgrade POST to GET.
			if currentMethod != http.MethodGet && currentMethod != http.MethodHead {
				currentMethod = http.MethodGet
				currentBody = nil
			}
		case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			// Method and body preserved.
		}
		current = next
	}
}

// dispatchOnce performs one HTTP round trip with milestone tracing.
// When the provider answers with a redirect status it returns the
// redirect target instead of an error — credentials were already sent
// to the trusted origin, and whether to follow is the caller's policy
// decision (bounded by Do above).
func (t *Transport) dispatchOnce(ctx context.Context, req ProviderHTTPRequest, method string, target *url.URL, body []byte, trace *DispatchTrace) (*ProviderHTTPResponse, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(string(body)))
	if err != nil {
		return nil, "", &DispatchError{Cause: CauseLocalExecutorCancel, Err: err, Trace: *trace}
	}
	httpReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(string(body))), nil
	}
	for name, value := range req.Headers {
		httpReq.Header.Set(name, value)
	}
	if req.Context.ExternalToken != "" {
		httpReq.Header.Set("X-Crabex-Operation", req.Context.ExternalToken)
	}

	// Credentials attach only here — after destination and DLP
	// checks, inside the dispatch that actually puts them on the
	// wire. The header is assembled by the transport; no handler ever
	// constructs it.
	if t.cfg.Credential != nil {
		t.cfg.Credential.Attach(httpReq)
	}

	// httptrace milestones: the durable contract's dispatch boundary
	// is "did request bytes leave the process", and only the trace
	// can answer that — an error class alone cannot.
	traceCtx := httptrace.WithClientTrace(httpReq.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			trace.Milestone = maxMilestone(trace.Milestone, MilestoneConnected)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			trace.Milestone = maxMilestone(trace.Milestone, MilestoneRequestWritten)
		},
		GotFirstResponseByte: func() {
			trace.Milestone = maxMilestone(trace.Milestone, MilestoneResponseBegan)
		},
	})
	httpReq = httpReq.WithContext(traceCtx)

	httpResp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, "", &DispatchError{
			Cause: classifyTransportError(err, *trace),
			Err:   err,
			Trace: *trace,
		}
	}
	defer httpResp.Body.Close()
	trace.Milestone = maxMilestone(trace.Milestone, MilestoneResponseBegan)

	if isRedirect(httpResp.StatusCode) {
		loc := httpResp.Header.Get("Location")
		if loc == "" {
			loc = httpResp.Header.Get("location")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, 1<<16))
		return &ProviderHTTPResponse{StatusCode: httpResp.StatusCode, Header: httpResp.Header.Clone()}, loc, nil
	}

	maxResponse := t.limits.MaxResponseBytes
	if req.MaxResponseBytes > 0 && req.MaxResponseBytes < maxResponse {
		maxResponse = req.MaxResponseBytes
	}
	respBody, readErr := io.ReadAll(io.LimitReader(httpResp.Body, maxResponse+1))
	if readErr != nil {
		return nil, "", &DispatchError{
			Cause: CauseProviderConnectionReset,
			Err:   fmt.Errorf("response body read failed: %w", readErr),
			Trace: *trace,
		}
	}
	if int64(len(respBody)) > maxResponse {
		return nil, "", &DispatchError{
			Cause: CauseProviderProtocolAmbiguity,
			Err:   fmt.Errorf("response body exceeds the %d-byte bound", maxResponse),
			Trace: *trace,
		}
	}
	return &ProviderHTTPResponse{
		StatusCode: httpResp.StatusCode,
		Header:     httpResp.Header.Clone(),
		Body:       respBody,
	}, "", nil
}

// isRedirect reports whether the status carries a Location hop.
func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func maxMilestone(a, b DispatchMilestone) DispatchMilestone {
	if b.reached(a) {
		return b
	}
	return a
}

// classifyTransportError maps a client.Do failure to its ambiguity
// cause, using the dispatch milestone for provenance the error class
// alone cannot give.
func classifyTransportError(err error, trace DispatchTrace) AmbiguityCause {
	if errors.Is(err, context.DeadlineExceeded) {
		if !trace.Milestone.RequestSent() {
			return CauseProviderTransportFailure
		}
		return CauseProviderTimeout
	}
	if errors.Is(err, context.Canceled) {
		return CauseLocalExecutorCancel
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return CauseProviderTransportFailure
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return CauseProviderTransportFailure
	}
	// A TLS handshake failure is provably pre-request: the HTTP
	// request does not exist until the handshake completes.
	var certErr *tls.CertificateVerificationError
	var recErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &recErr) {
		return CauseProviderTransportFailure
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return CauseProviderConnectionReset
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return CauseProviderTimeout
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// Unwrap one level — url.Error wraps the real cause.
		if inner := classifyTransportError(urlErr.Err, trace); inner != CauseUnknown {
			return inner
		}
	}
	return CauseUnknown
}

// causeOfError extracts the classified cause from a DispatchError.
func causeOfError(err error, trace DispatchTrace) AmbiguityCause {
	var de *DispatchError
	if errors.As(err, &de) && de.Cause != "" {
		return de.Cause
	}
	return trace.Cause
}

func resultCategoryOfError(err error) string {
	var pe *PolicyError
	if errors.As(err, &pe) {
		if pe.DLP {
			return "dlp_block"
		}
		return "policy_refusal"
	}
	var de *DispatchError
	if errors.As(err, &de) {
		return "dispatch_failure"
	}
	return "error"
}

func resultCategoryOfStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "success"
	case code >= 400 && code < 500:
		return "provider_rejection"
	case code >= 500:
		return "provider_error"
	case code >= 300 && code < 400:
		return "redirect"
	default:
		return "protocol"
	}
}

// endpointClass normalizes a path for audit: numbers become {id} so a
// high-cardinality path space cannot flood the audit stream.
func endpointClass(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "" {
			continue
		}
		numeric := len(p) > 0
		for _, r := range p {
			if r < '0' || r > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// requestDigest is the SHA-256 of the canonical outbound request —
// method, target, and the final (post-transform) body. Audit binds
// this; secret material is never digested into a loggable value.
func requestDigest(method string, target *url.URL, body []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", method, target.Redacted())
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func (t *Transport) emit(req ProviderHTTPRequest, trace DispatchTrace, decision DLPDecision, category string, started time.Time) {
	if t.cfg.AuditSink == nil {
		return
	}
	target, err := t.origin.resolveURL(req.URL)
	path := req.URL
	if err == nil {
		path = target.Path
	}
	profile := "none"
	if t.cfg.Credential != nil {
		profile = t.cfg.Credential.Profile()
	}
	t.cfg.AuditSink(AuditEvent{
		Provider:          t.cfg.ProviderID,
		Origin:            t.origin.String(),
		Method:            req.Method,
		EndpointClass:     endpointClass(path),
		RequestDigest:     requestDigest(req.Method, target, req.Body),
		DLPDecision:       decision.Kind.String(),
		DLPPolicyDigest:   decision.PolicyDigest,
		CredentialProfile: profile,
		RedirectCount:     trace.Redirects,
		ResultCategory:    category,
		DispatchMilestone: trace.Milestone,
		AmbiguityCause:    trace.Cause,
		Capability:        req.Context.Capability,
		Principal:         req.Context.Principal,
		ExecutionID:       req.Context.ExecutionID,
		LatencyMillis:     time.Since(started).Milliseconds(),
	})
}
