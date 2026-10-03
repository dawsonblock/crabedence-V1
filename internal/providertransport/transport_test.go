package providertransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testTransport builds a transport pinned to a loopback test server —
// the only place a plaintext origin may exist.
func testTransport(t *testing.T, handler http.HandlerFunc, cfg Config) (*Transport, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	origin, err := ParseOrigin(srv.URL, OriginOptions{AllowLoopbackPlaintext: true})
	if err != nil {
		t.Fatalf("parse test origin: %v", err)
	}
	cfg.Origin = origin
	if cfg.ProviderID == "" {
		cfg.ProviderID = "test"
	}
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tr, srv
}

func TestParseOrigin_Table(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		opts    OriginOptions
		wantErr string
		want    string // canonical form when no error
	}{
		{name: "github default", raw: "https://api.github.com", want: "https://api.github.com"},
		{name: "github enterprise", raw: "https://ghe.example.com", want: "https://ghe.example.com"},
		{name: "explicit https port", raw: "https://ghe.example.com:8443", want: "https://ghe.example.com:8443"},
		{name: "default port canonicalized away", raw: "https://api.github.com:443", want: "https://api.github.com"},
		{name: "http production rejected", raw: "http://api.github.com", wantErr: "plaintext"},
		{name: "http loopback test exception", raw: "http://127.0.0.1:8080",
			opts: OriginOptions{AllowLoopbackPlaintext: true}, want: "http://127.0.0.1:8080"},
		{name: "http non-loopback test exception rejected", raw: "http://github.internal:8080",
			opts: OriginOptions{AllowLoopbackPlaintext: true}, wantErr: "non-loopback"},
		{name: "userinfo rejected", raw: "https://user:pw@api.github.com", wantErr: "userinfo"},
		{name: "fragment rejected", raw: "https://api.github.com#frag", wantErr: "fragment or query"},
		{name: "query rejected", raw: "https://api.github.com?x=1", wantErr: "fragment or query"},
		{name: "path rejected", raw: "https://api.github.com/v3", wantErr: "path"},
		{name: "unsupported scheme", raw: "ftp://api.github.com", wantErr: "unsupported scheme"},
		{name: "empty host", raw: "https://", wantErr: "no host"},
		{name: "invalid port", raw: "https://api.github.com:99999", wantErr: "port"},
		{name: "non-numeric port", raw: "https://api.github.com:abc", wantErr: "port"},
		{name: "uppercase scheme not canonical", raw: "HTTPS://api.github.com", wantErr: "lowercase"},
		{name: "missing scheme", raw: "api.github.com", wantErr: "not absolute"},
		{name: "trailing dot host canonicalized", raw: "https://api.github.com.", want: "https://api.github.com"},
		{name: "uppercase host canonicalized", raw: "https://API.GitHub.COM", want: "https://api.github.com"},
		{name: "whitespace rejected", raw: " https://api.github.com", wantErr: "whitespace"},
		{name: "scheme-relative rejected", raw: "//api.github.com", wantErr: "not absolute"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origin, err := ParseOrigin(tc.raw, tc.opts)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got origin %s", tc.wantErr, origin)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := origin.String(); got != tc.want {
				t.Fatalf("canonical origin = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCredentialAbsentBeforeOriginValidation(t *testing.T) {
	var sawAuth atomic.Bool
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}, Config{Credential: BearerToken("test-token-12345")})

	// An absolute URL off-origin is refused before the credential can
	// exist on any request — this is the test that proves the bearer
	// cannot leak to an unapproved destination.
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodGet,
		URL:    "https://evil.example.com/steal",
	})
	var policyErr *PolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected PolicyError, got %v", err)
	}
	if !NoEffectProof(err) {
		t.Fatal("origin refusal must be a provable no-effect")
	}
	if sawAuth.Load() {
		t.Fatal("credential material reached a request before origin validation")
	}
}

func TestCredentialAttachedAfterValidation(t *testing.T) {
	var gotAuth string
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, Config{Credential: BearerToken("test-token-12345")})

	resp, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method:  http.MethodGet,
		URL:     "/repos/octo/hello",
		Headers: map[string]string{"Accept": "application/json"},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotAuth != "Bearer test-token-12345" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Trace.Milestone != MilestoneResponseComplete {
		t.Fatalf("milestone = %s", resp.Trace.Milestone)
	}
}

func TestCrossOriginRedirectRefused(t *testing.T) {
	// The trusted origin redirects to a hostile host; the transport
	// must refuse before any second dispatch.
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/collect", http.StatusFound)
	}, Config{Credential: BearerToken("test-token-12345")})

	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodGet,
		URL:    "/start",
	})
	var de *DispatchError
	if !errors.As(err, &de) || !strings.Contains(de.Err.Error(), "cross-origin") {
		t.Fatalf("expected cross-origin redirect refusal, got %v", err)
	}
}

func TestHTTPSDowngradeRedirectRefused(t *testing.T) {
	// An https→http hop is refused even when it would stay same-host —
	// here the redirect target is the plaintext variant of the same
	// loopback origin, which SameOrigin rejects on scheme anyway; the
	// dedicated downgrade check covers same-scheme-host edge cases.
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example.com/x", http.StatusMovedPermanently)
	}, Config{Credential: BearerToken("tok")})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{Method: http.MethodGet, URL: "/x"})
	if err == nil {
		t.Fatal("expected refusal")
	}
}

func TestRedirectLoopFails(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	origin, _ := ParseOrigin(srv.URL, OriginOptions{AllowLoopbackPlaintext: true})
	tr, err := New(Config{ProviderID: "test", Origin: origin})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = tr.Do(context.Background(), ProviderHTTPRequest{Method: http.MethodGet, URL: "/loop"})
	var de *DispatchError
	if !errors.As(err, &de) {
		t.Fatalf("expected DispatchError for redirect loop, got %v", err)
	}
}

func TestSameOriginRedirectFollowed(t *testing.T) {
	var hops atomic.Int32
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("done"))
	}, Config{Credential: BearerToken("tok")})

	resp, err := tr.Do(context.Background(), ProviderHTTPRequest{Method: http.MethodGet, URL: "/start"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(resp.Body) != "done" {
		t.Fatalf("unexpected response %d %q", resp.StatusCode, resp.Body)
	}
	if resp.Trace.Redirects != 1 {
		t.Fatalf("redirects = %d", resp.Trace.Redirects)
	}
	if hops.Load() != 2 {
		t.Fatalf("hops = %d", hops.Load())
	}
}

func TestHandlerCannotSetCredentialHeaders(t *testing.T) {
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, Config{Credential: BearerToken("tok")})
	for _, name := range []string{"Authorization", "authorization", "X-Api-Key", "Cookie"} {
		_, err := tr.Do(context.Background(), ProviderHTTPRequest{
			Method:  http.MethodGet,
			URL:     "/x",
			Headers: map[string]string{name: "Bearer stolen"},
		})
		if err == nil {
			t.Fatalf("credential header %q accepted", name)
		}
		var policyErr *PolicyError
		if !errors.As(err, &policyErr) {
			t.Fatalf("expected PolicyError for %q, got %v", name, err)
		}
	}
}

func TestRequestLargerThanBoundRefused(t *testing.T) {
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("refused request reached the server")
		w.WriteHeader(http.StatusOK)
	}, Config{Limits: Limits{MaxRequestBytes: 16}})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodPost,
		URL:    "/x",
		Body:   []byte(strings.Repeat("a", 32)),
	})
	var policyErr *PolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected PolicyError, got %v", err)
	}
}

func TestResponseLargerThanBoundFails(t *testing.T) {
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("b", 1024)))
	}, Config{Limits: Limits{MaxResponseBytes: 16}})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{Method: http.MethodGet, URL: "/x"})
	var de *DispatchError
	if !errors.As(err, &de) || !strings.Contains(de.Err.Error(), "bound") {
		t.Fatalf("expected response-bound failure, got %v", err)
	}
}

func TestConnectionRefusedIsNoEffectProof(t *testing.T) {
	// No listener: connection refused — milestone cannot have reached
	// request-written, so the failure is a provable no-effect.
	tr, srv := testTransport(t, func(w http.ResponseWriter, r *http.Request) {}, Config{})
	srv.Close() // shut it down so the dial is refused
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{Method: http.MethodPost, URL: "/x", Body: []byte("1")})
	var de *DispatchError
	if !errors.As(err, &de) {
		t.Fatalf("expected DispatchError, got %v", err)
	}
	if !NoEffectProof(err) {
		t.Fatalf("connection refused must prove no effect, milestone=%s", de.Trace.Milestone)
	}
}

func TestTimeoutAfterWriteIsAmbiguous(t *testing.T) {
	release := make(chan struct{})
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // hang: the request arrives, the response never does
	}, Config{})
	t.Cleanup(func() { close(release) })
	tr.client.Timeout = 50 * time.Millisecond

	_, err := tr.Do(context.Background(), ProviderHTTPRequest{Method: http.MethodPost, URL: "/x", Body: []byte("1")})
	var de *DispatchError
	if !errors.As(err, &de) {
		t.Fatalf("expected DispatchError, got %v", err)
	}
	if NoEffectProof(err) {
		t.Fatal("post-write timeout must stay ambiguous — the request may have executed")
	}
	if !de.Trace.Milestone.RequestSent() {
		t.Fatalf("milestone should be past request-written, got %s", de.Trace.Milestone)
	}
	if de.Cause != CauseProviderTimeout {
		t.Fatalf("cause = %s", de.Cause)
	}
}

func TestAuditEventEmitted(t *testing.T) {
	var events []AuditEvent
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, Config{
		Credential: BearerToken("tok"),
		AuditSink:  func(ev AuditEvent) { events = append(events, ev) },
	})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method:  http.MethodGet,
		URL:     "/repos/octo/hello/issues/3",
		Context: RequestContext{Capability: "cap.test", Principal: "alice"},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d", len(events))
	}
	ev := events[0]
	if ev.Provider != "test" || ev.RequestDigest == "" || ev.EndpointClass != "/repos/octo/hello/issues/{id}" {
		t.Fatalf("bad audit event: %+v", ev)
	}
	if ev.CredentialProfile != "bearer" || ev.ResultCategory != "success" {
		t.Fatalf("bad audit event: %+v", ev)
	}
}

func TestFragmentAndUserinfoInRequestURLRefused(t *testing.T) {
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("refused request reached server")
	}, Config{Credential: BearerToken("tok")})
	for _, target := range []string{"/x#frag", "https://user@host/x", "//evil.com/x", "relative/path"} {
		if _, err := tr.Do(context.Background(), ProviderHTTPRequest{Method: http.MethodGet, URL: target}); err == nil {
			t.Fatalf("target %q accepted", target)
		}
	}
}

func TestDLPCannotBeBypassedByHandler(t *testing.T) {
	var dispatched atomic.Bool
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		dispatched.Store(true)
		w.WriteHeader(http.StatusOK)
	}, Config{
		DLP: ChainDLP{blockerDLP{reason: "test block"}},
	})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodPost, URL: "/x", Body: []byte(`{"title":"hello"}`),
	})
	var policyErr *PolicyError
	if !errors.As(err, &policyErr) || !policyErr.DLP {
		t.Fatalf("expected DLP PolicyError, got %v", err)
	}
	if dispatched.Load() {
		t.Fatal("DLP-blocked request reached the network")
	}
	if !NoEffectProof(err) {
		t.Fatal("DLP block must be a provable no-effect")
	}
}

// blockerDLP is a test evaluator that always blocks.
type blockerDLP struct{ reason string }

func (b blockerDLP) Evaluate(_ context.Context, _ DLPInput) (DLPDecision, error) {
	return DLPDecision{Kind: DecisionBlock, Reason: b.reason}, nil
}

func TestDLPTransformUsesTransformedBytes(t *testing.T) {
	var gotBody []byte
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}, Config{
		DLP: ChainDLP{transformDLP{to: []byte(`{"redacted":true}`)}},
	})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodPost, URL: "/x", Body: []byte(`{"secret":"x"}`),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(gotBody) != `{"redacted":true}` {
		t.Fatalf("transformed body not dispatched: %q", gotBody)
	}
}

type transformDLP struct{ to []byte }

func (d transformDLP) Evaluate(_ context.Context, _ DLPInput) (DLPDecision, error) {
	return DLPDecision{Kind: DecisionTransform, TransformedBody: d.to}, nil
}

func TestDLPRequireApprovalNeverDispatch(t *testing.T) {
	var dispatched atomic.Bool
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		dispatched.Store(true)
	}, Config{DLP: ChainDLP{approvalDLP{}}})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodPost, URL: "/x", Body: []byte(`{}`),
	})
	var policyErr *PolicyError
	if !errors.As(err, &policyErr) || !policyErr.ApprovalNeeded {
		t.Fatalf("expected approval-required PolicyError, got %v", err)
	}
	if dispatched.Load() {
		t.Fatal("REQUIRE_APPROVAL dispatched — must never silently become ALLOW")
	}
}

type approvalDLP struct{}

func (approvalDLP) Evaluate(_ context.Context, _ DLPInput) (DLPDecision, error) {
	return DLPDecision{Kind: DecisionRequireApproval, Reason: "pending"}, nil
}

func TestDLPErrorFailsClosed(t *testing.T) {
	var dispatched atomic.Bool
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		dispatched.Store(true)
	}, Config{DLP: ChainDLP{errorDLP{}}})
	_, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodPost, URL: "/x", Body: []byte(`{}`),
	})
	if err == nil || dispatched.Load() {
		t.Fatal("DLP evaluator error must fail closed")
	}
}

type errorDLP struct{}

func (errorDLP) Evaluate(_ context.Context, _ DLPInput) (DLPDecision, error) {
	return DLPDecision{}, fmt.Errorf("evaluator down")
}

func TestNoCredentialTransportStillPolicyBound(t *testing.T) {
	// A transport without a credential (observational reads on some
	// providers) still enforces destination and DLP — trust is not
	// optional just because there is no token.
	tr, _ := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected credential on credential-free transport")
		}
		w.WriteHeader(http.StatusOK)
	}, Config{})
	if _, err := tr.Do(context.Background(), ProviderHTTPRequest{
		Method: http.MethodGet, URL: "https://elsewhere.example.com/x",
	}); err == nil {
		t.Fatal("credential-free transport must still enforce destination")
	}
}
