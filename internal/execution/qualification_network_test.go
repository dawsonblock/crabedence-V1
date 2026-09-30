package execution

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestQualificationAdapterLoopbackBoundary pins the provider network
// contract: the adapter accepts only the local host and refuses every
// remote, private-LAN, userinfo, and alternate-encoding form.
func TestQualificationAdapterLoopbackBoundary(t *testing.T) {
	accepted := []string{
		"http://127.0.0.1:8080",
		"http://127.9.9.9:1234",
		"http://127.0.0.1",
		"http://[::1]:8080",
		"http://[::1]",
		"http://[::ffff:127.0.0.1]:8080",
		"http://localhost:8080",
		"http://LOCALHOST:8080",
		"http://localhost.:8080",
		"https://127.0.0.1:8443",
	}
	for _, raw := range accepted {
		t.Run("accept/"+raw, func(t *testing.T) {
			adapter, err := NewQualificationAdapter(raw)
			if err != nil {
				t.Fatalf("NewQualificationAdapter(%q) = %v, want a loopback adapter", raw, err)
			}
			if adapter.baseURL == "" {
				t.Fatalf("NewQualificationAdapter(%q) produced an empty base URL", raw)
			}
		})
	}

	refused := []struct {
		name string
		url  string
	}{
		{"external hostname", "http://example.com"},
		{"localhost suffix trick", "http://localhost.example.com"},
		{"private LAN 10/8", "http://10.0.0.1:8080"},
		{"private LAN 192.168/16", "http://192.168.1.10"},
		{"private LAN 172.16/12", "http://172.16.0.1"},
		{"link-local metadata service", "http://169.254.169.254"},
		{"public resolver", "http://8.8.8.8"},
		{"unspecified address", "http://0.0.0.0:8080"},
		{"mapped private address", "http://[::ffff:10.0.0.1]"},
		{"short-form IPv4", "http://127.1"},
		{"decimal IPv4", "http://2130706433"},
		{"hex IPv4", "http://0x7f000001"},
		{"octal IPv4", "http://0177.0.0.1"},
		{"userinfo on loopback", "http://user:pass@127.0.0.1:8080"},
		{"userinfo host trick", "http://127.0.0.1@evil.example.com"},
		{"fragment host trick", "http://evil.example.com#@127.0.0.1"},
		{"percent-encoded loopback host", "http://127%2e0%2e0%2e1:8080"},
		{"percent-encoded remote host", "http://%65%76%69%6c.example.com/"},
		{"non-http scheme", "ftp://127.0.0.1"},
		{"missing host", "http://"},
		{"not a URL", "not-a-url"},
	}
	for _, tc := range refused {
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			if _, err := NewQualificationAdapter(tc.url); err == nil {
				t.Fatalf("NewQualificationAdapter(%q) accepted a non-loopback target", tc.url)
			}
		})
	}
}

// TestQualificationAdapterRefusesRedirects proves a redirect can never
// move a validated loopback request to a different destination: the
// redirect policy refuses every hop, so the request either reaches the
// configured local provider or fails closed.
func TestQualificationAdapterRefusesRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stats", http.StatusFound)
	}))
	defer redirector.Close()

	adapter, err := NewQualificationAdapter(redirector.URL)
	if err != nil {
		t.Fatalf("redirector adapter: %v", err)
	}
	err = adapter.ping(context.Background())
	if err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	if !strings.Contains(err.Error(), "redirect") || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected a redirect-refused error, got %v", err)
	}
}

// TestServeRejectsRemoteQualificationProvider proves the deployment
// boundary fails closed before any network attempt: a remote provider
// URL is a startup error, never a best-effort connection.
func TestServeRejectsRemoteQualificationProvider(t *testing.T) {
	t.Setenv("CRABEDENCE_STORE_BACKEND", "none")
	t.Setenv("CRABEDENCE_QUAL_PROVIDER_URL", "http://example.com:8080")
	err := Serve(context.Background(), ServeOptions{SocketPath: testSocketPath(t)})
	if err == nil || !strings.Contains(err.Error(), "must target the local host") {
		t.Fatalf("expected a loopback-enforcement startup error, got %v", err)
	}
}
