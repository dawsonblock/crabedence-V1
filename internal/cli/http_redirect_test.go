package cli

import (
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"
)

type recordingDefaultRoundTripper struct {
	calls int
}

func (r *recordingDefaultRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, errors.New("deny all")
}

func TestCloneDefaultTransportRejectsUnsupportedDefaults(t *testing.T) {
	recorder := &recordingDefaultRoundTripper{}
	var typedNil *http.Transport
	tests := []struct {
		name      string
		transport http.RoundTripper
	}{
		{name: "recording wrapper", transport: recorder},
		{name: "nil", transport: nil},
		{name: "typed nil transport", transport: typedNil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			http.DefaultTransport = tc.transport

			transport, err := CloneDefaultTransport()
			if transport != nil {
				t.Fatalf("transport=%#v, want nil", transport)
			}
			if err == nil || err.Error() != cloneDefaultTransportError {
				t.Fatalf("error=%v, want %q", err, cloneDefaultTransportError)
			}
		})
	}
	if recorder.calls != 0 {
		t.Fatalf("recording default invoked %d times, want 0", recorder.calls)
	}
}

func TestCloneDefaultTransportPreservesSettingsAndIsolatesMutableState(t *testing.T) {
	originalDefault := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalDefault })

	original := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          37,
		ResponseHeaderTimeout: 19 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ProxyConnectHeader:    http.Header{"X-Trace": {"preserved"}},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
			"custom": nil,
		},
	}
	http.DefaultTransport = original

	cloned, err := CloneDefaultTransport()
	if err != nil {
		t.Fatal(err)
	}
	if cloned == original {
		t.Fatal("clone reused http.DefaultTransport")
	}
	if cloned.Proxy == nil || !cloned.ForceAttemptHTTP2 || cloned.MaxIdleConns != 37 || cloned.ResponseHeaderTimeout != 19*time.Second {
		t.Fatalf("clone lost transport settings: %#v", cloned)
	}
	if cloned.TLSClientConfig == nil || cloned.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("clone lost TLS settings: %#v", cloned.TLSClientConfig)
	}
	if cloned.ProxyConnectHeader.Get("X-Trace") != "preserved" {
		t.Fatalf("clone lost proxy headers: %#v", cloned.ProxyConnectHeader)
	}
	if _, ok := cloned.TLSNextProto["custom"]; !ok {
		t.Fatalf("clone lost TLSNextProto: %#v", cloned.TLSNextProto)
	}

	cloned.TLSClientConfig.MinVersion = tls.VersionTLS13
	cloned.ProxyConnectHeader.Set("X-Trace", "changed")
	delete(cloned.TLSNextProto, "custom")
	if original.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("clone shared TLSClientConfig with default transport")
	}
	if original.ProxyConnectHeader.Get("X-Trace") != "preserved" {
		t.Fatal("clone shared ProxyConnectHeader with default transport")
	}
	if _, ok := original.TLSNextProto["custom"]; !ok {
		t.Fatal("clone shared TLSNextProto with default transport")
	}
}
