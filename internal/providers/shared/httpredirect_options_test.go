package shared

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return parsed
}

// The defaults must not change: existing callers rely on the fixed cap message
// and on SameOrigin.
func TestSecureHTTPClientKeepsItsDefaults(t *testing.T) {
	trusted := mustParse(t, "https://api.example.com/v1")
	client := SecureHTTPClient(&http.Client{}, trusted, func(dest *url.URL) error {
		return fmt.Errorf("refused %s", dest)
	})

	via := make([]*http.Request, 10)
	err := client.CheckRedirect(&http.Request{URL: mustParse(t, "https://api.example.com/v1/next")}, via)
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("the default cap message must be unchanged, got %v", err)
	}

	crossOrigin := &http.Request{URL: mustParse(t, "https://evil.example.net/v1")}
	if err := client.CheckRedirect(crossOrigin, nil); err == nil {
		t.Fatal("a cross-origin redirect must be refused by default")
	}
}

// A provider that matches on a sentinel needs its own error to come back, not
// the default message: errors.Is against the sentinel would never hold.
func TestWithRedirectLimitErrorPreservesASentinel(t *testing.T) {
	sentinel := errors.New("provider redirect stopped after 10 redirects")
	client := SecureHTTPClient(
		&http.Client{},
		mustParse(t, "https://api.example.com/v1"),
		func(dest *url.URL) error { return fmt.Errorf("refused %s", dest) },
		WithRedirectLimitError(sentinel),
	)

	via := make([]*http.Request, 10)
	err := client.CheckRedirect(&http.Request{URL: mustParse(t, "https://api.example.com/v1/next")}, via)
	if !errors.Is(err, sentinel) {
		t.Fatalf("the provider sentinel must survive, got %v", err)
	}
}

// A provider whose host comparison is stricter must keep it: the default would
// compare hosts more loosely than the check being replaced.
func TestWithHostComparatorReplacesTheComparison(t *testing.T) {
	// A comparator that refuses everything, so a redirect the default would
	// allow is visibly refused by the provider's own rule.
	refuseAll := func(a, b *url.URL) bool { return false }
	client := SecureHTTPClient(
		&http.Client{},
		mustParse(t, "https://api.example.com/v1"),
		func(dest *url.URL) error { return fmt.Errorf("refused %s", dest) },
		WithHostComparator(refuseAll),
	)

	sameOrigin := &http.Request{URL: mustParse(t, "https://api.example.com/v1/next")}
	if err := client.CheckRedirect(sameOrigin, nil); err == nil {
		t.Fatal("the provider's comparator must decide, not SameOrigin")
	}
}

// The existing hook must still win over the cap, with an option in play.
func TestOptionsPreserveTheOriginalRedirectHook(t *testing.T) {
	hooked := 0
	source := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			hooked++
			return nil
		},
	}
	client := SecureHTTPClient(
		source,
		mustParse(t, "https://api.example.com/v1"),
		func(dest *url.URL) error { return fmt.Errorf("refused %s", dest) },
		WithRedirectLimitError(errors.New("unused")),
	)

	via := make([]*http.Request, 12)
	if err := client.CheckRedirect(&http.Request{URL: mustParse(t, "https://api.example.com/v1/next")}, via); err != nil {
		t.Fatalf("the original hook returns nil, so the redirect stands: %v", err)
	}
	if hooked != 1 {
		t.Fatalf("the original hook must be consulted, got %d calls", hooked)
	}
}

// The source client must not be mutated: the helper returns a copy.
func TestSecureHTTPClientDoesNotMutateItsSource(t *testing.T) {
	source := &http.Client{}
	SecureHTTPClient(source, mustParse(t, "https://api.example.com/v1"), func(*url.URL) error { return nil })
	if source.CheckRedirect != nil {
		t.Fatal("the source client's CheckRedirect must be untouched")
	}
}
