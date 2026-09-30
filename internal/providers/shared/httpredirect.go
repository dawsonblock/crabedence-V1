package shared

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// SameOrigin reports whether two URLs share scheme, host, and effective port.
func SameOrigin(a, b *url.URL) bool {
	return a != nil && b != nil &&
		strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// SecureHTTPClientOption customizes SecureHTTPClient for a provider whose
// redirect policy needs more than the defaults. Every option exists because a
// site that implemented this itself needed it; see
// docs/plan/nemo-runtime-transfer.md for the classification that established
// the two below.
type SecureHTTPClientOption func(*secureHTTPClientConfig)

type secureHTTPClientConfig struct {
	limitError         func() error
	hostsAreSameOrigin func(a, b *url.URL) bool
}

// WithRedirectLimitError replaces the fixed 10-redirect message with the
// provider's own error. A provider that matches on a sentinel
// (`errors.Is(err, errProviderRedirectLimit)`) needs this: the default message
// is a fresh errors.New, so the match would never hold and the check would
// silently stop working.
func WithRedirectLimitError(err error) SecureHTTPClientOption {
	return func(config *secureHTTPClientConfig) {
		config.limitError = func() error { return err }
	}
}

// WithHostComparator replaces the origin comparison. A provider whose host
// canonicalization is stricter than SameOrigin — stripping IPv6 zone
// identifiers, for instance — needs this: the default would compare hosts more
// loosely than the check it replaces, which is the one comparison standing
// between a redirect and a destination the provider did not authorize.
func WithHostComparator(fn func(a, b *url.URL) bool) SecureHTTPClientOption {
	return func(config *secureHTTPClientConfig) { config.hostsAreSameOrigin = fn }
}

// SecureHTTPClient returns a copy of source whose CheckRedirect refuses
// redirects leaving the trusted origin, preserves source's CheckRedirect, and
// applies net/http's default 10-redirect cap when source has no redirect hook.
// newError builds the provider's refusal error for a rejected destination.
func SecureHTTPClient(
	source *http.Client,
	trusted *url.URL,
	newError func(dest *url.URL) error,
	options ...SecureHTTPClientOption,
) *http.Client {
	config := secureHTTPClientConfig{
		limitError:         func() error { return errors.New("stopped after 10 redirects") },
		hostsAreSameOrigin: SameOrigin,
	}
	for _, option := range options {
		option(&config)
	}

	client := *source
	originalCheckRedirect := source.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !config.hostsAreSameOrigin(trusted, req.URL) {
			return newError(req.URL)
		}
		if originalCheckRedirect != nil {
			return originalCheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return config.limitError()
		}
		return nil
	}
	return &client
}
