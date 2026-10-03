// Package providertransport is the single trusted outbound network
// boundary for provider calls. Every authenticated provider request in
// the system is built, checked, credentialed, and dispatched here —
// handlers describe WHAT to send (method, path, payload); this package
// owns WHERE it may go and what may never leave the process:
//
//   - destination policy: a validated, canonical provider origin; a
//     request URL must resolve onto it exactly — no userinfo, no
//     fragments, no scheme or host substitution, no arbitrary port;
//   - outbound DLP: the canonical payload is evaluated before any
//     credential touches the request and before any byte is dispatched;
//   - credential attachment: secrets are attached only after
//     destination and DLP checks pass, so an origin rejection or a DLP
//     block can never leak a token;
//   - redirect policy: cross-origin redirects are refused, HTTPS→HTTP
//     is always refused, loops and excess depth fail;
//   - dispatch provenance: httptrace milestones record how far a
//     request actually got, so an ambiguity reported to the durable
//     ledger carries a cause and a milestone rather than a bare
//     "something failed";
//   - audit: every outbound operation emits a non-secret event —
//     provider, origin, endpoint class, request digest, DLP decision,
//     credential profile, redirect count, result, latency.
package providertransport

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ProviderOrigin is the immutable, validated identity of a provider's
// network origin — scheme, host, and optional port in canonical form.
// A Transport pins exactly one origin and refuses any request or
// redirect that would leave it.
type ProviderOrigin struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   string `json:"port,omitempty"`
}

// DefaultPort returns the scheme's well-known port.
func DefaultPort(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// OriginOptions controls which origins ParseOrigin admits. Production
// callers leave AllowPlaintext unset: HTTPS is required. The plaintext
// exception exists for test transports pointed at loopback servers and
// must be refused by the deployment configuration before it can reach
// production — see LoadServiceConfig.
type OriginOptions struct {
	// AllowPlaintext admits http:// origins. Never true in production.
	AllowPlaintext bool
	// AllowLoopbackPlaintext admits http:// only for loopback hosts —
	// the test-server carve-out. Stricter than AllowPlaintext.
	AllowLoopbackPlaintext bool
}

// ParseOrigin validates and canonicalizes a provider origin. It rejects
// userinfo, fragments, query strings, non-root paths, unsupported
// schemes, empty or ambiguous hosts, invalid ports, and non-canonical
// spellings — an origin is a destination identity, not a URL.
func ParseOrigin(raw string, opts OriginOptions) (ProviderOrigin, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q is empty or not canonical whitespace", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q does not parse: %w", raw, err)
	}
	if !u.IsAbs() {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q is not absolute", raw)
	}
	if u.User != nil {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q carries userinfo — credentials in a URL are never trusted destination configuration", raw)
	}
	if u.Fragment != "" || u.ForceQuery || u.RawQuery != "" {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q carries a fragment or query — an origin is scheme://host[:port] only", raw)
	}
	if u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q carries a path — an origin is scheme://host[:port] only", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	// url.Parse lowercases the scheme, so compare against the raw
	// spelling: a non-canonical scheme spelling is a non-canonical
	// origin and refused rather than silently normalized.
	if !strings.HasPrefix(raw, scheme+"://") {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q scheme is not canonical lowercase", raw)
	}
	switch scheme {
	case "https":
	case "http":
		if !opts.AllowPlaintext && !opts.AllowLoopbackPlaintext {
			return ProviderOrigin{}, fmt.Errorf("provider origin %q uses plaintext http — production transports require https", raw)
		}
	default:
		return ProviderOrigin{}, fmt.Errorf("provider origin %q uses unsupported scheme %q", raw, scheme)
	}
	if u.Opaque != "" {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q is an opaque URL, not an origin", raw)
	}

	host := u.Hostname()
	if host == "" {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q has no host", raw)
	}
	if strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\@#? ") {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q has an ambiguous or malformed host", raw)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return ProviderOrigin{}, fmt.Errorf("provider origin %q has no usable host", raw)
	}
	// The parsed host must recompose to the canonical authority: no
	// alternate spellings (hex/octal/integer IPs, embedded dots that
	// reparse differently) may reach the wire under one identity.
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return ProviderOrigin{}, fmt.Errorf("provider origin %q has an invalid or non-canonical port %q", raw, port)
		}
		if port == DefaultPort(scheme) {
			port = ""
		}
	}
	if scheme == "http" && opts.AllowLoopbackPlaintext && !opts.AllowPlaintext {
		if !isLoopbackHost(host) {
			return ProviderOrigin{}, fmt.Errorf("provider origin %q is plaintext http to a non-loopback host — only loopback test origins may use http", raw)
		}
	}
	return ProviderOrigin{Scheme: scheme, Host: host, Port: port}, nil
}

// isLoopbackHost reports whether host is a loopback literal or
// localhost — the only hosts a plaintext test origin may target.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// String returns the canonical origin spelling: scheme://host[:port].
func (o ProviderOrigin) String() string {
	if o.Port == "" {
		return o.Scheme + "://" + o.Host
	}
	return o.Scheme + "://" + o.Host + ":" + o.Port
}

// HostPort returns the authority form for an HTTP request URL.
func (o ProviderOrigin) HostPort() string {
	if o.Port == "" {
		return o.Host
	}
	return net.JoinHostPort(o.Host, o.Port)
}

// SameOrigin reports whether u lands on this origin exactly — same
// scheme, same canonical host, same effective port.
func (o ProviderOrigin) SameOrigin(u *url.URL) bool {
	if u == nil || u.User != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, o.Scheme) {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(o.Host, host) {
		// Hostname() lowercases nothing by itself — compare
		// case-insensitively and confirm the canonical form.
		if strings.ToLower(strings.TrimSuffix(host, ".")) != o.Host {
			return false
		}
	} else {
		return false
	}
	port := u.Port()
	effective := port
	if effective == "" {
		effective = DefaultPort(u.Scheme)
	}
	mine := o.Port
	if mine == "" {
		mine = DefaultPort(o.Scheme)
	}
	return effective == mine
}

// resolveURL turns a request target into the canonical absolute URL
// the transport will dispatch. The target may be an origin-relative
// path (the normal case) or an absolute URL that must equal the
// trusted origin byte-for-byte after canonicalization — anything else
// is a destination-policy refusal.
func (o ProviderOrigin) resolveURL(target string) (*url.URL, error) {
	if target == "" {
		return nil, fmt.Errorf("request target is empty")
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("request target %q does not parse: %w", target, err)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("request target %q carries a fragment — fragments must never reach the wire", target)
	}
	if u.User != nil {
		return nil, fmt.Errorf("request target %q carries userinfo — credentials in a URL are refused", target)
	}
	if u.IsAbs() {
		if !o.SameOrigin(u) {
			return nil, fmt.Errorf("%w: request target %q does not resolve to the trusted origin %s", ErrUntrustedOrigin, target, o)
		}
		return u, nil
	}
	if !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("request target %q is not an absolute path — handlers pass origin-relative paths", target)
	}
	if strings.HasPrefix(target, "//") {
		return nil, fmt.Errorf("request target %q is a scheme-relative URL — host substitution is refused", target)
	}
	resolved := &url.URL{
		Scheme:   o.Scheme,
		Host:     o.HostPort(),
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
	}
	return resolved, nil
}
