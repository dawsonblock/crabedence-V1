package execution

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
)

func TestParsePeerPrincipalMap(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    PeerPrincipalMap
		wantErr string
	}{
		{name: "unset disables", raw: "", want: nil},
		{name: "whitespace disables", raw: "  ", want: nil},
		{name: "single mapping", raw: "501:alice@example.com", want: PeerPrincipalMap{501: "alice@example.com"}},
		{name: "wildcard", raw: "0:*", want: PeerPrincipalMap{0: "*"}},
		{name: "multiple", raw: "501:alice@example.com, 0:* ,502:bob@example.com", want: PeerPrincipalMap{501: "alice@example.com", 0: "*", 502: "bob@example.com"}},
		{name: "missing colon", raw: "501", wantErr: "malformed entry"},
		{name: "empty principal", raw: "501:", wantErr: "malformed entry"},
		{name: "non-numeric uid", raw: "abc:alice", wantErr: "malformed uid"},
		{name: "negative uid", raw: "-1:alice", wantErr: "malformed uid"},
		{name: "uid overflow", raw: "99999999999:alice", wantErr: "malformed uid"},
		{name: "duplicate uid", raw: "501:alice,501:bob", wantErr: "duplicate uid"},
		{name: "only separators", raw: ",,,", wantErr: "peer principal map is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePeerPrincipalMap(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d entries, got %v", len(tt.want), got)
			}
			for uid, principal := range tt.want {
				if got[uid] != principal {
					t.Fatalf("uid %d: expected %q, got %q", uid, principal, got[uid])
				}
			}
		})
	}
}

func TestPeerPrincipalMapAuthorize(t *testing.T) {
	m := PeerPrincipalMap{
		501: "alice@example.com",
		0:   PeerWildcardPrincipal,
	}
	tests := []struct {
		name      string
		uid       uint32
		claimed   string
		want      string
		wantAllow bool
	}{
		{name: "mapped uid matching claim", uid: 501, claimed: "alice@example.com", want: "alice@example.com", wantAllow: true},
		{name: "mapped uid empty claim is assigned", uid: 501, claimed: "", want: "alice@example.com", wantAllow: true},
		{name: "mapped uid mismatched claim denied", uid: 501, claimed: "mallory@example.com", wantAllow: false},
		{name: "unmapped uid denied", uid: 999, claimed: "alice@example.com", wantAllow: false},
		{name: "unmapped uid empty claim denied", uid: 999, claimed: "", wantAllow: false},
		{name: "wildcard uid keeps claim", uid: 0, claimed: "carol@example.com", want: "carol@example.com", wantAllow: true},
		{name: "wildcard uid empty claim denied", uid: 0, claimed: "", wantAllow: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := m.Authorize(tt.uid, tt.claimed)
			if ok != tt.wantAllow {
				t.Fatalf("expected allow=%v, got %v (%q)", tt.wantAllow, ok, got)
			}
			if ok && got != tt.want {
				t.Fatalf("expected principal %q, got %q", tt.want, got)
			}
		})
	}
}

func TestPeerAuthPolicyRequiresAuthenticationInProduction(t *testing.T) {
	// Development keeps the optional strict mode: unset stays the
	// bearer model, and a configured map is accepted.
	if err := validatePeerAuthPolicy(false, nil, nil); err != nil {
		t.Fatalf("development must not require peer authentication: %v", err)
	}
	if err := validatePeerAuthPolicy(false, PeerPrincipalMap{501: "alice@example.com"}, nil); err != nil {
		t.Fatalf("a configured map must satisfy the policy: %v", err)
	}

	// Production must authenticate the principal, not merely receive it.
	err := validatePeerAuthPolicy(true, nil, nil)
	if err == nil {
		t.Fatal("production without a peer map must fail closed")
	}
	if !strings.Contains(err.Error(), "CRABEDENCE_PEER_PRINCIPALS") {
		t.Fatalf("the refusal must name the configuration: %v", err)
	}
	if err := validatePeerAuthPolicy(true, PeerPrincipalMap{501: "alice@example.com"}, nil); err != nil {
		t.Fatalf("production with a declared map must satisfy the policy: %v", err)
	}
}

func TestPeerAuthPolicyWildcardRequiresTrustedProxy(t *testing.T) {
	wildcard := PeerPrincipalMap{0: PeerWildcardPrincipal, 501: "alice@example.com"}

	// Production: a wildcard peer may claim any principal — that
	// delegation is a separate privilege, declared by
	// CRABEDENCE_TRUSTED_PROXY_UIDS, not implied by the map itself.
	err := validatePeerAuthPolicy(true, wildcard, nil)
	if err == nil {
		t.Fatal("a production wildcard without a trusted-proxy declaration must fail closed")
	}
	if !strings.Contains(err.Error(), "CRABEDENCE_TRUSTED_PROXY_UIDS") {
		t.Fatalf("the refusal must name the missing declaration: %v", err)
	}
	if err := validatePeerAuthPolicy(true, wildcard, map[uint32]struct{}{0: {}}); err != nil {
		t.Fatalf("a declared trusted proxy must satisfy the policy: %v", err)
	}
	// A wildcard a declared list does not cover is refused in any
	// mode — a declared allowlist is authoritative.
	err = validatePeerAuthPolicy(false, wildcard, map[uint32]struct{}{502: {}})
	if err == nil {
		t.Fatal("a wildcard outside the declared trusted set must fail")
	}
	if !strings.Contains(err.Error(), "uid 0") {
		t.Fatalf("the refusal must name the uncovered uid: %v", err)
	}
	// Outside production with no declared list the wildcard stays the
	// documented development convenience.
	if err := validatePeerAuthPolicy(false, wildcard, nil); err != nil {
		t.Fatalf("development with no trusted list keeps the wildcard convenience: %v", err)
	}
	// Exact mappings are never gated — the privilege under test is
	// claiming arbitrary principals, not authenticating as one.
	if err := validatePeerAuthPolicy(true, PeerPrincipalMap{501: "alice@example.com"}, map[uint32]struct{}{0: {}}); err != nil {
		t.Fatalf("an exact-only map needs no trusted-proxy declaration: %v", err)
	}
}

func TestParseTrustedProxyUIDs(t *testing.T) {
	if got, err := ParseTrustedProxyUIDs(""); err != nil || got != nil {
		t.Fatalf("unset must disable, got %v, %v", got, err)
	}
	got, err := ParseTrustedProxyUIDs("0, 501 ,502")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, uid := range []uint32{0, 501, 502} {
		if _, ok := got[uid]; !ok {
			t.Fatalf("expected uid %d in %v", uid, got)
		}
	}
	for _, raw := range []string{"abc", "0,-1", "99999999999", ",,,"} {
		if _, err := ParseTrustedProxyUIDs(raw); err == nil {
			t.Fatalf("malformed input %q must refuse startup", raw)
		}
	}
}

// peerAuthService starts a real service on a real Unix socket with the
// echo capability and the given peer map.
func peerAuthService(t *testing.T, peerMap PeerPrincipalMap) string {
	t.Helper()
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	handler := NewMultiHandler(map[string]Handler{"system": NewEchoHandler()})
	service := NewService(registry, handler, socketPath)
	if peerMap != nil {
		service.SetPeerAuth(peerMap)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { service.Stop() })
	return socketPath
}

func peerAuthRoundTrip(t *testing.T, socketPath, principal string) Response {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return sendRequest(t, conn, Request{
		Capability: "system.echo",
		Arguments:  json.RawMessage(`{"message":"hello"}`),
		Authority:  RequestAuthority{Principal: principal},
	})
}

func TestPeerAuthOverSocket(t *testing.T) {
	uid := uint32(os.Getuid())

	t.Run("mapped uid accepted", func(t *testing.T) {
		socketPath := peerAuthService(t, PeerPrincipalMap{uid: "alice@example.com"})
		resp := peerAuthRoundTrip(t, socketPath, "alice@example.com")
		if resp.Status != StatusSucceeded {
			t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
		}
	})

	t.Run("empty claim assigned mapped principal", func(t *testing.T) {
		socketPath := peerAuthService(t, PeerPrincipalMap{uid: "alice@example.com"})
		resp := peerAuthRoundTrip(t, socketPath, "")
		if resp.Status != StatusSucceeded {
			t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
		}
	})

	t.Run("mismatched claim denied", func(t *testing.T) {
		socketPath := peerAuthService(t, PeerPrincipalMap{uid: "alice@example.com"})
		resp := peerAuthRoundTrip(t, socketPath, "mallory@example.com")
		if resp.Status != StatusDenied {
			t.Fatalf("expected DENIED, got %s: %s", resp.Status, resp.Error)
		}
	})

	t.Run("unmapped uid denied", func(t *testing.T) {
		// The map contains only a uid that is not ours: our own
		// connection must be refused.
		other := uid ^ 0x40000000 // a bit flip lands far away without overflow risk
		socketPath := peerAuthService(t, PeerPrincipalMap{other: "alice@example.com"})
		resp := peerAuthRoundTrip(t, socketPath, "alice@example.com")
		if resp.Status != StatusDenied {
			t.Fatalf("expected DENIED, got %s: %s", resp.Status, resp.Error)
		}
	})

	t.Run("wildcard uid may claim any principal", func(t *testing.T) {
		socketPath := peerAuthService(t, PeerPrincipalMap{uid: PeerWildcardPrincipal})
		resp := peerAuthRoundTrip(t, socketPath, "carol@example.com")
		if resp.Status != StatusSucceeded {
			t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
		}
	})

	t.Run("no map preserves claimed principal", func(t *testing.T) {
		socketPath := peerAuthService(t, nil)
		resp := peerAuthRoundTrip(t, socketPath, "whoever@example.com")
		if resp.Status != StatusSucceeded {
			t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
		}
	})
}
