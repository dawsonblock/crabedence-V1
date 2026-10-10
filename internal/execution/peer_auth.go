package execution

import (
	"fmt"
	"strconv"
	"strings"
)

// PeerPrincipalMap binds Unix peer UIDs to principals. It is the
// authenticated-identity leg of the authority model: the kernel
// supplies the caller's UID (SO_PEERCRED / LOCAL_PEERCRED), the map
// supplies which principal that UID represents, and the caller's
// principal claim must agree.
//
// Mapping semantics:
//
//	uid:principal  — the UID authenticates as exactly that principal.
//	                 The request's principal claim must match (or be
//	                 empty, in which case the mapped principal is
//	                 assigned); a mismatch is denied.
//	uid:*          — the UID is a trusted local caller that may claim
//	                 any principal (e.g. an orchestrator identity that
//	                 proxies authenticated principals upstream). A
//	                 wildcard additionally requires the UID to appear in
//	                 CRABEDENCE_TRUSTED_PROXY_UIDS whenever that list is
//	                 declared, and unconditionally in production.
//
// The map is a startup-time control: a malformed entry refuses service
// startup rather than silently narrowing or widening authority.
type PeerPrincipalMap map[uint32]string

// PeerWildcardPrincipal allows a UID to claim any principal.
const PeerWildcardPrincipal = "*"

// ParsePeerPrincipalMap parses CRABEDENCE_PEER_PRINCIPALS:
// a comma-separated list of "uid:principal" or "uid:*" entries.
// Empty input returns nil (peer authentication disabled).
func ParsePeerPrincipalMap(raw string) (PeerPrincipalMap, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	m := PeerPrincipalMap{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		uidStr, principal, found := strings.Cut(entry, ":")
		principal = strings.TrimSpace(principal)
		if !found || principal == "" {
			return nil, fmt.Errorf("malformed entry %q (want uid:principal or uid:*)", entry)
		}
		uid, err := strconv.ParseUint(strings.TrimSpace(uidStr), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed uid in entry %q: %w", entry, err)
		}
		if _, dup := m[uint32(uid)]; dup {
			return nil, fmt.Errorf("duplicate uid %d in peer principal map", uid)
		}
		m[uint32(uid)] = principal
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("peer principal map is empty; unset CRABEDENCE_PEER_PRINCIPALS to disable peer authentication")
	}
	return m, nil
}

// ParseTrustedProxyUIDs parses CRABEDENCE_TRUSTED_PROXY_UIDS: a
// comma-separated list of UIDs permitted to hold wildcard entries in
// CRABEDENCE_PEER_PRINCIPALS. Claiming any principal is a different and
// stronger privilege than authenticating as one, so wildcard mapping is
// gated on a separately declared set — a uid:* entry in the peer map
// cannot silently create a claim-anything peer. Empty input returns nil.
func ParseTrustedProxyUIDs(raw string) (map[uint32]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	trusted := map[uint32]struct{}{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		uid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed uid %q in CRABEDENCE_TRUSTED_PROXY_UIDS: %w", entry, err)
		}
		trusted[uint32(uid)] = struct{}{}
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("trusted proxy UID list is empty; unset CRABEDENCE_TRUSTED_PROXY_UIDS instead")
	}
	return trusted, nil
}

// validatePeerAuthPolicy enforces the authenticated-principal
// requirement for production. Without CRABEDENCE_PEER_PRINCIPALS the
// service keeps the bearer model's claimed principal, which is an
// unverified attribute: any local process that can reach the socket
// may act as any principal. Production must therefore declare which
// UIDs may connect and as whom. Development keeps the optional strict
// mode.
//
// The wildcard entry is checked separately because it is a different
// order of privilege: a uid:principal mapping authenticates one
// identity, a uid:* mapping delegates identity choice to the peer.
// Production requires every wildcard's UID to be declared in
// CRABEDENCE_TRUSTED_PROXY_UIDS; in any mode a declared list is
// authoritative — a wildcard it does not cover refuses startup rather
// than quietly standing. An undeclared list outside production leaves
// the wildcard as the documented development convenience.
func validatePeerAuthPolicy(production bool, peers PeerPrincipalMap, trustedProxies map[uint32]struct{}) error {
	if production && len(peers) == 0 {
		return fmt.Errorf("production mode (CRABBOX_MODE=production) requires CRABEDENCE_PEER_PRINCIPALS mapping the kernel-supplied peer UIDs to principals — without it every request's principal is an unverified claim")
	}
	for uid, mapped := range peers {
		if mapped != PeerWildcardPrincipal {
			continue
		}
		if _, trusted := trustedProxies[uid]; !trusted && (production || trustedProxies != nil) {
			return fmt.Errorf("CRABEDENCE_PEER_PRINCIPALS maps uid %d to *, but %d is not declared in CRABEDENCE_TRUSTED_PROXY_UIDS — a wildcard peer may claim any principal, which is a separately declared privilege", uid, uid)
		}
	}
	return nil
}

// Authorize resolves the authenticated principal for a connection
// whose peer is uid, given the caller's claimed principal. It returns
// the principal the request must carry — the mapped principal for an
// exact mapping, or the claim for a wildcard mapping — and whether the
// peer is permitted at all.
func (m PeerPrincipalMap) Authorize(uid uint32, claimed string) (string, bool) {
	mapped, ok := m[uid]
	if !ok {
		return "", false
	}
	if mapped == PeerWildcardPrincipal {
		// A wildcard peer still must claim a principal — authority
		// resolution binds whatever it claims.
		return claimed, claimed != ""
	}
	if claimed != "" && claimed != mapped {
		return "", false
	}
	return mapped, true
}

// authenticatePeer enforces the map against the request's claimed
// principal using the connection's once-resolved kernel credentials.
// On success it returns the authenticated principal to bind into the
// request.
func (m PeerPrincipalMap) authenticatePeer(creds PeerCredentials, credErr error, claimed string) (string, error) {
	if credErr != nil {
		return "", fmt.Errorf("peer credentials unavailable: %w", credErr)
	}
	principal, ok := m.Authorize(creds.UID, claimed)
	if !ok {
		return "", fmt.Errorf("peer uid %d is not authorized for the claimed principal", creds.UID)
	}
	return principal, nil
}
