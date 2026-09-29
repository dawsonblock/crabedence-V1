package execution

import (
	"fmt"
	"net"
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
//	                 proxies authenticated principals upstream).
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

// authenticatePeer extracts the kernel-supplied UID and enforces the
// map against the request's claimed principal. On success it returns
// the authenticated principal to bind into the request.
func (m PeerPrincipalMap) authenticatePeer(conn net.Conn, claimed string) (string, error) {
	uid, err := unixPeerUID(conn)
	if err != nil {
		return "", fmt.Errorf("peer credentials unavailable: %w", err)
	}
	principal, ok := m.Authorize(uid, claimed)
	if !ok {
		return "", fmt.Errorf("peer uid %d is not authorized for the claimed principal", uid)
	}
	return principal, nil
}
