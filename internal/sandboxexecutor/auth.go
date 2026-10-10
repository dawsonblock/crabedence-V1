package sandboxexecutor

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PeerAllowlist binds permitted kernel UIDs to submitter identities.
// It is the sidecar's authenticated-identity leg: the kernel supplies
// the caller's UID and the map supplies which submitter that UID is
// allowed to act as. There is no wildcard — the executor accepts jobs
// only from explicitly named authority identities, never a delegated
// claim-anything peer.
//
// The map is a startup-time control: a malformed entry refuses startup
// rather than silently narrowing or widening who may submit.
type PeerAllowlist map[uint32]string

// ParsePeerAllowlist parses SANDBOX_EXECUTOR_PEER_UIDS:
// a comma-separated list of "uid:submitter" entries. Empty input is an
// error — an executor with no allowed submitter must refuse to start,
// not open a socket that accepts nothing.
func ParsePeerAllowlist(raw string) (PeerAllowlist, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("peer allowlist is empty — the executor requires at least one permitted submitter uid")
	}
	m := PeerAllowlist{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		uidStr, submitter, found := strings.Cut(entry, ":")
		submitter = strings.TrimSpace(submitter)
		if !found || submitter == "" || submitter == "*" {
			return nil, fmt.Errorf("malformed entry %q (want uid:submitter; wildcards are not submitter identities)", entry)
		}
		uid, err := strconv.ParseUint(strings.TrimSpace(uidStr), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed uid in entry %q: %w", entry, err)
		}
		if _, dup := m[uint32(uid)]; dup {
			return nil, fmt.Errorf("duplicate uid %d in peer allowlist", uid)
		}
		m[uint32(uid)] = submitter
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("peer allowlist contains no entries")
	}
	return m, nil
}

// Authorize resolves the submitter for a connection whose kernel peer
// is uid. It returns the authenticated submitter identity and whether
// the peer is permitted to submit at all.
func (a PeerAllowlist) Authorize(uid uint32) (string, bool) {
	submitter, ok := a[uid]
	return submitter, ok
}

// SubmissionToken is the second authentication leg: a shared secret
// the authority and the sidecar hold in a file readable only by their
// own identities. It distinguishes the authority process from other
// processes running under the same UID — on a developer host the UID
// alone cannot separate the service from an arbitrary local client.
//
// The token file must be a regular file owned by the process user with
// no group/world access; anything less is a startup refusal, not a
// warning. Empty tokens are refused — a token that allows everything
// is a worse failure than none.
type SubmissionToken struct {
	secret []byte
}

// LoadSubmissionToken reads a bearer token from path, enforcing the
// file's ownership and permission constraints.
func LoadSubmissionToken(path string) (*SubmissionToken, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect submission token %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("submission token %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("submission token %s is not a regular file", path)
	}
	if err := verifyOwnership(path, info, "submission token"); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("submission token %s is group/world accessible (mode %04o)", path, perm)
	}
	if info.Size() == 0 || info.Size() > 4096 {
		return nil, fmt.Errorf("submission token %s has invalid size %d (want 1..4096 bytes)", path, info.Size())
	}
	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read submission token %s: %w", path, err)
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	if len(secret) == 0 {
		return nil, fmt.Errorf("submission token %s is empty", path)
	}
	return &SubmissionToken{secret: secret}, nil
}

// Verify reports whether presented matches the loaded token, in
// constant time. A nil receiver means token checking is disabled —
// callers must not construct one for production use; the daemon
// reports it in the startup line so the weaker posture is observable.
func (t *SubmissionToken) Verify(presented string) bool {
	if t == nil {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(presented), t.secret) == 1
}

// verifyOwnership checks the file is owned by the current user. Shared
// with the socket-path checks — a file another user can replace is not
// a credential. Inability to determine the owner fails closed.
func verifyOwnership(path string, info os.FileInfo, what string) error {
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("%s %s: cannot determine owner", what, path)
	}
	if uid != uint32(os.Getuid()) {
		return fmt.Errorf("%s %s is owned by uid %d, not the process uid %d", what, path, uid, os.Getuid())
	}
	return nil
}
