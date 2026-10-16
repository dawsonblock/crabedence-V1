package sandboxexecutor

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/openclaw/crabbox/internal/sockfile"
)

// AuthorityKeys is the executor's trust set for signed job contracts:
// signer fingerprint → Ed25519 public key. The executor holds public
// keys only — signing keys, approval logic, and privileged
// credentials live outside this process per the authority boundary.
// An empty set means signed-job verification is impossible, so the
// server refuses to accept any signed submission (and refuses a
// configured backend outright).
type AuthorityKeys map[string]ed25519.PublicKey

// LoadAuthorityKeys reads a public-key trust file. Format: one entry
// per line, either "<64-hex-fingerprint>:<base64-ed25519-public-key>"
// or a bare "<base64-ed25519-public-key>" whose fingerprint is
// derived. Blank lines and '#'-comments are ignored.
//
// The file carries the same ownership discipline as the submission
// token: regular file, owner-only, no group/world access, never a
// symlink. A trust file another user could edit is not a trust set —
// anything less is a startup refusal. Malformed entries, fingerprint
// mismatches, and duplicates refuse startup rather than silently
// narrowing who may authorize execution.
func LoadAuthorityKeys(path string) (AuthorityKeys, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect authority keys %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("authority keys %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("authority keys %s is not a regular file", path)
	}
	if err := sockfile.VerifyOwnership(path, info, "authority keys"); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("authority keys %s is group/world accessible (mode %04o)", path, perm)
	}
	if info.Size() == 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("authority keys %s has invalid size %d", path, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authority keys %s: %w", path, err)
	}
	keys := AuthorityKeys{}
	for lineno, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		declared, b64, found := strings.Cut(line, ":")
		if !found {
			declared, b64 = "", line
		}
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authority keys %s:%d: malformed public key", path, lineno+1)
		}
		fp := AuthorityFingerprint(ed25519.PublicKey(pub))
		if declared != "" {
			if !isHexFingerprint(strings.TrimSpace(declared)) {
				return nil, fmt.Errorf("authority keys %s:%d: malformed fingerprint", path, lineno+1)
			}
			if strings.TrimSpace(declared) != fp {
				return nil, fmt.Errorf("authority keys %s:%d: fingerprint %q does not match the key's identity %q", path, lineno+1, strings.TrimSpace(declared), fp)
			}
		}
		if _, dup := keys[fp]; dup {
			return nil, fmt.Errorf("authority keys %s:%d: duplicate key %s", path, lineno+1, fp)
		}
		keys[fp] = ed25519.PublicKey(pub)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("authority keys %s contains no keys", path)
	}
	return keys, nil
}
