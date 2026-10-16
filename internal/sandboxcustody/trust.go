package sandboxcustody

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sockfile"
)

// TransitionDomain separates witness key-transition signatures from
// every other signed record — a transition authorizes a successor
// witness key and can never be presented as an acknowledgement.
const TransitionDomain = "crabedence-custody-key-transition-v1\x00"

// TrustRoot is the custody trust anchor: the witness keys an operator
// has explicitly approved. It is supplied from controlled
// configuration — never learned from an acknowledgement, a custody
// directory, or any untrusted store. A verifier with no trust root
// fails closed: "the response claims a signer" is not identity.
type TrustRoot struct {
	// keys maps witness signer fingerprint → the approved public key.
	keys map[string]ed25519.PublicKey
	// fingerprints alone approves a key by its fingerprint without
	// holding the key bytes — the acknowledgement's own embedded
	// public key is then what the signature verifies under, with the
	// fingerprint pinning its identity cryptographically.
	fingerprints map[string]bool
}

// NewTrustRoot builds a trust root over approved witness public keys.
func NewTrustRoot(keys ...ed25519.PublicKey) *TrustRoot {
	t := &TrustRoot{keys: map[string]ed25519.PublicKey{}, fingerprints: map[string]bool{}}
	for _, k := range keys {
		t.keys[evidence.Fingerprint(k)] = k
	}
	return t
}

// NewFingerprintTrust builds a trust root that approves witness
// fingerprints without pinning the key bytes. The verifier still
// requires a valid signature under the acknowledgement's embedded
// key — the fingerprint pins which key identity may sign.
func NewFingerprintTrust(fingerprints ...string) *TrustRoot {
	t := &TrustRoot{keys: map[string]ed25519.PublicKey{}, fingerprints: map[string]bool{}}
	for _, fp := range fingerprints {
		t.fingerprints[strings.ToLower(strings.TrimSpace(fp))] = true
	}
	return t
}

// Empty reports whether the root approves no witness at all — a
// verifier over an empty root must refuse every acknowledgement.
func (t *TrustRoot) Empty() bool {
	return t == nil || (len(t.keys) == 0 && len(t.fingerprints) == 0)
}

// Approve reports whether pub is an approved witness key. Holding the
// key bytes is the stronger check: the embedded key must equal the
// approved one. Fingerprint-only trust accepts the key the fingerprint
// commits to — the caller has already bound signer==fingerprint(pub).
func (t *TrustRoot) Approve(signer string, pub ed25519.PublicKey) bool {
	if t == nil {
		return false
	}
	if approved, ok := t.keys[signer]; ok {
		return approved.Equal(pub)
	}
	return t.fingerprints[signer]
}

// trustRootFile is the controlled-configuration format. The first
// witness is the root anchor: the operator names it. Every later
// witness must carry a transition signature under the immediately
// preceding witness's key — a new signer never inherits authority by
// appearing in the file; it inherits it by being authorized.
type trustRootFile struct {
	Version   int                    `json:"version"`
	Witnesses []trustRootFileWitness `json:"witnesses"`
}

type trustRootFileWitness struct {
	PublicKey string `json:"public_key"`
	// Signature is the key-transition record for every witness after
	// the first: the previous witness's signature over the domain-
	// separated vector (prev public key, new public key). The first
	// witness must not carry one — it is the anchor, not a rotation.
	Signature string `json:"signature,omitempty"`
}

// transitionFields is the versioned signing vector a key-transition
// commits to.
func transitionFields(prevPub, newPub ed25519.PublicKey) []string {
	return []string{
		base64.StdEncoding.EncodeToString(prevPub),
		base64.StdEncoding.EncodeToString(newPub),
	}
}

// SignKeyTransition produces the signature a current witness issues
// to authorize its successor — the operator copies it into the trust
// file's next witness entry. Key rotation is an explicit act of the
// incumbent, not something the new key can claim.
func SignKeyTransition(signer *evidence.Signer, newPub ed25519.PublicKey) (string, error) {
	return signer.SignRecord(TransitionDomain, transitionFields(signer.PublicKey(), newPub)...)
}

// LoadTrustRoot reads a controlled custody trust file: regular file,
// owner-only, never a symlink — the same discipline the authority-key
// loader enforces, because a trust root another user could edit is
// not a trust root. Each witness after the first must prove a signed
// transition from its predecessor; a file that lists a new key with
// no authorization refuses to load rather than silently widening who
// may vouch for evidence.
func LoadTrustRoot(path string) (*TrustRoot, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect custody trust root %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("custody trust root %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("custody trust root %s is not a regular file", path)
	}
	if err := sockfile.VerifyOwnership(path, info, "custody trust root"); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("custody trust root %s is group/world accessible (mode %04o)", path, perm)
	}
	if info.Size() == 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("custody trust root %s has invalid size %d", path, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read custody trust root %s: %w", path, err)
	}
	f := &trustRootFile{}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(f); err != nil {
		return nil, fmt.Errorf("custody trust root %s malformed: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("custody trust root %s: unsupported version %d", path, f.Version)
	}
	root := &TrustRoot{keys: map[string]ed25519.PublicKey{}, fingerprints: map[string]bool{}}
	var prev ed25519.PublicKey
	for i, w := range f.Witnesses {
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(w.PublicKey))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("custody trust root %s witness %d: malformed public key", path, i+1)
		}
		key := ed25519.PublicKey(pub)
		fp := evidence.Fingerprint(key)
		if _, dup := root.keys[fp]; dup {
			return nil, fmt.Errorf("custody trust root %s witness %d: duplicate key %s", path, i+1, fp)
		}
		if i == 0 {
			if w.Signature != "" {
				return nil, fmt.Errorf("custody trust root %s: the anchor witness must not carry a transition signature", path)
			}
		} else {
			if w.Signature == "" {
				return nil, fmt.Errorf("custody trust root %s witness %d (%s): no key-transition signature — a new witness never inherits authority undeclared", path, i+1, fp)
			}
			if err := evidence.VerifyRecordSignature(prev, TransitionDomain, w.Signature,
				transitionFields(prev, key)...); err != nil {
				return nil, fmt.Errorf("custody trust root %s witness %d (%s): transition not authorized by the incumbent witness: %v", path, i+1, fp, err)
			}
		}
		root.keys[fp] = key
		prev = key
	}
	if root.Empty() {
		return nil, fmt.Errorf("custody trust root %s contains no witnesses", path)
	}
	return root, nil
}
