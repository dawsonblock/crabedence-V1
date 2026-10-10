package execution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Runtime attestation: the protocol by which Crabedence verifies the
// identity of the NEMO runtime making requests. Mediation digests and
// identity fields a caller writes are evidence, never proof — they
// describe what the caller claims to be. Attestation replaces the
// claim with a challenge-response bound to a runtime key the
// deployment trusts.
//
// Protocol (one frame per connection, matching the invocation wire):
//
//	client → {"type":"attest_challenge"}
//	server → {"session_id","nonce","expires_at","protocol"}
//	client → {"type":"attest","session_id","runtime_identity":{...},"signature"}
//	server → {"status":"attested","session_id","runtime_identity_digest","expires_at"}
//
// The runtime signs the pipe-joined attestation envelope with its
// Ed25519 key. The challenge nonce is single-use and short-lived, so a
// captured attestation cannot be replayed into a new session.
//
// Each subsequent invocation carries "session":{"id","proof"}: proof is
// the runtime's signature over the pipe-joined request binding, proving
// possession of the attested key for THIS request — a stolen session ID
// is worthless without the key, and a replayed request resolves to the
// same idempotent record by construction.
//
// Attestation supplements OS peer identity; it never replaces it. When
// peer authentication is configured the session also binds the
// connection's peer UID, and every invocation is checked against it.
const (
	attestationProtocol   = "crabedence-attestation-v1"
	sessionProofProtocol  = "crabedence-session-proof-v1"
	attestChallengeType   = "attest_challenge"
	attestType            = "attest"
	defaultChallengeTTL   = 60 * time.Second
	defaultSessionTTL     = 10 * time.Minute
	maxRuntimeIdentityLen = 4096
)

// RuntimeIdentity is the attested identity of the runtime process: the
// digests that name the exact software, plugin set, activation, and ABI
// the session speaks. Empty fields mean "not asserted"; policy decides
// whether an empty assertion is admissible.
type RuntimeIdentity struct {
	// RuntimeKey is the Ed25519 public key (base64) the session binds.
	RuntimeKey           string `json:"runtime_key"`
	ReleaseDigest        string `json:"release_digest,omitempty"`
	ReleaseRootDigest    string `json:"release_root_digest,omitempty"`
	PluginManifestDigest string `json:"plugin_manifest_digest,omitempty"`
	PluginHostVersion    string `json:"plugin_host_version,omitempty"`
	ActivationDigest     string `json:"activation_digest,omitempty"`
	ABIVersion           string `json:"abi_version,omitempty"`
	RuntimeConfigDigest  string `json:"runtime_config_digest,omitempty"`
}

// Digest returns the canonical identity digest — sha256 over the
// pipe-joined field set. It is the stable provenance value persisted on
// execution records as runtime_identity_digest.
func (id RuntimeIdentity) Digest() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		id.RuntimeKey, id.ReleaseDigest, id.ReleaseRootDigest,
		id.PluginManifestDigest, id.PluginHostVersion,
		id.ActivationDigest, id.ABIVersion, id.RuntimeConfigDigest,
	}, "|")))
	return hex.EncodeToString(sum[:])
}

// Fingerprint returns the SHA-256 fingerprint of the runtime key — the
// identity deployments allowlist.
func (id RuntimeIdentity) Fingerprint() (string, error) {
	key, err := decodeRuntimeKey(id.RuntimeKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:]), nil
}

// AttestationPolicy is the deployment's runtime-admission contract.
// Production fails closed: when Required is set, invocations without a
// valid attested session are denied and attestations from unapproved
// keys or identities are refused. Relaxed exists for development only —
// it accepts any well-formed signed attestation — and is refused in
// production mode.
type AttestationPolicy struct {
	// Required denies every invocation that does not carry a valid
	// attested session proof.
	Required bool
	// Relaxed admits any well-formed signed attestation regardless of
	// key or identity allowlists. Development only.
	Relaxed bool
	// ApprovedKeys maps runtime-key fingerprints to Ed25519 keys.
	// In strict mode an attestation whose key fingerprint is absent is
	// refused.
	ApprovedKeys map[string]ed25519.PublicKey
	// ApprovedReleases, when non-empty, is the allowlist of asserted
	// release digests.
	ApprovedReleases map[string]bool
	// ApprovedManifests, when non-empty, is the allowlist of asserted
	// plugin manifest digests.
	ApprovedManifests map[string]bool
	// ApprovedABI, when non-empty, is the allowlist of asserted
	// capability ABI versions.
	ApprovedABI map[string]bool
	// SessionTTL bounds an attested session's lifetime. Zero uses the
	// default.
	SessionTTL time.Duration
}

// attestedSession is one verified runtime session. uid and exe bind
// the local caller that attested: a session may only ride connections
// from the same kernel-authenticated peer — same UID, and where the
// platform reports it (Linux) the same executable, so a same-UID
// sibling binary cannot reuse a stolen session ID.
type attestedSession struct {
	identity    RuntimeIdentity
	digest      string
	fingerprint string
	uid         uint32
	hasUID      bool
	exe         string
	expiresAt   time.Time
}

// pendingChallenge is an issued, unspent challenge nonce.
type pendingChallenge struct {
	nonce     string
	expiresAt time.Time
}

// attestationRegistry owns issued challenges and attested sessions.
// Both are in-memory by design: a restarted kernel re-challenges the
// runtime — an attested session must never outlive the process that
// verified it.
type attestationRegistry struct {
	policy     AttestationPolicy
	now        func() time.Time
	mu         sync.Mutex
	challenges map[string]pendingChallenge
	sessions   map[string]attestedSession
}

func newAttestationRegistry(policy AttestationPolicy) *attestationRegistry {
	ttl := policy.SessionTTL
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	policy.SessionTTL = ttl
	return &attestationRegistry{
		policy:     policy,
		now:        time.Now,
		challenges: make(map[string]pendingChallenge),
		sessions:   make(map[string]attestedSession),
	}
}

// issueChallenge mints a single-use challenge for an attest handshake.
func (r *attestationRegistry) issueChallenge() (sessionID, nonce string, expiresAt time.Time, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", time.Time{}, err
	}
	sessionID = "rts-" + base64.RawURLEncoding.EncodeToString(buf[:16])
	nonce = base64.RawURLEncoding.EncodeToString(buf[16:])
	expiresAt = r.now().Add(defaultChallengeTTL)
	r.mu.Lock()
	r.challenges[sessionID] = pendingChallenge{nonce: nonce, expiresAt: expiresAt}
	r.mu.Unlock()
	return sessionID, nonce, expiresAt, nil
}

// attestationEnvelope is the exact byte string the runtime signs —
// pipe-joined, order-fixed, language-agnostic. Pipe-free fields are
// guaranteed by construction: digests are hex, the key is base64,
// session_id and nonce are base64url.
func attestationEnvelope(sessionID, nonce string, id RuntimeIdentity) string {
	return strings.Join([]string{
		attestationProtocol, sessionID, nonce, id.RuntimeKey,
		id.ReleaseDigest, id.ReleaseRootDigest, id.PluginManifestDigest,
		id.PluginHostVersion, id.ActivationDigest, id.ABIVersion,
		id.RuntimeConfigDigest,
	}, "|")
}

// attest consumes the challenge and binds a session when the signature
// verifies and policy admits the identity. The peer credentials, when
// the kernel supplies them, are bound into the session — attestation
// supplements peer identity, it does not replace it.
func (r *attestationRegistry) attest(conn net.Conn, sessionID string, id RuntimeIdentity, signature string) (*attestedSession, error) {
	r.mu.Lock()
	ch, ok := r.challenges[sessionID]
	if ok {
		// The nonce is single-use: consume it whether or not the
		// attestation succeeds so a failed guess cannot be retried.
		delete(r.challenges, sessionID)
	}
	r.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown or spent challenge session")
	}
	if r.now().After(ch.expiresAt) {
		return nil, errors.New("challenge expired")
	}
	key, err := decodeRuntimeKey(id.RuntimeKey)
	if err != nil {
		return nil, fmt.Errorf("invalid runtime key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		if sig, err = base64.RawURLEncoding.DecodeString(signature); err != nil {
			return nil, errors.New("signature is not valid base64")
		}
	}
	if !ed25519.Verify(key, []byte(attestationEnvelope(sessionID, ch.nonce, id)), sig) {
		return nil, errors.New("attestation signature verification failed")
	}
	fingerprintSum := sha256.Sum256(key)
	fingerprint := hex.EncodeToString(fingerprintSum[:])
	if err := r.policy.admit(fingerprint, key, id); err != nil {
		return nil, err
	}
	sess := &attestedSession{
		identity:    id,
		digest:      id.Digest(),
		fingerprint: fingerprint,
		expiresAt:   r.now().Add(r.policy.SessionTTL),
	}
	if conn != nil {
		if creds, err := unixPeerCredentials(conn); err == nil {
			sess.uid, sess.hasUID = creds.UID, true
			sess.exe = creds.ExePath
		}
	}
	r.mu.Lock()
	r.sessions[sessionID] = *sess
	r.mu.Unlock()
	return sess, nil
}

// admit enforces the identity allowlists. A nil policy map means the
// dimension is unrestricted; a configured map is authoritative.
func (p AttestationPolicy) admit(fingerprint string, key ed25519.PublicKey, id RuntimeIdentity) error {
	if p.Relaxed {
		return nil
	}
	if len(p.ApprovedKeys) > 0 {
		approved, ok := p.ApprovedKeys[fingerprint]
		if !ok {
			return fmt.Errorf("runtime key fingerprint %s is not approved", fingerprint[:12])
		}
		if !approved.Equal(key) {
			return fmt.Errorf("runtime key fingerprint %s does not match the approved key", fingerprint[:12])
		}
	}
	if len(p.ApprovedReleases) > 0 && !p.ApprovedReleases[id.ReleaseDigest] {
		return errors.New("runtime release digest is not approved")
	}
	if len(p.ApprovedManifests) > 0 && !p.ApprovedManifests[id.PluginManifestDigest] {
		return errors.New("runtime plugin manifest digest is not approved")
	}
	if len(p.ApprovedABI) > 0 && !p.ApprovedABI[id.ABIVersion] {
		return errors.New("runtime ABI version is not approved")
	}
	return nil
}

// verifyRequest checks the invocation's session binding: the session
// must exist, be unexpired, be bound to this connection's peer
// credentials (when the attesting connection reported any), and carry
// a valid proof-of-possession signature for THIS request. creds and
// credErr are the connection's once-resolved kernel credentials — a
// session bound to peer evidence cannot ride a connection whose peer
// cannot be resolved. The returned session is the verified provenance
// the execution record binds.
func (r *attestationRegistry) verifyRequest(creds PeerCredentials, credErr error, req Request) (*attestedSession, error) {
	if req.Session == nil || req.Session.ID == "" {
		if r.policy.Required {
			return nil, errors.New("runtime attestation required: request carries no session")
		}
		return nil, nil
	}
	r.mu.Lock()
	sess, ok := r.sessions[req.Session.ID]
	r.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown runtime session")
	}
	if r.now().After(sess.expiresAt) {
		return nil, errors.New("runtime session expired")
	}
	if sess.hasUID || sess.exe != "" {
		if credErr != nil {
			return nil, fmt.Errorf("peer credentials unavailable for session-bound request: %w", credErr)
		}
		if sess.hasUID && creds.UID != sess.uid {
			return nil, fmt.Errorf("session bound to uid %d, connection peer is uid %d", sess.uid, creds.UID)
		}
		if sess.exe != "" && creds.ExePath != sess.exe {
			return nil, fmt.Errorf("session bound to executable %q, connection peer executable is %q", sess.exe, creds.ExePath)
		}
	}
	key, ok := r.policy.keyFor(sess)
	if !ok {
		return nil, errors.New("session key is no longer approved")
	}
	if !ed25519.Verify(key, []byte(requestProofMessage(req)), mustDecodeSignature(req.Session.Proof)) {
		return nil, errors.New("session proof verification failed")
	}
	return &sess, nil
}

// keyFor resolves the session's verification key under the live
// policy — relaxed mode re-derives it from the attested identity;
// strict mode returns the approved key for the session fingerprint.
func (p AttestationPolicy) keyFor(sess attestedSession) (ed25519.PublicKey, bool) {
	if p.Relaxed {
		key, err := decodeRuntimeKey(sess.identity.RuntimeKey)
		return key, err == nil
	}
	key, ok := p.ApprovedKeys[sess.fingerprint]
	return key, ok
}

// requestProofMessage is the exact string the runtime signs per
// invocation — pipe-joined, order-fixed. It binds the session to the
// caller-supplied identity surface: capability, key, principal,
// authority ref, deadline, and the argument/mediation digests.
func requestProofMessage(req Request) string {
	argsSum := sha256.Sum256(req.Arguments)
	var medSum [32]byte
	if req.Mediation != nil {
		if b, err := json.Marshal(req.Mediation); err == nil {
			medSum = sha256.Sum256(b)
		}
	}
	return strings.Join([]string{
		sessionProofProtocol, req.Session.ID, req.Capability,
		req.IdempotencyKey, req.Authority.Principal,
		req.Authority.EffectiveAuthorityRef(), req.Deadline,
		hex.EncodeToString(argsSum[:]), hex.EncodeToString(medSum[:]),
	}, "|")
}

// SessionProof signs the request-binding for a session — the client
// half of the proof-of-possession contract, used by the in-process
// client and tests.
func SessionProof(key ed25519.PrivateKey, req Request) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(requestProofMessage(req))))
}

// AttestSignature signs the attestation envelope — the client half.
func AttestSignature(key ed25519.PrivateKey, sessionID, nonce string, id RuntimeIdentity) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(attestationEnvelope(sessionID, nonce, id))))
}

func decodeRuntimeKey(raw string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if key, err = base64.RawURLEncoding.DecodeString(raw); err != nil {
			return nil, errors.New("runtime key is not valid base64")
		}
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("runtime key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

func mustDecodeSignature(raw string) []byte {
	sig, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil
	}
	return sig
}

// ─── Wire messages ──────────────────────────────────────────────────

// wireEnvelope is the minimal message-type probe read before the
// strict invocation ABI. Unknown/absent type means invocation.
type wireEnvelope struct {
	Type string `json:"type"`
}

func messageType(data []byte) string {
	var env wireEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return ""
	}
	return env.Type
}

// attestRequest is the attest handshake frame.
type attestRequest struct {
	Type            string          `json:"type"`
	SessionID       string          `json:"session_id"`
	RuntimeIdentity RuntimeIdentity `json:"runtime_identity"`
	Signature       string          `json:"signature"`
}

// challengeResponse is the server's challenge answer.
type challengeResponse struct {
	SessionID string `json:"session_id"`
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
	Protocol  string `json:"protocol"`
}

// attestResponse is the server's attestation verdict.
type attestResponse struct {
	Status                string `json:"status"`
	SessionID             string `json:"session_id,omitempty"`
	RuntimeIdentityDigest string `json:"runtime_identity_digest,omitempty"`
	ExpiresAt             string `json:"expires_at,omitempty"`
	Error                 string `json:"error,omitempty"`
}

// writeJSONFrame writes one length-prefixed JSON frame — the wire
// format handleConnection and writeResponse share.
func writeJSONFrame(conn net.Conn, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		return
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	_, _ = writeFrame(conn, frame)
}

// handleAttestation processes the handshake messages: issue a
// challenge, or consume one and bind an attested session.
func (s *Service) handleAttestation(conn net.Conn, msgBuf []byte, msgType string) {
	switch msgType {
	case attestChallengeType:
		id, nonce, expires, err := s.attestation.issueChallenge()
		if err != nil {
			writeJSONFrame(conn, attestResponse{Status: "error", Error: err.Error()})
			return
		}
		writeJSONFrame(conn, challengeResponse{
			SessionID: id, Nonce: nonce,
			ExpiresAt: expires.UTC().Format(time.RFC3339Nano),
			Protocol:  attestationProtocol,
		})
	case attestType:
		var req attestRequest
		dec := json.NewDecoder(bytes.NewReader(msgBuf))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSONFrame(conn, attestResponse{Status: "error", Error: "malformed attest request"})
			return
		}
		if idBytes, _ := json.Marshal(req.RuntimeIdentity); len(idBytes) > maxRuntimeIdentityLen {
			writeJSONFrame(conn, attestResponse{Status: "error", Error: "runtime identity exceeds the bound"})
			return
		}
		sess, err := s.attestation.attest(conn, req.SessionID, req.RuntimeIdentity, req.Signature)
		if err != nil {
			writeJSONFrame(conn, attestResponse{Status: "denied", Error: err.Error()})
			return
		}
		writeJSONFrame(conn, attestResponse{
			Status:                "attested",
			SessionID:             req.SessionID,
			RuntimeIdentityDigest: sess.digest,
			ExpiresAt:             sess.expiresAt.UTC().Format(time.RFC3339Nano),
		})
	default:
		writeJSONFrame(conn, attestResponse{Status: "error", Error: "unknown attestation message type"})
	}
}

// ParseApprovedRuntimeKeys parses
// CRABEDENCE_APPROVED_RUNTIME_KEYS: comma-separated
// fingerprint:base64-ed25519-pubkey entries. A malformed entry fails
// closed at startup — the approved set is never silently narrowed.
func ParseApprovedRuntimeKeys(raw string) (map[string]ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		fp, keyRaw, found := strings.Cut(entry, ":")
		fp = strings.ToLower(strings.TrimSpace(fp))
		if !found || fp == "" || len(fp) != 64 {
			return nil, fmt.Errorf("malformed runtime key entry %q (want <sha256-fingerprint>:<base64-key>)", entry)
		}
		key, err := decodeRuntimeKey(strings.TrimSpace(keyRaw))
		if err != nil {
			return nil, fmt.Errorf("malformed runtime key in entry %q: %w", entry, err)
		}
		wantSum := sha256.Sum256(key)
		want := hex.EncodeToString(wantSum[:])
		if fp != want {
			return nil, fmt.Errorf("runtime key entry %q: declared fingerprint does not match the key", entry)
		}
		keys[fp] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("approved runtime key list is empty; unset it or use relaxed mode")
	}
	return keys, nil
}

// parseDigestSet parses a comma-separated allowlist of opaque tokens
// (release digests, manifest digests, ABI versions).
func parseDigestSet(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	set := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			set[entry] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}
