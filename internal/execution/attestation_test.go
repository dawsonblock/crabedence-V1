package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// testRuntimeKey generates an Ed25519 runtime identity and the
// RuntimeIdentity that asserts it.
func testRuntimeKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, RuntimeIdentity) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, RuntimeIdentity{
		RuntimeKey:           base64.StdEncoding.EncodeToString(pub),
		ReleaseDigest:        strings.Repeat("a", 64),
		ReleaseRootDigest:    strings.Repeat("b", 64),
		PluginManifestDigest: strings.Repeat("c", 64),
		PluginHostVersion:    "1.2.3",
		ActivationDigest:     strings.Repeat("d", 64),
		ABIVersion:           "capability-invocation-v1",
		RuntimeConfigDigest:  strings.Repeat("e", 64),
	}
}

func fingerprintOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// completeHandshake runs the challenge/attest exchange against the
// registry directly — the same flow the socket handler drives.
func completeHandshake(t *testing.T, reg *attestationRegistry, priv ed25519.PrivateKey, id RuntimeIdentity) (string, *attestedSession) {
	t.Helper()
	sid, nonce, _, err := reg.issueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	sig := AttestSignature(priv, sid, nonce, id)
	sess, err := reg.attest(nil, sid, id, sig)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	return sid, sess
}

func strictPolicyFor(pub ed25519.PublicKey, ids ...RuntimeIdentity) AttestationPolicy {
	p := AttestationPolicy{
		Required:     true,
		ApprovedKeys: map[string]ed25519.PublicKey{fingerprintOf(pub): pub},
	}
	if len(ids) > 0 {
		p.ApprovedReleases = map[string]bool{ids[0].ReleaseDigest: true}
		p.ApprovedManifests = map[string]bool{ids[0].PluginManifestDigest: true}
		p.ApprovedABI = map[string]bool{ids[0].ABIVersion: true}
	}
	return p
}

func TestAttestationHandshakeSucceeds(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub, id))
	sid, sess := completeHandshake(t, reg, priv, id)
	if sess.digest != id.Digest() {
		t.Fatal("session digest mismatch")
	}
	if sess.fingerprint != fingerprintOf(pub) {
		t.Fatal("fingerprint mismatch")
	}
	if _, ok := reg.sessions[sid]; !ok {
		t.Fatal("session not bound")
	}
}

func TestAttestationRejectsBadSignature(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	sid, nonce, _, err := reg.issueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Sign the correct envelope with the right key but present a
	// different runtime key: the signature cannot verify.
	sig := AttestSignature(priv, sid, nonce, id)
	id.RuntimeKey = base64.StdEncoding.EncodeToString(otherPub)
	if _, err := reg.attest(nil, sid, id, sig); err == nil {
		t.Fatal("attestation with forged runtime key must fail")
	}
}

func TestAttestationRejectsUnknownAndSpentChallenges(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))

	if _, err := reg.attest(nil, "rts-nonexistent", id, "AA=="); err == nil {
		t.Fatal("attestation against an unknown session must fail")
	}

	sid, nonce, _, err := reg.issueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	sig := AttestSignature(priv, sid, nonce, id)
	if _, err := reg.attest(nil, sid, id, sig); err != nil {
		t.Fatalf("first attest: %v", err)
	}
	// The nonce is single-use: replaying the same signed attestation
	// must fail.
	if _, err := reg.attest(nil, sid, id, sig); err == nil {
		t.Fatal("replayed attestation must fail")
	}
}

func TestAttestationChallengeExpiry(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	sid, nonce, _, err := reg.issueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	reg.now = func() time.Time { return now.Add(2 * defaultChallengeTTL) }
	sig := AttestSignature(priv, sid, nonce, id)
	if _, err := reg.attest(nil, sid, id, sig); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired-challenge denial, got %v", err)
	}
}

func TestAttestationUnapprovedKeyDenied(t *testing.T) {
	_, priv, id := testRuntimeKey(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	reg := newAttestationRegistry(AttestationPolicy{
		Required:     true,
		ApprovedKeys: map[string]ed25519.PublicKey{fingerprintOf(otherPub): otherPub},
	})
	sid, nonce, _, err := reg.issueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	sig := AttestSignature(priv, sid, nonce, id)
	if _, err := reg.attest(nil, sid, id, sig); err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("expected unapproved-key denial, got %v", err)
	}
}

func TestAttestationIdentityAllowlists(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	policy := strictPolicyFor(pub, id)

	// Wrong release digest is denied.
	badID := id
	badID.ReleaseDigest = strings.Repeat("f", 64)
	reg := newAttestationRegistry(policy)
	sid, nonce, _, err := reg.issueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.attest(nil, sid, badID, AttestSignature(priv, sid, nonce, badID)); err == nil {
		t.Fatal("unapproved release digest must be denied")
	}

	// Asserted identity inside the allowlists is admitted.
	reg = newAttestationRegistry(policy)
	if _, sess := completeHandshake(t, reg, priv, id); sess == nil {
		t.Fatal("approved identity must be admitted")
	}
}

func TestAttestationRelaxedAdmitsAnyKey(t *testing.T) {
	_, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(AttestationPolicy{Required: true, Relaxed: true})
	if _, sess := completeHandshake(t, reg, priv, id); sess == nil {
		t.Fatal("relaxed policy must admit a well-formed signed attestation")
	}
}

func attestedRequest(sessionID string, priv ed25519.PrivateKey) Request {
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"attest","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: "attest-key-1",
		Session:        &RequestSession{ID: sessionID},
	}
	req.Session.Proof = SessionProof(priv, req)
	return req
}

func TestSessionProofVerification(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	sid, _ := completeHandshake(t, reg, priv, id)

	req := attestedRequest(sid, priv)
	sess, err := reg.verifyRequest(PeerCredentials{}, nil, req)
	if err != nil {
		t.Fatalf("valid session proof denied: %v", err)
	}
	if sess == nil || sess.digest != id.Digest() {
		t.Fatal("verified session missing or identity mismatch")
	}
}

func TestSessionProofBindsThisRequest(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	sid, _ := completeHandshake(t, reg, priv, id)

	req := attestedRequest(sid, priv)
	// The proof signs the caller-supplied surface: a different
	// idempotency key under the same session is a different proof.
	tampered := req
	tampered.IdempotencyKey = "attest-key-2"
	if _, err := reg.verifyRequest(PeerCredentials{}, nil, tampered); err == nil {
		t.Fatal("proof must not cover a mutated request")
	}
	// And the session ID itself is bound.
	forged := req
	forged.Session = &RequestSession{ID: "rts-stolen", Proof: req.Session.Proof}
	if _, err := reg.verifyRequest(PeerCredentials{}, nil, forged); err == nil {
		t.Fatal("proof must not authenticate a different session")
	}
}

func TestSessionRequiredDeniesUnattested(t *testing.T) {
	pub, _, _ := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	req := Request{Capability: "test.counter.increment"}
	if _, err := reg.verifyRequest(PeerCredentials{}, nil, req); err == nil {
		t.Fatal("required policy must deny an unattested request")
	}
	// An empty session object is equally unattested.
	req.Session = &RequestSession{}
	if _, err := reg.verifyRequest(PeerCredentials{}, nil, req); err == nil {
		t.Fatal("required policy must deny an empty session binding")
	}
}

func TestSessionOptionalAdmitsUnattested(t *testing.T) {
	pub, _, _ := testRuntimeKey(t)
	p := strictPolicyFor(pub)
	p.Required = false
	reg := newAttestationRegistry(p)
	sess, err := reg.verifyRequest(PeerCredentials{}, nil, Request{})
	if err != nil || sess != nil {
		t.Fatalf("optional policy must admit an unattested request, got sess=%v err=%v", sess, err)
	}
}

func TestSessionExpiryDenies(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	p := strictPolicyFor(pub)
	p.SessionTTL = time.Minute
	reg := newAttestationRegistry(p)
	sid, _ := completeHandshake(t, reg, priv, id)
	now := time.Now()
	reg.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := reg.verifyRequest(PeerCredentials{}, nil, attestedRequest(sid, priv)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired-session denial, got %v", err)
	}
}

func TestSessionUnknownDenied(t *testing.T) {
	pub, priv, _ := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	req := attestedRequest("rts-fabricated", priv)
	if _, err := reg.verifyRequest(PeerCredentials{}, nil, req); err == nil {
		t.Fatal("unknown session must be denied")
	}
}

func TestParseApprovedRuntimeKeys(t *testing.T) {
	pub, _, _ := testRuntimeKey(t)
	fp := fingerprintOf(pub)
	valid := fp + ":" + base64.StdEncoding.EncodeToString(pub)

	keys, err := ParseApprovedRuntimeKeys(valid)
	if err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if !keys[fp].Equal(pub) {
		t.Fatal("parsed key mismatch")
	}

	// A fingerprint that does not match the key is rejected — the
	// deployment's declared identity must be the real key.
	other := strings.Repeat("0", 64) + ":" + base64.StdEncoding.EncodeToString(pub)
	if _, err := ParseApprovedRuntimeKeys(other); err == nil {
		t.Fatal("fingerprint/key mismatch must fail")
	}
	if _, err := ParseApprovedRuntimeKeys("not-a-key-entry"); err == nil {
		t.Fatal("malformed entry must fail")
	}
	if keys, err := ParseApprovedRuntimeKeys(""); keys != nil || err != nil {
		t.Fatal("empty input must produce no map and no error")
	}
}

// ─── Socket-level handshake ─────────────────────────────────────────

// attestHandshake drives the two-round handshake over the wire and
// returns the bound session ID.
func attestHandshake(t *testing.T, socketPath string, priv ed25519.PrivateKey, id RuntimeIdentity) string {
	t.Helper()

	// Round 1: challenge.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFrame(conn, map[string]string{"type": attestChallengeType})
	var ch challengeResponse
	readJSONFrame(t, conn, &ch)
	conn.Close()
	if ch.SessionID == "" || ch.Nonce == "" {
		t.Fatalf("challenge response incomplete: %+v", ch)
	}

	// Round 2: signed attestation.
	conn, err = net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writeJSONFrame(conn, attestRequest{
		Type:            attestType,
		SessionID:       ch.SessionID,
		RuntimeIdentity: id,
		Signature:       AttestSignature(priv, ch.SessionID, ch.Nonce, id),
	})
	var ar attestResponse
	readJSONFrame(t, conn, &ar)
	if ar.Status != "attested" {
		t.Fatalf("attestation denied: %s", ar.Error)
	}
	if ar.RuntimeIdentityDigest != id.Digest() {
		t.Fatalf("identity digest mismatch: %s vs %s", ar.RuntimeIdentityDigest, id.Digest())
	}
	return ch.SessionID
}

func readJSONFrame(t *testing.T, conn net.Conn, v any) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	lenBuf := make([]byte, 4)
	if _, err := readFull(conn, lenBuf); err != nil {
		t.Fatal(err)
	}
	n := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	buf := make([]byte, n)
	if _, err := readFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf, v); err != nil {
		t.Fatal(err)
	}
}

func TestServiceAttestationEndToEnd(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}
	counter := NewCounterHandler()
	service := setupServiceWithGrants(registry, NewMultiHandler(map[string]Handler{
		"test-counter": counter,
	}), socketPath)
	pub, priv, id := testRuntimeKey(t)
	service.SetAttestation(strictPolicyFor(pub))
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	// Unattested invocation is denied under the required policy.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	resp := sendRequest(t, conn, Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"e2e","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: "e2e-1",
	})
	conn.Close()
	if resp.Status != StatusDenied {
		t.Fatalf("unattested request must be denied, got %s", resp.Status)
	}

	// Handshake then an attested invocation succeeds.
	sid := attestHandshake(t, socketPath, priv, id)
	conn, err = net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"e2e","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: "e2e-1",
		Session:        &RequestSession{ID: sid},
	}
	req.Session.Proof = SessionProof(priv, req)
	resp = sendRequest(t, conn, req)
	if resp.Status != StatusSucceeded {
		t.Fatalf("attested request must succeed, got %s: %s", resp.Status, resp.Error)
	}
	if counter.GetCount("e2e") != 1 {
		t.Fatalf("expected counter=1, got %d", counter.GetCount("e2e"))
	}
}

func TestServiceAttestationForgedProofDenied(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := setupServiceWithGrants(registry, NewMultiHandler(map[string]Handler{
		"test-counter": NewCounterHandler(),
	}), socketPath)
	pub, priv, id := testRuntimeKey(t)
	service.SetAttestation(strictPolicyFor(pub))
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	sid := attestHandshake(t, socketPath, priv, id)

	// A proof signed by a different key cannot verify.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"forged","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: "forged-1",
		Session:        &RequestSession{ID: sid},
	}
	req.Session.Proof = SessionProof(attacker, req)
	resp := sendRequest(t, conn, req)
	if resp.Status != StatusDenied {
		t.Fatalf("forged proof must be denied, got %s", resp.Status)
	}
}

func TestClientAttestAndInvoke(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}
	counter := NewCounterHandler()
	service := setupServiceWithGrants(registry, NewMultiHandler(map[string]Handler{
		"test-counter": counter,
	}), socketPath)
	pub, priv, id := testRuntimeKey(t)
	service.SetAttestation(strictPolicyFor(pub))
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	client := NewClient(socketPath, ClientOptions{})
	sid, err := client.Attest(context.Background(), priv, id)
	if err != nil {
		t.Fatalf("client attestation: %v", err)
	}
	if sid == "" {
		t.Fatal("attestation must return a session id")
	}
	resp, err := client.Invoke(context.Background(), Request{
		Capability:     "test.counter.increment",
		Arguments:      json.RawMessage(`{"counter":"client-e2e","by":1}`),
		Authority:      RequestAuthority{Principal: "alice@example.com", AuthorityRef: "grant_123"},
		IdempotencyKey: "client-e2e-1",
	})
	if err != nil {
		t.Fatalf("attested invoke: %v", err)
	}
	if resp.Status != StatusSucceeded {
		t.Fatalf("attested invoke must succeed, got %s: %s", resp.Status, resp.Error)
	}
	if counter.GetCount("client-e2e") != 1 {
		t.Fatalf("expected counter=1, got %d", counter.GetCount("client-e2e"))
	}
}

func TestAttestationRefusedWhenUnconfigured(t *testing.T) {
	socketPath := testSocketPath(t)
	registry := capability.NewRegistry()
	if err := RegisterEchoCapability(registry); err != nil {
		t.Fatal(err)
	}
	service := setupServiceWithGrants(registry, NewMultiHandler(map[string]Handler{
		"system": NewEchoHandler(),
	}), socketPath)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writeJSONFrame(conn, map[string]string{"type": attestChallengeType})
	var ar attestResponse
	readJSONFrame(t, conn, &ar)
	if ar.Status != "error" || !strings.Contains(ar.Error, "not configured") {
		t.Fatalf("unconfigured attestation must be refused, got %+v", ar)
	}
}

// ─── Session peer binding ───────────────────────────────────────────

// seedBoundSession attests and then writes the kernel-supplied peer
// binding onto the stored session — the same binding attest() writes
// when the handshake rides a real Unix connection.
func seedBoundSession(t *testing.T, reg *attestationRegistry, priv ed25519.PrivateKey, id RuntimeIdentity, uid uint32, exe string) string {
	t.Helper()
	sid, _ := completeHandshake(t, reg, priv, id)
	reg.mu.Lock()
	sess := reg.sessions[sid]
	sess.uid, sess.hasUID, sess.exe = uid, true, exe
	reg.sessions[sid] = sess
	reg.mu.Unlock()
	return sid
}

func TestSessionPeerBinding(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	sid := seedBoundSession(t, reg, priv, id, 501, "/usr/local/bin/nemo-relay")
	req := attestedRequest(sid, priv)

	// The attesting caller: same UID, same executable — admitted.
	if _, err := reg.verifyRequest(
		PeerCredentials{UID: 501, PID: 100, ExePath: "/usr/local/bin/nemo-relay"}, nil, req); err != nil {
		t.Fatalf("the attesting caller's own credentials must admit: %v", err)
	}
	// A same-UID sibling binary must not ride the session.
	if _, err := reg.verifyRequest(
		PeerCredentials{UID: 501, PID: 200, ExePath: "/tmp/sibling"}, nil, req); err == nil {
		t.Fatal("a same-uid sibling executable must not ride the session")
	}
	// A different UID is denied even when the executable matches.
	if _, err := reg.verifyRequest(
		PeerCredentials{UID: 999, PID: 300, ExePath: "/usr/local/bin/nemo-relay"}, nil, req); err == nil {
		t.Fatal("a foreign uid must not ride the session")
	}
	// A platform that cannot name the executable cannot disprove the
	// binding, but it cannot satisfy it either — a bound session only
	// rides a connection whose peer evidence matches.
	if _, err := reg.verifyRequest(
		PeerCredentials{UID: 501}, nil, req); err == nil {
		t.Fatal("a peer with no executable evidence must not satisfy an executable-bound session")
	}
	// Unresolvable peer credentials deny outright.
	if _, err := reg.verifyRequest(
		PeerCredentials{}, errors.New("peer credentials unsupported"), req); err == nil {
		t.Fatal("unresolvable peer credentials must deny a bound session")
	}
}

func TestSessionUIDOnlyBinding(t *testing.T) {
	pub, priv, id := testRuntimeKey(t)
	reg := newAttestationRegistry(strictPolicyFor(pub))
	// A session attested where the kernel reports UID only (BSD):
	// executable is not part of the binding.
	sid := seedBoundSession(t, reg, priv, id, 501, "")
	req := attestedRequest(sid, priv)
	if _, err := reg.verifyRequest(PeerCredentials{UID: 501}, nil, req); err != nil {
		t.Fatalf("uid-bound session must admit its uid regardless of executable: %v", err)
	}
	if _, err := reg.verifyRequest(PeerCredentials{UID: 502, ExePath: "/anything"}, nil, req); err == nil {
		t.Fatal("a foreign uid must not ride a uid-bound session")
	}
}

// setupServiceWithGrants is defined in service_test.go.
