// Package execution provides the persistent Crabedence execution service.
//
// This is the long-lived Go process that owns the Unix socket and handles
// execution requests from NeMo. It replaces the per-call subprocess bridge
// with a persistent RPC connection.
//
// The service owns:
//   - Capability registry (authoritative execution classes)
//   - Authority verification
//   - Durable idempotency (PostgreSQL-backed)
//   - Provider dispatch
//   - Evidence generation and V3 receipt signing
//   - Reconciliation
package execution

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// Request is the wire-format capability invocation.
// This is the Capability Invocation ABI (see docs/spec/capability-invocation-abi.md).
// The semantic contract is stable; the transport is replaceable.
type Request struct {
	Capability     string           `json:"capability"`
	Arguments      json.RawMessage  `json:"arguments"`
	Authority      RequestAuthority `json:"authority"`
	ExecutionClass string           `json:"execution_class,omitempty"` // advisory; registry is authoritative
	IdempotencyKey string           `json:"idempotency_key,omitempty"`
	Deadline       string           `json:"deadline,omitempty"`
	// Mediation carries caller-declared middleware provenance — the
	// middleware set that ran and the pre-mediation argument digest.
	// It is evidence, never a policy input: it binds into the request
	// digest and is persisted on the durable record, but cannot select
	// route, provider, assurance, or authority.
	Mediation *RequestMediation `json:"mediation,omitempty"`
	// Session carries the runtime-attestation binding: the session ID
	// issued by the challenge/attest handshake and the runtime's
	// proof-of-possession signature for THIS request. Like
	// AuthorityGeneration it is caller-supplied material the server
	// verifies — it grants nothing by itself.
	Session *RequestSession `json:"session,omitempty"`
	// Attestation is the server-verified runtime identity resolved
	// from Session — assigned by the service after proof verification,
	// never trusted from the wire. It is provenance bound onto the
	// durable execution record.
	Attestation *AttestedRuntime `json:"-"`
	// Peer is the kernel-supplied local-caller evidence resolved once
	// per connection — assigned by the service, never trusted from the
	// wire. It is provenance bound onto the durable execution record.
	Peer *PeerEvidence `json:"-"`
}

// RequestSession is the caller-supplied attestation binding.
type RequestSession struct {
	ID    string `json:"id"`
	Proof string `json:"proof"`
}

// AttestedRuntime is the verified runtime provenance bound onto the
// durable record — the attested session ID and the digest of the
// runtime identity that attested it.
type AttestedRuntime struct {
	SessionID      string
	IdentityDigest string
	KeyFingerprint string
}

// RequestAuthority carries the principal and authority reference.
// AuthorityRef is an unguessable bearer reference to authority
// material — today a grant ID, tomorrow a capability token, workload
// identity, or signed assertion. Possession of the reference plus a
// Principal matching the resolved material is the complete
// authorization proof. Treat the reference as a credential — it must
// never be logged or exposed. The ABI does not prescribe the authority
// mechanism.
//
// Principal is a claim unless the deployment enables peer
// authentication (CRABEDENCE_PEER_PRINCIPALS): then the kernel-supplied
// Unix peer UID is mapped to a principal and the claim must agree —
// the authenticated value replaces the claim before admission.
type RequestAuthority struct {
	Principal    string `json:"principal"`
	AuthorityRef string `json:"authority_ref"`
	// GrantID is accepted for backward compatibility and mapped to AuthorityRef.
	GrantID string `json:"grant_id,omitempty"`
	// AuthorityGeneration and AuthorityDigest bind the exact immutable
	// authority material that admitted this request into the execution
	// identity (request digest). They are SERVER-ASSIGNED after grant
	// resolution — the service overwrites whatever the caller sent —
	// so a caller can neither forge authority binding nor omit it.
	// Zero values mean no grant-bound authority (in-memory resolvers,
	// grant-free capabilities).
	AuthorityGeneration int64  `json:"authority_generation,omitempty"`
	AuthorityDigest     string `json:"authority_digest,omitempty"`
}

// RequestMediation is the caller-declared middleware provenance object
// the NEMO runtime attaches when middleware (including trusted native
// plugins) mediated the invocation. MiddlewareSetDigest names the exact
// middleware set that ran — activated plugin identities, registration
// descriptors, activation configuration, and host identity.
// OriginalArgsDigest is the canonical digest of the arguments before
// middleware rewrote them. ReleaseRootDigest names the component
// manifest of the qualified distribution the runtime shipped in, when
// it runs inside one. Both required fields mirror the Rust ABI, which
// rejects a mediation object that omits them.
type RequestMediation struct {
	MiddlewareSetDigest    string `json:"middleware_set_digest"`
	OriginalArgsDigest     string `json:"original_args_digest"`
	ReleaseRootDigest      string `json:"release_root_digest,omitempty"`
	PluginManifestSHA256   string `json:"plugin_manifest_sha256,omitempty"`
	PluginLibrarySHA256    string `json:"plugin_library_sha256,omitempty"`
	ActivationConfigSHA256 string `json:"activation_config_sha256,omitempty"`
}

// Response is the wire-format execution response.
type Response struct {
	Status      string          `json:"status"`
	FailureCode string          `json:"failure_code,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	Evidence    *EvidenceRef    `json:"evidence,omitempty"`
	Execution   *ExecutionMeta  `json:"execution,omitempty"`

	// DefinitiveFailure indicates that a FAILED response is a
	// definitive failure — the handler asserts no external side
	// effect occurred. This is required for a FAILED response after
	// the dispatch boundary (IN_FLIGHT) to be persisted as StateFailed
	// rather than StateUnknown. If false (the default), a FAILED
	// response after dispatch is treated as UNKNOWN (post-dispatch
	// uncertainty) per the durable execution contract §6.
	//
	// For CRITICAL operations, this flag alone is NOT sufficient —
	// the Store enforces proof requirements (evidence digest,
	// receipt_version 3, provider_id, provider_run_id) inside
	// Finalize(). The flag is a routing signal; the proof is in
	// the receipt fields.
	DefinitiveFailure bool `json:"definitive_failure,omitempty"`

	// EvidenceArtifact carries the provider evidence bytes the digest
	// is computed FROM — e.g. the raw provider response body or the
	// provider operation record. Crabedence recomputes
	// sha256(EvidenceArtifact) itself before attesting or persisting
	// an evidence digest; a handler-supplied digest string is never
	// signed. For CRITICAL executions a terminal outcome without an
	// artifact cannot be attested and fails closed to UNKNOWN.
	// Transient: never serialized to the wire or the ledger.
	EvidenceArtifact []byte `json:"-"`

	// Dispatch carries the outbound transport's dispatch provenance —
	// how far the provider request actually got and, for failures, the
	// classified cause — so an UNKNOWN transition records WHY it is
	// ambiguous rather than a bare fact of ambiguity. Transient: set
	// by the trusted transport, consumed by the executor's observation
	// ledger, never serialized.
	Dispatch *DispatchProvenance `json:"-"`
}

// DispatchProvenance is the ambiguity provenance one outbound dispatch
// produced: the furthest milestone reached and the classified cause.
// It distinguishes "provably never dispatched" (definite no-effect)
// from every shape of post-dispatch uncertainty.
type DispatchProvenance struct {
	// Milestone is the furthest dispatch milestone reached
	// (providertransport.DispatchMilestone).
	Milestone string
	// Cause is the classified ambiguity cause
	// (providertransport.AmbiguityCause).
	Cause string
}

// EvidenceRef is the evidence reference returned to the caller.
type EvidenceRef struct {
	Digest         string `json:"digest"`
	ReceiptVersion int    `json:"receipt_version,omitempty"`
}

// ExecutionMeta is execution metadata.
type ExecutionMeta struct {
	Provider string `json:"provider"`
	RunID    string `json:"run_id"`
}

// EffectiveAuthorityRef returns the authority reference, preferring
// authority_ref and falling back to grant_id for backward compatibility.
func (a RequestAuthority) EffectiveAuthorityRef() string {
	if a.AuthorityRef != "" {
		return a.AuthorityRef
	}
	return a.GrantID
}

// Status values.
const (
	StatusSucceeded = "SUCCEEDED"
	StatusFailed    = "FAILED"
	StatusDenied    = "DENIED"
	StatusUnknown   = "UNKNOWN"
	StatusInFlight  = "IN_FLIGHT"
)

// Handler dispatches an admitted execution request to the provider.
type Handler interface {
	Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response
}

// Admission ceilings. The connection ceiling bounds simultaneously
// open connections (and therefore handler goroutines, memory, and file
// descriptors); the handshake ceiling is a smaller, separate bound on
// the unauthenticated phase — attestation handshakes and peer
// authentication — whose work (signature verification, session
// bookkeeping) an unauthenticated peer can trigger.
const (
	DefaultMaxConnections          = 64
	DefaultMaxHandshakeConnections = 16
	// DefaultCheckpointInterval paces the periodic signed evidence
	// checkpoint the service emits when CRABEDENCE_CHECKPOINT_PATH is
	// configured.
	DefaultCheckpointInterval = 5 * time.Minute
	// refusalWorkerLimit bounds concurrently delivered BUSY refusals:
	// refusing a connection means consuming its frame so the client can
	// read the answer, and that work is bounded like any other.
	refusalWorkerLimit = 8
	// headerReadTimeout bounds the length prefix of a request: a
	// connection that does not speak is a slowloris attempt, not a
	// request. The body keeps the full request lifetime.
	headerReadTimeout = 5 * time.Second
	// busyWriteTimeout bounds delivering a refusal.
	busyWriteTimeout = 5 * time.Second
	// shutdownDrainTimeout bounds how long Stop waits for in-flight
	// handlers before returning.
	shutdownDrainTimeout = 5 * time.Second
)

// Service is the persistent Crabedence execution service.
type Service struct {
	registry      *capability.Registry
	handler       Handler
	socketPath    string
	listener      net.Listener
	mu            sync.Mutex
	running       bool
	grantResolver capability.GrantResolver
	// adapterAvailability is the deployment's runtime adapter state. It
	// is nil when the caller did not declare one (tests that construct
	// the service directly); production always sets it.
	adapterAvailability capability.AdapterAvailability
	// peerAuth, when non-nil, enforces UID→principal authentication on
	// every connection: the kernel-supplied peer UID must be mapped and
	// the claimed principal must agree with the mapping. nil preserves
	// the bearer model's claimed principal (single-user local socket).
	peerAuth PeerPrincipalMap
	// attestation, when non-nil, is the runtime-attestation registry:
	// challenges, verified sessions, and the deployment policy. nil
	// means attestation is disabled (a non-required deployment); the
	// handshake messages are refused rather than answered.
	attestation *attestationRegistry
	// connSlots bounds simultaneously open connections; handshakeSlots
	// bounds the unauthenticated phase. Both are acquired before the
	// work they bound and released after it.
	connSlots      chan struct{}
	handshakeSlots chan struct{}
	refusalSlots   chan struct{}
	// handlers tracks in-flight connection handlers so Stop can drain
	// them instead of abandoning admitted work mid-flight.
	handlers sync.WaitGroup
	// drainTimeout bounds the Stop drain; overridable in tests.
	drainTimeout time.Duration
	// acceptGate, when non-nil, runs in the accept loop after a
	// connection is accepted and its slot acquired but before its
	// handler registers with the drain group — the exact window a
	// racing Stop must own. It exists so the shutdown-barrier
	// regression can hold a connection inside that window
	// deterministically; nil in production.
	acceptGate func()
}

// NewService creates a new execution service.
func NewService(registry *capability.Registry, handler Handler, socketPath string) *Service {
	return &Service{
		registry:       registry,
		handler:        handler,
		socketPath:     socketPath,
		grantResolver:  capability.NoopGrantResolver{},
		connSlots:      make(chan struct{}, DefaultMaxConnections),
		handshakeSlots: make(chan struct{}, DefaultMaxHandshakeConnections),
		refusalSlots:   make(chan struct{}, refusalWorkerLimit),
		drainTimeout:   shutdownDrainTimeout,
	}
}

// SetAdmissionLimits overrides the admission ceilings. Call it before
// Start. Non-positive values leave the corresponding default in place;
// production resolves both from the validated deployment configuration
// (CRABEDENCE_MAX_CONNECTIONS, CRABEDENCE_MAX_HANDSHAKES).
func (s *Service) SetAdmissionLimits(connections, handshakes int) {
	if connections > 0 {
		s.connSlots = make(chan struct{}, connections)
	}
	if handshakes > 0 {
		s.handshakeSlots = make(chan struct{}, handshakes)
	}
}

// tryAcquireConnection takes one connection slot without waiting.
func (s *Service) tryAcquireConnection() bool {
	select {
	case s.connSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Service) releaseConnection() { <-s.connSlots }

// tryAcquireHandshake takes one unauthenticated-phase slot without
// waiting.
func (s *Service) tryAcquireHandshake() bool {
	select {
	case s.handshakeSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Service) releaseHandshake() { <-s.handshakeSlots }

// SetAdapterAvailability declares which adapters this deployment wired.
// A known capability whose adapter is not AVAILABLE fails as
// CAPABILITY_UNAVAILABLE at the deployment boundary, before dispatch.
func (s *Service) SetAdapterAvailability(availability capability.AdapterAvailability) {
	s.adapterAvailability = availability
}

// SetGrantResolver sets the grant resolver for authority verification.
func (s *Service) SetGrantResolver(resolver capability.GrantResolver) {
	s.grantResolver = resolver
}

// SetPeerAuth enables strict UID→principal peer authentication. When
// set, every request's principal claim is verified against the
// kernel-supplied peer UID; the authenticated principal replaces the
// claim for admission, grant resolution, and the durable record.
func (s *Service) SetPeerAuth(m PeerPrincipalMap) {
	s.peerAuth = m
}

// SetAttestation enables the runtime-attestation handshake and session
// verification under the deployment's policy. When policy.Required is
// set, every invocation must carry a valid attested-session proof.
func (s *Service) SetAttestation(policy AttestationPolicy) {
	s.attestation = newAttestationRegistry(policy)
}

// Start begins listening on the Unix socket.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	// Secure the socket directory and clear any stale socket before
	// listening. Both steps fail closed: a path that cannot be
	// secured, or that is not provably a stale socket owned by the
	// current user, is never removed.
	if dir := filepath.Dir(s.socketPath); dir != "" && dir != "." {
		if err := ensureSocketDir(dir); err != nil {
			return err
		}
	}
	if err := clearStaleSocket(s.socketPath); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.socketPath, err)
	}

	// Restrict socket access to owner only, and verify the result — a
	// socket that cannot be proven owner-only must not serve.
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		listener.Close()
		return fmt.Errorf("secure socket permissions on %s: %w", s.socketPath, err)
	}
	if err := verifySocketFile(s.socketPath); err != nil {
		listener.Close()
		os.Remove(s.socketPath)
		return err
	}

	s.listener = listener
	s.running = true

	go s.acceptLoop(ctx)

	return nil
}

// Stop closes the listener, stops accepting connections, and drains
// in-flight handlers (bounded by the drain timeout) so a shutdown does
// not abandon admitted work mid-flight. A dispatch that outlives the
// drain is not silently lost: its durable record is already in flight
// state for reconciliation, which is the designed recovery path.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}

	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Unlock()

	drained := make(chan struct{})
	go func() {
		s.handlers.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(s.drainTimeout):
	}
	os.Remove(s.socketPath)

	return nil
}

func (s *Service) acceptLoop(ctx context.Context) {
	// A persistent accept error (EMFILE, ENFILE, a transient kernel
	// condition) must not become a hot spin that pegs a core and floods
	// the log. Mirror net/http: back off exponentially on consecutive
	// failures, resetting after a successful accept.
	const (
		acceptBackoffMin = 5 * time.Millisecond
		acceptBackoffMax = time.Second
	)
	backoff := acceptBackoffMin
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if !running {
				return
			}
			log.Printf("execution service: accept error: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > acceptBackoffMax {
				backoff = acceptBackoffMax
			}
			continue
		}
		backoff = acceptBackoffMin

		// Bound admission before any goroutine exists: a connection at
		// the ceiling is refused explicitly — a definitive pre-dispatch
		// denial — instead of spawning unbounded handlers.
		if !s.tryAcquireConnection() {
			s.refuseBusyConnection(conn, "the execution service is at its connection ceiling")
			continue
		}
		if s.acceptGate != nil {
			s.acceptGate()
		}
		s.handlers.Add(1)
		go func() {
			defer s.handlers.Done()
			s.handleConnection(ctx, conn)
		}()
	}
}

func (s *Service) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer s.releaseConnection()

	start := time.Now()
	// The length prefix must arrive promptly: a connection that never
	// speaks is a slowloris attempt, not a request. The body keeps the
	// full request lifetime.
	_ = conn.SetReadDeadline(start.Add(headerReadTimeout))

	// Read 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > maxMessageBytes {
		s.writeResponse(conn, Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             "message too large",
			DefinitiveFailure: true,
		}, "")
		return
	}

	// Read message body
	_ = conn.SetReadDeadline(start.Add(connectionLifetime))
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msgBuf); err != nil {
		return
	}

	// The unauthenticated phase — the attestation handshake, request
	// parsing, attestation verification, and peer authentication — is
	// bounded by a smaller, separate ceiling: it is the work an
	// unauthenticated peer can trigger. The slot is released once the
	// caller is authenticated (or the deployment authenticates nobody),
	// before admission and dispatch.
	if !s.tryAcquireHandshake() {
		s.refuseUnauthenticated(conn, msgBuf)
		return
	}
	handshakeHeld := true
	defer func() {
		if handshakeHeld {
			s.releaseHandshake()
		}
	}()

	// Attestation handshake messages are dispatched before the strict
	// invocation ABI — they are service frames, not capability
	// invocations. A handshake message when attestation is unconfigured
	// is refused, not ignored.
	if t := messageType(msgBuf); t == attestChallengeType || t == attestType {
		if s.attestation == nil {
			writeJSONFrame(conn, attestResponse{Status: "error", Error: "runtime attestation is not configured on this service"})
			return
		}
		s.handleAttestation(conn, msgBuf, t)
		return
	}

	// Parse request under the strict invocation ABI: duplicate keys,
	// explicit nulls, unknown fields, invalid UTF-8, excessive nesting,
	// and trailing data are refused before admission ever sees the
	// request.
	req, err := parseInvocationRequest(msgBuf)
	if err != nil {
		s.writeResponse(conn, Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             fmt.Sprintf("invalid request: %v", err),
			DefinitiveFailure: true,
		}, "")
		return
	}

	// ─── Local-caller evidence ─────────────────────────────────────────
	// Resolve the kernel-supplied peer credentials once: the same
	// snapshot feeds the attestation session binding, peer principal
	// authentication, and the durable provenance record — the recorded
	// caller is exactly the caller that was authenticated.
	peerCreds, peerErr := unixPeerCredentials(conn)
	if peerErr == nil {
		req.Peer = peerCreds.Evidence()
	}

	// ─── Peer authentication ────────────────────────────────────────────
	// When the deployment configures a UID→principal map, the caller's
	// principal is not merely claimed: the kernel supplies the peer UID
	// and the claim must agree with the mapping. The authenticated
	// principal replaces the claim for everything downstream — admission,
	// grant resolution, and the durable execution record — so authority
	// binds to a kernel-authenticated identity, not a string the client
	// wrote.
	// ─── Runtime attestation ──────────────────────────────────────────
	// Verified before peer authentication: the proof signs the request
	// exactly as the runtime sent it, and peer authentication rewrites
	// the principal claim — verifying after the rewrite would deny a
	// correctly signed request. The session must exist, be unexpired,
	// be bound to this connection's peer UID, and carry a valid
	// proof-of-possession for this request. The verified identity — not
	// the caller's claim — becomes the execution's runtime provenance.
	if s.attestation != nil {
		sess, err := s.attestation.verifyRequest(peerCreds, peerErr, req)
		if err != nil {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureAdmissionDenied),
				Error:       "runtime attestation failed: " + err.Error(),
			}, "")
			return
		}
		if sess != nil {
			req.Attestation = &AttestedRuntime{
				SessionID:      req.Session.ID,
				IdentityDigest: sess.digest,
				KeyFingerprint: sess.fingerprint,
			}
		}
	}

	if s.peerAuth != nil {
		principal, err := s.peerAuth.authenticatePeer(peerCreds, peerErr, req.Authority.Principal)
		if err != nil {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureAdmissionDenied),
				Error:       "peer authentication failed: " + err.Error(),
			}, "")
			return
		}
		req.Authority.Principal = principal
	}

	// The caller is authenticated (or this deployment authenticates
	// nobody): release the unauthenticated-phase bound before admission
	// and dispatch.
	s.releaseHandshake()
	handshakeHeld = false

	// Admit the request
	decision := s.registry.Admit(capability.AdmissionRequest{
		Capability:     req.Capability,
		Arguments:      req.Arguments,
		Principal:      req.Authority.Principal,
		GrantID:        req.Authority.EffectiveAuthorityRef(),
		ExecutionClass: req.ExecutionClass,
		IdempotencyKey: req.IdempotencyKey,
		Deadline:       req.Deadline,
	})

	if !decision.Allowed {
		s.writeResponse(conn, Response{
			Status:      StatusDenied,
			FailureCode: string(decision.FailureCode),
			Error:       decision.Reason,
		}, "")
		return
	}

	// ─── Availability: deployment state, checked before dispatch ──────
	// The capability is KNOWN (admission succeeded), but this deployment
	// may not have the adapter wired. That is CAPABILITY_UNAVAILABLE with
	// the adapter's availability status as the machine-readable reason —
	// never CAPABILITY_NOT_FOUND, never a routing or class fallback, and
	// never a dispatch attempt. The dispatch layer re-checks as defense
	// in depth.
	if s.adapterAvailability != nil {
		desc := decision.Descriptor
		if status, reason := s.adapterAvailability.StatusOf(desc.AdapterID); status != capability.AvailabilityAvailable {
			s.writeResponse(conn, Response{
				Status:      StatusFailed,
				FailureCode: string(capability.FailureCapabilityUnavailable),
				// The gate runs before dispatch — no handler ran and no
				// provider was contacted, so no effect is possible for
				// any execution class. Definitive, not UNKNOWN.
				DefinitiveFailure: true,
				Error: fmt.Sprintf("capability %s requires adapter %q, which is not available in this deployment (reason=%s: %s)",
					req.Capability, desc.AdapterID, status, reason),
			}, "")
			return
		}
	}

	// Check deadline before any further validation. An expired deadline
	// means the request is stale — there is no point validating schema or
	// authority for a request the caller already abandoned.
	if req.Deadline != "" {
		deadline, err := time.Parse(time.RFC3339, req.Deadline)
		if err != nil {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureAdmissionDenied),
				Error:       fmt.Sprintf("invalid deadline: %v", err),
			}, "")
			return
		}
		if time.Now().After(deadline) {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureAdmissionDenied),
				Error:       "deadline expired",
			}, "")
			return
		}
	}

	// ─── Argument schema validation ──────────────────────────────────────
	// The capability descriptor may declare a JSON Schema for arguments.
	// If declared, arguments must validate against it before dispatch.
	// An empty schema means no validation. A malformed schema is a
	// registration error and fails closed.
	if len(decision.Descriptor.Schema) > 0 {
		if err := capability.ValidateArguments(decision.Descriptor.Schema, req.Arguments); err != nil {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureInvalidRequest),
				Error:       fmt.Sprintf("argument schema validation failed: %v", err),
			}, "")
			return
		}
	}

	// Verify authority (grant resolution)
	var resolvedGrant *capability.Grant
	if decision.Descriptor.AuthorityPolicy.GrantRequired {
		// A request that names no authority reference asks the service
		// to broker the principal's authority. That is only as strong as
		// the principal's authentication: under the bearer model anyone
		// who can reach the socket could claim a principal holding
		// grants, so the brokered path exists only when the peer map
		// has authenticated who is asking. A caller-supplied reference
		// remains valid — it must still resolve against the
		// (authenticated or claimed) principal.
		if req.Authority.EffectiveAuthorityRef() == "" && s.peerAuth == nil {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureUnauthorized),
				Error: "no authority reference supplied and brokered authority requires peer " +
					"authentication (CRABEDENCE_PEER_PRINCIPALS): without it the principal is an " +
					"unverified claim the service cannot resolve grants against",
			}, "")
			return
		}
		grant, fc, reason := s.registry.VerifyAuthority(ctx, capability.AdmissionRequest{
			Capability: req.Capability,
			Arguments:  req.Arguments,
			Principal:  req.Authority.Principal,
			GrantID:    req.Authority.EffectiveAuthorityRef(),
		}, s.grantResolver)
		if fc != "" {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(fc),
				Error:       reason,
			}, "")
			return
		}
		resolvedGrant = grant
		// The resolved grant's identity is server-determined: when the
		// caller carried no reference, the record binds the grant the
		// store selected, so the durable execution names the authority
		// that actually admitted it.
		if req.Authority.EffectiveAuthorityRef() == "" {
			req.Authority.AuthorityRef = resolvedGrant.ID
		}
	}

	// Bind the verified authority material into the request before
	// dispatch: grant generation + grant digest become part of the
	// execution identity, so the durable record proves which immutable
	// authority admitted it. Server-assigned — caller-supplied values
	// are overwritten whether or not a grant was required.
	req.Authority.AuthorityGeneration = 0
	req.Authority.AuthorityDigest = ""
	if resolvedGrant != nil {
		req.Authority.AuthorityGeneration = resolvedGrant.Generation
		req.Authority.AuthorityDigest = resolvedGrant.Digest
	}

	// Dispatch to handler. The DispatchExecutor handles CRITICAL evidence
	// validation internally — post-dispatch evidence failures become
	// UNKNOWN (not FAILED) per the durable execution contract.
	response := s.handler.Execute(ctx, req, decision.Descriptor)

	s.writeResponse(conn, response, decision.Descriptor.ExecutionClass)
}

// refuseBusyConnection delivers a definitive BUSY response to a
// connection the service cannot admit. The refusal itself is bounded
// work: at most refusalWorkerLimit refusals are in flight, each bounded
// by the header timeout and the frame bound. Beyond that pool the
// connection is closed without a frame — still a pre-dispatch failure,
// because nothing was dispatched and nothing can have happened.
func (s *Service) refuseBusyConnection(conn net.Conn, reason string) {
	select {
	case s.refusalSlots <- struct{}{}:
	default:
		conn.Close()
		return
	}
	go func() {
		defer func() { <-s.refusalSlots }()
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(headerReadTimeout))
		// Consume the request frame (bounded) so the client's write
		// completes and it can read the refusal.
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		if n := binary.BigEndian.Uint32(lenBuf); n <= maxMessageBytes {
			_, _ = io.CopyN(io.Discard, conn, int64(n))
		}
		s.writeBusy(conn, reason)
	}()
}

// refuseUnauthenticated delivers an explicit refusal for a connection
// that could not take an unauthenticated-phase slot, shaped for the
// frame the caller sent.
func (s *Service) refuseUnauthenticated(conn net.Conn, msgBuf []byte) {
	if t := messageType(msgBuf); t == attestChallengeType || t == attestType {
		writeJSONFrame(conn, attestResponse{
			Status: "error",
			Error:  "execution service busy: the attestation handshake ceiling is reached — retry when the backlog drains",
		})
		return
	}
	s.writeBusy(conn, "the authentication and attestation concurrency ceiling is reached")
}

// writeBusy writes a definitive pre-dispatch refusal.
func (s *Service) writeBusy(conn net.Conn, reason string) {
	s.writeResponseDeadline(conn, Response{
		Status:            StatusFailed,
		FailureCode:       string(capability.FailureServiceBusy),
		Error:             "execution service busy: " + reason + " — the request was not dispatched; retry when the backlog drains",
		DefinitiveFailure: true,
	}, "", busyWriteTimeout)
}

// writeResponse writes one framed response. executedClass is the
// resolved execution class of the request whose handler produced resp,
// or "" before admission. A response that cannot be framed must never be
// written as a truncated frame, but the substitute must not manufacture
// a definitive failure either: after a side-effectful execution the
// effect may already have happened and only the wire could not carry the
// result, so a MUTATION/CRITICAL response becomes UNKNOWN. A PURE/READ
// execution can prove no effect occurred, so FAILED stays truthful.
func (s *Service) writeResponse(conn net.Conn, resp Response, executedClass capability.ExecutionClass) {
	s.writeResponseDeadline(conn, resp, executedClass, responseWriteTimeout)
}

func (s *Service) writeResponseDeadline(conn net.Conn, resp Response, executedClass capability.ExecutionClass, writeTimeout time.Duration) {
	payload, err := json.Marshal(resp)
	if err != nil {
		log.Printf("execution service: marshal error: %v", err)
		return
	}

	if len(payload) > maxMessageBytes {
		status, failureCode := StatusFailed, capability.FailureInternalError
		definitive := true
		if executedClass == capability.ClassMutation || executedClass == capability.ClassCritical {
			status, failureCode = StatusUnknown, capability.FailureExecutionUnknown
			definitive = false
		}
		payload, err = json.Marshal(Response{
			Status:            status,
			FailureCode:       string(failureCode),
			Error:             fmt.Sprintf("response exceeds the %d-byte frame bound", maxMessageBytes),
			DefinitiveFailure: definitive,
		})
		if err != nil {
			log.Printf("execution service: marshal error: %v", err)
			return
		}
	}

	// Set write deadline to prevent blocking on hung clients
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		log.Printf("execution service: set write deadline: %v", err)
		return
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if err := writeFull(conn, lenBuf); err != nil {
		log.Printf("execution service: write frame header: %v", err)
		return
	}
	if err := writeFull(conn, payload); err != nil {
		log.Printf("execution service: write frame payload: %v", err)
	}
}

// maxMessageBytes bounds a single framed message in either direction —
// the ABI's declared maximum.
const maxMessageBytes = 4 * 1024 * 1024

// connectionLifetime bounds the BODY side of a client connection: the
// read that must produce one request frame after its length prefix, with
// no indefinite holds. It deliberately does not bound the response: the
// provider budget is minutes, and writeResponse sets its own write
// deadline, so an invocation that finishes after this lifetime still
// delivers its definitive answer rather than stranding the caller with
// an ambiguity it did not have.
const connectionLifetime = 60 * time.Second

// responseWriteTimeout bounds delivering a response to a caller.
const responseWriteTimeout = 30 * time.Second

// writeFull writes the entire buffer. A Unix stream write may accept
// fewer bytes than requested, and a truncated frame would corrupt the
// protocol — short writes are continued, and a zero-byte write is a
// hard error rather than a silent stall.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		p = p[n:]
	}
	return nil
}
