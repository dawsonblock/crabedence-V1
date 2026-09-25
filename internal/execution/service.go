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
}

// NewService creates a new execution service.
func NewService(registry *capability.Registry, handler Handler, socketPath string) *Service {
	return &Service{
		registry:      registry,
		handler:       handler,
		socketPath:    socketPath,
		grantResolver: capability.NoopGrantResolver{},
	}
}

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

// Stop closes the listener and stops accepting connections.
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	if s.listener != nil {
		s.listener.Close()
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

		go s.handleConnection(ctx, conn)
	}
}

func (s *Service) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Bound the whole connection: one request, one response, no
	// indefinite holds.
	_ = conn.SetDeadline(time.Now().Add(connectionLifetime))

	// Read 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > maxMessageBytes {
		s.writeResponse(conn, Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       "message too large",
		})
		return
	}

	// Read message body
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msgBuf); err != nil {
		return
	}

	// Parse request under the strict invocation ABI: duplicate keys,
	// explicit nulls, unknown fields, invalid UTF-8, excessive nesting,
	// and trailing data are refused before admission ever sees the
	// request.
	req, err := parseInvocationRequest(msgBuf)
	if err != nil {
		s.writeResponse(conn, Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       fmt.Sprintf("invalid request: %v", err),
		})
		return
	}

	// ─── Peer authentication ────────────────────────────────────────────
	// When the deployment configures a UID→principal map, the caller's
	// principal is not merely claimed: the kernel supplies the peer UID
	// and the claim must agree with the mapping. The authenticated
	// principal replaces the claim for everything downstream — admission,
	// grant resolution, and the durable execution record — so authority
	// binds to a kernel-authenticated identity, not a string the client
	// wrote.
	if s.peerAuth != nil {
		principal, err := s.peerAuth.authenticatePeer(conn, req.Authority.Principal)
		if err != nil {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureAdmissionDenied),
				Error:       "peer authentication failed: " + err.Error(),
			})
			return
		}
		req.Authority.Principal = principal
	}

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
		})
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
				Error: fmt.Sprintf("capability %s requires adapter %q, which is not available in this deployment (reason=%s: %s)",
					req.Capability, desc.AdapterID, status, reason),
			})
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
			})
			return
		}
		if time.Now().After(deadline) {
			s.writeResponse(conn, Response{
				Status:      StatusDenied,
				FailureCode: string(capability.FailureAdmissionDenied),
				Error:       "deadline expired",
			})
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
			})
			return
		}
	}

	// Verify authority (grant resolution)
	var resolvedGrant *capability.Grant
	if decision.Descriptor.AuthorityPolicy.GrantRequired {
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
			})
			return
		}
		resolvedGrant = grant
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

	s.writeResponse(conn, response)
}

func (s *Service) writeResponse(conn net.Conn, resp Response) {
	payload, err := json.Marshal(resp)
	if err != nil {
		log.Printf("execution service: marshal error: %v", err)
		return
	}

	// A response that cannot be framed must never be written as a
	// truncated frame: replace it with an error response the caller can
	// parse.
	if len(payload) > maxMessageBytes {
		payload, err = json.Marshal(Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("response exceeds the %d-byte frame bound", maxMessageBytes),
		})
		if err != nil {
			log.Printf("execution service: marshal error: %v", err)
			return
		}
	}

	// Set write deadline to prevent blocking on hung clients
	if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
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

// connectionLifetime bounds a whole client connection: one request, one
// response, no indefinite holds.
const connectionLifetime = 60 * time.Second

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
