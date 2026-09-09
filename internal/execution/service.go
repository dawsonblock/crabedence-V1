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
// AuthorityRef is an opaque reference to authority material — today
// a grant ID, tomorrow a capability token, workload identity, or
// signed assertion. The ABI does not prescribe the authority mechanism.
type RequestAuthority struct {
	Principal    string `json:"principal"`
	AuthorityRef string `json:"authority_ref"`
	// GrantID is accepted for backward compatibility and mapped to AuthorityRef.
	GrantID string `json:"grant_id,omitempty"`
}

// Response is the wire-format execution response.
type Response struct {
	Status      string          `json:"status"`
	FailureCode string          `json:"failure_code,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	Evidence    *EvidenceRef    `json:"evidence,omitempty"`
	Execution   *ExecutionMeta  `json:"execution,omitempty"`
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

// SetGrantResolver sets the grant resolver for authority verification.
func (s *Service) SetGrantResolver(resolver capability.GrantResolver) {
	s.grantResolver = resolver
}

// Start begins listening on the Unix socket.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	// Remove existing socket
	if _, err := os.Stat(s.socketPath); err == nil {
		os.Remove(s.socketPath)
	}

	// Ensure socket directory exists with restrictive permissions
	if dir := filepath.Dir(s.socketPath); dir != "" && dir != "." {
		os.MkdirAll(dir, 0o700)
		os.Chmod(dir, 0o700)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.socketPath, err)
	}

	// Restrict socket access to owner only
	os.Chmod(s.socketPath, 0o600)

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
			continue
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *Service) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}

	msgLen := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	if msgLen > 4*1024*1024 {
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

	// Parse request
	var req Request
	if err := json.Unmarshal(msgBuf, &req); err != nil {
		s.writeResponse(conn, Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       fmt.Sprintf("invalid JSON: %v", err),
		})
		return
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

	// Verify authority (grant resolution)
	if decision.Descriptor.AuthorityPolicy.GrantRequired {
		fc, reason := s.registry.VerifyAuthority(ctx, capability.AdmissionRequest{
			Capability: req.Capability,
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
	}

	// Check deadline
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

	// Dispatch to handler
	response := s.handler.Execute(ctx, req, decision.Descriptor)

	// Validate CRITICAL evidence
	if decision.Descriptor.ExecutionClass.RequiresEvidence() && response.Status == StatusSucceeded {
		if response.Evidence == nil || response.Evidence.Digest == "" {
			response = Response{
				Status:      StatusFailed,
				FailureCode: string(capability.FailureExecutionFailed),
				Error:       "CRITICAL capability returned SUCCEEDED without evidence digest",
				Execution:   response.Execution,
			}
		} else if !isValidEvidenceDigest(response.Evidence.Digest) {
			response = Response{
				Status:      StatusFailed,
				FailureCode: string(capability.FailureExecutionFailed),
				Error:       "CRITICAL capability returned invalid evidence digest (must be 64-char lowercase hex)",
				Execution:   response.Execution,
			}
		} else if response.Evidence.ReceiptVersion != 3 {
			response = Response{
				Status:      StatusFailed,
				FailureCode: string(capability.FailureExecutionFailed),
				Error:       fmt.Sprintf("CRITICAL capability returned receipt_version %d (must be 3)", response.Evidence.ReceiptVersion),
				Execution:   response.Execution,
			}
		} else if response.Execution == nil || response.Execution.RunID == "" {
			response = Response{
				Status:      StatusFailed,
				FailureCode: string(capability.FailureExecutionFailed),
				Error:       "CRITICAL capability returned SUCCEEDED without run_id",
			}
		}
	}

	s.writeResponse(conn, response)
}

func (s *Service) writeResponse(conn net.Conn, resp Response) {
	payload, err := json.Marshal(resp)
	if err != nil {
		log.Printf("execution service: marshal error: %v", err)
		return
	}

	// Set write deadline to prevent blocking on hung clients
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(payload) >> 24)
	lenBuf[1] = byte(len(payload) >> 16)
	lenBuf[2] = byte(len(payload) >> 8)
	lenBuf[3] = byte(len(payload))

	conn.Write(lenBuf)
	conn.Write(payload)
}

// isValidEvidenceDigest checks that a digest is a 64-character lowercase
// hexadecimal SHA-256 digest.
func isValidEvidenceDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
