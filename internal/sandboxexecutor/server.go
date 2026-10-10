package sandboxexecutor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// JobRecord is the executor's account of one accepted submission —
// which authenticated submitter sent it, which principal it claims,
// and when it arrived. Records are in-memory in PR-03; the durable
// lifecycle ledger lands with reconciliation in PR-06.
type JobRecord struct {
	JobID      string    `json:"job_id"`
	Submitter  string    `json:"submitter"`
	Principal  string    `json:"principal"`
	Image      string    `json:"image"`
	State      string    `json:"state"`
	ReceivedAt time.Time `json:"received_at"`
}

// JobStateRecorded marks a job the executor accepted into its registry.
// Nothing runs it yet — admission without a signed contract is recorded
// intent, never execution authority.
const JobStateRecorded = "RECORDED"

// maxJobs bounds the in-memory registry. The spike has no eviction or
// durable ledger, so a permitted peer could otherwise grow it without
// limit; refusal is louder than silent memory exhaustion.
const maxJobs = 4096

// Backend is where an authenticated submission would go for execution.
// PR-03 wires no backend — the type exists so the auth boundary is
// exercised against the same call shape the real executor will take.
type Backend interface {
	Submit(job *JobSubmission, submitter string) (string, error)
}

// AuditSink receives one structured line per admission decision —
// accepted or refused — so a silent gate is never silent.
type AuditSink func(format string, args ...any)

// Config is the executor's startup contract.
type Config struct {
	// SocketDir is the owner-only directory the socket lives in.
	SocketDir string
	// Peers maps permitted kernel UIDs to submitter identities.
	// Required — an executor that cannot name its submitter must not run.
	Peers PeerAllowlist
	// Token is the optional shared submission secret. Nil disables the
	// token leg; the startup line reports it so the weaker posture is
	// observable rather than implied.
	Token *SubmissionToken
	// Backend receives authenticated submissions; nil means jobs are
	// recorded but never executed (PR-03's intended state).
	Backend Backend
	// Audit receives decision lines; nil discards them.
	Audit AuditSink
}

// Server is the sandbox executor daemon: a bounded Unix socket that
// accepts job submissions only from kernel-verified peer identities
// carrying the shared submission token. It holds no authority keys,
// cannot mint admissions, and never executes what it cannot record.
type Server struct {
	cfg    Config
	audit  AuditSink
	socket string

	mu       sync.Mutex
	listener *net.UnixListener
	ident    *socketIdentity
	started  bool
	stopped  bool
	acceptWg sync.WaitGroup

	jobs   map[string]*JobRecord
	seq    atomic.Uint64
	closed chan struct{}
}

// NewServer validates the config and returns a runnable server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.SocketDir == "" {
		return nil, fmt.Errorf("socket directory is required")
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("peer allowlist is required — the executor refuses to run without a named submitter")
	}
	audit := cfg.Audit
	if audit == nil {
		audit = func(string, ...any) {}
	}
	return &Server{
		cfg:    cfg,
		audit:  audit,
		socket: filepath.Join(cfg.SocketDir, "executor.sock"),
		jobs:   map[string]*JobRecord{},
		closed: make(chan struct{}),
	}, nil
}

// SocketPath reports the bound path once started.
func (s *Server) SocketPath() string { return s.socket }

// Start binds the socket inside the owner-only directory and begins
// accepting. It runs at most once: a stopped or started server refuses
// a second Start — there is no restart cycle to race cleanup with.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("server already started")
	}
	if s.stopped {
		return fmt.Errorf("server already stopped")
	}
	if err := ensureSocketDir(s.cfg.SocketDir); err != nil {
		return err
	}
	if err := clearStaleSocket(s.socket); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socket, Net: "unix"})
	if err != nil {
		return fmt.Errorf("bind executor socket %s: %w", s.socket, err)
	}
	// The finalizer owns unlinking — never let the listener itself
	// remove a path that might no longer be ours.
	listener.SetUnlinkOnClose(false)
	// Bind lands at the umask (0755 typically) — tighten before any
	// accept; the identity check below verifies the result.
	if err := os.Chmod(s.socket, 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("secure executor socket %s: %w", s.socket, err)
	}
	ident, err := socketIdentityFor(s.socket)
	if err != nil {
		_ = listener.Close()
		return err
	}
	s.listener, s.ident, s.started = listener, ident, true
	tokenPosture := "shared-token"
	if s.cfg.Token == nil {
		tokenPosture = "peer-uid-only (token disabled)"
	}
	s.audit("sandbox-executord listening on %s (peers=%d, auth=%s, backend=%t)",
		s.socket, len(s.cfg.Peers), tokenPosture, s.cfg.Backend != nil)
	s.acceptWg.Add(1)
	go s.acceptLoop(listener)
	return nil
}

// Stop closes the listener and removes the socket — once. A second
// Stop is a no-op.
func (s *Server) Stop() error {
	s.mu.Lock()
	if s.stopped || !s.started {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	listener, ident := s.listener, s.ident
	s.mu.Unlock()

	err := listener.Close()
	if rmErr := removeOwnedSocket(s.socket, ident); rmErr != nil && err == nil {
		err = rmErr
	}
	close(s.closed)
	s.acceptWg.Wait()
	return err
}

// Done closes when the server has stopped.
func (s *Server) Done() <-chan struct{} { return s.closed }

// Jobs returns a snapshot of the recorded registry.
func (s *Server) Jobs() []*JobRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*JobRecord, 0, len(s.jobs))
	for _, j := range s.jobs {
		cpy := *j
		out = append(out, &cpy)
	}
	return out
}

func (s *Server) acceptLoop(listener *net.UnixListener) {
	defer s.acceptWg.Done()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if s.isStopped() || errors.Is(err, net.ErrClosed) {
				return
			}
			s.audit("accept error: %v", err)
			continue
		}
		s.acceptWg.Add(1)
		go s.serve(conn)
	}
}

func (s *Server) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

// serve handles one connection: resolve the kernel peer, authorize,
// read one bounded frame, authenticate, record, respond.
func (s *Server) serve(conn *net.UnixConn) {
	defer s.acceptWg.Done()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	creds, credErr := unixPeerCredentials(conn)
	submitter := "<unauthenticated>"
	if credErr == nil {
		submitter = fmt.Sprintf("uid=%d", creds.UID)
	}

	fail := func(reason string) {
		s.audit("refused connection from %s: %s", submitter, reason)
		_ = writeResponse(conn, &Response{OK: false, Error: reason})
	}

	if credErr != nil {
		fail(fmt.Sprintf("peer credentials unavailable: %v", credErr))
		return
	}
	submitter, ok := s.cfg.Peers.Authorize(creds.UID)
	if !ok {
		fail(fmt.Sprintf("peer uid %d is not a permitted submitter", creds.UID))
		return
	}

	reader := bufio.NewReader(conn)
	for {
		req, err := readRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fail(err.Error())
			return
		}
		if req.Type != RequestTypeSubmit {
			fail(fmt.Sprintf("unsupported request type %q", req.Type))
			return
		}
		if !s.cfg.Token.Verify(req.Token) {
			fail("submission token mismatch")
			return
		}
		if err := req.Job.Validate(); err != nil {
			fail(fmt.Sprintf("invalid job: %v", err))
			return
		}

		s.mu.Lock()
		if _, dup := s.jobs[req.Job.JobID]; dup {
			s.mu.Unlock()
			fail(fmt.Sprintf("job_id %q already submitted", req.Job.JobID))
			return
		}
		if len(s.jobs) >= maxJobs {
			s.mu.Unlock()
			fail(fmt.Sprintf("job registry full (%d records)", maxJobs))
			return
		}
		rec := &JobRecord{
			JobID:      req.Job.JobID,
			Submitter:  submitter,
			Principal:  req.Job.Principal,
			Image:      req.Job.Image,
			State:      JobStateRecorded,
			ReceivedAt: time.Now().UTC(),
		}
		s.jobs[rec.JobID] = rec
		s.seq.Add(1)
		s.mu.Unlock()

		// A configured backend takes the submission next — outside
		// the registry lock, so a slow executor never stalls other
		// admissions. The slot is reserved up front: a refused
		// hand-off is unrecorded rather than left half-registered.
		if s.cfg.Backend != nil {
			state, err := s.cfg.Backend.Submit(req.Job, submitter)
			s.mu.Lock()
			if err != nil {
				delete(s.jobs, rec.JobID)
				s.mu.Unlock()
				fail(fmt.Sprintf("backend refused job %q: %v", req.Job.JobID, err))
				return
			}
			rec.State = state
			s.mu.Unlock()
		}

		s.audit("accepted job %s from %s (principal=%s image=%s)",
			rec.JobID, submitter, rec.Principal, rec.Image)
		if err := writeResponse(conn, &Response{OK: true, JobID: rec.JobID, State: rec.State}); err != nil {
			return
		}
	}
}
