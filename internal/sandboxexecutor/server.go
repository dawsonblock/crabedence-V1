package sandboxexecutor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sandboxcustody"
	"github.com/openclaw/crabbox/internal/sockfile"
)

// JobStateRecorded marks a job the executor accepted into its durable
// registry. Admission without dispatch is recorded intent, never
// execution — the ledger entry exists before any backend is asked.
const JobStateRecorded = "RECORDED"

// maxJobs bounds the ACTIVE registry — jobs whose outcome or cleanup
// could still change, plus rows admitted but not yet settled. Settled
// terminal history lives in the archive, not here, so the bound now
// means "how much live work this executor tracks", not "how much work
// it ever did". Refusal is still louder than silent growth.
const maxJobs = 4096

// maxArchiveBatch bounds one admission-time archival pass so a full
// registry's relief is bounded work, not an unbounded pause.
const maxArchiveBatch = 1024

// Default bounds. Every executor resource is bounded; these are the
// values an operator gets without asking.
const (
	// defaultMaxConns caps simultaneous client connections — the
	// goroutine pool can never grow past it regardless of flood.
	defaultMaxConns = 64
	// maxPeerConns caps how many of those slots one submitter
	// identity may hold, so one misbehaving peer cannot starve the
	// others.
	maxPeerConns = 32
	// connIdleDeadline bounds a connection's total lifetime. One
	// absolute deadline means a slow-drip reader and a fast pipeline
	// get the same eviction.
	connIdleDeadline = 30 * time.Second
	// defaultDispatchTimeout bounds the synchronous launch call —
	// a wedged backend cannot pin an admission slot forever.
	defaultDispatchTimeout = 45 * time.Second
	// prepareTimeout bounds the dispatch-plan computation. It is
	// separate from DispatchTimeout because the plan resolves at most
	// one cached, idempotent lookup (the pinned image's config
	// environment) — a cold lookup must not consume the budget that
	// governs creating and launching the VM.
	prepareTimeout = 30 * time.Second
	// defaultReconcileTimeout bounds one startup recovery attempt —
	// a run that is still live is left unresolved rather than
	// blocking reconciliation indefinitely.
	defaultReconcileTimeout = 30 * time.Second
	// recoveryPageSize bounds one page of the startup recovery walk.
	// The walk follows its keyset cursor to exhaustion, so the bound
	// is on memory, never on which candidates are seen.
	recoveryPageSize = 64
	// defaultMaxContractTTL bounds how far past issued_at a contract
	// may remain valid — long-lived contracts are long-lived forgery
	// windows.
	defaultMaxContractTTL = time.Hour
)

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
	// AuthorityKeys is the contract trust set (fingerprint → public
	// key). When non-empty, every submission must carry a valid
	// signed SandboxJobV2 contract — unsigned submissions refuse.
	// When empty the server runs in the weaker unsigned-admission
	// posture, which the startup line reports.
	AuthorityKeys AuthorityKeys
	// Backend receives authorized, persisted jobs for execution. It
	// requires AuthorityKeys — a backend that ran unsigned jobs would
	// execute workloads with no per-job authorization, which is the
	// exact gap this architecture exists to close. Nil means jobs
	// are recorded but never executed.
	Backend Backend
	// LedgerPath is the durable job registry. Empty defaults to
	// <SocketDir>/executor-ledger.db. The ledger opens before the
	// socket binds so a daemon that cannot persist never accepts.
	LedgerPath string
	// MaxConns bounds simultaneous client connections. Zero uses the
	// default; negative refuses startup.
	MaxConns int
	// DispatchTimeout bounds one backend Dispatch call. Zero uses
	// the default.
	DispatchTimeout time.Duration
	// ReconcileTimeout bounds one recovery attempt for a run a
	// previous lifetime left unresolved — the observation window a
	// resumed run gets before it is left unresolved again. Zero uses
	// the default; negative refuses startup.
	ReconcileTimeout time.Duration
	// MaintenanceInterval paces the continuous-recovery scheduler:
	// stranded dispatch claims, cleanup retries, unresolved
	// re-observation, archival and residue escalation. Zero uses the
	// default; negative disables the periodic passes (the startup
	// recovery walks still run).
	MaintenanceInterval time.Duration
	// ResumeBackoff and CleanupBackoff set the per-job durable pacing
	// windows for re-observing unresolved runs and retrying pending
	// removals — durable across restarts, so a longer backoff also
	// delays the first post-restart attempt. Zero uses the defaults;
	// negative refuses startup.
	ResumeBackoff  time.Duration
	CleanupBackoff time.Duration
	// ArchiveCustodian witnesses archive segments to external custody
	// before the operational rows release — nil keeps custody local
	// (the archive is its own custody).
	ArchiveCustodian ArchiveCustodian
	// CustodyTrust is the operator-administered custody-witness trust
	// root the recording boundary verifies acknowledgements under.
	// It is mandatory whenever ArchiveCustodian is configured: the
	// trust decision must come from controlled configuration, never
	// from the acknowledgement-producing component itself — an
	// adapter that names its own trusted witnesses grades its own
	// work.
	CustodyTrust *sandboxcustody.TrustRoot
	// MaxContractTTL bounds contract validity windows. Zero uses the
	// default; negative disables the bound.
	MaxContractTTL time.Duration
	// ResourceCeiling optionally bounds what any contract may
	// request; a contract exceeding a non-zero ceiling field refuses.
	// Nil imposes no ceiling beyond structural sanity.
	ResourceCeiling *ResourceBudget
	// ResourcePool optionally bounds the executor's aggregate
	// in-flight consumption: concurrent VMs and the summed declared
	// CPU, memory, disk and output budgets. A configured dimension
	// also requires every admitted contract to declare it — an
	// aggregate bound over undeclared budgets bounds nothing. Nil
	// imposes no aggregate bound beyond the per-contract ceilings.
	ResourcePool *ResourcePool
	// EvidenceDir holds the executor's execution-evidence chain:
	// receipts.jsonl, signed checkpoints, and the evidence signer
	// key. Empty defaults to <SocketDir>/evidence. Every terminal
	// job emits a signed receipt before its ledger transition —
	// evidence precedes the claim it supports.
	EvidenceDir string
	// EvidenceKeyPath is the executor's evidence-signing key (PKCS8
	// PEM, created durably if absent). Empty defaults to
	// <EvidenceDir>/executor-evidence.pem. This key attests that
	// work ran — it can never authorize work.
	EvidenceKeyPath string
	// Audit receives decision lines; nil discards them.
	Audit AuditSink
	// now is the wall clock — injectable for tests.
	now func() time.Time
}

// Server is the sandbox executor daemon: a bounded Unix socket that
// accepts job submissions only from kernel-verified peer identities
// carrying the shared submission token, and — when configured —
// authority-signed job contracts. It holds no signing keys, persists
// every admitted job before dispatch, and never executes what it
// cannot record.
type Server struct {
	cfg    Config
	audit  AuditSink
	socket string
	now    func() time.Time

	mu       sync.Mutex
	listener *net.UnixListener
	ident    *sockfile.SocketIdentity
	started  bool
	stopped  bool
	acceptWg sync.WaitGroup
	conns    map[*net.UnixConn]string // live conn → authenticated submitter ("" until known)
	slots    chan struct{}
	peerLoad map[string]int
	// admitMu serializes pool check → ledger insert → dispatch
	// intent, so two concurrent admissions can never both pass the
	// same budget. Released before the backend is asked to launch.
	admitMu sync.Mutex

	ledger     *Ledger
	monitorWg  sync.WaitGroup
	shutdown   context.Context
	shutdownFn context.CancelFunc
	closed     chan struct{}

	// evidence is the append-only execution-evidence chain; nil only
	// before Start or after a failed Start. backendName is the
	// provider identity attested in receipts.
	evidence    *EvidenceLog
	backendName string
}

// NewServer validates the config and returns a runnable server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.SocketDir == "" {
		return nil, fmt.Errorf("socket directory is required")
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("peer allowlist is required — the executor refuses to run without a named submitter")
	}
	if cfg.Backend != nil && len(cfg.AuthorityKeys) == 0 {
		return nil, fmt.Errorf("a backend requires configured authority keys — unsigned jobs must never reach execution")
	}
	if cfg.MaxConns < 0 {
		return nil, fmt.Errorf("max connections must not be negative")
	}
	if cfg.DispatchTimeout < 0 {
		return nil, fmt.Errorf("dispatch timeout must not be negative")
	}
	if cfg.ReconcileTimeout < 0 {
		return nil, fmt.Errorf("reconcile timeout must not be negative")
	}
	if cfg.ResumeBackoff < 0 || cfg.CleanupBackoff < 0 {
		return nil, fmt.Errorf("recovery backoffs must not be negative")
	}
	if p := cfg.ResourcePool; p != nil {
		if p.MaxConcurrentVMs < 0 || p.MaxSubmitterVMs < 0 || p.TotalCPUs < 0 {
			return nil, fmt.Errorf("resource pool bounds must not be negative")
		}
	}
	// An execution backend runs untrusted code: the aggregate resource
	// bounds are mandatory, and every dimension must be a positive
	// bound. "Unbounded" is not a posture an untrusted-code executor
	// may take, and a zero-valued dimension is a disabled bound.
	if cfg.Backend != nil {
		if cfg.ResourcePool == nil {
			return nil, fmt.Errorf("an execution backend requires a resource pool — aggregate bounds (concurrent VMs, per-submitter VMs, cpus, memory, disk, output) are mandatory for untrusted code")
		}
		if err := cfg.ResourcePool.validate(); err != nil {
			return nil, err
		}
	}
	if cfg.ArchiveCustodian != nil && (cfg.CustodyTrust == nil || cfg.CustodyTrust.Empty()) {
		return nil, fmt.Errorf("a configured custodian requires an operator-administered custody trust root — trusting the acknowledgement producer to name its own witnesses is not custody")
	}
	if cfg.LedgerPath == "" {
		cfg.LedgerPath = filepath.Join(cfg.SocketDir, "executor-ledger.db")
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.DispatchTimeout == 0 {
		cfg.DispatchTimeout = defaultDispatchTimeout
	}
	if cfg.ReconcileTimeout == 0 {
		cfg.ReconcileTimeout = defaultReconcileTimeout
	}
	if cfg.MaxContractTTL == 0 {
		cfg.MaxContractTTL = defaultMaxContractTTL
	}
	if cfg.EvidenceDir == "" {
		cfg.EvidenceDir = filepath.Join(cfg.SocketDir, "evidence")
	}
	if cfg.EvidenceKeyPath == "" {
		cfg.EvidenceKeyPath = DefaultEvidenceKeyPath(cfg.EvidenceDir)
	}
	now := cfg.now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	audit := cfg.Audit
	if audit == nil {
		audit = func(string, ...any) {}
	}
	shutdown, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:        cfg,
		audit:      audit,
		socket:     filepath.Join(cfg.SocketDir, "executor.sock"),
		now:        now,
		conns:      map[*net.UnixConn]string{},
		slots:      make(chan struct{}, cfg.MaxConns),
		peerLoad:   map[string]int{},
		shutdown:   shutdown,
		shutdownFn: cancel,
		closed:     make(chan struct{}),
	}, nil
}

// SocketPath reports the bound path once started.
func (s *Server) SocketPath() string { return s.socket }

// Ledger exposes the durable registry — job identities live there,
// not in process memory.
func (s *Server) Ledger() *Ledger { return s.ledger }

// Start opens the ledger (fencing, epoch, reconcile), binds the
// socket inside the owner-only directory, and begins accepting. It
// runs at most once: a stopped or started server refuses a second
// Start — there is no restart cycle to race cleanup with.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("server already started")
	}
	if s.stopped {
		return fmt.Errorf("server already stopped")
	}
	if err := sockfile.EnsureDir(s.cfg.SocketDir); err != nil {
		return err
	}
	// The ledger opens first: an executor that cannot persist an
	// admission must never accept one. Open bumps the fence epoch and
	// reconciles any previous lifetime's in-flight states.
	ledger, err := OpenLedger(s.cfg.LedgerPath)
	if err != nil {
		return err
	}
	s.ledger = ledger
	if n := ledger.Reconciled(); n > 0 {
		s.audit("reconciled %d job(s) from a previous lifetime to %s", n, JobStateDispatchAmbig)
	}
	// External custody is installed before any archive pass can run —
	// a pending segment from a previous lifetime must resume under the
	// same custodian it was committed to.
	if s.cfg.ArchiveCustodian != nil {
		if err := ledger.SetArchiveCustodian(s.cfg.ArchiveCustodian); err != nil {
			_ = s.ledger.Close()
			s.ledger = nil
			return err
		}
		// The operator's trust root is installed separately from the
		// custodian adapter: the recording boundary verifies every
		// acknowledgement under this root and this root only.
		ledger.SetCustodyTrust(s.cfg.CustodyTrust)
	}
	// Failures before the evidence chain exists still owe the ledger
	// its close — a server that never started holds the fence lock
	// until this runs.
	failLedger := func(err error) error {
		_ = s.ledger.Close()
		s.ledger = nil
		return err
	}
	// The evidence chain opens before the socket binds: an executor
	// that cannot produce evidence must never accept work. The
	// evidence signer is executor-local and distinct from every
	// authority key — it attests outcomes, it cannot grant them.
	backendName := "none"
	if s.cfg.Backend != nil {
		backendName = s.cfg.Backend.Name()
	}
	signer, err := evidence.LoadOrCreateSigner(s.cfg.EvidenceKeyPath)
	if err != nil {
		return failLedger(err)
	}
	evLog, err := OpenEvidenceLog(s.cfg.EvidenceDir, signer, backendName)
	if err != nil {
		return failLedger(err)
	}
	s.evidence, s.backendName = evLog, backendName
	// Any failure past this point must release the evidence log too —
	// the fence lock and an open receipts file both stay held
	// otherwise.
	failStart := func(err error) error {
		_ = s.evidence.Close(nil)
		s.evidence = nil
		return failLedger(err)
	}
	if err := sockfile.ClearStale(s.socket, sockfile.ProbeAlive); err != nil {
		return failStart(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socket, Net: "unix"})
	if err != nil {
		return failStart(fmt.Errorf("bind executor socket %s: %w", s.socket, err))
	}
	// The finalizer owns unlinking — never let the listener itself
	// remove a path that might no longer be ours.
	listener.SetUnlinkOnClose(false)
	// Bind lands at the umask (0755 typically) — tighten before any
	// accept; the identity check below verifies the result.
	if err := os.Chmod(s.socket, 0o600); err != nil {
		_ = listener.Close()
		return failStart(fmt.Errorf("secure executor socket %s: %w", s.socket, err))
	}
	ident, err := sockfile.IdentityFor(s.socket)
	if err != nil {
		_ = listener.Close()
		return failStart(err)
	}
	s.listener, s.ident, s.started = listener, ident, true
	tokenPosture := "shared-token"
	if s.cfg.Token == nil {
		tokenPosture = "peer-uid-only (token disabled)"
	}
	authPosture := "unsigned-admission (no authority keys)"
	if len(s.cfg.AuthorityKeys) > 0 {
		authPosture = fmt.Sprintf("signed-contracts (%d authority keys)", len(s.cfg.AuthorityKeys))
	}
	s.audit("sandbox-executord listening on %s (peers=%d, auth=%s, jobs=%s, backend=%t, max_conns=%d, ledger=%s epoch=%d, evidence_dir=%s evidence_signer=%s)",
		s.socket, len(s.cfg.Peers), tokenPosture, authPosture,
		s.cfg.Backend != nil, s.cfg.MaxConns, s.cfg.LedgerPath, ledger.Epoch(),
		s.cfg.EvidenceDir, evLog.SignerFingerprint())
	s.acceptWg.Add(1)
	go s.acceptLoop(listener)
	// Surface unresolved backend work from previous lifetimes: resume
	// what the runtime can still prove, audit what it cannot. Never a
	// re-dispatch and never an auto-destroy.
	s.acceptWg.Add(1)
	go s.reconcileUnresolved()
	// Retry removals that were recorded as pending — a VM whose job
	// already has a terminal result is cleaned up, never forgotten.
	s.acceptWg.Add(1)
	go s.retryCleanups()
	// And keep draining forever: the maintenance loop is the startup
	// walks' continuation — stranded dispatches, re-observation,
	// cleanup retries, archival and residue escalation.
	s.acceptWg.Add(1)
	go s.maintenanceLoop()
	return nil
}

// reconcileUnresolved re-establishes observation of runs a previous
// daemon lifetime left unresolved. A run the runtime still records is
// resumed — its identity adopted from the runtime's own job list when
// the crash lost it — and observed to a terminal result, so a
// recovered job reaches the same receipt and artifact a live monitor
// would have produced. A run that cannot be demonstrated stays
// unresolved, with a liveness audit so an orphaned workload surfaces
// instead of being discovered manually.
//
// Nothing here launches a job and nothing here destroys one: a
// resumed run is settled only from the runtime's own record, and an
// unresolved row's VM belongs to an operator.
func (s *Server) reconcileUnresolved() {
	defer s.acceptWg.Done()
	if s.cfg.Backend == nil {
		return
	}
	s.reconcileWalk()
}

// reconcileOne re-establishes observation of one unresolved row, or
// audits why it cannot be resumed. claim is the durable recovery
// fence the pass holds: it is validated before the external
// observation is issued and again inside the commit that settles the
// outcome — a claimant that lost the lease mid-flight can interrogate
// nothing and commit nothing.
func (s *Server) reconcileOne(j *LedgerJob, claim *RecoveryClaim) {
	if err := s.ledger.ValidateRecoveryClaim(claim, s.now()); err != nil {
		s.audit("reconcile: job %s (%s) claim is no longer valid — skipping the backend observation: %v", j.JobID, j.State, err)
		return
	}
	// The observation may run long: extend the lease to cover the
	// reconcile window before issuing work the backend cannot recall.
	if err := s.ledger.ExtendRecoveryLease(claim, s.cfg.ReconcileTimeout+time.Minute, s.now()); err != nil {
		s.audit("reconcile: job %s (%s) claim could not be extended for the observation window: %v", j.JobID, j.State, err)
		return
	}
	contract, cerr := ParseContract(json.RawMessage(j.ContractJSON))
	if cerr != nil {
		s.audit("reconcile: job %s (%s) stored contract is unreadable (%v) — leaving it unresolved", j.JobID, j.State, cerr)
		return
	}
	run := RunIdentity{Handle: j.BackendHandle, RunID: j.BackendJobID, BootID: j.BackendBootID, PolicyDigest: j.PolicyDigest, Nonce: j.DispatchNonce}
	ctx, cancel := context.WithTimeout(s.shutdown, s.cfg.ReconcileTimeout)
	adopted, res, rerr := s.cfg.Backend.Resume(ctx, contract, run)
	cancel()
	if adopted.RunID != run.RunID || adopted.BootID != run.BootID {
		if aerr := s.ledger.AdoptBackendRun(j.JobID, adopted.RunID, adopted.BootID); aerr != nil {
			s.audit("reconcile: job %s recovered run %s (boot %s) but the ledger refused the adoption: %v", j.JobID, adopted.RunID, adopted.BootID, aerr)
			return
		}
		s.audit("reconcile: job %s adopted runtime run %s boot generation %s (identity was lost with the crash)", j.JobID, adopted.RunID, adopted.BootID)
	}
	if rerr == nil && res != nil {
		s.audit("reconcile: job %s (%s) resumed from run %s boot %s — settling the observed outcome", j.JobID, j.State, adopted.RunID, adopted.BootID)
		s.settleObserved(j, []string{JobStateDispatchAmbig, JobStateInterrupted}, adopted, res, contract, claim)
		return
	}
	// Not resumable: audit the handle's liveness so an orphaned
	// workload is visible rather than remembered.
	lctx, lcancel := context.WithTimeout(s.shutdown, 10*time.Second)
	live, ierr := s.cfg.Backend.Inspect(lctx, j.BackendHandle)
	lcancel()
	switch {
	case ierr != nil:
		s.audit("reconcile: job %s (%s) handle %s — not resumable (%v); inspect failed: %v", j.JobID, j.State, j.BackendHandle, rerr, ierr)
	case live:
		s.audit("reconcile: job %s (%s) backend %s handle %s is STILL RUNNING — operator must inspect/remove it (evidence preserved, never auto-destroyed)", j.JobID, j.State, j.BackendID, j.BackendHandle)
	default:
		s.audit("reconcile: job %s (%s) backend %s handle %s is gone", j.JobID, j.State, j.BackendID, j.BackendHandle)
	}
}

// retryCleanups retries removal for terminal jobs whose backend
// resources could not be removed after their result was observed —
// cleanup is tracked separately from the outcome, so a VM that
// outlived its job is reconciled rather than forgotten. It never
// touches a job whose outcome is unresolved: those VMs may still be
// running the workload and are for an operator to inspect.
//
// Like reconcileUnresolved it walks every candidate, so a pending
// removal is never abandoned for having fallen outside the first page.
func (s *Server) retryCleanups() {
	defer s.acceptWg.Done()
	if s.cfg.Backend == nil {
		return
	}
	s.cleanupWalk()
}

// cleanupOne retries the pending removal of one terminal job's
// backend resources — the row's outcome is already recorded, so a
// failure audits rather than rewriting it. The destructive request
// binds the job's *current* persisted identity — the walk's row is a
// snapshot and a stale snapshot must never authorize a destroy — and
// the clear commits only while the recovery claim is still the live
// owner: a claimant that lost the lease mid-operation cannot commit
// the outcome it triggered.
func (s *Server) cleanupOne(j *LedgerJob, claim *RecoveryClaim) {
	fresh, err := s.ledger.Get(j.JobID)
	if err != nil || fresh == nil {
		s.audit("cleanup retry: cannot re-read job %s before issuing a destructive operation: %v", j.JobID, err)
		return
	}
	if !fresh.CleanupPending {
		return
	}
	if err := s.ledger.ValidateRecoveryClaim(claim, s.now()); err != nil {
		s.audit("cleanup retry: job %s claim is no longer valid — skipping the destructive operation: %v", j.JobID, err)
		return
	}
	req := cleanupRequestFor(fresh)
	req.RecoveryFence = fenceFromClaim(claim)
	ctx, cancel := context.WithTimeout(s.shutdown, 15*time.Second)
	res, cerr := s.cfg.Backend.Cleanup(ctx, req)
	cancel()
	if cerr != nil {
		s.audit("cleanup retry: job %s handle %s still pending: %v", j.JobID, fresh.BackendHandle, cerr)
		return
	}
	if !res.Outcome.ResolvesObligation() {
		// The backend could not resolve the obligation — a
		// substitution it refused to touch, an identity it could not
		// verify, or an uncertain removal. Record the classification
		// as the pending reason so the residue escalation carries
		// why it is still owed.
		if nerr := s.ledger.NoteCleanupPendingFor(j.JobID, fmt.Sprintf("%s: %s", res.Outcome, res.Detail), claim); nerr != nil {
			s.audit("cleanup retry: job %s outcome %s could not be recorded: %v", j.JobID, res.Outcome, nerr)
		}
		s.audit("cleanup retry: job %s handle %s still pending (%s): %s", j.JobID, fresh.BackendHandle, res.Outcome, res.Detail)
		return
	}
	if res.Outcome == CleanupRetainedByPolicy {
		// Retention discharges the removal obligation while the
		// resource still exists — record it in the inventory before
		// the clear, so cleanup accounting can never leave resource
		// accounting silent about a live instance.
		if rerr := s.ledger.RecordRetainedResource(fresh.JobID, fresh.BackendID, fresh.BackendHandle,
			fresh.DispatchNonce, res.Detail); rerr != nil {
			s.audit("cleanup retry: job %s retained by policy but the inventory refused the record — keeping the obligation pending: %v", j.JobID, rerr)
			return
		}
	}
	if err := s.ledger.ClearCleanupPendingFor(j.JobID, claim, s.now()); err != nil {
		s.audit("cleanup retry: job %s removed (%s) but the ledger refused the clear: %v", j.JobID, res.Outcome, err)
		return
	}
	s.audit("cleanup retry: job %s handle %s obligation resolved (%s)", j.JobID, fresh.BackendHandle, res.Outcome)
	s.releaseRecovery(claim, fmt.Sprintf("pending removal completed: %s", res.Outcome))
}

// cleanupRequestFor builds the identity-bound destruction
// authorization from the job's persisted dispatch record — the nonce,
// boot generation, policy digest and run identity a substituted VM
// cannot present.
func cleanupRequestFor(j *LedgerJob) CleanupRequest {
	return CleanupRequest{
		JobID:         j.JobID,
		BackendID:     j.BackendID,
		Handle:        j.BackendHandle,
		DispatchNonce: j.DispatchNonce,
		BootID:        j.BackendBootID,
		PolicyDigest:  j.PolicyDigest,
		RunID:         j.BackendJobID,
	}
}

// Stop shuts the server down in drain order: cancel monitors'
// context, close the listener, drop live connections, wait for every
// handler and monitor to finish, then close the ledger and remove the
// socket. Done() only closes after all of that completes — a caller
// that observes Done() never sees a handler still in flight. A second
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

	s.shutdownFn()
	err := listener.Close()
	s.closeLiveConns()
	s.acceptWg.Wait()
	s.monitorWg.Wait()

	var ledgerErr error
	if s.ledger != nil {
		// A clean stop distinguishes "was running when we stopped"
		// from "crashed mid-watch" — both still need operator
		// reconciliation, only the provenance differs.
		if n, ierr := s.ledger.InterruptRunning(); ierr != nil {
			ledgerErr = ierr
		} else if n > 0 {
			s.audit("marked %d running job(s) %s at shutdown", n, JobStateInterrupted)
		}
		// The final checkpoint must precede the ledger close — it
		// commits to the terminal enumeration this lifetime leaves
		// behind.
		if s.evidence != nil {
			refs, rerr := s.ledger.TerminalRefs()
			if rerr != nil {
				ledgerErr = rerr
			} else if cerr := s.evidence.Close(refs); cerr != nil && ledgerErr == nil {
				ledgerErr = cerr
			}
			s.evidence = nil
		}
		if cerr := s.ledger.Close(); ledgerErr == nil {
			ledgerErr = cerr
		}
	}
	if rmErr := sockfile.RemoveOwned(s.socket, ident); rmErr != nil && err == nil {
		err = rmErr
	}
	if ledgerErr != nil && err == nil {
		err = ledgerErr
	}
	close(s.closed)
	return err
}

// Done closes when the server has fully stopped — listener closed,
// every connection handler drained, every job monitor finished,
// ledger closed. It never reports completion while work is in flight.
func (s *Server) Done() <-chan struct{} { return s.closed }

// Jobs returns a snapshot of the durable registry in admission order.
func (s *Server) Jobs() []*JobRecord {
	jobs, err := s.ledger.List()
	if err != nil {
		return nil
	}
	out := make([]*JobRecord, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, &JobRecord{
			JobID:      j.JobID,
			Submitter:  j.Submitter,
			Principal:  j.Principal,
			Image:      j.Image,
			State:      j.State,
			ReceivedAt: j.ReceivedAt,
		})
	}
	return out
}

// JobRecord is the executor's account of one accepted submission.
// The ledger row carries the full state; this is the read model.
type JobRecord struct {
	JobID      string    `json:"job_id"`
	Submitter  string    `json:"submitter"`
	Principal  string    `json:"principal"`
	Image      string    `json:"image"`
	State      string    `json:"state"`
	ReceivedAt time.Time `json:"received_at"`
}

func (s *Server) acceptLoop(listener *net.UnixListener) {
	defer s.acceptWg.Done()
	backoff := 0
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if s.isStopped() || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient accept failures (EMFILE under flood, ENOMEM)
			// must not spin the accept loop at 100% — bounded backoff,
			// still audited, still accepting.
			backoff++
			delay := time.Duration(backoff) * 25 * time.Millisecond
			if delay > time.Second {
				delay = time.Second
			}
			s.audit("accept error (backoff %s): %v", delay, err)
			select {
			case <-time.After(delay):
			case <-s.shutdown.Done():
				return
			}
			continue
		}
		backoff = 0

		select {
		case s.slots <- struct{}{}:
		default:
			// The executor is at its connection bound — refuse loudly
			// rather than queue a handler the caller will wait on.
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_ = writeResponse(conn, &Response{OK: false, Error: "executor at connection limit"})
			conn.Close()
			s.audit("refused connection: executor at connection limit (%d)", s.cfg.MaxConns)
			continue
		}
		s.mu.Lock()
		s.conns[conn] = ""
		s.mu.Unlock()
		s.acceptWg.Add(1)
		go s.serve(conn)
	}
}

// closeLiveConns interrupts every in-flight handler so Stop's drain
// is bounded by shutdown, not by the conn deadline.
func (s *Server) closeLiveConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		conn.Close()
	}
}

func (s *Server) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

// releaseConn returns a handler's slot and untracks the connection.
func (s *Server) releaseConn(conn *net.UnixConn) {
	s.mu.Lock()
	submitter := s.conns[conn]
	if submitter != "" {
		if n := s.peerLoad[submitter] - 1; n <= 0 {
			delete(s.peerLoad, submitter)
		} else {
			s.peerLoad[submitter] = n
		}
	}
	delete(s.conns, conn)
	s.mu.Unlock()
	<-s.slots
}

// peerConns reports how many live connections the submitter currently
// holds. The per-peer bound is accounted in the handler goroutine —
// the peer's kernel identity is unknown at accept — so this is the
// observable a test waits on before asserting the refusal that
// accounting produces; a fixed sleep is not a synchronization.
func (s *Server) peerConns(submitter string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerLoad[submitter]
}

// serve handles one connection: resolve the kernel peer, authorize,
// read bounded frames, verify admission (token, then contract),
// persist, dispatch, respond.
func (s *Server) serve(conn *net.UnixConn) {
	defer s.acceptWg.Done()
	defer s.releaseConn(conn)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(connIdleDeadline))

	creds, credErr := unixPeerCredentials(conn)
	submitter := "<unauthenticated>"
	if credErr == nil {
		submitter = fmt.Sprintf("uid=%d", creds.UID)
	}

	fail := func(reason string) {
		s.audit("refused connection from %s: %s", submitter, reason)
		_ = writeResponse(conn, &Response{OK: false, Error: reason})
	}
	// failJob reports a refusal on an already-recorded job: the
	// response carries the job's durable state so the caller learns
	// what the ledger holds, not just that it said no.
	failJob := func(jobID, state, reason string) {
		s.audit("job %s from %s -> %s: %s", jobID, submitter, state, reason)
		_ = writeResponse(conn, &Response{OK: false, JobID: jobID, State: state, Error: reason})
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

	// Per-peer occupancy bound: one submitter may not hold every
	// slot while others wait.
	s.mu.Lock()
	if s.peerLoad[submitter] >= maxPeerConns {
		s.mu.Unlock()
		fail(fmt.Sprintf("submitter %s holds too many connections (%d)", submitter, maxPeerConns))
		return
	}
	s.peerLoad[submitter]++
	s.conns[conn] = submitter
	s.mu.Unlock()

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
		if req.Job != nil && req.SignedJob != nil {
			fail("request must carry exactly one of job or signed_job")
			return
		}

		var (
			jobID, principal, image, contractJSON, contractHash string
			contract                                            *JobContractV2
		)
		switch {
		case req.SignedJob != nil:
			if len(s.cfg.AuthorityKeys) == 0 {
				fail("signed job submitted but no authority keys are configured")
				return
			}
			c, err := VerifyContract(req.SignedJob, s.cfg.AuthorityKeys, submitter, s.now(), s.cfg.MaxContractTTL)
			if err != nil {
				fail(fmt.Sprintf("job contract refused: %v", err))
				return
			}
			if cerr := s.checkCeiling(c); cerr != nil {
				fail(fmt.Sprintf("job contract refused: %v", cerr))
				return
			}
			contract = c
			jobID, principal, image = c.JobID, c.Principal, c.Image
			contractHash = ContractHash(c)
			raw, _ := json.Marshal(c)
			contractJSON = string(raw)
		case req.Job != nil:
			if len(s.cfg.AuthorityKeys) > 0 {
				fail("unsigned job refused: a signed job contract is required")
				return
			}
			if err := req.Job.Validate(); err != nil {
				fail(fmt.Sprintf("invalid job: %v", err))
				return
			}
			jobID, principal, image = req.Job.JobID, req.Job.Principal, req.Job.Image
			raw, _ := json.Marshal(req.Job)
			contractJSON = string(raw)
			sum := sha256.Sum256(append([]byte("unsigned\x00"), jobID...))
			contractHash = hex.EncodeToString(sum[:])
		default:
			fail("request carries no job")
			return
		}

		// Persist before dispatch, under the pool reservation: if the
		// process dies after this commit, the job identity survives —
		// that is the point of the ledger.
		lj, err := s.admitJob(jobID, contractHash, submitter, principal, image, contractJSON, contractBudget(contract))
		if err != nil {
			switch {
			case errors.Is(err, ErrDuplicateJobID):
				fail(fmt.Sprintf("job_id %q already submitted", jobID))
			case errors.Is(err, ErrContractReplay):
				fail(fmt.Sprintf("job contract is a replay: %v", err))
			case errors.Is(err, ErrPoolExhausted):
				s.audit("refused job %s from %s: %v", jobID, submitter, err)
				fail(fmt.Sprintf("job refused: %v", err))
			default:
				fail(fmt.Sprintf("record job %q: %v", jobID, err))
			}
			return
		}

		if s.cfg.Backend == nil {
			s.audit("accepted job %s from %s (principal=%s image=%s signed=%t)",
				jobID, submitter, principal, image, contract != nil)
			if err := writeResponse(conn, &Response{OK: true, JobID: jobID, State: JobStateRecorded}); err != nil {
				return
			}
			continue
		}

		// The row is already claimed DISPATCHING — admitJob wrote the
		// intent atomically with the record. The shared pipeline takes
		// it from here; the response reports the durable outcome.
		s.audit("accepted job %s from %s (principal=%s image=%s signed=%t)",
			jobID, submitter, principal, image, contract != nil)
		state, reason := s.driveDispatch(lj, contract)
		if state == JobStateRunning {
			if err := writeResponse(conn, &Response{OK: true, JobID: jobID, State: JobStateRunning}); err != nil {
				return
			}
			continue
		}
		if state == "" {
			fail(reason.Error())
			return
		}
		failJob(jobID, state, reason.Error())
		return
	}
}

// driveDispatch runs one claimed DISPATCHING row through the backend
// pipeline: prepare, persist the dispatch authorization, dispatch,
// monitor. It returns the durable state the row now holds and, for a
// non-running outcome, the operator-facing reason; an empty state
// means the drive itself failed before any claim could be recorded,
// and the row is left DISPATCHING for reconcile to mark ambiguous.
// The socket handler and the maintenance scheduler share this — one
// definition of dispatch truth, never a silent retry.
func (s *Server) driveDispatch(j *LedgerJob, contract *JobContractV2) (string, error) {
	// The dispatch identity is computed without creating anything
	// and persisted before the backend may create a VM: a crash can
	// then never leave a VM whose authorization is not on disk, and
	// recovery validates a discovered VM against this stored
	// identity rather than reconstructing authority from a
	// matching command.
	prepareCtx, cancelPrepare := context.WithTimeout(s.shutdown, prepareTimeout)
	plan, perr := s.cfg.Backend.Prepare(prepareCtx, contract)
	cancelPrepare()
	if perr != nil {
		// Nothing was created: a pre-launch refusal, the only kind
		// that may attest NO_EFFECT.
		receiptSHA, rerr := s.emitReceipt(&LedgerJob{
			JobID: j.JobID, Principal: j.Principal, ContractHash: j.ContractHash,
		}, evidence.OutcomeNoEffect, "", "")
		if rerr != nil {
			s.audit("job %s: evidence emission failed (%v) — refusing the terminal claim too", j.JobID, rerr)
			return "", fmt.Errorf("backend refused and evidence emission failed for %q: %v", j.JobID, rerr)
		}
		if err := s.ledger.Transition(j.JobID, JobStateDispatchFailed, []string{JobStateDispatching},
			func(lj *LedgerJob) error {
				lj.ReceiptSHA256 = receiptSHA
				lj.DispatchClass = string(DispatchNotAttempted)
				lj.Error = fmt.Sprintf("dispatch refused before launch: %v", perr)
				return nil
			}); err != nil {
			s.audit("job %s: refused-dispatch terminal record could not be committed (%v) — the row stays DISPATCHING for the straggler walk", j.JobID, err)
		}
		return JobStateDispatchFailed, fmt.Errorf("backend refused job: %v", perr)
	}
	if err := s.ledger.RecordDispatchPlan(j.JobID, s.backendName, plan); err != nil {
		return "", fmt.Errorf("persist dispatch identity of %q: %v", j.JobID, err)
	}

	dispatchCtx, cancel := context.WithTimeout(s.shutdown, s.cfg.DispatchTimeout)
	disp, derr := s.cfg.Backend.Dispatch(dispatchCtx, contract, plan)
	cancel()
	switch {
	case derr == nil:
		err := s.ledger.Transition(j.JobID, JobStateRunning, []string{JobStateDispatching},
			func(lj *LedgerJob) error {
				applyRunIdentity(lj, s.backendName, disp)
				lj.DispatchClass = string(DispatchStarted)
				return nil
			})
		if err != nil {
			return "", fmt.Errorf("persist dispatch of %q: %v", j.JobID, err)
		}
		s.audit("dispatched job %s (handle=%s run_id=%s boot_id=%s policy=%s)",
			j.JobID, disp.Handle, disp.RunID, disp.BootID, disp.PolicyDigest)
		s.monitorWg.Add(1)
		go s.monitor(j.JobID, disp)
		return JobStateRunning, nil
	case errors.Is(derr, ErrAmbiguousDispatch):
		// The job may already be running. Record everything we
		// know and refuse the retry path outright — an operator
		// reconciles against the backend, never a blind relaunch.
		// The record is mandatory: a transition that cannot be
		// committed leaves the row DISPATCHING, which the straggler
		// walk resolves to the same uncertain classification.
		if err := s.ledger.Transition(j.JobID, JobStateDispatchAmbig, []string{JobStateDispatching},
			func(lj *LedgerJob) error {
				applyRunIdentity(lj, s.backendName, disp)
				lj.DispatchClass = string(DispatchUncertain)
				lj.Error = derr.Error()
				return nil
			}); err != nil {
			s.audit("job %s: ambiguous dispatch outcome could not be recorded (%v) — the row stays DISPATCHING for the straggler walk; the possibly-running workload is never retried or destroyed", j.JobID, err)
		}
		return JobStateDispatchAmbig, fmt.Errorf("dispatch outcome uncertain — reconciling manually; the job will NOT be retried: %v", derr)
	case errors.Is(derr, ErrDispatchRefused):
		// Definitive refusal: the backend proved nothing launched,
		// but the job identity stays recorded — a backend error
		// must never erase an acknowledged job. The NO_EFFECT
		// receipt attests the refusal itself.
		receiptSHA, rerr := s.emitReceipt(&LedgerJob{
			JobID: j.JobID, Principal: j.Principal, ContractHash: j.ContractHash,
		}, evidence.OutcomeNoEffect, "", disp.Handle)
		if rerr != nil {
			s.audit("job %s: evidence emission failed (%v) — refusing the terminal claim too", j.JobID, rerr)
			return "", fmt.Errorf("backend refused and evidence emission failed for %q: %v", j.JobID, rerr)
		}
		if err := s.ledger.Transition(j.JobID, JobStateDispatchFailed, []string{JobStateDispatching},
			func(lj *LedgerJob) error {
				lj.Error, lj.BackendID, lj.BackendHandle, lj.ReceiptSHA256 =
					derr.Error(), s.backendName, disp.Handle, receiptSHA
				lj.DispatchClass = string(DispatchProvenRejected)
				return nil
			}); err != nil {
			s.audit("job %s: refused-dispatch terminal record could not be committed (%v) — the row stays DISPATCHING for the straggler walk", j.JobID, err)
		}
		s.checkpoint()
		return JobStateDispatchFailed, fmt.Errorf("backend refused job: %v", derr)
	default:
		// Unclassified dispatch error: the executor cannot prove
		// nothing executed, so it must not claim it. Record the
		// uncertainty exactly as an ambiguous dispatch — the job
		// is never retried blind and never receives a NO_EFFECT
		// receipt it cannot support.
		if err := s.ledger.Transition(j.JobID, JobStateDispatchAmbig, []string{JobStateDispatching},
			func(lj *LedgerJob) error {
				applyRunIdentity(lj, s.backendName, disp)
				lj.DispatchClass = string(DispatchUncertain)
				lj.Error = fmt.Sprintf("dispatch error could not be classified as a pre-launch refusal — treating the outcome as uncertain: %v", derr)
				return nil
			}); err != nil {
			s.audit("job %s: uncertain dispatch outcome could not be recorded (%v) — the row stays DISPATCHING for the straggler walk; the possibly-running workload is never retried or destroyed", j.JobID, err)
		}
		s.audit("job %s: unclassified dispatch error treated as uncertain (never a no-effect claim): %v", j.JobID, derr)
		return JobStateDispatchAmbig, fmt.Errorf("dispatch outcome uncertain — reconciling manually; the job will NOT be retried: %v", derr)
	}
}

// monitor observes one dispatched job's terminal outcome and binds it
// to the ledger row. The outcome comes from the backend's structured
// observation of the runtime's own record — never from a CLI process
// exit code. Context cancellation means the daemon is stopping — the
// ledger row stays RUNNING and the next lifetime's reconcile marks it
// ambiguous; it never reports a result it did not observe.
func (s *Server) monitor(jobID string, run RunIdentity) {
	defer s.monitorWg.Done()

	// The observation needs the row's bound identity — the stored
	// contract is what the runtime's record must correlate against,
	// and principal and contract hash are what the receipt attests.
	// If the row cannot be read or parsed, nothing can be observed,
	// so the job is left unresolved rather than guessed at.
	job, jerr := s.ledger.Get(jobID)
	if jerr != nil || job == nil {
		s.audit("job %s: cannot read ledger row for observation: %v", jobID, jerr)
		return
	}
	contract, cerr := ParseContract(json.RawMessage(job.ContractJSON))
	if cerr != nil {
		s.audit("job %s: stored contract is unreadable (%v) — leaving the job unresolved", jobID, cerr)
		s.markUnobserved(jobID, fmt.Sprintf("stored contract is unreadable: %v", cerr))
		return
	}

	res, werr := s.cfg.Backend.Wait(s.shutdown, contract, run)
	switch {
	case werr == nil:
		// A fully observed outcome — settled below.
	case errors.Is(werr, context.Canceled) || s.isStopped():
		// The daemon is stopping: the job may still be live in the
		// runtime, whose own record survives for the next lifetime
		// to reconcile. The row stays RUNNING.
		return
	case res != nil:
		// The exit was observed but the artifact could not be
		// finalized: "result not fully verified" — the job stays
		// unresolved rather than terminal without its evidence.
		s.audit("job %s: exit observed but artifact finalization failed: %v — leaving the job unresolved", jobID, werr)
		s.markUnobserved(jobID, fmt.Sprintf("exit observed but artifact finalization failed: %v", werr))
		return
	default:
		// The outcome was never observed. No receipt, no terminal
		// state: the row becomes DISPATCH_AMBIGUOUS — "may still be
		// live, never retried blind, operator reconciles". Attesting
		// an outcome this executor never observed would fabricate it.
		s.audit("job %s outcome unobserved: %v — leaving the job unresolved, never a fabricated result", jobID, werr)
		s.markUnobserved(jobID, fmt.Sprintf("outcome unobserved: %v", werr))
		return
	}
	s.settleObserved(job, []string{JobStateRunning}, run, res, contract, nil)
}

// classifyObserved maps one backend observation to the terminal
// state, receipt outcome, ledger exit code and reason. ok is false
// when the observation cannot support a terminal claim at all — a
// backend that reports no verified exit, no timeout and no typed
// rejection has demonstrated nothing.
func classifyObserved(contract *JobContractV2, res *ExecResult) (state, outcome string, exit *int64, errText string, ok bool) {
	if !res.ExitVerified && res.FailureKind == "" && !res.TimedOut {
		return "", "", nil, "", false
	}
	state, outcome = JobStateSucceeded, evidence.OutcomeCompleted
	switch {
	case res.FailureKind != "":
		// A no-effect claim rests on the runtime's own statement that
		// it failed before creating a process. The stage is the proof,
		// so it is re-checked here rather than trusted from the
		// backend: a rejection the executor cannot read as
		// pre-execution has demonstrated nothing about whether the
		// workload ran, and claiming NO_EFFECT for it would be a false
		// receipt.
		if !preExecutionStages[res.FailureStage] {
			return "", "", nil, "", false
		}
		state, outcome = JobStateDispatchFailed, evidence.OutcomeNoEffect
		errText = fmt.Sprintf("command rejected before start (%s at %s): %s", res.FailureKind, res.FailureStage, res.FailureMessage)
	case res.TimedOut:
		// The runtime killed the command at the contract deadline: an
		// observed outcome, but not a guest exit — no exit code is
		// invented for it.
		state = JobStateFailed
		errText = fmt.Sprintf("contract timeout: the runtime killed the command at %ds", contract.Resources.TimeoutSeconds)
	case res.ExitVerified:
		// The runtime recorded the guest's termination: the exit
		// code is observed, never derived. Zero is success; any
		// other code is a verified guest failure.
		code := int64(res.ExitCode)
		exit = &code
		if res.ExitCode != 0 {
			state = JobStateFailed
		}
	}
	return state, outcome, exit, errText, true
}

// settleObserved writes one observed outcome to the ledger and then
// removes the job's backend resources. from is the set of states the
// row may hold — RUNNING for a live monitor, the unresolved states
// for a recovery pass. An observation the backend cannot demonstrate
// writes no terminal claim: the row is left (or made) unresolved.
//
// The terminal write precedes cleanup and records the intent to clean
// up: a crash between the two leaves a terminal result with
// cleanup_pending set, which the next startup retries. The other
// order would let a crash strand a VM with nothing recorded — and a
// terminal row whose transition failed never destroys its VM,
// because an unresolved row's workload is for an operator to
// reconcile.
func (s *Server) settleObserved(job *LedgerJob, from []string, run RunIdentity, res *ExecResult, contract *JobContractV2, claim *RecoveryClaim) {
	state, outcome, exit, errText, ok := classifyObserved(contract, res)
	if !ok {
		s.audit("job %s: backend returned an unverified outcome (%+v) — refusing the terminal claim", job.JobID, res)
		if terr := s.ledger.TransitionWithClaim(job.JobID, JobStateDispatchAmbig, from, claim,
			func(j *LedgerJob) error {
				j.Error = "backend returned an unverified outcome"
				return nil
			}); terr != nil {
			s.audit("job %s: could not record the unverified outcome: %v", job.JobID, terr)
		}
		return
	}
	resultJSON, _ := json.Marshal(res)
	if err := s.finishTerminal(job, from, state, outcome, receiptRunIdentity(job, res), res.OutputSHA256, claim,
		func(j *LedgerJob) error {
			j.ExitCode = exit
			j.Error = errText
			j.ResultJSON = string(resultJSON)
			j.ArtifactSHA256 = res.OutputSHA256
			j.CleanupPending = true
			return nil
		}); err != nil {
		return
	}
	cleanupPending := false
	cres, cerr := s.cleanupBackend(job, run, claim)
	switch {
	case cerr != nil:
		cleanupPending = true
		s.audit("job %s: cleanup pending — %v", job.JobID, cerr)
		if merr := s.ledger.MarkCleanupPendingFor(job.JobID, cerr.Error(), claim); merr != nil {
			s.audit("job %s: could not record the pending cleanup: %v", job.JobID, merr)
		}
	case !cres.Outcome.ResolvesObligation():
		cleanupPending = true
		s.audit("job %s: cleanup pending (%s) — %s", job.JobID, cres.Outcome, cres.Detail)
		if merr := s.ledger.NoteCleanupPendingFor(job.JobID, fmt.Sprintf("%s: %s", cres.Outcome, cres.Detail), claim); merr != nil {
			s.audit("job %s: could not record the cleanup classification: %v", job.JobID, merr)
		}
	default:
		if cres.Outcome == CleanupRetainedByPolicy {
			// The obligation is discharged by policy while the
			// resource still exists — the inventory record must land
			// before the clear or the live instance becomes
			// unaccounted-for.
			if rerr := s.ledger.RecordRetainedResource(job.JobID, job.BackendID, job.BackendHandle,
				job.DispatchNonce, cres.Detail); rerr != nil {
				s.audit("job %s: retained by policy but the inventory refused the record — keeping the obligation pending: %v", job.JobID, rerr)
				cleanupPending = true
				break
			}
		}
		if err := s.ledger.ClearCleanupPendingFor(job.JobID, claim, s.now()); err != nil {
			s.audit("job %s: cleaned up (%s) but the ledger refused the clear: %v", job.JobID, cres.Outcome, err)
		}
	}
	exitText := "none"
	if exit != nil {
		exitText = fmt.Sprint(*exit)
	}
	s.audit("job %s finished: state=%s exit=%s timed_out=%t runtime_state=%s run_id=%s output_sha256=%s cleanup_pending=%t",
		job.JobID, state, exitText, res.TimedOut, res.RuntimeState, res.RunID, res.OutputSHA256, cleanupPending)
}

// composedRunIdentity renders the run identity a signed receipt binds
// to. When the full execution identity is known — the runtime-owned
// run id, the VM boot generation and the effective-policy digest — the
// receipt binds all three as one composite value, so the signed
// evidence names the exact run, boot and policy rather than only the
// run id; a row from before the identity existed (rc.5 era) binds its
// bare run id, and a backend without one binds its handle.
func composedRunIdentity(runID, bootID, policyDigest, handle string) string {
	if runID == "" {
		return handle
	}
	if bootID == "" || policyDigest == "" {
		return runID
	}
	return runID + "@" + bootID + "@" + policyDigest
}

// receiptRunIdentity is the run identity a receipt for this job binds
// to, preferring the result's own observation over the row's record.
func receiptRunIdentity(job *LedgerJob, res *ExecResult) string {
	runID, bootID, policy := job.BackendJobID, job.BackendBootID, job.PolicyDigest
	if res != nil {
		if res.RunID != "" {
			runID = res.RunID
		}
		if res.BootID != "" {
			bootID = res.BootID
		}
		if res.PolicyDigest != "" {
			policy = res.PolicyDigest
		}
	}
	return composedRunIdentity(runID, bootID, policy, job.BackendHandle)
}

// applyRunIdentity persists one dispatch's full execution identity —
// handle, runtime run id, VM boot generation and effective-policy
// digest — on the ledger row.
func applyRunIdentity(j *LedgerJob, backendName string, run RunIdentity) {
	j.BackendID, j.BackendHandle = backendName, run.Handle
	j.BackendJobID, j.BackendBootID, j.PolicyDigest = run.RunID, run.BootID, run.PolicyDigest
	if run.Nonce != "" {
		j.DispatchNonce = run.Nonce
	}
}

// cleanupBackend removes a finished job's backend resources under a
// bounded deadline, bound to the job's persisted dispatch identity —
// the request is built from the ledger row with the observed run
// identity preferred (adoption may have refreshed it this pass). A
// failure or a non-proven outcome is recorded as cleanup pending,
// never as a result change.
func (s *Server) cleanupBackend(job *LedgerJob, run RunIdentity, claim *RecoveryClaim) (CleanupResult, error) {
	req := cleanupRequestFor(job)
	if run.Handle != "" {
		req.Handle = run.Handle
	}
	if run.Nonce != "" {
		req.DispatchNonce = run.Nonce
	}
	if run.BootID != "" {
		req.BootID = run.BootID
	}
	if run.RunID != "" {
		req.RunID = run.RunID
	}
	if run.PolicyDigest != "" {
		req.PolicyDigest = run.PolicyDigest
	}
	req.RecoveryFence = fenceFromClaim(claim)
	ctx, cancel := context.WithTimeout(s.shutdown, 15*time.Second)
	defer cancel()
	return s.cfg.Backend.Cleanup(ctx, req)
}

// markUnobserved records a job whose outcome could not be
// demonstrated as DISPATCH_AMBIGUOUS — may still be live, never
// retried blind, operator reconciles. It never emits a receipt.
func (s *Server) markUnobserved(jobID, reason string) {
	if terr := s.ledger.Transition(jobID, JobStateDispatchAmbig, []string{JobStateRunning},
		func(j *LedgerJob) error {
			j.Error = reason
			return nil
		}); terr != nil {
		s.audit("job %s: could not record the unresolved outcome: %v", jobID, terr)
	}
}

// emitReceipt signs and durably appends one terminal receipt to the
// evidence chain. It must succeed before its ledger transition —
// evidence precedes the claim it supports, or the claim does not get
// made.
func (s *Server) emitReceipt(job *LedgerJob, outcome, artifactSHA, runID string) (string, error) {
	if s.evidence == nil {
		return "", fmt.Errorf("evidence chain not open")
	}
	return s.evidence.EmitForJob(job, outcome, artifactSHA, runID)
}

// finishTerminal is the shared terminal write: sign the receipt, then
// commit the transition binding the receipt digest, then checkpoint
// the post-transition enumeration. from is the set of states the row
// may hold — RUNNING for a live monitor, the unresolved states for a
// recovery pass. A failure at any stage leaves the job non-terminal —
// the next reconcile marks it ambiguous for an operator, never
// silently terminal or silently lost — and the caller must not treat
// the job's resources as disposable.
func (s *Server) finishTerminal(job *LedgerJob, from []string, state, outcome, handle, artifactSHA string, claim *RecoveryClaim, mutate func(*LedgerJob) error) error {
	receiptSHA, rerr := s.emitReceipt(job, outcome, artifactSHA, handle)
	if rerr != nil {
		s.audit("job %s: evidence emission failed (%v) — staying non-terminal for reconcile", job.JobID, rerr)
		return rerr
	}
	err := s.ledger.TransitionWithClaim(job.JobID, state, from, claim,
		func(j *LedgerJob) error {
			j.ReceiptSHA256 = receiptSHA
			return mutate(j)
		})
	if err != nil {
		s.audit("job %s finished %s but the ledger refused the transition: %v", job.JobID, state, err)
		return err
	}
	s.checkpoint()
	return nil
}

// checkpoint issues a signed checkpoint over the current terminal
// enumeration. Failure is loud — the receipt and row already stand,
// but the missing checkpoint is a coverage gap a verifier flags.
func (s *Server) checkpoint() {
	if s.evidence == nil {
		return
	}
	refs, err := s.ledger.TerminalRefs()
	if err != nil {
		s.audit("evidence checkpoint failed: cannot enumerate terminal records: %v", err)
		return
	}
	if err := s.evidence.Checkpoint(refs); err != nil {
		s.audit("evidence checkpoint failed: %v", err)
	}
}

// checkCeiling refuses contracts whose declared budget exceeds a
// configured ceiling — the operator's bound on the authority's grant.
func (s *Server) checkCeiling(c *JobContractV2) error {
	ceil := s.cfg.ResourceCeiling
	if ceil == nil {
		return nil
	}
	if ceil.CPUs > 0 && c.Resources.CPUs > ceil.CPUs {
		return fmt.Errorf("cpus %g exceeds the executor ceiling %g", c.Resources.CPUs, ceil.CPUs)
	}
	if ceil.MemoryMB > 0 && c.Resources.MemoryMB > ceil.MemoryMB {
		return fmt.Errorf("memory_mb %d exceeds the executor ceiling %d", c.Resources.MemoryMB, ceil.MemoryMB)
	}
	if ceil.DiskMB > 0 && c.Resources.DiskMB > ceil.DiskMB {
		return fmt.Errorf("disk_mb %d exceeds the executor ceiling %d", c.Resources.DiskMB, ceil.DiskMB)
	}
	if ceil.Pids > 0 && c.Resources.Pids > ceil.Pids {
		return fmt.Errorf("pids %d exceeds the executor ceiling %d", c.Resources.Pids, ceil.Pids)
	}
	if ceil.TimeoutSeconds > 0 && c.Resources.TimeoutSeconds > ceil.TimeoutSeconds {
		return fmt.Errorf("timeout_seconds %d exceeds the executor ceiling %d", c.Resources.TimeoutSeconds, ceil.TimeoutSeconds)
	}
	if ceil.MaxOutputBytes > 0 && c.Resources.MaxOutputBytes > ceil.MaxOutputBytes {
		return fmt.Errorf("max_output_bytes %d exceeds the executor ceiling %d", c.Resources.MaxOutputBytes, ceil.MaxOutputBytes)
	}
	return nil
}

// ResourcePool is the operator's aggregate budget across every job
// whose VM may exist — the bound that keeps N authorized jobs from
// consuming N× the machine. Usage is recomputed from durable ledger
// rows on every admission, so the bound survives restarts and crashes
// rather than living in process memory; an unresolved row
// (DISPATCH_AMBIGUOUS, INTERRUPTED) keeps its reservation until an
// operator reconciles it or the VM's own contract timeout — the
// backend pins --max-duration to it — has provably elapsed.
type ResourcePool struct {
	// MaxConcurrentVMs bounds jobs in a state where a VM may exist
	// (DISPATCHING, RUNNING, DISPATCH_AMBIGUOUS, INTERRUPTED).
	MaxConcurrentVMs int
	// MaxSubmitterVMs bounds that same count per submitter identity.
	MaxSubmitterVMs int
	// TotalCPUs, TotalMemoryMB, TotalDiskMB and TotalOutputBytes
	// bound the summed declared budgets of in-flight jobs. Zero
	// disables the dimension; a configured dimension requires every
	// admitted contract to declare it.
	TotalCPUs        float64
	TotalMemoryMB    uint64
	TotalDiskMB      uint64
	TotalOutputBytes uint64
}

// validate requires every dimension to be a positive bound. A
// zero-valued dimension is a disabled bound, which an untrusted-code
// backend may not run without — and a pool that bounds a dimension
// also requires every admitted contract to declare it, so positive
// aggregate bounds are what make the per-contract limits mandatory.
func (p *ResourcePool) validate() error {
	missing := []string{}
	if p.MaxConcurrentVMs <= 0 {
		missing = append(missing, "concurrent VMs (-pool-vms)")
	}
	if p.MaxSubmitterVMs <= 0 {
		missing = append(missing, "per-submitter VMs (-pool-submitter-vms)")
	}
	if p.TotalCPUs <= 0 {
		missing = append(missing, "cpus (-pool-cpus)")
	}
	if p.TotalMemoryMB == 0 {
		missing = append(missing, "memory (-pool-memory-mb)")
	}
	if p.TotalDiskMB == 0 {
		missing = append(missing, "disk (-pool-disk-mb)")
	}
	if p.TotalOutputBytes == 0 {
		missing = append(missing, "output (-pool-output-bytes)")
	}
	if len(missing) != 0 {
		return fmt.Errorf("an execution backend requires every aggregate bound to be positive; missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

// check refuses one admission that would exceed the pool. Every
// configured dimension is a hard bound; a contract that leaves a
// bounded dimension undeclared refuses rather than being counted as
// free.
func (p *ResourcePool) check(usage *PoolUsage, submitter string, budget *ResourceBudget) error {
	if p == nil {
		return nil
	}
	if p.MaxConcurrentVMs > 0 && usage.VMs+1 > p.MaxConcurrentVMs {
		return fmt.Errorf("concurrent VMs would exceed the pool bound (%d/%d)", usage.VMs+1, p.MaxConcurrentVMs)
	}
	if p.MaxSubmitterVMs > 0 && usage.PerSubmitter[submitter]+1 > p.MaxSubmitterVMs {
		return fmt.Errorf("submitter %s would exceed its concurrent VM bound (%d/%d)",
			submitter, usage.PerSubmitter[submitter]+1, p.MaxSubmitterVMs)
	}
	if p.TotalCPUs > 0 {
		if budget.CPUs <= 0 {
			return fmt.Errorf("the pool bounds cpus but the contract declares none")
		}
		if usage.CPUs+budget.CPUs > p.TotalCPUs {
			return fmt.Errorf("cpus would exceed the pool bound (%g+%g > %g)", usage.CPUs, budget.CPUs, p.TotalCPUs)
		}
	}
	if p.TotalMemoryMB > 0 {
		if budget.MemoryMB == 0 {
			return fmt.Errorf("the pool bounds memory but the contract declares none")
		}
		if usage.MemoryMB+budget.MemoryMB > p.TotalMemoryMB {
			return fmt.Errorf("memory would exceed the pool bound (%d+%d > %d MiB)",
				usage.MemoryMB, budget.MemoryMB, p.TotalMemoryMB)
		}
	}
	if p.TotalDiskMB > 0 {
		if budget.DiskMB == 0 {
			return fmt.Errorf("the pool bounds disk but the contract declares none")
		}
		if usage.DiskMB+budget.DiskMB > p.TotalDiskMB {
			return fmt.Errorf("disk would exceed the pool bound (%d+%d > %d MiB)",
				usage.DiskMB, budget.DiskMB, p.TotalDiskMB)
		}
	}
	if p.TotalOutputBytes > 0 {
		if budget.MaxOutputBytes == 0 {
			return fmt.Errorf("the pool bounds output but the contract declares none")
		}
		if usage.OutputBytes+budget.MaxOutputBytes > p.TotalOutputBytes {
			return fmt.Errorf("output would exceed the pool bound (%d+%d > %d bytes)",
				usage.OutputBytes, budget.MaxOutputBytes, p.TotalOutputBytes)
		}
	}
	return nil
}

// ErrPoolExhausted marks an admission refused by the aggregate
// resource pool — distinct from a malformed or replayed submission.
var ErrPoolExhausted = errors.New("executor resource pool exhausted")

// contractBudget extracts the budget admission reserves. A signed
// contract carries it; the unsigned submission shape declares none
// (and can never reach a backend anyway).
func contractBudget(c *JobContractV2) *ResourceBudget {
	if c != nil {
		return &c.Resources
	}
	return &ResourceBudget{}
}

// admitJob reserves the job against the aggregate pool and persists
// it, all inside one critical section: bound → pool check → ledger
// insert → dispatch intent. A concurrent admission's check observes
// this job's durable DISPATCHING row, so two jobs can never both pass
// the same budget. The lock is released before any backend launch.
func (s *Server) admitJob(jobID, contractHash, submitter, principal, image, contractJSON string, budget *ResourceBudget) (*LedgerJob, error) {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	// The registry bound is checked against durable ACTIVE state —
	// settled terminal history no longer counts against it. When the
	// active table is full, archive its settled rows first and recount:
	// only a registry still full of live or unresolved work refuses.
	if count, err := s.ledger.Count(); err != nil {
		return nil, fmt.Errorf("registry unavailable: %w", err)
	} else if count >= maxJobs {
		if _, aerr := s.ledger.ArchiveCompleted(maxArchiveBatch); aerr != nil {
			return nil, fmt.Errorf("registry full and archival failed: %w", aerr)
		}
		if count, err = s.ledger.Count(); err != nil {
			return nil, fmt.Errorf("registry unavailable: %w", err)
		}
		if count >= maxJobs {
			return nil, fmt.Errorf("job registry full (%d active records)", maxJobs)
		}
	}
	// The pool bounds execution, so it applies only when a backend can
	// execute: a record-only executor admits (and records) jobs it
	// will never run.
	if s.cfg.Backend != nil && s.cfg.ResourcePool != nil {
		usage, err := s.ledger.ActiveUsage(s.cfg.DispatchTimeout + time.Minute)
		if err != nil {
			return nil, fmt.Errorf("read pool usage: %w", err)
		}
		if err := s.cfg.ResourcePool.check(usage, submitter, budget); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPoolExhausted, err)
		}
	}
	// The row and the dispatch intent commit together when a backend
	// exists — there is no durable RECORDED state to strand in. A
	// record-only executor still writes RECORDED and stops.
	if s.cfg.Backend == nil {
		return s.ledger.InsertJob(jobID, contractHash, submitter, principal, image, contractJSON)
	}
	// Persisted intent to dispatch before the backend sees anything —
	// a crash between dispatch and result leaves a DISPATCHING row,
	// which reconcile marks ambiguous rather than guessing.
	return s.ledger.AdmitJob(jobID, contractHash, submitter, principal, image, contractJSON)
}
