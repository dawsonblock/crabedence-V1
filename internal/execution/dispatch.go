package execution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// DispatchState tracks where an execution is in the dispatch lifecycle.
type DispatchState string

const (
	// DispatchPre means the request has not yet been sent to the provider.
	// Failure here is safe FAILED — no side effect could have occurred.
	DispatchPre DispatchState = "PRE_DISPATCH"

	// DispatchPost means the request has been sent to the provider.
	// Failure here is UNKNOWN — the side effect may have occurred.
	DispatchPost DispatchState = "POST_DISPATCH"
)

// ExecutorTimeouts bounds each durability stage of the dispatch path.
// Every stage derives its own bounded context from its own budget, and
// each budget starts when the stage starts — a database operation that
// exhausts its budget must never consume the budget of the stage that
// follows it. Emergency recovery in particular must not inherit a
// context already exhausted by the operation that failed: that is the
// difference between a record that reaches UNKNOWN with its provider
// observation persisted and one stranded IN_FLIGHT.
//
// The stage contexts are detached from the caller's cancellation
// (values preserved) so that a client disconnect or service shutdown
// cannot lose the provider's already-returned answer.
type ExecutorTimeouts struct {
	// ObservationPersistence bounds the durable provider-observation
	// write after the provider returns.
	ObservationPersistence time.Duration
	// Terminalization bounds the terminal stage: CRITICAL evidence
	// signing, the lease-generation lookup, and the fenced Finalize.
	Terminalization time.Duration
	// EmergencyRecovery bounds entering UNKNOWN recovery with the
	// provider observation. Derived fresh at every recovery entry.
	EmergencyRecovery time.Duration
	// LeaseOperation bounds a single lease store operation — a
	// heartbeat renewal or a pre-dispatch abandon.
	LeaseOperation time.Duration
	// ProviderExecution is the executor-owned ceiling on a single
	// provider invocation — independent of the caller's deadline. A
	// handler may ignore context cancellation entirely; without this
	// ceiling a hung adapter would heartbeat its lease forever and
	// reconcilers could never take ownership of the record. Exceeding
	// the ceiling after dispatch is post-dispatch ambiguity: the
	// record converges to UNKNOWN + reconciliation, never FAILED,
	// never redispatch.
	ProviderExecution time.Duration
	// ProviderExecutionGrace is the short window after the caller
	// deadline or the provider ceiling fires during which a
	// cooperative handler may still return its answer (the answer can
	// carry provider evidence the durable observation must persist).
	ProviderExecutionGrace time.Duration
}

// DefaultExecutorTimeouts returns the production budgets for the
// post-dispatch durability stages.
func DefaultExecutorTimeouts() ExecutorTimeouts {
	return ExecutorTimeouts{
		ObservationPersistence: 5 * time.Second,
		Terminalization:        5 * time.Second,
		EmergencyRecovery:      5 * time.Second,
		LeaseOperation:         3 * time.Second,
		ProviderExecution:      5 * time.Minute,
		ProviderExecutionGrace: 2 * time.Second,
	}
}

// withDefaults fills zero fields from DefaultExecutorTimeouts.
func (t ExecutorTimeouts) withDefaults() ExecutorTimeouts {
	d := DefaultExecutorTimeouts()
	if t.ObservationPersistence <= 0 {
		t.ObservationPersistence = d.ObservationPersistence
	}
	if t.Terminalization <= 0 {
		t.Terminalization = d.Terminalization
	}
	if t.EmergencyRecovery <= 0 {
		t.EmergencyRecovery = d.EmergencyRecovery
	}
	if t.LeaseOperation <= 0 {
		t.LeaseOperation = d.LeaseOperation
	}
	if t.ProviderExecution <= 0 {
		t.ProviderExecution = d.ProviderExecution
	}
	if t.ProviderExecutionGrace <= 0 {
		t.ProviderExecutionGrace = d.ProviderExecutionGrace
	}
	return t
}

// durabilityContext derives the bounded context for one durability
// stage: detached from the caller's cancellation (values preserved),
// bounded by the stage's own budget.
func durabilityContext(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), budget)
}

// requestDigestProtocolVersion is the digest ABI version. The
// descriptor-identity binding is additive (zero values bind nothing),
// so it does not require a protocol bump; the executor's legacy-digest
// retry covers records created before descriptor identity existed.
const requestDigestProtocolVersion = 1

// DispatchExecutor wraps a Handler with dispatch-point tracking and
// durable idempotency. It ensures:
//   - Pre-dispatch failures return FAILED (safe)
//   - Post-dispatch failures return UNKNOWN (may have executed)
//   - Idempotent requests return the stored result
//   - Same key + different request returns CONFLICT
//   - MUTATION/CRITICAL fail closed when durable store is unavailable
//   - CRITICAL evidence is validated BEFORE terminal state is persisted
//   - Only the reservation owner (lease holder) may dispatch
type DispatchExecutor struct {
	handler  Handler
	store    idempotency.EffectStore
	signer   *evidence.Signer
	mu       sync.Mutex
	inFlight map[string]context.CancelFunc
	// preFinalizeHook, when set, runs after the terminal decision and
	// before Finalize — a test seam for simulating slow evidence
	// verification while the lease heartbeat must keep the lease alive.
	preFinalizeHook func()
	// postDispatchHook, when set, runs immediately after the provider
	// returns and before the observation is persisted — a test seam for
	// simulating a crash inside the observation window.
	postDispatchHook func()
	// crashHook, when set, is invoked at every CrashPoint in the
	// execution path — a deterministic failure-injection seam for
	// crash/qualification testing. The hook may do anything (close the
	// database, panic, os.Exit); the executor makes no guarantees
	// after it runs.
	crashHook func(CrashPoint)
	// timeouts bound each durability stage of the post-dispatch path.
	// See ExecutorTimeouts.
	timeouts ExecutorTimeouts
}

// CrashPoint names a deterministic boundary in the execution path at
// which a crash can be injected. The set covers every durable
// transition so qualification tests can kill the executor — or the
// process — at each state boundary and assert the recovery contract:
// pre-dispatch crash → safely abandoned or FAILED; post-dispatch
// crash → UNKNOWN and reconcilable, never silently lost.
type CrashPoint string

const (
	// CrashAfterAcquire — lease acquired, before any state transition.
	CrashAfterAcquire CrashPoint = "after_acquire"
	// CrashAfterBeginExecution — EXECUTING persisted, before the
	// recovery locator / IN_FLIGHT transition.
	CrashAfterBeginExecution CrashPoint = "after_begin_execution"
	// CrashAfterMarkInFlight — IN_FLIGHT and the recovery locator are
	// durable, but the provider has not been invoked.
	CrashAfterMarkInFlight CrashPoint = "after_mark_in_flight"
	// CrashBeforeProvider — heartbeat started, provider invocation
	// about to begin.
	CrashBeforeProvider CrashPoint = "before_provider"
	// CrashAfterProvider — provider returned; no observation,
	// recovery, or terminal state persisted yet.
	CrashAfterProvider CrashPoint = "after_provider"
	// CrashBeforeObservation — about to persist the provider
	// observation.
	CrashBeforeObservation CrashPoint = "before_observation"
	// CrashAfterObservation — provider observation persisted (or
	// attempted), before the terminal decision.
	CrashAfterObservation CrashPoint = "after_observation"
	// CrashBeforeFinalize — terminal receipt built and (for CRITICAL)
	// signed, about to call Finalize.
	CrashBeforeFinalize CrashPoint = "before_finalize"
	// CrashAfterFinalize — terminal state durably committed.
	CrashAfterFinalize CrashPoint = "after_finalize"
	// CrashBeforeRecovery — about to persist the UNKNOWN recovery
	// transition.
	CrashBeforeRecovery CrashPoint = "before_recovery"
	// CrashAfterRecovery — UNKNOWN durably persisted.
	CrashAfterRecovery CrashPoint = "after_recovery"
)

// fireCrashPoint invokes the configured crash hook at p.
func (e *DispatchExecutor) fireCrashPoint(p CrashPoint) {
	if e.crashHook != nil {
		e.crashHook(p)
	}
}

// SetCrashHook installs a failure-injection hook invoked at every
// CrashPoint. Passing nil disables it. Intended for crash and
// adversarial qualification tests.
func (e *DispatchExecutor) SetCrashHook(h func(CrashPoint)) {
	e.crashHook = h
}

// SetTimeouts overrides the per-stage durability budgets. Zero fields
// keep their defaults. Intended for tests that exercise stage-boundary
// behavior with sub-second budgets; production keeps
// DefaultExecutorTimeouts.
func (e *DispatchExecutor) SetTimeouts(t ExecutorTimeouts) {
	e.timeouts = t.withDefaults()
}

// NewDispatchExecutor creates a new dispatch executor with durable idempotency.
func NewDispatchExecutor(handler Handler, store idempotency.EffectStore) *DispatchExecutor {
	return &DispatchExecutor{
		handler:  handler,
		store:    store,
		inFlight: make(map[string]context.CancelFunc),
		timeouts: DefaultExecutorTimeouts(),
	}
}

// SetEvidenceSigner configures the Ed25519 receipt signer used to attest
// CRITICAL terminal outcomes. Without a signer, CRITICAL finalization
// cannot produce the signed evidence receipt the store requires, so
// CRITICAL executions fail closed into UNKNOWN recovery.
func (e *DispatchExecutor) SetEvidenceSigner(s *evidence.Signer) {
	e.signer = s
}

// ExecuteWithIdempotency executes a request with durable idempotency.
func (e *DispatchExecutor) ExecuteWithIdempotency(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	// For PURE and READ, skip idempotency (no side effects)
	if desc.ExecutionClass == capability.ClassPure || desc.ExecutionClass == capability.ClassRead {
		resp, _ := e.dispatch(ctx, req, desc)
		return resp
	}

	// For MUTATION and CRITICAL, durable idempotency is REQUIRED.
	// Fail closed — never execute unguarded mutations.
	if e.store == nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       "durable idempotency unavailable: MUTATION/CRITICAL operations require a database connection",
		}
	}

	// Provider capability gate — a CRITICAL execution is admitted only
	// when the provider declares it can prove both completion and
	// non-effect; anything less could never be reconciled to a
	// terminal state after post-dispatch ambiguity.
	if denied := checkCriticalProviderCapability(e.handler, desc); denied != nil {
		return *denied
	}

	// Compute request digest. The resolved authority generation and
	// grant digest are bound into the execution identity so the same
	// grant_id under different immutable authority material is a
	// different request — reissuing or mutating a grant never silently
	// reinterprets a durable execution or idempotency key.
	//
	// The capability policy identity is bound too: the descriptor
	// version and its canonical digest. A registry policy change
	// (schema, class, assurance, route, authority policy, adapter) is
	// therefore a new execution identity, never a silent
	// reinterpretation of an existing record.
	descriptorDigest, err := desc.DescriptorDigest()
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to compute descriptor digest: %v", err),
		}
	}
	digest, err := idempotency.ComputeDigestFromRawWithDescriptor(
		requestDigestProtocolVersion,
		req.Authority.Principal,
		req.Capability,
		req.Arguments,
		req.Authority.EffectiveAuthorityRef(),
		string(desc.ExecutionClass),
		req.Authority.AuthorityGeneration,
		req.Authority.AuthorityDigest,
		string(desc.AssuranceProfile),
		string(desc.ExecutionRoute),
		desc.DescriptorVersion,
		descriptorDigest,
	)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to compute digest: %v", err),
		}
	}

	// Acquire the execution atomically using the typed API.
	// The lease duration comes from the store's LeaseConfig.
	leaseCfg := e.store.LeaseConfig()
	leaseDuration := leaseCfg.DefaultDuration
	if leaseDuration <= 0 {
		leaseDuration = idempotency.DefaultLeaseDuration
	}
	authorityBinding := idempotency.AuthorityBinding{
		Ref:        req.Authority.EffectiveAuthorityRef(),
		Generation: req.Authority.AuthorityGeneration,
		Digest:     req.Authority.AuthorityDigest,
	}
	acq, err := e.store.AcquireWithAuthority(ctx, req.IdempotencyKey, req.Authority.Principal, req.Capability, digest,
		authorityBinding, string(desc.ExecutionClass), leaseDuration)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("idempotency acquire failed: %v", err),
		}
	}

	// Compatibility window for records created before descriptor
	// identity was bound: their stored digest is the legacy digest, so
	// the descriptor-bound digest conflicts. Recompute the legacy
	// digest and retry the acquisition exactly once — a genuine
	// conflict (neither digest matches the stored record) still fails
	// closed, and new records always store the descriptor-bound digest.
	if acq.Kind == idempotency.IdempotencyConflict {
		legacyDigest, legacyErr := idempotency.ComputeDigestFromRawWithAuthority(
			requestDigestProtocolVersion,
			req.Authority.Principal,
			req.Capability,
			req.Arguments,
			req.Authority.EffectiveAuthorityRef(),
			string(desc.ExecutionClass),
			req.Authority.AuthorityGeneration,
			req.Authority.AuthorityDigest,
			string(desc.AssuranceProfile),
			string(desc.ExecutionRoute),
		)
		if legacyErr == nil && legacyDigest != digest {
			if legacyAcq, legacyAcquireErr := e.store.AcquireWithAuthority(ctx, req.IdempotencyKey,
				req.Authority.Principal, req.Capability, legacyDigest, authorityBinding,
				string(desc.ExecutionClass), leaseDuration); legacyAcquireErr == nil {
				acq = legacyAcq
			}
		}
	}

	// Check for conflict — same key, different request
	if acq.Kind == idempotency.IdempotencyConflict {
		return Response{
			Status:      StatusDenied,
			FailureCode: string(capability.FailureIdempotencyConflict),
			Error:       "same idempotency key used with different request",
		}
	}

	// Check for existing terminal result — replay the stored result.
	// Terminal replay must use the STORED provider identity, not the
	// current adapter. The stored provider_id/provider_run_id are part
	// of the audit trail for CRITICAL operations.
	if acq.Kind == idempotency.TerminalReplay && acq.Record != nil {
		replayProvider := acq.Record.ProviderID
		replayRunID := acq.Record.ProviderRunID
		if replayProvider == "" {
			replayProvider = desc.AdapterID
		}
		if replayRunID == "" {
			replayRunID = acq.Record.ExecutionID
		}
		return Response{
			Status:   stateToStatus(acq.State),
			Result:   acq.Record.Result,
			Evidence: parseEvidence(acq.Record.EvidenceDigest, acq.Record.ReceiptVersion),
			Execution: &ExecutionMeta{
				Provider: replayProvider,
				RunID:    replayRunID,
			},
		}
	}

	// Check for existing in-flight — another caller owns the reservation
	// or the record is in a non-terminal state.
	if !acq.Acquired() {
		replayProvider := desc.AdapterID
		replayRunID := ""
		if acq.Record != nil {
			replayRunID = acq.Record.ExecutionID
			if acq.Record.ProviderRunID != "" {
				replayRunID = acq.Record.ProviderRunID
			}
			if acq.Record.ProviderID != "" {
				replayProvider = acq.Record.ProviderID
			}
		}
		if acq.Kind == idempotency.RecoveryRequired {
			// The record is UNKNOWN — caller-terminal, not in-flight.
			// The prior dispatch outcome could not be determined and
			// reconciliation owns the record; reporting IN_FLIGHT
			// would invite the caller to wait or retry an operation
			// that may already have executed.
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       "prior execution outcome is unknown and under reconciliation — do not retry",
				Execution: &ExecutionMeta{
					Provider: replayProvider,
					RunID:    replayRunID,
				},
			}
		}
		return Response{
			Status:      StatusInFlight,
			FailureCode: string(capability.FailureInFlight),
			Execution: &ExecutionMeta{
				Provider: replayProvider,
				RunID:    replayRunID,
			},
		}
	}

	// Acquired — THIS caller owns the reservation and holds the lease.
	// Only now may we dispatch.
	executionID := acq.Record.ExecutionID
	leaseToken := acq.LeaseToken
	leaseGen := acq.Generation
	e.fireCrashPoint(CrashAfterAcquire)

	// Deadline preflight BEFORE the dispatch boundary: an already-expired
	// deadline is a provable no-effect failure — the handler will never
	// run. IN_FLIGHT must continue to mean "provider invocation may have
	// begun"; marking it before this check would let a crash in the gap
	// strand a record in UNKNOWN that provably never ran, which a
	// negative provider lookup may never resolve. Abandon returns the
	// record to claimable PREPARED so a retry with a valid deadline
	// reacquires immediately — the expired deadline is not a durable
	// terminal outcome. The check inside dispatch() remains for the
	// residual window where the deadline expires between this preflight
	// and handler invocation (the record is legitimately IN_FLIGHT then).
	if expired := deadlineExpired(req.Deadline); expired {
		e.abandonPreDispatch(ctx, executionID, leaseToken, leaseGen)
		return Response{
			Status:            StatusFailed,
			FailureCode:       string(capability.FailureInvalidRequest),
			Error:             fmt.Sprintf("request deadline %s already passed", req.Deadline),
			DefinitiveFailure: true,
		}
	}

	// Mark as EXECUTING using the typed API (fenced by token + generation).
	// This is PRE_DISPATCH — if this fails, return FAILED (safe).
	if err := e.store.BeginExecution(ctx, executionID, leaseToken, leaseGen); err != nil {
		e.abandonPreDispatch(ctx, executionID, leaseToken, leaseGen)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to begin execution (lease lost or state changed): %v", err),
		}
	}
	e.fireCrashPoint(CrashAfterBeginExecution)

	// ─── IN_FLIGHT: the dispatch boundary ───────────────────────────────────
	// Persist the recovery locator BEFORE crossing IN_FLIGHT.
	// The locator carries enough information for a RecoveryResolver to
	// query the provider and determine whether the side effect occurred.
	// Providers implementing RecoveryLocatorProvider supply a minimal
	// provider-specific locator; anything else gets a metadata-only
	// generic locator (never raw arguments).
	recoveryLocator, err := e.prepareRecoveryLocator(ctx, req, desc, digest, executionID)
	if err != nil {
		// Pre-dispatch failure — no side effect could have occurred.
		e.abandonPreDispatch(ctx, executionID, leaseToken, leaseGen)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to prepare recovery locator: %v", err),
		}
	}
	locatorRaw, err := json.Marshal(recoveryLocator)
	if err != nil {
		e.abandonPreDispatch(ctx, executionID, leaseToken, leaseGen)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to marshal recovery locator: %v", err),
		}
	}
	if len(locatorRaw) > idempotency.MaxRecoveryLocatorBytes {
		e.abandonPreDispatch(ctx, executionID, leaseToken, leaseGen)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error: fmt.Sprintf("recovery locator exceeds %d bytes (got %d)",
				idempotency.MaxRecoveryLocatorBytes, len(locatorRaw)),
		}
	}
	if err := e.store.MarkInFlight(ctx, executionID, leaseToken, leaseGen, desc.AdapterID, locatorRaw); err != nil {
		e.abandonPreDispatch(ctx, executionID, leaseToken, leaseGen)
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to transition to IN_FLIGHT (lease lost or state changed): %v", err),
		}
	}
	e.fireCrashPoint(CrashAfterMarkInFlight)

	// Lease heartbeat — renew the lease while the provider is
	// executing. Without this, a long-running provider call can exceed
	// the lease duration, causing the record to become UNKNOWN even
	// though the provider eventually succeeds. The heartbeat uses the
	// store's LeaseConfig for renewal interval and duration.
	//
	// The heartbeat is detached from the caller's cancellation: the
	// dispatch boundary is already crossed (IN_FLIGHT is persisted),
	// so the lease must stay valid while the provider call runs AND
	// while mandatory post-dispatch persistence completes on the
	// detached durability context below. Deriving the heartbeat from
	// ctx would let a caller disconnect kill lease renewal mid-
	// finalization, opening a window where another worker reclaims
	// the record while this executor is still committing the outcome.
	// The heartbeat stops only when Execute returns — after the
	// terminal or recovery state is durably persisted.
	heartbeatCtx, heartbeatCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer heartbeatCancel()
	go e.leaseHeartbeat(heartbeatCtx, executionID, leaseToken, leaseGen)

	// Dispatch — from this point, we are POST_DISPATCH.
	// Any failure after this point is UNKNOWN (may have executed).
	// The external token persisted in the recovery locator is injected
	// into the dispatch context so the provider uses the SAME token in
	// the external request — the stable external operation identity.
	dispatchCtx := ctx
	if recoveryLocator.ExternalToken != "" {
		dispatchCtx = context.WithValue(ctx, externalTokenKey{}, recoveryLocator.ExternalToken)
	}
	e.fireCrashPoint(CrashBeforeProvider)
	resp, provableNoEffect := e.dispatch(dispatchCtx, req, desc)
	e.fireCrashPoint(CrashAfterProvider)

	// The provider has answered. Everything from here until the terminal
	// write is mandatory persistence — it must survive caller
	// cancellation and service shutdown. Each stage below derives its
	// OWN bounded, detached context (durabilityContext): observation
	// persistence, emergency recovery, and terminalization never share a
	// budget, so one exhausted stage cannot strand the next.

	// ─── DURABLE PROVIDER OBSERVATION ────────────────────────────────────
	// Persist the provider's response metadata BEFORE any terminal
	// decision. If the record races into UNKNOWN (lease expiry claimed
	// by a reconciler) or Finalize fails, the observation — provider_id,
	// provider_run_id, evidence digest, result — is already durable and
	// does not depend on winning another state-transition race.
	// RecordProviderObservation accepts both the fenced IN_FLIGHT write
	// and the already-UNKNOWN update.
	//
	// providerResp preserves the raw provider response — the classifier
	// may rewrite resp to an UNKNOWN wire response, but the durable
	// observation must always carry what the provider actually said.
	providerResp := resp
	// A definitive failure the EXECUTOR itself proved pre-transmission
	// (the handler was never invoked) still yields attestable evidence:
	// the dispatcher's synthesized failure record. The handler's
	// DefinitiveFailure flag is only a routing hint — a handler that
	// performed the effect and then asserts the flag must not be able
	// to conjure signed NO_EFFECT proof, so synthesis requires the
	// executor's own provable-no-effect provenance. A handler-claimed
	// definitive failure without a real artifact fails closed to
	// UNKNOWN at the CRITICAL sign gate below.
	if len(resp.EvidenceArtifact) == 0 && resp.DefinitiveFailure && provableNoEffect {
		resp.EvidenceArtifact, _ = json.Marshal(map[string]string{
			"definitive_failure": "true",
			"failure_code":       resp.FailureCode,
			"error":              resp.Error,
		})
		// classifyPostDispatch runs on providerResp — keep the
		// artifact visible there too or the CRITICAL sign gate
		// never sees it.
		providerResp.EvidenceArtifact = resp.EvidenceArtifact
	}
	// Evidence authenticity boundary: the evidence digest is recomputed
	// from the provider's evidence ARTIFACT bytes, never taken from a
	// handler-supplied digest string. What the trusted signer attests
	// is a digest Crabedence itself computed — a handler cannot invent
	// a digest and have it blessed.
	if len(resp.EvidenceArtifact) > 0 {
		sum := sha256.Sum256(resp.EvidenceArtifact)
		recomputed := fmt.Sprintf("%x", sum)
		if resp.Evidence == nil {
			resp.Evidence = &EvidenceRef{ReceiptVersion: 3}
		}
		resp.Evidence.Digest = recomputed
		providerResp.Evidence = resp.Evidence
	} else {
		// A digest the executor cannot recompute from provider bytes is
		// unverifiable — drop it rather than persist or attest a claim
		// the ledger cannot prove.
		resp.Evidence = nil
		providerResp.Evidence = nil
	}
	if e.postDispatchHook != nil {
		e.postDispatchHook()
	}
	e.fireCrashPoint(CrashBeforeObservation)
	obsCtx, obsCancel := durabilityContext(ctx, e.timeouts.ObservationPersistence)
	obsErr := e.recordObservation(obsCtx, executionID, leaseToken, leaseGen, providerResp, desc)
	obsCancel()
	e.fireCrashPoint(CrashAfterObservation)

	// The heartbeat stays alive through finalization — the lease must
	// remain valid while we validate evidence, construct the receipt,
	// and commit the terminal state. Cancelling it here would create
	// a window where the lease expires between provider return and
	// Finalize.

	// ─── TERMINAL DECISION — single post-dispatch decision table ─────────
	state, resp := classifyPostDispatch(providerResp, desc)

	evidenceDigest := ""
	receiptVersion := 0
	if resp.Evidence != nil {
		evidenceDigest = resp.Evidence.Digest
		receiptVersion = resp.Evidence.ReceiptVersion
	}

	// ─── IMMUTABLE FINALIZATION ────────────────────────────────────────────
	// Finalize uses CAS semantics: only the lease holder may finalize,
	// the expected state must match, and terminal states are immutable.
	// A second identical finalize is idempotent; a conflicting receipt
	// is rejected as FINALIZATION_CONFLICT.
	//
	// If the handler returned an ambiguous result after IN_FLIGHT
	// (post-dispatch uncertainty), the state is UNKNOWN — we do NOT
	// finalize as FAILED. The side effect may have occurred.
	if state == idempotency.StateUnknown {
		// Post-dispatch uncertainty — enter recovery carrying the
		// ORIGINAL provider observation (already persisted above; the
		// atomic transition also writes it). Do not finalize.
		recErr := e.enterRecovery(ctx, executionID, providerResp, desc)
		errMsg := "post-dispatch ambiguity: entered recovery (side effect may have occurred)"
		if recErr != nil {
			errMsg = fmt.Sprintf("post-dispatch ambiguity: %v", recErr)
		}
		if obsErr != nil {
			errMsg += fmt.Sprintf("; provider observation NOT persisted: %v", obsErr)
		}
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       errMsg,
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    executionID,
			},
		}
	}

	// The durable provider observation is part of the record the
	// terminal receipt attests. If the write failed — including a
	// monotonic conflict with a previously stored observation — the
	// terminal outcome must not be committed over it: the receipt
	// would contradict the durable observation. Route to UNKNOWN so
	// reconciliation sees the record rather than sealing the
	// contradiction into an immutable terminal state.
	if obsErr != nil {
		recErr := e.enterRecovery(ctx, executionID, providerResp, desc)
		errMsg := fmt.Sprintf("provider observation not persisted: %v", obsErr)
		if recErr != nil {
			errMsg += fmt.Sprintf("; %v", recErr)
		}
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       errMsg,
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    executionID,
			},
		}
	}

	providerID := ""
	providerRunID := ""
	if resp.Execution != nil {
		providerID = resp.Execution.Provider
		providerRunID = resp.Execution.RunID
	}
	if providerID == "" {
		// The provider that performed the operation is always the
		// resolved adapter — fall back to it rather than leaving the
		// receipt's provider identity empty.
		providerID = desc.AdapterID
	}

	// The unified terminal policy requires every definitive outcome to
	// carry proof — an evidence digest or a result payload. A definitive
	// failure without a provider result is recorded as an error payload
	// so the receipt is never empty.
	canonicalResult := resp.Result
	if len(canonicalResult) == 0 && state == idempotency.StateFailed {
		canonicalResult, _ = json.Marshal(map[string]string{
			"error":        resp.Error,
			"failure_code": resp.FailureCode,
		})
	}

	receipt := idempotency.TerminalReceipt{
		ExecutionID:     executionID,
		Capability:      req.Capability,
		Principal:       req.Authority.Principal,
		RequestDigest:   digest,
		TerminalStatus:  state,
		CanonicalResult: canonicalResult,
		ProviderID:      providerID,
		ProviderRunID:   providerRunID,
		EvidenceDigest:  evidenceDigest,
		ReceiptVersion:  receiptVersion,
	}

	// ─── TERMINALIZATION BUDGET ───────────────────────────────────────────
	// The terminal stage gets its own budget, starting here — after the
	// observation stage completed or failed — so a slow observation
	// write can never leave the finalize with an exhausted context. The
	// budget covers CRITICAL evidence signing, the lease-generation
	// lookup, and the fenced Finalize; a failure in any of them still
	// reaches emergency recovery with a fresh budget.
	termCtx, termCancel := durabilityContext(ctx, e.timeouts.Terminalization)
	defer termCancel()

	// CRITICAL proof authenticity: attest the terminal outcome with a
	// signed effect receipt binding the evidence digest, provider/run
	// identity, and execution/request identity. The store verifies the
	// signature and binding against trusted signers — a well-formed but
	// unsigned digest is not proof. Without a configured signer the
	// receipt stays unsigned and the store fails closed below.
	// A CRITICAL terminal outcome can only be attested when the
	// handler supplied an evidence ARTIFACT — bytes the digest was
	// recomputed from. Without an artifact there is nothing to prove;
	// leave the receipt unsigned and the store fails closed below.
	if desc.ExecutionClass == capability.ClassCritical && e.signer != nil && len(resp.EvidenceArtifact) > 0 {
		// The signed outcome is the semantic attestation about the
		// external world, not the state name: COMMITTED requires
		// COMPLETED proof; FAILED requires NO_EFFECT proof.
		outcome := evidence.OutcomeCompleted
		if state == idempotency.StateFailed {
			outcome = evidence.OutcomeNoEffect
		}
		signed, signErr := e.signer.Sign(evidence.Binding{
			ExecutionID:    executionID,
			Capability:     req.Capability,
			Principal:      req.Authority.Principal,
			RequestDigest:  digest,
			ProviderID:     providerID,
			ProviderRunID:  providerRunID,
			Outcome:        outcome,
			EvidenceSHA256: evidenceDigest,
		})
		if signErr != nil {
			// Cannot produce the required proof — treat as post-dispatch
			// uncertainty, not a terminal outcome.
			recErr := e.enterRecovery(ctx, executionID, providerResp, desc)
			errMsg := fmt.Sprintf("failed to sign CRITICAL evidence receipt: %v", signErr)
			if recErr != nil {
				errMsg += fmt.Sprintf("; %v", recErr)
			}
			return Response{
				Status:      StatusUnknown,
				FailureCode: string(capability.FailureExecutionUnknown),
				Error:       errMsg,
				Execution: &ExecutionMeta{
					Provider: providerID,
					RunID:    providerRunID,
				},
			}
		}
		receipt.EvidenceReceipt = signed
	}

	// Look up the lease generation for the fenced finalize.
	rec, err := e.store.Lookup(termCtx, executionID)
	if err != nil {
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       fmt.Sprintf("failed to lookup execution for finalize: %v", err),
			Execution: &ExecutionMeta{
				Provider: desc.AdapterID,
				RunID:    executionID,
			},
		}
	}

	if e.preFinalizeHook != nil {
		e.preFinalizeHook()
	}
	e.fireCrashPoint(CrashBeforeFinalize)
	if err := e.store.Finalize(termCtx, executionID, leaseToken, rec.LeaseGeneration, idempotency.StateInFlight, receipt); err != nil {
		// Finalization failed AFTER dispatch — the side effect may
		// have occurred. The provider observation was already persisted
		// durably right after the provider returned; the recovery
		// transition below also writes it atomically. Report persistence
		// honestly — never claim the observation was stored if it wasn't.
		recErr := e.enterRecovery(ctx, executionID, providerResp, desc)
		errMsg := fmt.Sprintf("failed to finalize execution after dispatch: %v", err)
		if recErr == nil {
			errMsg += " (provider observation persisted)"
		} else {
			errMsg += fmt.Sprintf(" (%v)", recErr)
		}
		if obsErr != nil {
			errMsg += fmt.Sprintf("; earlier observation write failed: %v", obsErr)
		}
		return Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       errMsg,
			Execution: &ExecutionMeta{
				Provider: providerID,
				RunID:    providerRunID,
			},
		}
	}
	e.fireCrashPoint(CrashAfterFinalize)

	// Add execution metadata
	if resp.Execution == nil {
		resp.Execution = &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    executionID,
		}
	}

	return resp
}

// deadlineExpired reports whether the request deadline is already past.
// Malformed deadlines return false here — schema validation owns that
// rejection; this check only guards timing.
func deadlineExpired(deadline string) bool {
	if deadline == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, deadline)
	if err != nil {
		return false
	}
	return !time.Now().Before(t)
}

// abandonPreDispatch releases the execution lease after a pre-dispatch
// failure so a retry reclaims immediately instead of waiting for lease
// expiry. AbandonPreDispatch only touches PREPARED/EXECUTING records,
// so it is safe even when the preceding transition may have applied
// server-side (e.g. a dropped connection after MarkInFlight) — a record
// that crossed the dispatch boundary is never unmarked. On failure the
// lease expiry path is the backstop.
func (e *DispatchExecutor) abandonPreDispatch(ctx context.Context, executionID, leaseToken string, leaseGen int) {
	// Bounded and detached: the caller's context is commonly already
	// cancelled in the pre-dispatch abandon paths, and a completed
	// abandon lets a retry reclaim the record immediately instead of
	// waiting out the lease. AbandonPreDispatch only touches
	// PREPARED/EXECUTING records, so running it on a detached context
	// cannot unmark a record that crossed the dispatch boundary.
	abandonCtx, cancel := durabilityContext(ctx, e.timeouts.LeaseOperation)
	defer cancel()
	_ = e.store.AbandonPreDispatch(abandonCtx, executionID, leaseToken, leaseGen)
}

// dispatch sends the request to the handler.
// This crosses the dispatch boundary — any failure after this call
// begins is POST_DISPATCH (may have executed).
//
// The second return value reports executor-established pre-transmission
// provenance: true only when the executor itself proved the provider was
// never invoked (e.g. an already-expired deadline). A handler-set
// DefinitiveFailure is a routing hint, not proof — only responses with
// executor provenance may be synthesized into attestable no-effect
// evidence upstream.
func (e *DispatchExecutor) dispatch(ctx context.Context, req Request, desc capability.ResolvedDescriptor) (Response, bool) {
	// Set a timeout if deadline is provided
	dispatchCtx := ctx
	if req.Deadline != "" {
		deadline, err := time.Parse(time.RFC3339, req.Deadline)
		if err == nil {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				// The deadline already passed — do not invoke the
				// handler at all. The provider was never called, so
				// this is a provable no-effect failure.
				return Response{
					Status:            StatusFailed,
					FailureCode:       string(capability.FailureInvalidRequest),
					Error:             fmt.Sprintf("request deadline %s already passed", req.Deadline),
					DefinitiveFailure: true,
				}, true
			}
			var cancel context.CancelFunc
			dispatchCtx, cancel = context.WithTimeout(ctx, remaining)
			defer cancel()
		}
	}

	// Executor-owned provider ceiling. The caller's deadline bounds the
	// provider call only when the caller supplies one — and a handler
	// may ignore context cancellation entirely. Without a framework
	// ceiling a hung adapter would hold the dispatch open while the
	// heartbeat renews its lease indefinitely: the record would never
	// reach a reconciler. The provider invocation therefore runs under
	// the executor's own budget; exceeding it is post-dispatch
	// ambiguity and converges to UNKNOWN + reconciliation — never
	// FAILED, never a redispatch.
	max := e.timeouts.ProviderExecution
	if max > 0 {
		var cancel context.CancelFunc
		dispatchCtx, cancel = context.WithTimeout(dispatchCtx, max)
		defer cancel()
	}

	// The handler.Execute call crosses the dispatch boundary. It runs
	// in its own goroutine so the ceiling can bound even a handler
	// that never observes cancellation. The channel is buffered: a
	// late handler answer is dropped rather than blocking a leaked
	// goroutine on send forever.
	respCh := make(chan Response, 1)
	go func() { respCh <- e.handler.Execute(dispatchCtx, req, desc) }()

	if max <= 0 {
		return <-respCh, false
	}
	select {
	case resp := <-respCh:
		return resp, false
	case <-dispatchCtx.Done():
		// The caller deadline, caller cancellation, or the provider
		// ceiling fired while the handler was still running. Give a
		// cooperative handler a brief grace to return its own answer —
		// it may carry provider evidence the durable observation must
		// persist — then converge conservatively without waiting
		// further. The record stays IN_FLIGHT-owned by this executor
		// until the recovery transition below; the heartbeat stops
		// when Execute returns, so an ignored handler can never pin
		// the lease beyond ceiling+grace.
		select {
		case resp := <-respCh:
			return resp, false
		case <-time.After(e.timeouts.ProviderExecutionGrace):
			return e.providerCeilingResponse(desc), false
		}
	}
}

// providerCeilingResponse is the conservative outcome when the
// provider invocation exceeds the executor's own ceiling. For
// MUTATION/CRITICAL the side effect may already have occurred —
// UNKNOWN, and the reconciler owns the record from there. PURE/READ
// have no external effect, so the same ceiling is a safe FAILED.
func (e *DispatchExecutor) providerCeilingResponse(desc capability.ResolvedDescriptor) Response {
	if desc.ExecutionClass == capability.ClassPure || desc.ExecutionClass == capability.ClassRead {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureExecutionFailed),
			Error: fmt.Sprintf("provider execution exceeded the framework ceiling (%s)",
				e.timeouts.ProviderExecution),
		}
	}
	return Response{
		Status:      StatusUnknown,
		FailureCode: string(capability.FailureExecutionUnknown),
		Error: fmt.Sprintf("provider execution exceeded the framework ceiling (%s) — post-dispatch ambiguity, entered recovery",
			e.timeouts.ProviderExecution),
	}
}

// classifyPostDispatch is the single post-dispatch decision table.
// Every provider response maps to exactly one durable decision:
//
//	Provider result                    Durable decision
//	───────────────────────────────    ───────────────
//	SUCCEEDED (evidence valid)         COMMITTED
//	SUCCEEDED, CRITICAL evidence
//	  missing/invalid/mismatched       UNKNOWN
//	FAILED + DefinitiveFailure         FAILED
//	FAILED (not definitive)            UNKNOWN
//	DENIED after dispatch              UNKNOWN
//	anything else                      UNKNOWN
//
// DENIED is a pre-dispatch admission concept: after IN_FLIGHT has been
// persisted the handler cannot prove no side effect occurred, so it maps
// to UNKNOWN for reconciliation — never to a terminal failure that would
// permit a blind retry.
//
// The returned Response may be rewritten to an UNKNOWN wire response
// when the provider's answer cannot be trusted; the caller must keep the
// original response for observation persistence.
func classifyPostDispatch(resp Response, desc capability.ResolvedDescriptor) (idempotency.State, Response) {
	unknown := func(reason string) (idempotency.State, Response) {
		return idempotency.StateUnknown, Response{
			Status:      StatusUnknown,
			FailureCode: string(capability.FailureExecutionUnknown),
			Error:       reason,
			Execution:   resp.Execution,
		}
	}

	// CRITICAL evidence contract — validated before the terminal state
	// is persisted. Persisting SUCCEEDED with invalid evidence would
	// create a poisoned record that replays invalid evidence on retry.
	// Per the durable execution contract: "provider says success +
	// required evidence invalid/missing → UNKNOWN → reconciliation."
	if desc.ExecutionClass.RequiresEvidence() && resp.Status == StatusSucceeded {
		switch {
		case resp.Evidence == nil || resp.Evidence.Digest == "":
			return unknown("CRITICAL capability returned SUCCEEDED without evidence digest (post-dispatch uncertainty)")
		case !isValidEvidenceDigest(resp.Evidence.Digest):
			return unknown("CRITICAL capability returned invalid evidence digest (post-dispatch uncertainty)")
		case resp.Evidence.ReceiptVersion != 3:
			return unknown(fmt.Sprintf("CRITICAL capability returned receipt_version %d (must be 3, post-dispatch uncertainty)", resp.Evidence.ReceiptVersion))
		case resp.Execution == nil || resp.Execution.RunID == "":
			return unknown("CRITICAL capability returned SUCCEEDED without run_id (post-dispatch uncertainty)")
		}
		return idempotency.StateCommitted, resp
	}

	switch resp.Status {
	case StatusSucceeded:
		return idempotency.StateCommitted, resp
	case StatusFailed:
		if resp.DefinitiveFailure {
			return idempotency.StateFailed, resp
		}
		return idempotency.StateUnknown, resp
	default:
		return idempotency.StateUnknown, resp
	}
}

// buildObservation constructs the provider observation from the
// provider's response — the durable snapshot persisted before any
// terminal decision.
func buildObservation(resp Response, desc capability.ResolvedDescriptor) idempotency.ProviderObservation {
	obs := idempotency.ProviderObservation{
		ProviderID:     desc.AdapterID,
		ProviderStatus: string(resp.Status),
		Result:         resp.Result,
	}
	if resp.Execution != nil {
		if resp.Execution.Provider != "" {
			obs.ProviderID = resp.Execution.Provider
		}
		obs.ProviderRunID = resp.Execution.RunID
	}
	if resp.Evidence != nil {
		obs.EvidenceDigest = resp.Evidence.Digest
		obs.ReceiptVersion = resp.Evidence.ReceiptVersion
	}
	return obs
}

// recordObservation durably records the provider's response metadata
// via Store.RecordProviderObservation. Every provider response is
// persisted — including status-only responses with no run ID, result,
// or evidence — because provider_id/provider_status are themselves
// observation data and provider_observed_at marks that the provider
// answered at all. Returns the store error so callers can report
// persistence honestly.
func (e *DispatchExecutor) recordObservation(ctx context.Context, executionID, leaseToken string, leaseGen int, resp Response, desc capability.ResolvedDescriptor) error {
	return e.store.RecordProviderObservation(ctx, executionID, leaseToken, leaseGen, buildObservation(resp, desc))
}

// enterRecovery derives a FRESH emergency-recovery context and enters
// UNKNOWN recovery carrying the provider observation. It is
// deliberately not called with the observation or terminalization
// context: those may already be exhausted by the database operation
// that just failed, and recovery must still be able to persist the
// provider observation.
func (e *DispatchExecutor) enterRecovery(ctx context.Context, executionID string, resp Response, desc capability.ResolvedDescriptor) error {
	recCtx, cancel := durabilityContext(ctx, e.timeouts.EmergencyRecovery)
	defer cancel()
	return e.enterRecoveryWithObservation(recCtx, executionID, resp, desc)
}

// enterRecoveryWithObservation transitions the record to UNKNOWN while
// carrying the provider observation atomically. If the record already
// raced into UNKNOWN (reconciler claimed the expired lease first), it
// falls back to a direct observation update — the observation is still
// persisted rather than lost to the CAS race.
//
// The IN_FLIGHT CAS is retried a bounded number of times: between our
// Lookup and the EnterRecoveryWithObservation CAS another writer may
// bump the record version (a lease-renewing loser, an observation, a
// state transition). A version bump alone does not prove the lease is
// lost — re-reading and retrying a small bounded number of times
// resolves transient races without ever retrying indefinitely. A CAS
// failure that persists past the bound means real contention, and the
// error is returned rather than silently dropped.
func (e *DispatchExecutor) enterRecoveryWithObservation(ctx context.Context, executionID string, resp Response, desc capability.ResolvedDescriptor) error {
	e.fireCrashPoint(CrashBeforeRecovery)
	obs := buildObservation(resp, desc)
	var lastErr error
	for attempt := 0; attempt < recoveryCASMaxAttempts; attempt++ {
		rec, lookupErr := e.store.Lookup(ctx, executionID)
		if lookupErr != nil {
			return fmt.Errorf("recovery entry failed (lookup error: %v); provider observation may not be persisted", lookupErr)
		}
		switch {
		case rec.State == idempotency.StateInFlight:
			err := e.store.EnterRecoveryWithObservation(ctx, executionID,
				idempotency.StateInFlight, rec.Version, obs)
			if err == nil {
				e.fireCrashPoint(CrashAfterRecovery)
				return nil
			}
			// A state/version CAS miss is retryable — the record moved
			// under us but may still be IN_FLIGHT at a newer version.
			// An observation contradiction is not: our provider truth
			// conflicts with what is durably stored, which retrying
			// cannot fix.
			if !errors.Is(err, idempotency.LeaseStateConflict) {
				return fmt.Errorf("recovery entry failed: %v; provider observation may not be persisted", err)
			}
			lastErr = err
			continue
		case rec.State == idempotency.StateUnknown:
			// Already in recovery — persist the observation directly.
			if err := e.store.RecordProviderObservation(ctx, executionID, "", 0, obs); err != nil {
				return fmt.Errorf("execution already in recovery; observation update failed: %v", err)
			}
			e.fireCrashPoint(CrashAfterRecovery)
			return nil
		case rec.State.IsDurablyFinal():
			// A concurrent finalizer already committed — no recovery
			// needed and none permitted.
			return nil
		default:
			return fmt.Errorf("cannot enter recovery from state %s", rec.State)
		}
	}
	return fmt.Errorf("recovery entry failed after %d CAS attempts: %v; provider observation may not be persisted", recoveryCASMaxAttempts, lastErr)
}

// recoveryCASMaxAttempts bounds the lookup→CAS retry loop in
// enterRecoveryWithObservation. Two attempts handle the common
// read-then-write version race; three gives margin for a second
// concurrent writer without ever looping unboundedly.
const recoveryCASMaxAttempts = 3

// recoveryPreparer is the explicit recovery-locator routing contract
// DispatchExecutor requires of its handler. MultiHandler implements
// it by delegating to the adapter's handler — the executor never
// type-asserts into nested handler structure.
type recoveryPreparer interface {
	PrepareRecovery(ctx context.Context, adapterID string, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error)
}

// prepareRecoveryLocator asks the provider for a minimal recovery
// locator via the RecoveryLocatorProvider contract (delegated through
// the handler's PrepareRecovery routing). Providers that do not
// implement the contract get the generic metadata-only locator — raw
// request arguments are never persisted for them.
func (e *DispatchExecutor) prepareRecoveryLocator(ctx context.Context, req Request, desc capability.ResolvedDescriptor, digest, executionID string) (*idempotency.RecoveryLocator, error) {
	in := idempotency.RecoveryLocatorInput{
		ExecutionID:    executionID,
		AdapterID:      desc.AdapterID,
		CapabilityID:   req.Capability,
		Principal:      req.Authority.Principal,
		IdempotencyKey: req.IdempotencyKey,
		RequestDigest:  digest,
		Arguments:      req.Arguments,
	}
	var locator *idempotency.RecoveryLocator
	if preparer, ok := e.handler.(recoveryPreparer); ok {
		l, err := preparer.PrepareRecovery(ctx, desc.AdapterID, in)
		if err != nil {
			return nil, err
		}
		locator = l
	}
	if locator == nil {
		// Generic fallback: metadata only, never raw arguments.
		locator = genericRecoveryLocator(req, desc, digest, executionID)
	}
	return locator, nil
}

// genericRecoveryLocator is the fallback locator for providers that do
// not implement RecoveryLocatorProvider. It carries request metadata
// only — never raw arguments, which may contain sensitive operation
// data that would otherwise sit in the ledger while UNKNOWN.
func genericRecoveryLocator(req Request, desc capability.ResolvedDescriptor, digest, executionID string) *idempotency.RecoveryLocator {
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     desc.AdapterID,
		Strategy:       "metadata",
		RequestDigest:  digest,
		ExecutionID:    executionID,
		PrincipalID:    req.Authority.Principal,
		CapabilityID:   req.Capability,
		IdempotencyKey: req.IdempotencyKey,
	}
}

// externalTokenKey carries the provider external-operation token from
// the persisted recovery locator to the provider's Execute call, so
// the token recorded before IN_FLIGHT is the same token used in the
// external request.
type externalTokenKey struct{}

// ExternalTokenFromContext returns the provider external-operation
// token DispatchExecutor persisted in the recovery locator, if any.
// Providers use it as their idempotency/operation token in the
// external request.
func ExternalTokenFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(externalTokenKey{}).(string); ok {
		return v
	}
	return ""
}

// parseEvidence reconstructs an EvidenceRef from stored evidence data.
// It uses the STORED receipt version — it does NOT invent V3 metadata.
// If the stored receipt version is 0 (legacy records), it returns
// the digest without a receipt version claim, rather than fabricating one.
func parseEvidence(digest string, receiptVersion int) *EvidenceRef {
	if digest == "" {
		return nil
	}
	ref := &EvidenceRef{
		Digest: digest,
	}
	// Only set ReceiptVersion if it was actually stored.
	// Never fabricate a version the original execution did not produce.
	if receiptVersion > 0 {
		ref.ReceiptVersion = receiptVersion
	}
	return ref
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

// stateToStatus maps a durable store state to a wire protocol status.
// The store uses COMMITTED; the wire protocol uses SUCCEEDED.
func stateToStatus(state idempotency.State) string {
	switch state {
	case idempotency.StateCommitted:
		return StatusSucceeded
	case idempotency.StateFailed:
		return StatusFailed
	case idempotency.StateDenied:
		return StatusDenied
	case idempotency.StateUnknown:
		return StatusUnknown
	default:
		return string(state)
	}
}

// leaseHeartbeat periodically renews the lease while a provider call is
// active. This prevents long-running provider calls from exceeding the
// lease duration and falling into UNKNOWN despite successful execution.
//
// The heartbeat derives its interval and renewal duration from the
// store's LeaseConfig:
//   - renewal duration = DefaultDuration (clamped to MaxDuration)
//   - renewal interval = DefaultDuration - RenewalWindow
//     (i.e., renew RenewalWindow before expiry)
//
// If RenewalWindow is zero or exceeds DefaultDuration, the interval
// falls back to 80% of DefaultDuration.
//
// Renewal failures are logged but do not cancel the provider call —
// the provider may still succeed, and finalization will fail-closed
// if the lease was actually lost.
func (e *DispatchExecutor) leaseHeartbeat(ctx context.Context, executionID, leaseToken string, leaseGeneration int) {
	cfg := e.store.LeaseConfig()

	// Renewal duration: use the configured default, clamped to max.
	renewDuration := cfg.DefaultDuration
	if renewDuration <= 0 {
		renewDuration = 5 * time.Minute
	}
	if cfg.MaxDuration > 0 && renewDuration > cfg.MaxDuration {
		renewDuration = cfg.MaxDuration
	}

	// Renewal interval: renew RenewalWindow before expiry.
	renewalInterval := renewDuration - cfg.RenewalWindow
	if cfg.RenewalWindow <= 0 || renewalInterval <= 0 {
		// Fallback: renew at 80% of the lease duration.
		renewalInterval = renewDuration * 4 / 5
	}
	// Floor at 50ms to prevent a degenerate tight loop while still
	// supporting sub-second leases (used by qualification tests with
	// deliberately tiny lease durations).
	if renewalInterval < 50*time.Millisecond {
		renewalInterval = 50 * time.Millisecond
	}

	ticker := time.NewTicker(renewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Bound each renewal: a hung store call must not stall the
			// heartbeat loop until the lease expires.
			renewCtx, renewCancel := context.WithTimeout(ctx, e.timeouts.LeaseOperation)
			err := e.store.RenewLease(renewCtx, executionID, leaseToken, leaseGeneration, renewDuration)
			renewCancel()
			if err != nil {
				// Lease renewal failed — the lease may have expired,
				// been taken over, or the record advanced. Stop renewing.
				// The provider call continues; if it succeeds, Finalize
				// will fail-closed on the stale lease.
				return
			}
		}
	}
}
