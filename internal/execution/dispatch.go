package execution

import (
	"context"
	"encoding/json"
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
	store    *idempotency.Store
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
}

// NewDispatchExecutor creates a new dispatch executor with durable idempotency.
func NewDispatchExecutor(handler Handler, store *idempotency.Store) *DispatchExecutor {
	return &DispatchExecutor{
		handler:  handler,
		store:    store,
		inFlight: make(map[string]context.CancelFunc),
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
		return e.dispatch(ctx, req, desc)
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

	// Compute request digest
	digest, err := idempotency.ComputeDigestFromRaw(
		1, // protocol version
		req.Authority.Principal,
		req.Capability,
		req.Arguments,
		req.Authority.EffectiveAuthorityRef(),
		string(desc.ExecutionClass),
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
	acq, err := e.store.Acquire(ctx, req.IdempotencyKey, req.Authority.Principal, req.Capability, digest, req.Authority.EffectiveAuthorityRef(), string(desc.ExecutionClass), leaseDuration)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("idempotency acquire failed: %v", err),
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
			if acq.Record.ProviderID != "" {
				replayProvider = acq.Record.ProviderID
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

	// Mark as EXECUTING using the typed API (fenced by token + generation).
	// This is PRE_DISPATCH — if this fails, return FAILED (safe).
	if err := e.store.BeginExecution(ctx, executionID, leaseToken, leaseGen); err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to begin execution (lease lost or state changed): %v", err),
		}
	}

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
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to prepare recovery locator: %v", err),
		}
	}
	locatorRaw, err := json.Marshal(recoveryLocator)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to marshal recovery locator: %v", err),
		}
	}
	if len(locatorRaw) > idempotency.MaxRecoveryLocatorBytes {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error: fmt.Sprintf("recovery locator exceeds %d bytes (got %d)",
				idempotency.MaxRecoveryLocatorBytes, len(locatorRaw)),
		}
	}
	if err := e.store.MarkInFlight(ctx, executionID, leaseToken, leaseGen, desc.AdapterID, locatorRaw); err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInternalError),
			Error:       fmt.Sprintf("failed to transition to IN_FLIGHT (lease lost or state changed): %v", err),
		}
	}

	// Lease heartbeat — renew the lease while the provider is
	// executing. Without this, a long-running provider call can exceed
	// the lease duration, causing the record to become UNKNOWN even
	// though the provider eventually succeeds. The heartbeat uses the
	// store's LeaseConfig for renewal interval and duration.
	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
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
	resp := e.dispatch(dispatchCtx, req, desc)

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
	if e.postDispatchHook != nil {
		e.postDispatchHook()
	}
	obsErr := e.recordObservation(ctx, executionID, leaseToken, leaseGen, providerResp, desc)

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
		recErr := e.enterRecoveryWithObservation(ctx, executionID, providerResp, desc)
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

	// CRITICAL proof authenticity: attest the terminal outcome with a
	// signed effect receipt binding the evidence digest, provider/run
	// identity, and execution/request identity. The store verifies the
	// signature and binding against trusted signers — a well-formed but
	// unsigned digest is not proof. Without a configured signer the
	// receipt stays unsigned and the store fails closed below.
	if desc.ExecutionClass == capability.ClassCritical && e.signer != nil {
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
			recErr := e.enterRecoveryWithObservation(ctx, executionID, providerResp, desc)
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
	rec, err := e.store.Lookup(ctx, executionID)
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
	if err := e.store.Finalize(ctx, executionID, leaseToken, rec.LeaseGeneration, idempotency.StateInFlight, receipt); err != nil {
		// Finalization failed AFTER dispatch — the side effect may
		// have occurred. The provider observation was already persisted
		// durably right after the provider returned; the recovery
		// transition below also writes it atomically. Report persistence
		// honestly — never claim the observation was stored if it wasn't.
		recErr := e.enterRecoveryWithObservation(ctx, executionID, providerResp, desc)
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

	// Add execution metadata
	if resp.Execution == nil {
		resp.Execution = &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    executionID,
		}
	}

	return resp
}

// dispatch sends the request to the handler.
// This crosses the dispatch boundary — any failure after this call
// begins is POST_DISPATCH (may have executed).
func (e *DispatchExecutor) dispatch(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	// Set a timeout if deadline is provided
	dispatchCtx := ctx
	if req.Deadline != "" {
		deadline, err := time.Parse(time.RFC3339, req.Deadline)
		if err == nil {
			remaining := time.Until(deadline)
			if remaining > 0 {
				var cancel context.CancelFunc
				dispatchCtx, cancel = context.WithTimeout(ctx, remaining)
				defer cancel()
			}
		}
	}

	// The handler.Execute call crosses the dispatch boundary.
	resp := e.handler.Execute(dispatchCtx, req, desc)
	return resp
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
// via Store.RecordProviderObservation. Returns nil when nothing needs
// recording (empty observation) or when the write succeeds; returns the
// store error otherwise so callers can report persistence honestly.
func (e *DispatchExecutor) recordObservation(ctx context.Context, executionID, leaseToken string, leaseGen int, resp Response, desc capability.ResolvedDescriptor) error {
	obs := buildObservation(resp, desc)
	if obs.ProviderRunID == "" && obs.EvidenceDigest == "" && len(obs.Result) == 0 {
		return nil // nothing worth persisting
	}
	return e.store.RecordProviderObservation(ctx, executionID, leaseToken, leaseGen, obs)
}

// enterRecoveryWithObservation transitions the record to UNKNOWN while
// carrying the provider observation atomically. If the record already
// raced into UNKNOWN (reconciler claimed the expired lease first), it
// falls back to a direct observation update — the observation is still
// persisted rather than lost to the CAS race.
func (e *DispatchExecutor) enterRecoveryWithObservation(ctx context.Context, executionID string, resp Response, desc capability.ResolvedDescriptor) error {
	obs := buildObservation(resp, desc)
	rec, lookupErr := e.store.Lookup(ctx, executionID)
	if lookupErr != nil {
		return fmt.Errorf("recovery entry failed (lookup error: %v); provider observation may not be persisted", lookupErr)
	}
	if rec.State == idempotency.StateInFlight {
		if err := e.store.EnterRecoveryWithObservation(ctx, executionID,
			idempotency.StateInFlight, rec.Version, obs); err != nil {
			return fmt.Errorf("recovery entry failed: %v; provider observation may not be persisted", err)
		}
		return nil
	}
	if rec.State == idempotency.StateUnknown {
		// Already in recovery — persist the observation directly.
		if err := e.store.RecordProviderObservation(ctx, executionID, "", 0, obs); err != nil {
			return fmt.Errorf("execution already in recovery; observation update failed: %v", err)
		}
		return nil
	}
	// Terminal or pre-dispatch state — no recovery needed. A terminal
	// state here means a concurrent finalizer already committed.
	if rec.State.IsDurablyFinal() {
		return nil
	}
	return fmt.Errorf("cannot enter recovery from state %s", rec.State)
}

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
			if err := e.store.RenewLease(ctx, executionID, leaseToken, leaseGeneration, renewDuration); err != nil {
				// Lease renewal failed — the lease may have expired,
				// been taken over, or the record advanced. Stop renewing.
				// The provider call continues; if it succeeds, Finalize
				// will fail-closed on the stale lease.
				return
			}
		}
	}
}
