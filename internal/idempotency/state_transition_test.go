package idempotency

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestStateTransitionMatrixIsExhaustive pins the lifecycle graph
// encoded centrally in legalTransitions: every permitted transition is
// permitted, every other transition is refused, terminal states are
// immutable, and UNKNOWN can never return to an active state — a
// stranded effect is reconciled, never blindly redispatched.
func TestStateTransitionMatrixIsExhaustive(t *testing.T) {
	states := []State{StatePrepared, StateExecuting, StateInFlight, StateUnknown, StateCommitted, StateFailed, StateDenied}
	permitted := map[State]map[State]bool{
		StatePrepared:  {StateExecuting: true},
		StateExecuting: {StateInFlight: true, StatePrepared: true},
		StateInFlight:  {StateCommitted: true, StateFailed: true, StateUnknown: true},
		StateUnknown:   {StateCommitted: true, StateFailed: true},
	}
	for _, from := range states {
		for _, to := range states {
			want := permitted[from][to]
			if got := isLegalTransition(from, to); got != want {
				t.Errorf("isLegalTransition(%s → %s) = %v, want %v", from, to, got, want)
			}
		}
	}
	for _, terminal := range []State{StateCommitted, StateFailed, StateDenied} {
		for _, to := range states {
			if isLegalTransition(terminal, to) {
				t.Errorf("terminal state %s has an outgoing transition to %s", terminal, to)
			}
		}
	}
	for _, active := range []State{StatePrepared, StateExecuting, StateInFlight} {
		if isLegalTransition(StateUnknown, active) {
			t.Errorf("UNKNOWN must not return to the active state %s (no blind redispatch)", active)
		}
	}
}

// TestStoreEnforcesTransitionMatrix drives the matrix through the
// durable contract on every engine: permitted transitions succeed and
// the state actually advances; prohibited transitions are refused by
// the store itself, whatever the caller believes.
func TestStoreEnforcesTransitionMatrix(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		unique := func(name string) string {
			return fmt.Sprintf("trans-%s-%d", name, time.Now().UnixNano())
		}
		const principal = "alice@example.com"
		const capability = "cap.transitions"

		// ── A fresh record may only move PREPARED → EXECUTING. ─────────
		preparedKey := unique("prepared")
		preparedDigest := confDigestClass(principal, capability, `{"q":"x"}`, "MUTATION")
		acq, err := s.Acquire(ctx, preparedKey, principal, capability, preparedDigest, "", "MUTATION", 5*time.Minute)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		if acq.Kind != LeaseAcquired {
			t.Fatalf("acquire kind = %v, want LeaseAcquired", acq.Kind)
		}
		prepared := acq.Record
		if err := s.MarkInFlight(ctx, prepared.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil); err == nil {
			t.Fatal("PREPARED → IN_FLIGHT must be refused: EXECUTING is not optional")
		}
		if err := s.Finalize(ctx, prepared.ExecutionID, acq.LeaseToken, acq.Generation, StatePrepared,
			confReceipt(prepared.ExecutionID, capability, principal, preparedDigest, "prov", "run-1", StateCommitted)); err == nil {
			t.Fatal("PREPARED → COMMITTED must be refused")
		}
		if err := s.EnterRecovery(ctx, prepared.ExecutionID, StatePrepared, prepared.Version+100); err == nil {
			t.Fatal("EnterRecovery with a stale version must be refused")
		}
		if err := s.BeginExecution(ctx, prepared.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
			t.Fatalf("PREPARED → EXECUTING must be permitted: %v", err)
		}
		if got := lookupState(t, s, prepared.ExecutionID); got != StateExecuting {
			t.Fatalf("state after BeginExecution = %s, want EXECUTING", got)
		}

		// ── An IN_FLIGHT record may reach a terminal state or UNKNOWN. ─
		inFlight, token, gen, digest := acquireFor(t, s, ctx, unique("inflight"), principal, capability, "MUTATION", 5*time.Minute)
		if err := s.MarkInFlight(ctx, inFlight.ExecutionID, token, gen, "prov", nil); err == nil {
			t.Fatal("IN_FLIGHT → IN_FLIGHT must be refused")
		}
		if err := s.AbandonPreDispatch(ctx, inFlight.ExecutionID, token, gen); err == nil {
			t.Fatal("abandoning a post-dispatch (IN_FLIGHT) record must be refused")
		}
		if err := s.Finalize(ctx, inFlight.ExecutionID, token, gen, StateExecuting,
			confReceipt(inFlight.ExecutionID, capability, principal, digest, "prov", "run-1", StateCommitted)); err == nil {
			t.Fatal("Finalize with a mismatched expected state must be refused")
		}
		if err := s.Finalize(ctx, inFlight.ExecutionID, token, gen, StateInFlight,
			confReceipt(inFlight.ExecutionID, capability, principal, digest, "prov", "run-1", StateCommitted)); err != nil {
			t.Fatalf("IN_FLIGHT → COMMITTED must be permitted: %v", err)
		}
		if got := lookupState(t, s, inFlight.ExecutionID); got != StateCommitted {
			t.Fatalf("state after Finalize = %s, want COMMITTED", got)
		}

		// ── A terminal record is immutable. ───────────────────────────
		if err := s.BeginExecution(ctx, inFlight.ExecutionID, token, gen); err == nil {
			t.Fatal("COMMITTED → EXECUTING must be refused")
		}
		if err := s.EnterRecovery(ctx, inFlight.ExecutionID, StateCommitted, inFlight.Version); err == nil {
			t.Fatal("COMMITTED → UNKNOWN must be refused")
		}
		if err := s.Finalize(ctx, inFlight.ExecutionID, token, gen, StateInFlight,
			confReceipt(inFlight.ExecutionID, capability, principal, digest, "prov", "run-2", StateFailed)); err == nil {
			t.Fatal("re-finalizing a terminal record with a different receipt must be refused")
		}

		// ── UNKNOWN reconciles to a terminal state, never back to an
		//    active one. ───────────────────────────────────────────────
		unknown, unknownToken, unknownGen, unknownDigest := acquireFor(t, s, ctx, unique("unknown"), principal, capability, "MUTATION", 5*time.Minute)
		unknownCurrent, err := s.Lookup(ctx, unknown.ExecutionID)
		if err != nil {
			t.Fatalf("lookup unknown: %v", err)
		}
		if err := s.EnterRecovery(ctx, unknown.ExecutionID, StateInFlight, unknownCurrent.Version); err != nil {
			t.Fatalf("IN_FLIGHT → UNKNOWN must be permitted: %v", err)
		}
		if got := lookupState(t, s, unknown.ExecutionID); got != StateUnknown {
			t.Fatalf("state after EnterRecovery = %s, want UNKNOWN", got)
		}
		if err := s.BeginExecution(ctx, unknown.ExecutionID, unknownToken, unknownGen); err == nil {
			t.Fatal("UNKNOWN → EXECUTING must be refused (no blind redispatch)")
		}
		if err := s.MarkInFlight(ctx, unknown.ExecutionID, unknownToken, unknownGen, "prov", nil); err == nil {
			t.Fatal("UNKNOWN → IN_FLIGHT must be refused (no blind redispatch)")
		}
		recovered, err := s.Lookup(ctx, unknown.ExecutionID)
		if err != nil {
			t.Fatalf("lookup unknown: %v", err)
		}
		if err := s.ResolveRecovery(ctx, unknown.ExecutionID, recovered.Version, RecoveryResult{
			Decision:      RecoveryFailed,
			ProviderID:    "prov",
			ProviderRunID: "run-1",
			// A definitive resolution requires proof: evidence or a
			// result. Termination without either is refused.
			Result: json.RawMessage(`{"resolved":false}`),
		}); err != nil {
			t.Fatalf("UNKNOWN → FAILED resolution must be permitted: %v", err)
		}
		if got := lookupState(t, s, unknown.ExecutionID); got != StateFailed {
			t.Fatalf("state after ResolveRecovery = %s, want FAILED", got)
		}
		if err := s.ResolveRecovery(ctx, unknown.ExecutionID, recovered.Version+1, RecoveryResult{Decision: RecoveryCommitted}); err == nil {
			t.Fatal("resolving an already-terminal record must be refused")
		}

		// ── IN_FLIGHT → FAILED requires appropriate evidence: a
		//    CRITICAL record cannot finalize without an authenticated
		//    signed receipt. ────────────────────────────────────────────
		criticalKey := unique("critical")
		criticalDigest := confDigestClass(principal, capability, `{"q":"x"}`, "CRITICAL")
		criticalAcq, err := s.Acquire(ctx, criticalKey, principal, capability, criticalDigest, "", "CRITICAL", 5*time.Minute)
		if err != nil {
			t.Fatalf("acquire critical: %v", err)
		}
		critical := criticalAcq.Record
		if err := s.BeginExecution(ctx, critical.ExecutionID, criticalAcq.LeaseToken, criticalAcq.Generation); err != nil {
			t.Fatalf("begin critical: %v", err)
		}
		if err := s.MarkInFlight(ctx, critical.ExecutionID, criticalAcq.LeaseToken, criticalAcq.Generation, "prov", nil); err != nil {
			t.Fatalf("mark critical in flight: %v", err)
		}
		if err := s.Finalize(ctx, critical.ExecutionID, criticalAcq.LeaseToken, criticalAcq.Generation, StateInFlight,
			confReceipt(critical.ExecutionID, capability, principal, criticalDigest, "prov", "run-1", StateFailed)); err == nil {
			t.Fatal("CRITICAL IN_FLIGHT → FAILED without a verified signed receipt must be refused")
		}
		if got := lookupState(t, s, critical.ExecutionID); got != StateInFlight {
			t.Fatalf("refused CRITICAL finalization changed state to %s, want IN_FLIGHT", got)
		}

		_ = unknownDigest
	})
}

// lookupState reads the durable state of one execution.
func lookupState(t *testing.T, s EffectStore, executionID string) State {
	t.Helper()
	rec, err := s.Lookup(context.Background(), executionID)
	if err != nil {
		t.Fatalf("lookup %s: %v", executionID, err)
	}
	return rec.State
}
