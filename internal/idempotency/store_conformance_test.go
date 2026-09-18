package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// eachEffectStore runs a conformance check against every storage
// engine that implements EffectStore. The embedded SQLite backend
// always runs; the PostgreSQL backend runs when
// CRABBOX_TEST_DATABASE_URL is configured. Both engines must satisfy
// the same durable-execution contract — this suite is what prevents
// the implementations from acquiring weaker semantics over time.
func eachEffectStore(t *testing.T, fn func(t *testing.T, s EffectStore)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		fn(t, openSQLiteStore(t))
	})
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		return
	}
	t.Run("postgres", func(t *testing.T) {
		db, err := openTestDB(dbURL)
		if err != nil {
			t.Fatalf("open test db: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		store, err := NewStore(db)
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		if _, err := db.ExecContext(context.Background(),
			`DELETE FROM execution_requests`); err != nil {
			t.Fatalf("reset table: %v", err)
		}
		// Epoch-fencing tests leave the shared cluster_meta row in
		// post-restore recovery mode — reset it so recovery gating
		// cannot poison sibling tests.
		if _, err := db.ExecContext(context.Background(),
			`UPDATE cluster_meta SET recovery_required = FALSE WHERE id = 1`); err != nil {
			t.Fatalf("reset recovery mode: %v", err)
		}
		fn(t, store)
	})
}

func confDigest(principal, capability, args string) string {
	return confDigestClass(principal, capability, args, "MUTATION")
}

func confDigestClass(principal, capability, args, class string) string {
	d, err := ComputeDigestFromRaw(1, principal, capability,
		json.RawMessage(args), "", class)
	if err != nil {
		panic(err)
	}
	return d
}

func confReceipt(execID, capability, principal, digest, providerID, runID string, status State) TerminalReceipt {
	return TerminalReceipt{
		ExecutionID:     execID,
		Capability:      capability,
		Principal:       principal,
		RequestDigest:   digest,
		CanonicalResult: json.RawMessage(`{"ok":true}`),
		ReceiptVersion:  3,
		ProviderID:      providerID,
		ProviderRunID:   runID,
		TerminalStatus:  status,
	}
}

// acquireFor advances a fresh record through PREPARED → EXECUTING →
// IN_FLIGHT, returning the record, lease token, and generation.
func acquireFor(t *testing.T, s EffectStore, ctx context.Context, key, principal, capability, class string, lease time.Duration) (*Record, string, int, string) {
	t.Helper()
	digest := confDigestClass(principal, capability, `{"q":"x"}`, class)
	acq, err := s.Acquire(ctx, key, principal, capability, digest, "", class, lease)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if acq.Kind != LeaseAcquired {
		t.Fatalf("acquire kind = %v, want LeaseAcquired", acq.Kind)
	}
	rec := acq.Record
	if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil); err != nil {
		t.Fatalf("mark in flight: %v", err)
	}
	return rec, acq.LeaseToken, acq.Generation, digest
}

// TestStoreConformanceLifecycle covers the happy path plus replay:
// acquire → begin → in-flight → observe → finalize → terminal replay.
func TestStoreConformanceLifecycle(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, token, gen, digest := acquireFor(t, s, ctx, "k1", "alice", "cap.mut", "MUTATION", 5*time.Minute)

		// Status-only observation persists (no skip).
		obs := ProviderObservation{ProviderID: "prov", ProviderStatus: "SUCCEEDED"}
		if err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen, obs); err != nil {
			t.Fatalf("observe: %v", err)
		}
		stored, err := s.Lookup(ctx, rec.ExecutionID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if stored.ProviderStatus != "SUCCEEDED" || stored.ProviderObservedAt == nil {
			t.Fatalf("observation not persisted: status=%q observed_at=%v",
				stored.ProviderStatus, stored.ProviderObservedAt)
		}

		receipt := confReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
		if err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight, receipt); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		final, _ := s.Lookup(ctx, rec.ExecutionID)
		if final.State != StateCommitted || final.ProviderRunID != "run-1" {
			t.Fatalf("final: %s run=%q", final.State, final.ProviderRunID)
		}
		if final.LeaseToken != "" {
			t.Fatal("lease not cleared on finalization")
		}

		// Idempotent replay.
		acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
		if err != nil || acq.Kind != TerminalReplay || acq.Record.State != StateCommitted {
			t.Fatalf("replay: %v kind=%v", err, acq.Kind)
		}
		// Identical finalize replay is idempotent.
		if err := s.Finalize(ctx, rec.ExecutionID, "any", 0, StateInFlight, receipt); err != nil {
			t.Fatalf("finalize replay: %v", err)
		}
	})
}

// TestStoreConformanceAcquireSemantics covers idempotency-key
// conflict, held-lease contention, and expiry semantics.
func TestStoreConformanceAcquireSemantics(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		digest := confDigest("alice", "cap.mut", `{"q":"x"}`)

		acq, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
		if err != nil || acq.Kind != LeaseAcquired {
			t.Fatalf("acquire: %v kind=%v", err, acq.Kind)
		}
		// Same identity while lease held.
		acq2, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
		if acq2.Kind != LeaseHeldByOther {
			t.Fatalf("want LeaseHeldByOther, got %v", acq2.Kind)
		}
		// Same key, different request → conflict.
		acq3, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", confDigest("alice", "cap.mut", `{"q":"y"}`), "", "MUTATION", 5*time.Minute)
		if acq3.Kind != IdempotencyConflict {
			t.Fatalf("want IdempotencyConflict, got %v", acq3.Kind)
		}
		// Different principal → independent identity, acquires cleanly.
		acq4, err := s.Acquire(ctx, "k1", "bob", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
		if err != nil || acq4.Kind != LeaseAcquired {
			t.Fatalf("cross-principal acquire: %v kind=%v", err, acq4.Kind)
		}
	})
}

// TestStoreConformanceFencing covers stale-token/generation rejection.
func TestStoreConformanceFencing(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		digest := confDigest("alice", "cap.mut", `{"q":"x"}`)
		acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
		rec := acq.Record
		if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := s.MarkInFlight(ctx, rec.ExecutionID, "wrong-token", acq.Generation, "", nil); !errors.Is(err, LeaseTokenMismatch) {
			t.Fatalf("want LeaseTokenMismatch, got %v", err)
		}
		if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation+7, "", nil); !errors.Is(err, LeaseGenerationMismatch) {
			t.Fatalf("want LeaseGenerationMismatch, got %v", err)
		}
		// Illegal transition — PREPARED record cannot finalize.
		rec2 := acq2Record(t, s, ctx, "k2", "alice")
		bad := confReceipt(rec2.ExecutionID, "cap.mut", "alice", digest, "p", "r", StateCommitted)
		if err := s.Finalize(ctx, rec2.ExecutionID, "", 0, StatePrepared, bad); !errors.Is(err, LeaseStateConflict) {
			t.Fatalf("illegal finalize: want LeaseStateConflict, got %v", err)
		}
	})
}

func acq2Record(t *testing.T, s EffectStore, ctx context.Context, key, principal string) *Record {
	t.Helper()
	digest := confDigest(principal, "cap.mut", `{"q":"x"}`)
	acq, err := s.Acquire(ctx, key, principal, "cap.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil || acq.Kind != LeaseAcquired {
		t.Fatalf("acquire: %v kind=%v", err, acq.Kind)
	}
	return acq.Record
}

// TestStoreConformanceExpiredInFlight covers the central safety rule:
// an expired IN_FLIGHT lease is never reclaimed — the record goes to
// UNKNOWN and the caller gets RecoveryRequired.
func TestStoreConformanceExpiredInFlight(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		digest := confDigest("alice", "cap.mut", `{"q":"x"}`)
		acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 80*time.Millisecond)
		rec := acq.Record
		if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", nil); err != nil {
			t.Fatalf("in flight: %v", err)
		}
		time.Sleep(120 * time.Millisecond)

		acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", time.Minute)
		if err != nil || acq2.Kind != RecoveryRequired {
			t.Fatalf("want RecoveryRequired, got %v err=%v", acq2.Kind, err)
		}
		cur, _ := s.Lookup(ctx, rec.ExecutionID)
		if cur.State != StateUnknown {
			t.Fatalf("state = %s, want UNKNOWN", cur.State)
		}
		if cur.EnteredUnknownAt == nil {
			t.Fatal("entered_unknown_at not set")
		}

		// UNKNOWN never redispatches: re-acquire keeps returning
		// RecoveryRequired.
		acq3, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", time.Minute)
		if acq3.Kind != RecoveryRequired {
			t.Fatalf("UNKNOWN re-acquire: want RecoveryRequired, got %v", acq3.Kind)
		}
	})
}

// TestStoreConformanceExpiredPreDispatch covers the safe side of
// expiry: a PREPARED/EXECUTING record that never crossed the dispatch
// boundary normalizes back to lease-less PREPARED and reacquires.
func TestStoreConformanceExpiredPreDispatch(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		digest := confDigest("alice", "cap.mut", `{"q":"x"}`)
		acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 60*time.Millisecond)
		rec := acq.Record
		time.Sleep(100 * time.Millisecond)

		cur, _ := s.Lookup(ctx, rec.ExecutionID)
		if err := s.RecoverExpiredPreDispatch(ctx, rec.ExecutionID, cur.Version); err != nil {
			t.Fatalf("recover expired: %v", err)
		}
		norm, _ := s.Lookup(ctx, rec.ExecutionID)
		if norm.State != StatePrepared || norm.LeaseToken != "" || norm.LeaseExpiresAt != nil {
			t.Fatalf("normalized: state=%s token=%q", norm.State, norm.LeaseToken)
		}
		acq2, err := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", time.Minute)
		if err != nil || acq2.Kind != LeaseAcquired {
			t.Fatalf("reacquire: %v kind=%v", err, acq2.Kind)
		}
	})
}

// TestStoreConformanceObservationMonotonic covers the additive-write
// rule: identical observations are idempotent, contradictions are
// typed conflicts, and the write never bumps version.
func TestStoreConformanceObservationMonotonic(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, token, gen, _ := acquireFor(t, s, ctx, "k1", "alice", "cap.mut", "MUTATION", 5*time.Minute)

		// MarkInFlight already stored provider_id="prov"; the
		// observation confirms it and adds run ID + status.
		obs := ProviderObservation{ProviderID: "prov", ProviderRunID: "run-1", ProviderStatus: "SUCCEEDED"}
		if err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen, obs); err != nil {
			t.Fatalf("observe: %v", err)
		}
		// Idempotent re-record.
		if err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen, obs); err != nil {
			t.Fatalf("re-observe: %v", err)
		}
		// Contradictory provider identity → typed conflict.
		bad := ProviderObservation{ProviderID: "prov-B"}
		if err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen, bad); !errors.Is(err, ProviderObservationConflict) {
			t.Fatalf("want ProviderObservationConflict, got %v", err)
		}
		// Observation does not bump version (claims stay valid).
		cur, _ := s.Lookup(ctx, rec.ExecutionID)
		if cur.Version != rec.Version+2 {
			t.Fatalf("version = %d, want %d (begin+inflight only)", cur.Version, rec.Version+2)
		}
		// Terminal receipt contradicting stored identity → conflict.
		badReceipt := confReceipt(rec.ExecutionID, "cap.mut", "alice", rec.RequestDigest, "prov-B", "run-9", StateCommitted)
		if err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight, badReceipt); !errors.Is(err, ProviderObservationConflict) {
			t.Fatalf("finalize: want ProviderObservationConflict, got %v", err)
		}
	})
}

// TestStoreConformanceObservationResultPreserved covers the forensic
// invariant: the provider's original result bytes are durably stored
// in provider_result at observation time and are NEVER overwritten by
// reconciliation. `result` carries the canonical terminal result —
// which a resolver legitimately replaces — while provider_result
// preserves what the provider actually said.
func TestStoreConformanceObservationResultPreserved(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, token, gen, _ := acquireFor(t, s, ctx, "k1", "alice", "cap.mut", "MUTATION", 5*time.Minute)

		providerBytes := json.RawMessage(`{"amb":true,"provider":"raw"}`)
		obs := ProviderObservation{
			ProviderID: "prov", ProviderRunID: "run-1",
			ProviderStatus: "SUCCEEDED", Result: providerBytes,
		}
		if err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen, obs); err != nil {
			t.Fatalf("observe: %v", err)
		}
		cur, err := s.Lookup(ctx, rec.ExecutionID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if string(cur.ProviderResult) != string(providerBytes) {
			t.Fatalf("provider_result = %s, want observed bytes %s", cur.ProviderResult, providerBytes)
		}
		// A contradictory provider_result is a monotonic conflict.
		bad := ProviderObservation{ProviderID: "prov", ProviderRunID: "run-1",
			ProviderStatus: "SUCCEEDED", Result: json.RawMessage(`{"amb":false}`)}
		if err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen, bad); !errors.Is(err, ProviderObservationConflict) {
			t.Fatalf("conflicting provider_result: want ProviderObservationConflict, got %v", err)
		}

		// Enter recovery carrying the same observation, then resolve
		// with a DIFFERENT canonical result — provider_result must
		// survive while result becomes the resolver's output.
		if err := s.EnterRecoveryWithObservation(ctx, rec.ExecutionID, StateInFlight, cur.Version, obs); err != nil {
			t.Fatalf("enter recovery: %v", err)
		}
		cur, _ = s.Lookup(ctx, rec.ExecutionID)
		res := RecoveryResult{
			Decision:       RecoveryCommitted,
			EvidenceDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ReceiptVersion: 3,
			ProviderID:     "prov",
			ProviderRunID:  "run-1",
			Result:         json.RawMessage(`{"resolved":true}`),
		}
		if err := s.ResolveRecovery(ctx, rec.ExecutionID, cur.Version, res); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		final, _ := s.Lookup(ctx, rec.ExecutionID)
		if final.State != StateCommitted {
			t.Fatalf("state = %s, want COMMITTED", final.State)
		}
		if string(final.ProviderResult) != string(providerBytes) {
			t.Fatalf("provider_result overwritten by resolution: got %s, want %s",
				final.ProviderResult, providerBytes)
		}
		if string(final.Result) != `{"resolved":true}` {
			t.Fatalf("canonical result = %s, want resolver output", final.Result)
		}
	})
}

// TestStoreConformanceReconcile covers the UNKNOWN lifecycle: claim,
// single ownership, renewal, resolution with proof, and the
// RecoveryRetryable rejection.
func TestStoreConformanceReconcile(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, _, _, _ := acquireFor(t, s, ctx, "k1", "alice", "cap.mut", "MUTATION", 5*time.Minute)

		cur, _ := s.Lookup(ctx, rec.ExecutionID)
		obs := ProviderObservation{ProviderID: "prov", ProviderRunID: "run-1", ProviderStatus: "UNKNOWN", Result: json.RawMessage(`{"amb":true}`)}
		if err := s.EnterRecoveryWithObservation(ctx, rec.ExecutionID, StateInFlight, cur.Version, obs); err != nil {
			t.Fatalf("enter recovery: %v", err)
		}

		claimed, err := s.ClaimUnknownBatch(ctx, "w1", 10, time.Minute)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("claim: %v n=%d", err, len(claimed))
		}
		if claimed[0].ReconcileOwner != "w1" || claimed[0].ReconcileAttempt != 1 {
			t.Fatalf("claim fields: owner=%q attempt=%d", claimed[0].ReconcileOwner, claimed[0].ReconcileAttempt)
		}
		// Second worker sees nothing while the claim is live.
		claimed2, err := s.ClaimUnknownBatch(ctx, "w2", 10, time.Minute)
		if err != nil || len(claimed2) != 0 {
			t.Fatalf("double claim: %v n=%d", err, len(claimed2))
		}
		if err := s.RenewReconcileClaim(ctx, rec.ExecutionID, claimed[0].Version, time.Minute); err != nil {
			t.Fatalf("renew: %v", err)
		}
		// Retryable is rejected at the store boundary.
		retry := RecoveryResult{Decision: RecoveryRetryable}
		if err := s.ResolveRecovery(ctx, rec.ExecutionID, claimed[0].Version, retry); !errors.Is(err, LeaseStateConflict) {
			t.Fatalf("retryable: want LeaseStateConflict, got %v", err)
		}
		// Continued UNKNOWN touches updated_at without resolving.
		if err := s.ResolveRecovery(ctx, rec.ExecutionID, claimed[0].Version, RecoveryResult{Decision: RecoveryUnknown}); err != nil {
			t.Fatalf("unknown resolve: %v", err)
		}
		// Definitive resolution with the stored provider identity.
		res := RecoveryResult{
			Decision:       RecoveryCommitted,
			EvidenceDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ReceiptVersion: 3,
			ProviderID:     "prov",
			ProviderRunID:  "run-1",
			Result:         json.RawMessage(`{"completed":true}`),
		}
		if err := s.ResolveRecovery(ctx, rec.ExecutionID, claimed[0].Version, res); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		final, _ := s.Lookup(ctx, rec.ExecutionID)
		if final.State != StateCommitted || final.RecoveryLocator != nil {
			t.Fatalf("resolved: %s locator=%v", final.State, final.RecoveryLocator)
		}
	})
}

// TestStoreConformanceCriticalProof verifies CRITICAL finalization
// fails closed without a trusted signer on both engines.
func TestStoreConformanceCriticalProof(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, token, gen, digest := acquireFor(t, s, ctx, "kc", "alice", "cap.crit", "CRITICAL", 5*time.Minute)
		receipt := confReceipt(rec.ExecutionID, "cap.crit", "alice", digest, "prov", "run-1", StateCommitted)
		receipt.EvidenceDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight, receipt)
		if err == nil {
			t.Fatal("CRITICAL finalize without trusted signer must fail")
		}
	})
}

// TestStoreConformanceLocatorPolicy covers the size bound, the
// denylist, and the redactor-before-scan ordering.
func TestStoreConformanceLocatorPolicy(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		digest := confDigest("alice", "cap.mut", `{"q":"x"}`)
		acq, _ := s.Acquire(ctx, "k1", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
		rec := acq.Record
		if err := s.BeginExecution(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation); err != nil {
			t.Fatalf("begin: %v", err)
		}
		deny := json.RawMessage(`{"client_secret":"abc"}`)
		if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", deny); !errors.Is(err, LocatorContainsSecret) {
			t.Fatalf("want LocatorContainsSecret, got %v", err)
		}
		// Redactor strips the denied field before the scan.
		s.SetLocatorRedactor(func(raw json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{"external_token":"tok"}`), nil
		})
		if err := s.MarkInFlight(ctx, rec.ExecutionID, acq.LeaseToken, acq.Generation, "prov", deny); err != nil {
			t.Fatalf("redacted locator rejected: %v", err)
		}
		s.SetLocatorRedactor(nil)
		// Oversize locator rejected before the redactor even runs.
		big := json.RawMessage(fmt.Sprintf(`{"external_token":%q}`, string(make([]byte, MaxRecoveryLocatorBytes))))
		acq2, _ := s.Acquire(ctx, "k2", "alice", "cap.mut", digest, "", "MUTATION", 5*time.Minute)
		s.BeginExecution(ctx, acq2.Record.ExecutionID, acq2.LeaseToken, acq2.Generation)
		if err := s.MarkInFlight(ctx, acq2.Record.ExecutionID, acq2.LeaseToken, acq2.Generation, "prov", big); !errors.Is(err, LocatorTooLarge) {
			t.Fatalf("want LocatorTooLarge, got %v", err)
		}
	})
}

// TestStoreConformanceForensicRecord pins the cross-engine forensic
// contract: a full lifecycle produces the same ordered event history,
// the observation ledger preserves exact asserted bytes with a
// self-verifying digest, provider-time and terminal-time evidence are
// split, and a fenced writer leaves a LEASE_LOST annotation.
func TestStoreConformanceForensicRecord(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, token, gen, digest := acquireFor(t, s, ctx, "forensic-k1", "alice", "cap.mut", "MUTATION", 5*time.Minute)

		// Non-canonical bytes: the ledger keeps the exact asserted form.
		raw := json.RawMessage(`{  "b": 2, "a": 1 }`)
		obs := ProviderObservation{
			ProviderID:     "prov",
			ProviderRunID:  "run-1",
			ProviderStatus: "SUCCEEDED",
			Result:         raw,
			EvidenceDigest: "ev-provider",
		}
		if err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen, obs); err != nil {
			t.Fatalf("observe: %v", err)
		}
		receipt := confReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
		receipt.EvidenceDigest = "ev-terminal"
		if err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight, receipt); err != nil {
			t.Fatalf("finalize: %v", err)
		}

		events, err := s.ListEffectEvents(ctx, rec.ExecutionID)
		if err != nil {
			t.Fatalf("list events: %v", err)
		}
		want := []string{
			EventAcquired, EventExecutionBegun, EventDispatchStarted,
			EventProviderObserved, EventTerminalResolved,
		}
		got := make([]string, len(events))
		for i, e := range events {
			got[i] = e.EventType
			if e.Sequence != i+1 {
				t.Fatalf("event %d sequence = %d", i, e.Sequence)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("event history = %v, want %v", got, want)
		}

		obsRows, err := s.ListProviderObservations(ctx, rec.ExecutionID)
		if err != nil {
			t.Fatalf("list observations: %v", err)
		}
		if len(obsRows) != 1 || obsRows[0].Kind != ObservationDispatch {
			t.Fatalf("observation rows = %+v", obsRows)
		}
		if string(obsRows[0].ResultBytes) != string(raw) {
			t.Errorf("result_bytes = %q, want exact asserted %q", obsRows[0].ResultBytes, raw)
		}
		sum := sha256.Sum256(raw)
		if obsRows[0].ResultSHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("result_sha256 = %q", obsRows[0].ResultSHA256)
		}

		final, err := s.Lookup(ctx, rec.ExecutionID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if final.ProviderEvidenceDigest != "ev-provider" {
			t.Errorf("provider_evidence_digest = %q", final.ProviderEvidenceDigest)
		}
		if final.TerminalEvidenceDigest != "ev-terminal" {
			t.Errorf("terminal_evidence_digest = %q", final.TerminalEvidenceDigest)
		}
		rsum := sha256.Sum256(receipt.CanonicalResult)
		if final.TerminalResultDigest != hex.EncodeToString(rsum[:]) {
			t.Errorf("terminal_result_digest = %q", final.TerminalResultDigest)
		}

		// A fenced writer on a live record leaves a LEASE_LOST event.
		rec2, _, _, _ := acquireFor(t, s, ctx, "forensic-k2", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		err = s.RecordProviderObservation(ctx, rec2.ExecutionID, "stale-token", 99,
			ProviderObservation{ProviderID: "prov", ProviderStatus: "X"})
		if err == nil {
			t.Fatal("stale observation must be rejected")
		}
		events2, err := s.ListEffectEvents(ctx, rec2.ExecutionID)
		if err != nil {
			t.Fatalf("list events 2: %v", err)
		}
		var lostFound bool
		for _, e := range events2 {
			if e.EventType == EventLeaseLost {
				lostFound = true
			}
		}
		if !lostFound {
			t.Fatal("no LEASE_LOST event recorded for fenced writer")
		}
	})
}

// TestStoreConformancePayloadBounds pins the fail-closed validation
// contract on both engines: malformed provider results are rejected
// rather than stored, a caller-supplied digest that contradicts the
// bytes is never trusted, oversized payloads hit the storage bounds,
// and negative receipt versions are invalid.
func TestStoreConformancePayloadBounds(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, token, gen, digest := acquireFor(t, s, ctx, "bounds-k1", "alice", "cap.mut", "MUTATION", 5*time.Minute)

		// Malformed provider result — never silently persisted.
		err := s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen,
			ProviderObservation{ProviderID: "prov", Result: json.RawMessage(`{not json`)})
		if err == nil {
			t.Fatal("malformed provider result must be rejected")
		}

		// Caller digest contradicting the bytes — never trusted.
		err = s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen,
			ProviderObservation{
				ProviderID:   "prov",
				Result:       json.RawMessage(`{"a":1}`),
				ResultDigest: "0000000000000000000000000000000000000000000000000000000000000000",
			})
		if !errors.Is(err, ObservationDigestMismatch) {
			t.Fatalf("want ObservationDigestMismatch, got %v", err)
		}

		// Oversize result payload.
		oversize := json.RawMessage(`{"pad":"` + strings.Repeat("x", MaxResultBytes) + `"}`)
		err = s.RecordProviderObservation(ctx, rec.ExecutionID, token, gen,
			ProviderObservation{ProviderID: "prov", Result: oversize})
		if !errors.Is(err, ResultTooLarge) {
			t.Fatalf("want ResultTooLarge, got %v", err)
		}

		// Oversize evidence receipt and negative version on finalize.
		receipt := confReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
		receipt.EvidenceReceipt = json.RawMessage(strings.Repeat("x", MaxEvidenceReceiptBytes+1))
		if err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight, receipt); !errors.Is(err, EvidenceReceiptTooLarge) {
			t.Fatalf("want EvidenceReceiptTooLarge, got %v", err)
		}
		receipt.EvidenceReceipt = nil
		receipt.ReceiptVersion = -1
		if err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight, receipt); err == nil {
			t.Fatal("negative receipt_version must be rejected")
		}
	})
}

// TestStoreConformanceClusterEpochFencing covers the DR fence: a
// store admitted under epoch N is permanently fenced from every
// mutation path once the cluster epoch advances past N — the typed
// CLUSTER_EPOCH_MISMATCH error must surface, never a lease-conflict
// misclassification. The epoch persists per database, so this test
// must not assume the epoch starts at 1.
func TestStoreConformanceClusterEpochFencing(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		base := s.ClusterEpoch()

		// Records admitted before the advance carry the epoch stamp.
		inFlight, token, gen, digest := acquireFor(t, s, ctx, "epoch-if", "epoch-p", "cap.epoch", "STANDARD", 5*time.Minute)
		if inFlight.AdmittedEpoch != base {
			t.Fatalf("admitted_epoch = %d, want %d", inFlight.AdmittedEpoch, base)
		}
		prepared, ptoken, pgen, _ := acquireFor(t, s, ctx, "epoch-pr", "epoch-p", "cap.epoch", "STANDARD", 5*time.Minute)

		// UNKNOWN record for the recovery paths — enter recovery now,
		// while the store is still epoch-valid.
		rec3, _, _, _ := acquireFor(t, s, ctx, "epoch-un", "epoch-p", "cap.epoch", "STANDARD", 5*time.Minute)
		stored3, err := s.Lookup(ctx, rec3.ExecutionID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if err := s.EnterRecovery(ctx, rec3.ExecutionID, StateInFlight, stored3.Version); err != nil {
			t.Fatalf("enter recovery: %v", err)
		}
		unknown, err := s.Lookup(ctx, rec3.ExecutionID)
		if err != nil {
			t.Fatalf("lookup unknown: %v", err)
		}

		// CAS on the wrong expected epoch reports the typed error.
		if _, err := s.AdvanceClusterEpoch(ctx, base+99, "bogus"); !errors.Is(err, ClusterEpochMismatch) {
			t.Fatalf("advance with wrong expected: want ClusterEpochMismatch, got %v", err)
		}

		// The DR bump — everything after this is fenced for s.
		next, err := s.AdvanceClusterEpoch(ctx, base, "restore rehearsal")
		if err != nil {
			t.Fatalf("advance: %v", err)
		}
		if next != base+1 {
			t.Fatalf("advance returned %d, want %d", next, base+1)
		}
		// The advance declared recovery mode — on a shared database
		// (postgres leg) it must be cleared or every sibling test's
		// acquire is fenced. CompleteClusterRecovery is epoch-guarded
		// on the LIVE epoch, so the stale store can still clear it.
		t.Cleanup(func() {
			if err := s.CompleteClusterRecovery(context.Background(), next, "conformance cleanup"); err != nil {
				t.Logf("recovery cleanup: %v", err)
			}
		})

		wantFenced := func(name string, err error) {
			t.Helper()
			if !errors.Is(err, ClusterEpochMismatch) {
				t.Fatalf("%s: want ClusterEpochMismatch, got %v", name, err)
			}
		}

		// Fresh admission is fenced at the transaction boundary.
		_, err = s.Acquire(ctx, "epoch-new", "epoch-p", "cap.epoch", digest, "", "STANDARD", time.Minute)
		wantFenced("acquire", err)

		// Every record mutation on the stale store is fenced — even
		// writes that would otherwise succeed.
		storedIF, _ := s.Lookup(ctx, inFlight.ExecutionID)
		wantFenced("mark in flight obs", s.RecordProviderObservation(ctx, inFlight.ExecutionID, token, gen,
			ProviderObservation{ProviderID: "prov", ProviderStatus: "SUCCEEDED"}))
		wantFenced("renew lease", s.RenewLease(ctx, inFlight.ExecutionID, token, gen, time.Minute))
		wantFenced("finalize", s.Finalize(ctx, inFlight.ExecutionID, token, gen, StateInFlight,
			confReceipt(inFlight.ExecutionID, "cap.epoch", "epoch-p", digest, "prov", "run-1", StateCommitted)))
		wantFenced("enter recovery", s.EnterRecovery(ctx, inFlight.ExecutionID, StateInFlight, storedIF.Version))
		wantFenced("begin execution", s.BeginExecution(ctx, prepared.ExecutionID, ptoken, pgen))
		wantFenced("abandon", s.AbandonPreDispatch(ctx, prepared.ExecutionID, ptoken, pgen))
		wantFenced("resolve recovery", s.ResolveRecovery(ctx, unknown.ExecutionID, unknown.Version,
			RecoveryResult{Decision: RecoveryCommitted, ProviderID: "prov", EvidenceDigest: "ev"}))
		wantFenced("release claim", s.ReleaseReconcileClaim(ctx, unknown.ExecutionID, unknown.Version, time.Minute, "x"))
		wantFenced("suspend", s.SuspendReconciliation(ctx, unknown.ExecutionID, unknown.Version, "x"))
		wantFenced("renew claim", s.RenewReconcileClaim(ctx, unknown.ExecutionID, unknown.Version, time.Minute))
		if _, err := s.ClaimUnknownBatch(ctx, "w", 10, time.Minute); err != nil {
			wantFenced("claim unknown", err)
		}
		if _, err := s.ClaimExpiredBatch(ctx, "w", 10, time.Minute); err != nil {
			wantFenced("claim expired", err)
		}
		if _, err := s.ScrubStaleRecoveryLocators(ctx, time.Hour); err != nil {
			wantFenced("scrub", err)
		}

		// Reads are not fenced — a fenced executor can still look.
		if _, err := s.Lookup(ctx, inFlight.ExecutionID); err != nil {
			t.Fatalf("lookup after advance: %v", err)
		}
	})
}
