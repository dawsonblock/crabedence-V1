package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Validation hardening tests — the observation and terminal write
// paths fail closed on malformed, oversized, or dishonest payloads.

func TestObservationFailClosedInvalidJSON(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("invalid-obs")
	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-inv", digest)

	// A malformed provider result is rejected, not silently stored.
	err := s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation,
		ProviderObservation{ProviderID: "prov", Result: json.RawMessage(`{not json`)})
	if err == nil {
		t.Fatal("malformed provider result must be rejected")
	}
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.ProviderResultDigest != "" || len(rec.ProviderResult) != 0 {
		t.Fatalf("malformed observation was persisted: digest=%q", rec.ProviderResultDigest)
	}
}

func TestObservationDigestHonesty(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("digest-honest")
	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-dh", digest)

	result := json.RawMessage(`{"a":1}`)
	// A supplied digest that contradicts the bytes is a caller lie —
	// rejected, never trusted.
	err := s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation,
		ProviderObservation{
			ProviderID:   "prov",
			Result:       result,
			ResultDigest: "0000000000000000000000000000000000000000000000000000000000000000",
		})
	if !errors.Is(err, ObservationDigestMismatch) {
		t.Fatalf("want ObservationDigestMismatch, got %v", err)
	}

	// The correct digest is accepted (and recomputed anyway).
	canonical, _ := canonicalizeJSON(result)
	sum := sha256.Sum256(canonical)
	err = s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation,
		ProviderObservation{
			ProviderID:   "prov",
			Result:       result,
			ResultDigest: hex.EncodeToString(sum[:]),
		})
	if err != nil {
		t.Fatalf("correct digest rejected: %v", err)
	}
	rec, _ := s.Lookup(ctx, execID)
	if rec.ProviderResultDigest != hex.EncodeToString(sum[:]) {
		t.Fatalf("stored digest = %q", rec.ProviderResultDigest)
	}
}

func TestObservationPayloadBounds(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("bounds")
	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-bounds", digest)

	oversize := json.RawMessage(`{"pad":"` + strings.Repeat("x", MaxResultBytes) + `"}`)
	err := s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation,
		ProviderObservation{ProviderID: "prov", Result: oversize})
	if !errors.Is(err, ResultTooLarge) {
		t.Fatalf("want ResultTooLarge, got %v", err)
	}

	err = s.RecordProviderObservation(ctx, execID, acq.LeaseToken, acq.Generation,
		ProviderObservation{ProviderID: "prov", Result: json.RawMessage(`{"a":1}`), ReceiptVersion: -1})
	if err == nil {
		t.Fatal("negative receipt_version must be rejected")
	}
}

func TestFinalizePayloadBounds(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("fin-bounds")
	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-fb", digest)

	receipt := sqliteReceipt(execID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)

	receipt.ReceiptVersion = -1
	if err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err == nil {
		t.Fatal("negative receipt_version must be rejected")
	}
	receipt.ReceiptVersion = 3

	receipt.CanonicalResult = json.RawMessage(`{"pad":"` + strings.Repeat("x", MaxResultBytes) + `"}`)
	if err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); !errors.Is(err, ResultTooLarge) {
		t.Fatalf("want ResultTooLarge, got %v", err)
	}
	receipt.CanonicalResult = json.RawMessage(`{"ok":true}`)

	receipt.EvidenceReceipt = json.RawMessage(strings.Repeat("x", MaxEvidenceReceiptBytes+1))
	if err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); !errors.Is(err, EvidenceReceiptTooLarge) {
		t.Fatalf("want EvidenceReceiptTooLarge, got %v", err)
	}
}

func TestFinalizeStoresAssertedResultBytes(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("fin-canon")
	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-fc", digest)

	receipt := sqliteReceipt(execID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)
	// Non-canonical input: the stored result column keeps the asserted
	// bytes verbatim — replay fidelity — and terminal_result_digest
	// binds those bytes.
	receipt.CanonicalResult = json.RawMessage(`{  "b": 2, "a": 1 }`)
	if err := s.Finalize(ctx, execID, acq.LeaseToken, acq.Generation, StateInFlight, receipt); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if string(rec.Result) != string(receipt.CanonicalResult) {
		t.Fatalf("stored result = %q, want asserted bytes %q", rec.Result, receipt.CanonicalResult)
	}
	sum := sha256.Sum256(receipt.CanonicalResult)
	if rec.TerminalResultDigest != hex.EncodeToString(sum[:]) {
		t.Fatalf("terminal_result_digest = %q", rec.TerminalResultDigest)
	}
}

func TestResolveRecoveryPayloadBounds(t *testing.T) {
	ctx := context.Background()
	s := openSQLiteStore(t)
	digest := sqliteDigest("res-bounds")
	acq, execID := forensicDriveToInFlight(t, ctx, s, "k-rb2", digest)

	rec, err := s.Lookup(ctx, execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if err := s.EnterRecovery(ctx, execID, StateInFlight, rec.Version); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}
	rec, _ = s.Lookup(ctx, execID)

	res := RecoveryResult{
		Decision: RecoveryCommitted,
		Result:   json.RawMessage(`{"pad":"` + strings.Repeat("x", MaxResultBytes) + `"}`),
	}
	if err := s.ResolveRecovery(ctx, execID, rec.Version, res); !errors.Is(err, ResultTooLarge) {
		t.Fatalf("want ResultTooLarge, got %v", err)
	}

	res.Result = json.RawMessage(`{broken`)
	if err := s.ResolveRecovery(ctx, execID, rec.Version, res); err == nil {
		t.Fatal("malformed resolver result must be rejected")
	}

	res.Result = json.RawMessage(`{"done":true}`)
	res.ReceiptVersion = -2
	if err := s.ResolveRecovery(ctx, execID, rec.Version, res); err == nil {
		t.Fatal("negative receipt_version must be rejected")
	}
	_ = acq
}
