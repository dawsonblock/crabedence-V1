package idempotency

import (
	"context"
	"testing"
	"time"
)

// TestStoreConformanceRejectsReceiptIdentityMismatch proves a terminal
// receipt is bound to the record it finalizes: a receipt minted for a
// different execution, capability, principal, or request digest can
// never finalize this record — evidence is not transferable between
// executions, and a refused write leaves the record untouched.
func TestStoreConformanceRejectsReceiptIdentityMismatch(t *testing.T) {
	eachEffectStore(t, func(t *testing.T, s EffectStore) {
		ctx := context.Background()
		rec, token, gen, digest := acquireFor(t, s, ctx, "receipt-bind-a", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		other, _, _, _ := acquireFor(t, s, ctx, "receipt-bind-b", "alice", "cap.mut", "MUTATION", 5*time.Minute)
		otherDigest := confDigestClass("alice", "cap.mut", `{"q":"y"}`, "MUTATION")

		cases := []struct {
			name    string
			receipt TerminalReceipt
		}{
			{"another execution's id", confReceipt(other.ExecutionID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)},
			{"another capability", confReceipt(rec.ExecutionID, "cap.other", "alice", digest, "prov", "run-1", StateCommitted)},
			{"another principal", confReceipt(rec.ExecutionID, "cap.mut", "bob", digest, "prov", "run-1", StateCommitted)},
			{"another request digest", confReceipt(rec.ExecutionID, "cap.mut", "alice", otherDigest, "prov", "run-1", StateCommitted)},
		}
		for _, tc := range cases {
			if err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight, tc.receipt); err == nil {
				t.Errorf("finalize with %s must be refused", tc.name)
			}
		}

		// Refused writes must not have advanced the record.
		cur, err := s.Lookup(ctx, rec.ExecutionID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if cur.State != StateInFlight {
			t.Fatalf("state after refused finalizations = %s, want IN_FLIGHT", cur.State)
		}

		// The genuine receipt still finalizes it.
		if err := s.Finalize(ctx, rec.ExecutionID, token, gen, StateInFlight,
			confReceipt(rec.ExecutionID, "cap.mut", "alice", digest, "prov", "run-1", StateCommitted)); err != nil {
			t.Fatalf("the genuine receipt must finalize: %v", err)
		}
		if got := lookupState(t, s, rec.ExecutionID); got != StateCommitted {
			t.Fatalf("state = %s, want COMMITTED", got)
		}
	})
}
