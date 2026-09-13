package execution

import (
	"encoding/json"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// TestClassifyPostDispatchMatrix exhaustively covers the post-dispatch
// decision table: every provider response maps to exactly one durable
// decision, and ambiguous responses never become terminal.
func TestClassifyPostDispatchMatrix(t *testing.T) {
	validDigest := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	critical := capability.ResolvedDescriptor{ExecutionClass: capability.ClassCritical, AdapterID: "deploy"}
	mutation := capability.ResolvedDescriptor{ExecutionClass: capability.ClassMutation, AdapterID: "counter"}

	meta := &ExecutionMeta{Provider: "p", RunID: "run-1"}
	validEvidence := &EvidenceRef{Digest: validDigest, ReceiptVersion: 3}

	cases := []struct {
		name string
		resp Response
		desc capability.ResolvedDescriptor
		want idempotency.State
	}{
		{"critical success valid evidence", Response{Status: StatusSucceeded, Result: json.RawMessage(`{"ok":1}`), Evidence: validEvidence, Execution: meta}, critical, idempotency.StateCommitted},
		{"critical success missing evidence", Response{Status: StatusSucceeded, Execution: meta}, critical, idempotency.StateUnknown},
		{"critical success empty digest", Response{Status: StatusSucceeded, Evidence: &EvidenceRef{ReceiptVersion: 3}, Execution: meta}, critical, idempotency.StateUnknown},
		{"critical success bad digest", Response{Status: StatusSucceeded, Evidence: &EvidenceRef{Digest: "nothex", ReceiptVersion: 3}, Execution: meta}, critical, idempotency.StateUnknown},
		{"critical success wrong receipt version", Response{Status: StatusSucceeded, Evidence: &EvidenceRef{Digest: validDigest, ReceiptVersion: 2}, Execution: meta}, critical, idempotency.StateUnknown},
		{"critical success missing run id", Response{Status: StatusSucceeded, Evidence: validEvidence, Execution: &ExecutionMeta{Provider: "p"}}, critical, idempotency.StateUnknown},
		{"critical success nil execution meta", Response{Status: StatusSucceeded, Evidence: validEvidence}, critical, idempotency.StateUnknown},
		{"mutation success", Response{Status: StatusSucceeded, Result: json.RawMessage(`{"ok":1}`), Execution: meta}, mutation, idempotency.StateCommitted},
		{"mutation definitive failure", Response{Status: StatusFailed, DefinitiveFailure: true, Execution: meta}, mutation, idempotency.StateFailed},
		{"mutation ambiguous failure", Response{Status: StatusFailed, Execution: meta}, mutation, idempotency.StateUnknown},
		{"critical ambiguous failure", Response{Status: StatusFailed, Execution: meta}, critical, idempotency.StateUnknown},
		{"denied after dispatch", Response{Status: StatusDenied, Execution: meta}, mutation, idempotency.StateUnknown},
		{"in-flight status", Response{Status: StatusInFlight, Execution: meta}, mutation, idempotency.StateUnknown},
		{"unknown status", Response{Status: StatusUnknown, Execution: meta}, mutation, idempotency.StateUnknown},
		{"empty status", Response{Status: "", Execution: meta}, mutation, idempotency.StateUnknown},
		{"garbage status", Response{Status: "BANANA", Execution: meta}, mutation, idempotency.StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, out := classifyPostDispatch(tc.resp, tc.desc)
			if state != tc.want {
				t.Errorf("classifyPostDispatch(%s) = %s, want %s", tc.name, state, tc.want)
			}
			// When the provider claimed success but the decision is
			// UNKNOWN (invalid CRITICAL evidence), the wire response
			// must be rewritten — never leak a fake success.
			if state == idempotency.StateUnknown && tc.resp.Status == StatusSucceeded && out.Status != StatusUnknown {
				t.Errorf("UNKNOWN decision on a SUCCEEDED response must rewrite the wire status, got %s", out.Status)
			}
		})
	}
}
