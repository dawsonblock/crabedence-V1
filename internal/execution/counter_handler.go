package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// CounterExecution records one applied increment with its full durable
// execution identity. The provider run ID is preserved so recovery can
// return the real external operation identity instead of fabricating a
// replacement.
type CounterExecution struct {
	ExecutionID    string
	PrincipalID    string
	CapabilityID   string
	IdempotencyKey string
	Counter        string
	Amount         int64
	ProviderRunID  string
}

// counterExecutionKey scopes an applied increment to the durable
// execution identity the store uses: (principal, capability,
// idempotency_key) — the store's uniqueness constraint. Keying by the
// bare idempotency key is wrong: different principals or capabilities
// may reuse the same key and are distinct durable executions.
func counterExecutionKey(principal, capability, idempotencyKey string) string {
	return "pk:" + principal + "\x1f" + capability + "\x1f" + idempotencyKey
}

// counterTokenKey scopes an applied increment to the external operation
// token persisted in the recovery locator — the strongest correlation,
// since the token is derived from the durable execution_id and is the
// same token used in the external request.
func counterTokenKey(externalToken string) string {
	return "tok:" + externalToken
}

// CounterHandler implements the test.counter.increment capability.
// This is a harmless mutation capability backed by an in-memory counter
// (or optionally a database). It proves that idempotency works:
// 100 concurrent identical calls result in exactly one increment.
//
// For recovery, the handler tracks which executions incremented which
// counters — keyed by the locator's external token (derived from
// execution_id) and by (principal, capability, idempotency_key) for
// records that predate tokens — storing the applied amount plus the
// original run ID. This allows Resolve() to prove "this specific
// execution caused the effect" and to return the real provider run ID
// rather than a fabricated one.
type CounterHandler struct {
	mu         sync.Mutex
	counters   map[string]int64
	executions map[string]map[string]CounterExecution // counter → correlation key → execution
}

// NewCounterHandler creates a handler for test.counter.increment.
func NewCounterHandler() *CounterHandler {
	return &CounterHandler{
		counters:   make(map[string]int64),
		executions: make(map[string]map[string]CounterExecution),
	}
}

// GetCount returns the current count for a counter (for testing).
func (h *CounterHandler) GetCount(name string) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counters[name]
}

// counterArgs is the normalized argument shape for the capability.
type counterArgs struct {
	Counter string `json:"counter"`
	By      int64  `json:"by"`
}

// normalizeCounterArgs applies the provider's semantic defaults —
// counter defaults to "default", by defaults to 1. This is provider
// argument normalization, distinct from JSON canonicalization: two
// inputs that canonicalize differently ({"by":0} vs {}) normalize to
// the same executed form here.
func normalizeCounterArgs(raw json.RawMessage) (counterArgs, error) {
	var args counterArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, err
	}
	if args.Counter == "" {
		args.Counter = "default"
	}
	if args.By == 0 {
		args.By = 1
	}
	return args, nil
}

// Execute handles a test.counter.increment request.
func (h *CounterHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	runID := fmt.Sprintf("counter-%d", time.Now().UnixNano())

	args, err := normalizeCounterArgs(req.Arguments)
	if err != nil {
		return Response{
			Status:      StatusFailed,
			FailureCode: string(capability.FailureInvalidRequest),
			Error:       fmt.Sprintf("invalid arguments: %v", err),
			Execution: &ExecutionMeta{
				Provider: "test-counter",
				RunID:    runID,
			},
		}
	}

	// Increment the counter and record the execution identity that
	// caused it. The record is keyed under the external operation token
	// (from the persisted recovery locator, derived from execution_id)
	// when present, and always under (principal, capability,
	// idempotency_key) — the store's durable uniqueness scope — so
	// records written before tokens existed still resolve.
	h.mu.Lock()
	h.counters[args.Counter] += args.By
	newValue := h.counters[args.Counter]
	if h.executions[args.Counter] == nil {
		h.executions[args.Counter] = make(map[string]CounterExecution)
	}
	exec := CounterExecution{
		PrincipalID:    req.Authority.Principal,
		CapabilityID:   req.Capability,
		IdempotencyKey: req.IdempotencyKey,
		Counter:        args.Counter,
		Amount:         args.By,
		ProviderRunID:  runID,
	}
	if token := ExternalTokenFromContext(ctx); token != "" {
		exec.ExecutionID = token // token encodes the execution identity
		h.executions[args.Counter][counterTokenKey(token)] = exec
	}
	h.executions[args.Counter][counterExecutionKey(req.Authority.Principal, req.Capability, req.IdempotencyKey)] = exec
	h.mu.Unlock()

	result, _ := json.Marshal(map[string]any{
		"counter": args.Counter,
		"value":   newValue,
		"by":      args.By,
	})
	// The evidence artifact is the provider's own execution record —
	// the object that proves this execution caused the effect. The
	// dispatcher recomputes its digest; the handler never supplies one.
	artifact, _ := json.Marshal(exec)

	return Response{
		Status:           StatusSucceeded,
		Result:           result,
		EvidenceArtifact: artifact,
		Execution: &ExecutionMeta{
			Provider: "test-counter",
			RunID:    runID,
		},
	}
}

// PrepareRecovery implements idempotency.RecoveryLocatorProvider. The
// counter's recovery locator is minimal and normalized: a typed
// RecoveryLocator carrying the external operation token (derived from
// the durable execution_id — the same token DispatchExecutor injects
// into the dispatch context for Execute) plus the normalized executed
// parameters in Extensions. Never the raw argument blob.
func (h *CounterHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (*idempotency.RecoveryLocator, error) {
	args, err := normalizeCounterArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	ext, _ := json.Marshal(map[string]any{
		"counter": args.Counter,
		"by":      args.By,
	})
	return &idempotency.RecoveryLocator{
		Version:        1,
		ProviderID:     "test-counter",
		Strategy:       "external-token",
		ExternalToken:  "ctr-op-" + in.ExecutionID,
		RequestDigest:  in.RequestDigest,
		ExecutionID:    in.ExecutionID,
		PrincipalID:    in.Principal,
		CapabilityID:   in.CapabilityID,
		IdempotencyKey: in.IdempotencyKey,
		Extensions:     ext,
	}, nil
}

// Resolve implements idempotency.RecoveryResolver for the counter
// capability. It checks whether the counter described in the recovery
// locator was actually incremented BY THIS SPECIFIC EXECUTION.
//
// Execution correlation: the handler tracks which (principal,
// idempotency_key) pairs incremented which counters, together with the
// original provider run ID. Recovery proves "this execution caused the
// effect" — not merely "the counter exists" and not merely "some
// execution with this key ran" (a different principal with the same
// key is a different durable execution).
//
// For an in-memory counter, a process crash loses all state — so this
// resolver can only prove COMMITTED (the execution is recorded), not
// FAILED (the counter may have existed before the crash).
// RecoveryFailed is not possible for in-memory providers.
func (h *CounterHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	// Parse the recovery locator. The typed provider-owned locator
	// carries the external token and normalized params in Extensions;
	// legacy locators stored counter/by at top level or nested under
	// "arguments". Support all for records written before the typed
	// path existed.
	counterName := ""
	var by int64
	externalToken := ""
	if len(rec.RecoveryLocator) > 0 {
		var loc idempotency.RecoveryLocator
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err == nil {
			externalToken = loc.ExternalToken
			if len(loc.Extensions) > 0 {
				var ext struct {
					Counter string `json:"counter"`
					By      int64  `json:"by"`
				}
				if err := json.Unmarshal(loc.Extensions, &ext); err == nil {
					counterName = ext.Counter
					by = ext.By
				}
			}
		}
		// Legacy formats.
		var legacy struct {
			Counter   string          `json:"counter"`
			By        int64           `json:"by"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(rec.RecoveryLocator, &legacy); err == nil {
			if counterName == "" {
				counterName = legacy.Counter
			}
			if by == 0 {
				by = legacy.By
			}
			if len(legacy.Arguments) > 0 {
				var args counterArgs
				if err := json.Unmarshal(legacy.Arguments, &args); err == nil {
					if args.Counter != "" && counterName == "" {
						counterName = args.Counter
					}
					if args.By != 0 && by == 0 {
						by = args.By
					}
				}
			}
		}
	}
	if counterName == "" {
		counterName = "default"
	}
	if by == 0 {
		by = 1
	}

	h.mu.Lock()
	// Strongest correlation first: the external token bound to the
	// durable execution_id. Fall back to (principal, capability,
	// idempotency_key) for pre-token records.
	var exec CounterExecution
	wasExecuted := false
	if externalToken != "" {
		exec, wasExecuted = h.executions[counterName][counterTokenKey(externalToken)]
		if wasExecuted && (exec.PrincipalID != rec.PrincipalID ||
			exec.CapabilityID != rec.CapabilityID ||
			exec.IdempotencyKey != rec.IdempotencyKey) {
			// The token resolves to an execution whose durable
			// identity contradicts this record — a grafted or stale
			// locator, not proof for this record.
			wasExecuted = false
		}
	}
	if !wasExecuted {
		exec, wasExecuted = h.executions[counterName][counterExecutionKey(rec.PrincipalID, rec.CapabilityID, rec.IdempotencyKey)]
	}
	value := h.counters[counterName]
	h.mu.Unlock()

	if !wasExecuted {
		// This specific execution did not increment the counter.
		// Either the handler never ran for this execution, or the
		// process crashed and in-memory state was lost.
		// We cannot distinguish these cases — return UNKNOWN.
		return idempotency.RecoveryResult{
			Decision: idempotency.RecoveryUnknown,
		}, nil
	}

	// This execution provably incremented the counter. The recorded
	// amount must match the recovery parameters — a mismatch means the
	// locator does not describe the recorded effect.
	if exec.Amount != by {
		return idempotency.RecoveryResult{
			Decision: idempotency.RecoveryUnknown,
		}, nil
	}

	result, _ := json.Marshal(map[string]any{
		"counter": counterName,
		"value":   value,
		"by":      by,
	})
	// The evidence artifact is the stored execution record — the
	// provider-side object proving THIS execution caused the effect.
	// The attestor recomputes its digest.
	artifact, _ := json.Marshal(exec)
	return idempotency.RecoveryResult{
		Decision:         idempotency.RecoveryCommitted,
		Result:           result,
		ReceiptVersion:   3,
		ProviderID:       "test-counter",
		EvidenceArtifact: artifact,
		// Return the original provider run ID recorded at execution
		// time — never a fabricated replacement.
		ProviderRunID: exec.ProviderRunID,
	}, nil
}

// RegisterCounterCapability registers test.counter.increment in the registry.
func RegisterCounterCapability(reg *capability.Registry) error {
	return reg.Register(capability.CapabilityDescriptor{
		ID:             "test.counter.increment",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "test-counter",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "test.counter",
			GrantRequired: true,
		},
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"counter": {
					"type": "string",
					"minLength": 1,
					"maxLength": 256,
					"description": "Counter name (defaults to 'default')"
				},
				"by": {
					"type": "integer",
					"minimum": -1000000,
					"maximum": 1000000,
					"description": "Increment amount (defaults to 1)"
				}
			},
			"additionalProperties": false
		}`),
	})
}
