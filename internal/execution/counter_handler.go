package execution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// counterExecution records one applied increment: the amount and the
// provider run ID assigned at execution time. The run ID is preserved
// so recovery can return the real external operation identity instead
// of fabricating a replacement.
type counterExecution struct {
	amount int64
	runID  string
}

// counterExecutionKey scopes an applied increment to the durable
// execution identity the store uses: (principal, idempotency_key) —
// the same pair that, together with the capability this handler serves,
// forms the store's uniqueness constraint. Keying by the bare
// idempotency key is wrong: two different principals may reuse the same
// key and are distinct durable executions.
func counterExecutionKey(principal, idempotencyKey string) string {
	return principal + "\x1f" + idempotencyKey
}

// CounterHandler implements the test.counter.increment capability.
// This is a harmless mutation capability backed by an in-memory counter
// (or optionally a database). It proves that idempotency works:
// 100 concurrent identical calls result in exactly one increment.
//
// For recovery, the handler tracks which executions incremented which
// counters — keyed by (principal, idempotency_key) and storing the
// applied amount plus the original run ID. This allows Resolve() to
// prove "this specific execution caused the effect" and to return the
// real provider run ID rather than a fabricated one.
type CounterHandler struct {
	mu         sync.Mutex
	counters   map[string]int64
	executions map[string]map[string]counterExecution // counter → (principal,key) → execution
}

// NewCounterHandler creates a handler for test.counter.increment.
func NewCounterHandler() *CounterHandler {
	return &CounterHandler{
		counters:   make(map[string]int64),
		executions: make(map[string]map[string]counterExecution),
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
	// caused it: (principal, idempotency_key) → {amount, runID}. This
	// matches the store's durable uniqueness scope — the bare key alone
	// does not uniquely identify an execution across principals.
	h.mu.Lock()
	h.counters[args.Counter] += args.By
	newValue := h.counters[args.Counter]
	if h.executions[args.Counter] == nil {
		h.executions[args.Counter] = make(map[string]counterExecution)
	}
	h.executions[args.Counter][counterExecutionKey(req.Authority.Principal, req.IdempotencyKey)] = counterExecution{
		amount: args.By,
		runID:  runID,
	}
	h.mu.Unlock()

	result, _ := json.Marshal(map[string]any{
		"counter": args.Counter,
		"value":   newValue,
		"by":      args.By,
	})

	return Response{
		Status: StatusSucceeded,
		Result: result,
		Execution: &ExecutionMeta{
			Provider: "test-counter",
			RunID:    runID,
		},
	}
}

// PrepareRecovery implements idempotency.RecoveryLocatorProvider. The
// counter's recovery locator is minimal and normalized: it stores the
// counter name and increment amount in the form actually executed
// (semantic defaults applied), plus the durable execution identity —
// never the raw argument blob.
func (h *CounterHandler) PrepareRecovery(_ context.Context, in idempotency.RecoveryLocatorInput) (json.RawMessage, error) {
	args, err := normalizeCounterArgs(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	return json.Marshal(map[string]any{
		"v":               1,
		"provider":        "test-counter",
		"capability_id":   in.CapabilityID,
		"execution_id":    in.ExecutionID,
		"principal":       in.Principal,
		"idempotency_key": in.IdempotencyKey,
		"counter":         args.Counter,
		"by":              args.By,
	})
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
	// Parse the recovery locator. The provider-owned locator stores
	// counter/by at top level; the legacy generic locator nested them
	// under "arguments". Support both for records written before the
	// provider-owned path existed.
	counterName := ""
	var by int64
	if len(rec.RecoveryLocator) > 0 {
		var loc struct {
			Counter   string          `json:"counter"`
			By        int64           `json:"by"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err == nil {
			counterName = loc.Counter
			by = loc.By
			if len(loc.Arguments) > 0 {
				var args counterArgs
				if err := json.Unmarshal(loc.Arguments, &args); err == nil {
					if args.Counter != "" {
						counterName = args.Counter
					}
					if args.By != 0 {
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
	exec, wasExecuted := h.executions[counterName][counterExecutionKey(rec.PrincipalID, rec.IdempotencyKey)]
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
	if exec.amount != by {
		return idempotency.RecoveryResult{
			Decision: idempotency.RecoveryUnknown,
		}, nil
	}

	result, _ := json.Marshal(map[string]any{
		"counter": counterName,
		"value":   value,
		"by":      by,
	})
	evidenceDigest := fmt.Sprintf("%x", sha256.Sum256(result))
	return idempotency.RecoveryResult{
		Decision:       idempotency.RecoveryCommitted,
		Result:         result,
		EvidenceDigest: evidenceDigest,
		ReceiptVersion: 3,
		ProviderID:     "test-counter",
		// Return the original provider run ID recorded at execution
		// time — never a fabricated replacement.
		ProviderRunID: exec.runID,
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
