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

// CounterHandler implements the test.counter.increment capability.
// This is a harmless mutation capability backed by an in-memory counter
// (or optionally a database). It proves that idempotency works:
// 100 concurrent identical calls result in exactly one increment.
//
// For recovery, the handler tracks which execution IDs incremented
// which counters. This allows Resolve() to prove "this specific
// execution caused the effect" rather than just "the counter exists."
type CounterHandler struct {
	mu         sync.Mutex
	counters   map[string]int64
	executions map[string]map[string]int64 // counter → execution_id → amount
}

// NewCounterHandler creates a handler for test.counter.increment.
func NewCounterHandler() *CounterHandler {
	return &CounterHandler{
		counters:   make(map[string]int64),
		executions: make(map[string]map[string]int64),
	}
}

// GetCount returns the current count for a counter (for testing).
func (h *CounterHandler) GetCount(name string) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counters[name]
}

// Execute handles a test.counter.increment request.
func (h *CounterHandler) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	runID := fmt.Sprintf("counter-%d", time.Now().UnixNano())

	// Parse arguments
	var args struct {
		Counter string `json:"counter"`
		By      int64  `json:"by"`
	}
	if err := json.Unmarshal(req.Arguments, &args); err != nil {
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
	if args.Counter == "" {
		args.Counter = "default"
	}
	if args.By == 0 {
		args.By = 1
	}

	// Increment the counter and record the idempotency key that
	// caused it. The idempotency key uniquely identifies the logical
	// execution — two different executions with different keys are
	// tracked separately.
	h.mu.Lock()
	h.counters[args.Counter] += args.By
	newValue := h.counters[args.Counter]
	if h.executions[args.Counter] == nil {
		h.executions[args.Counter] = make(map[string]int64)
	}
	h.executions[args.Counter][req.IdempotencyKey] = args.By
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

// Resolve implements idempotency.RecoveryResolver for the counter
// capability. It checks whether the counter described in the recovery
// locator was actually incremented BY THIS SPECIFIC EXECUTION.
//
// Execution correlation: the handler tracks which idempotency keys
// incremented which counters. Recovery proves "this execution caused
// the effect" — not merely "the counter exists."
//
// For an in-memory counter, a process crash loses all state — so this
// resolver can only prove COMMITTED (the idempotency key is recorded),
// not FAILED (the counter may have existed before the crash).
// RecoveryFailed is not possible for in-memory providers.
func (h *CounterHandler) Resolve(ctx context.Context, rec *idempotency.Record) (idempotency.RecoveryResult, error) {
	// Parse the recovery locator to find which counter was incremented.
	var locator struct {
		Arguments struct {
			Counter string `json:"counter"`
			By      int64  `json:"by"`
		} `json:"arguments"`
	}
	if len(rec.RecoveryLocator) > 0 {
		var loc struct {
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(rec.RecoveryLocator, &loc); err == nil {
			json.Unmarshal(loc.Arguments, &locator.Arguments)
		}
	}

	counterName := locator.Arguments.Counter
	if counterName == "" {
		counterName = "default"
	}
	// Apply the same normalization as Execute: By defaults to 1.
	by := locator.Arguments.By
	if by == 0 {
		by = 1
	}

	h.mu.Lock()
	execAmount, wasExecuted := h.executions[counterName][rec.IdempotencyKey]
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

	// This execution provably incremented the counter. The amount
	// matches the canonical parameters.
	if execAmount != by {
		// The recorded amount differs from the recovery parameters —
		// something is inconsistent. Stay UNKNOWN.
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
		ProviderRunID:  fmt.Sprintf("counter-recovered-%s-%s", counterName, rec.IdempotencyKey),
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
