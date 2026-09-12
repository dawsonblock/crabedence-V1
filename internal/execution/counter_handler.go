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
type CounterHandler struct {
	mu       sync.Mutex
	counters map[string]int64
}

// NewCounterHandler creates a handler for test.counter.increment.
func NewCounterHandler() *CounterHandler {
	return &CounterHandler{
		counters: make(map[string]int64),
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

	// Increment the counter
	h.mu.Lock()
	h.counters[args.Counter] += args.By
	newValue := h.counters[args.Counter]
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
// locator was actually incremented.
//
// For an in-memory counter, a process crash loses all state — so this
// resolver can only prove COMMITTED (the counter exists and was
// incremented), not FAILED (the counter may have existed before the
// crash). RecoveryFailed is not possible for in-memory providers.
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

	h.mu.Lock()
	value, exists := h.counters[counterName]
	h.mu.Unlock()

	if !exists {
		// The counter does not exist — either the handler never ran,
		// or the process crashed and in-memory state was lost.
		// We cannot distinguish these cases, so return UNKNOWN.
		return idempotency.RecoveryResult{
			Decision: idempotency.RecoveryUnknown,
		}, nil
	}

	// The counter exists — the increment happened (or the counter
	// was incremented by a different execution). For the test counter,
	// this is sufficient proof of COMMITTED.
	result, _ := json.Marshal(map[string]any{
		"counter": counterName,
		"value":   value,
		"by":      locator.Arguments.By,
	})
	// Compute a deterministic evidence digest from the result so the
	// recovery receipt carries the same proof schema as a normal
	// finalization (receipt_version=3, non-empty evidence digest).
	evidenceDigest := fmt.Sprintf("%x", sha256.Sum256(result))
	return idempotency.RecoveryResult{
		Decision:       idempotency.RecoveryCommitted,
		Result:         result,
		EvidenceDigest: evidenceDigest,
		ReceiptVersion: 3,
		ProviderID:     "test-counter",
		ProviderRunID:  fmt.Sprintf("counter-recovered-%s", counterName),
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
