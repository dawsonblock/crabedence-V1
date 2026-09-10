package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
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
