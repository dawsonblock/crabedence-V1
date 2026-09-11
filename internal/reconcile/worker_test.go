package reconcile

import (
	"context"
	"testing"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// TestNoopResolverReturnsUnknown verifies that the NoopResolver
// returns RecoveryUnknown, ensuring fail-closed reconciliation.
func TestNoopResolverReturnsUnknown(t *testing.T) {
	r := NoopResolver{}
	result, err := r.Resolve(context.Background(), &idempotency.Record{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryUnknown {
		t.Errorf("expected RecoveryUnknown, got %s", result.Decision)
	}
}

// TestWorkerRegisterResolver verifies that capability-specific
// resolvers are selected over the default.
func TestWorkerRegisterResolver(t *testing.T) {
	defaultResolver := NoopResolver{}
	w := NewWorker(nil, defaultResolver, 0)

	custom := &mockResolver{decision: idempotency.RecoveryCommitted}
	w.RegisterResolver("test.capability", custom)

	// Default should be NoopResolver (UNKNOWN)
	result, err := w.resolve(context.Background(), &idempotency.Record{CapabilityID: "other.capability"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryUnknown {
		t.Errorf("expected RecoveryUnknown for unregistered capability, got %s", result.Decision)
	}

	// Registered capability should use custom resolver
	result, err = w.resolve(context.Background(), &idempotency.Record{CapabilityID: "test.capability"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryCommitted {
		t.Errorf("expected RecoveryCommitted for registered capability, got %s", result.Decision)
	}
}

// TestWorkerNilDefaultResolver verifies that a nil default resolver
// returns UNKNOWN (fail-closed).
func TestWorkerNilDefaultResolver(t *testing.T) {
	w := NewWorker(nil, nil, 0)
	result, err := w.resolve(context.Background(), &idempotency.Record{CapabilityID: "any.capability"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != idempotency.RecoveryUnknown {
		t.Errorf("expected RecoveryUnknown with nil default resolver, got %s", result.Decision)
	}
}

// mockResolver is a test RecoveryResolver that returns a fixed decision.
type mockResolver struct {
	decision idempotency.RecoveryDecision
	result   idempotency.RecoveryResult
}

func (m *mockResolver) Resolve(_ context.Context, _ *idempotency.Record) (idempotency.RecoveryResult, error) {
	return idempotency.RecoveryResult{Decision: m.decision}, nil
}
