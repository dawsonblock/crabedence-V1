package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// statusOnlyHandler returns a provider response carrying only a status
// and provider identity — no run ID, no result payload, no evidence.
// The durable execution contract requires every provider response to be
// persisted before classification: provider_id/provider_status and the
// observation timestamp are themselves observation data.
type statusOnlyHandler struct {
	status     string
	definitive bool
}

func (h statusOnlyHandler) Execute(_ context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	return Response{
		Status:            h.status,
		DefinitiveFailure: h.definitive,
		FailureCode:       "PROVIDER_ERROR",
		Error:             "provider answered without payload",
		Execution:         &ExecutionMeta{Provider: desc.AdapterID},
	}
}

// TestLiveProviderObservationAlwaysPersisted is the regression test for
// the observation-skip defect: a provider response with no run ID, no
// result, and no evidence digest must STILL be recorded — the contract
// is "every provider response persisted before classification", not
// "only responses carrying payload".
//
// Requires CRABBOX_TEST_DATABASE_URL. Skipped when absent.
func TestLiveProviderObservationAlwaysPersisted(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	prefix := fmt.Sprintf("test-alwaysobs-%d", time.Now().UnixNano())
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key LIKE $1`, prefix+"%")

	multiHandler := NewMultiHandler(map[string]Handler{
		"statusonly": statusOnlyHandler{status: StatusFailed, definitive: true},
	})
	exec := NewDispatchExecutor(multiHandler, store)

	desc := capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "statusonly",
	}
	resp := exec.ExecuteWithIdempotency(ctx, Request{
		Capability: "test.statusonly",
		Arguments:  json.RawMessage(`{}`),
		Authority: RequestAuthority{
			Principal:    "alice@example.com",
			AuthorityRef: "grant_obs",
		},
		IdempotencyKey: prefix + "-failed",
	}, desc)
	if resp.Status != StatusFailed {
		t.Fatalf("expected FAILED, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(ctx, "alice@example.com", "test.statusonly", prefix+"-failed")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.ProviderStatus != StatusFailed {
		t.Errorf("provider_status not persisted for status-only response, got %q", rec.ProviderStatus)
	}
	if rec.ProviderID != "statusonly" {
		t.Errorf("provider_id not persisted for status-only response, got %q", rec.ProviderID)
	}
	if rec.ProviderObservedAt == nil {
		t.Error("provider_observed_at not set — the provider response was never durably recorded")
	}
}
