package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// sleepyHandler simulates a provider that takes its time, then succeeds.
type sleepyHandler struct {
	delay time.Duration
}

func (h sleepyHandler) Execute(ctx context.Context, _ Request, desc capability.ResolvedDescriptor) Response {
	select {
	case <-ctx.Done():
		return Response{Status: StatusUnknown, Error: ctx.Err().Error()}
	case <-time.After(h.delay):
	}
	return Response{
		Status: StatusSucceeded,
		Result: json.RawMessage(`{"ok":true}`),
		Execution: &ExecutionMeta{
			Provider: desc.AdapterID,
			RunID:    fmt.Sprintf("sleepy-%d", time.Now().UnixNano()),
		},
	}
}

// TestLiveLeaseHeartbeatSurvivesSlowFinalize proves the execution lease
// heartbeat keeps the lease alive through BOTH the provider call and
// slow post-provider verification — the heartbeat must not stop at
// provider return.
//
// Timing: lease = 300ms, provider = 150ms, post-provider verification
// (preFinalizeHook) = 400ms. Total post-dispatch ≈ 550ms > 300ms lease.
// Without heartbeat renewal past the 300ms mark, Finalize's fenced CAS
// (lease_expires_at > clock_timestamp()) would fail and the record
// would drop into UNKNOWN despite a clean provider success.
//
// Requires CRABBOX_TEST_DATABASE_URL. Skipped when absent.
func TestLiveLeaseHeartbeatSurvivesSlowFinalize(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := idempotency.NewStoreWithConfig(db, idempotency.LeaseConfig{
		DefaultDuration: 300 * time.Millisecond,
		MaxDuration:     10 * time.Second,
		RenewalWindow:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	ctx := context.Background()

	key := fmt.Sprintf("test-tiny-lease-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
	defer db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	multiHandler := NewMultiHandler(map[string]Handler{
		"sleepy": sleepyHandler{delay: 150 * time.Millisecond},
	})
	exec := NewDispatchExecutor(multiHandler, store)
	// Simulate slow post-provider evidence verification: 400ms spent
	// between provider return and Finalize while the 300ms lease would
	// otherwise expire.
	exec.preFinalizeHook = func() { time.Sleep(400 * time.Millisecond) }

	desc := capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "sleepy",
	}
	resp := exec.ExecuteWithIdempotency(ctx, Request{
		Capability: "test.sleepy",
		Arguments:  json.RawMessage(`{}`),
		Authority: RequestAuthority{
			Principal:    "alice@example.com",
			AuthorityRef: "grant_hb",
		},
		IdempotencyKey: key,
	}, desc)

	if resp.Status != StatusSucceeded {
		t.Fatalf("expected SUCCEEDED after 550ms post-dispatch window on a 300ms lease, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(ctx, "alice@example.com", "test.sleepy", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s — heartbeat did not keep the lease alive through verification", rec.State)
	}
}
