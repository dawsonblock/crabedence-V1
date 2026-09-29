package execution

import (
	"context"
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
// Timing: lease = 300ms, provider = 150ms. The post-provider
// verification window is synchronized on durable state rather than a
// fixed sleep: the hook waits until the original 300ms deadline has
// passed AND the heartbeat has provably renewed the lease (a
// LEASE_RENEWED effect event), so Finalize's fenced CAS
// (lease_expires_at > clock_timestamp()) can only succeed on a lease
// the heartbeat kept alive. Without the renewal the CAS fails and the
// record drops into UNKNOWN despite a clean provider success.
//
// Requires CRABBOX_TEST_DATABASE_URL. Skipped when absent.
func TestLiveLeaseHeartbeatSurvivesSlowFinalize(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := openTestDB(dbURL)
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
	// Simulate slow post-provider evidence verification, synchronized on
	// durable state instead of a fixed sleep: the heartbeat must provably
	// renew the lease and the original deadline must have passed before
	// Finalize runs. The fixed sleep this replaces raced a sub-second
	// wall-clock lease against CI scheduling and failed whenever the
	// heartbeat goroutine was delayed past the expiry.
	exec.preFinalizeHook = func() {
		deadline := time.Now().Add(10 * time.Second)
		for {
			var pastOriginalDeadline, renewed, leaseAlive bool
			err := db.QueryRowContext(ctx, `
				SELECT
				  clock_timestamp() >= r.lease_started_at + make_interval(secs => $2),
				  EXISTS (
				    SELECT 1 FROM effect_events e
				    WHERE e.execution_id = r.execution_id::text AND e.event_type = $3
				  ),
				  r.lease_expires_at > clock_timestamp()
				FROM execution_requests r
				WHERE r.idempotency_key = $1`,
				key, 0.3, idempotency.EventLeaseRenewed,
			).Scan(&pastOriginalDeadline, &renewed, &leaseAlive)
			if err == nil {
				if pastOriginalDeadline && !leaseAlive {
					t.Errorf("lease expired before Finalize: the heartbeat did not keep it alive through verification")
					return
				}
				if pastOriginalDeadline && renewed {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Errorf("timed out waiting for the heartbeat to renew the lease past its original deadline")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

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
