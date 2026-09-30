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
// Timing: lease = 1s (renewal interval = 500ms), provider = 150ms. The
// renewal window is the only scheduling slack a heartbeat tick has: the
// store refuses to renew an expired lease, so a tick that lands after
// the deadline kills the heartbeat permanently — a starved goroutine
// missing a sub-second window is what made the shorter lease flaky on
// CI. A 500ms window gives a loaded runner five times that slack.
//
// The post-provider verification window waits until the ORIGINAL lease
// deadline has passed AND a renewal has landed since the hook began —
// observed through a recording store rather than sampled expiry, so a
// renewal can never be missed between poll phases. Finalize's fenced
// CAS (lease_expires_at > clock_timestamp()) can then only succeed on
// a lease the heartbeat kept alive. Without the renewal the CAS fails
// and the record drops into UNKNOWN despite a clean provider success.
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
		DefaultDuration: time.Second,
		MaxDuration:     10 * time.Second,
		RenewalWindow:   500 * time.Millisecond,
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
	wrapped := &renewalObservingStore{EffectStore: store}
	exec := NewDispatchExecutor(multiHandler, wrapped)
	// Simulate slow post-provider evidence verification, synchronized on
	// durable state and the recording store instead of a wall clock: wait
	// until the ORIGINAL lease deadline has passed AND a renewal has
	// landed since this hook began — a renewal after provider return
	// proves the heartbeat did not stop at dispatch. Finalize then runs
	// on a lease the heartbeat provably kept alive. The bound stays
	// below the terminalization stage budget (5s) so a genuine failure
	// reports the heartbeat problem instead of dying as a context
	// deadline inside Finalize.
	exec.preFinalizeHook = func() {
		bound := time.Now().Add(4 * time.Second)
		renewalsAtHookStart := wrapped.succeeded.Load()
		for {
			var pastOriginalDeadline bool
			var expiresAt time.Time
			err := db.QueryRowContext(ctx, `
				SELECT
				  clock_timestamp() >= r.lease_started_at + make_interval(secs => $2),
				  r.lease_expires_at
				FROM execution_requests r
				WHERE r.idempotency_key = $1`,
				key, 1.0,
			).Scan(&pastOriginalDeadline, &expiresAt)
			if err == nil && pastOriginalDeadline &&
				wrapped.succeeded.Load() > renewalsAtHookStart && expiresAt.After(time.Now()) {
				return
			}
			if time.Now().After(bound) {
				t.Errorf("no post-dispatch lease renewal landed (renewals attempted=%d succeeded=%d, baseline %d): "+
					"the heartbeat did not keep the lease alive through verification",
					wrapped.attempted.Load(), wrapped.succeeded.Load(), renewalsAtHookStart)
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
		t.Fatalf("expected SUCCEEDED past the original lease deadline on a renewed lease, got %s: %s", resp.Status, resp.Error)
	}

	rec, err := store.LookupByKey(ctx, "alice@example.com", "test.sleepy", key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s — heartbeat did not keep the lease alive through verification", rec.State)
	}
}
