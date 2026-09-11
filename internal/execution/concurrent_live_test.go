package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// TestLiveConcurrentIdenticalMutationSingleDispatch verifies the full
// dispatch chain: 100 concurrent identical MUTATION requests through the
// Unix socket → Service → authority → DispatchExecutor → PostgreSQL
// Acquire → CounterHandler → exactly ONE side effect.
//
// This is the end-to-end proof for CRAB-V1-021:
// "concurrent identical mutations cause at most one provider dispatch."
//
// Unlike the store-level concurrent reserve test, this test goes through
// the actual service socket, authority verification, dispatch executor,
// and handler — proving the entire chain enforces idempotency.
//
// Requires CRABBOX_TEST_DATABASE_URL. Skipped when absent.
func TestLiveConcurrentIdenticalMutationSingleDispatch(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	store, err := idempotency.NewStore(db)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Clean up prior test data.
	ctx := context.Background()
	key := fmt.Sprintf("test-100way-%d", time.Now().UnixNano())
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)

	// Set up the service with DispatchExecutor + real store.
	registry := capability.NewRegistry()
	if err := RegisterCounterCapability(registry); err != nil {
		t.Fatal(err)
	}

	counter := NewCounterHandler()
	multiHandler := NewMultiHandler(map[string]Handler{
		"test-counter": counter,
	})

	dispatchExecutor := NewDispatchExecutor(multiHandler, store)

	socketPath := testSocketPath(t)
	service := NewService(registry, dispatchExecutor, socketPath)
	service.SetGrantResolver(testGrantResolver())

	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()

	// Send 100 concurrent identical mutation requests.
	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)

	var successCount, failCount, inFlightCount int64
	var firstResult []byte
	var resultMu sync.Mutex

	counterName := fmt.Sprintf("concurrent_%d", time.Now().UnixNano())

	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			conn, err := net.Dial("unix", socketPath)
			if err != nil {
				t.Errorf("dial error: %v", err)
				return
			}
			defer conn.Close()

			req := Request{
				Capability: "test.counter.increment",
				Arguments:  json.RawMessage(fmt.Sprintf(`{"counter":%q,"by":1}`, counterName)),
				Authority: RequestAuthority{
					Principal:    "alice@example.com",
					AuthorityRef: "grant_123",
				},
				IdempotencyKey: key,
			}
			resp := sendRequest(t, conn, req)

			switch resp.Status {
			case StatusSucceeded:
				atomic.AddInt64(&successCount, 1)
				resultMu.Lock()
				if firstResult == nil {
					firstResult = resp.Result
				}
				resultMu.Unlock()
			case StatusFailed:
				atomic.AddInt64(&failCount, 1)
			case StatusInFlight:
				atomic.AddInt64(&inFlightCount, 1)
			case StatusUnknown:
				// Unknown is acceptable for concurrent losers —
				// the store may have transitioned to UNKNOWN if the
				// winner's lease expired mid-flight.
				atomic.AddInt64(&inFlightCount, 1)
			}
		}()
	}

	wg.Wait()

	// CRAB-V1-021: exactly one provider dispatch.
	// The counter should be exactly 1 (one increment by one handler call).
	// Multiple callers may receive SUCCEEDED via terminal replay — that
	// is correct idempotent behavior. The invariant is that the side
	// effect occurred exactly once, not that only one caller sees success.
	finalCount := counter.GetCount(counterName)
	if finalCount != 1 {
		t.Errorf("CRAB-V1-021 violation: expected counter=1 (exactly one dispatch), got counter=%d", finalCount)
	}

	// At least one caller should succeed.
	if successCount < 1 {
		t.Errorf("expected at least 1 success, got 0 (fail=%d, in-flight/unknown=%d)",
			failCount, inFlightCount)
	}

	// The successful result should contain value=1.
	if firstResult != nil {
		var res struct {
			Value int64 `json:"value"`
		}
		if err := json.Unmarshal(firstResult, &res); err != nil {
			t.Fatalf("failed to parse result: %v", err)
		}
		if res.Value != 1 {
			t.Errorf("expected result value=1, got %d", res.Value)
		}
	}

	t.Logf("100-way concurrent mutation: success=%d, fail=%d, in-flight/unknown=%d, counter=%d",
		successCount, failCount, inFlightCount, finalCount)

	// Clean up.
	db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
}
