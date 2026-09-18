package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// TestConcurrencyTortureSingleDispatch runs N competing workers against
// the same logical execution on the embedded SQLite backend. The core
// invariant: provider dispatch count must be exactly 1 — concurrent
// callers get IN_FLIGHT or the terminal replay, never a second
// provider invocation.
func TestConcurrencyTortureSingleDispatch(t *testing.T) {
	for _, workers := range []int{10, 50} {
		t.Run(fmt.Sprintf("workers-%d", workers), func(t *testing.T) {
			store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)

			var calls atomic.Int32
			p := &simProvider{
				effect: true,
				delay:  20 * time.Millisecond,
				respond: func(n int32) Response {
					calls.Add(1)
					return Response{
						Status: StatusSucceeded,
						Result: json.RawMessage(`{"ok":true}`),
					}
				},
			}
			exec := NewDispatchExecutor(p, store)

			key := fmt.Sprintf("torture-%d-%d", workers, time.Now().UnixNano())
			req := crashRequest("alice@example.com", key)

			var wg sync.WaitGroup
			statuses := make([]string, workers)
			start := make(chan struct{})
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					statuses[i] = exec.ExecuteWithIdempotency(context.Background(), req, crashDesc).Status
				}(i)
			}
			close(start)
			wg.Wait()

			if got := p.calls.Load(); got != 1 {
				t.Errorf("provider dispatch count = %d, want exactly 1", got)
			}
			if got := p.effects.Load(); got != 1 {
				t.Errorf("external effects = %d, want exactly 1", got)
			}

			rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
			if err != nil {
				t.Fatal(err)
			}
			if rec.State != idempotency.StateCommitted {
				t.Errorf("durable state = %s, want COMMITTED", rec.State)
			}

			var succeeded, inFlight, unknown, other int
			for _, s := range statuses {
				switch s {
				case StatusSucceeded:
					succeeded++
				case StatusInFlight:
					inFlight++
				case StatusUnknown:
					unknown++
				default:
					other++
				}
			}
			t.Logf("statuses: succeeded=%d in_flight=%d unknown=%d other=%d", succeeded, inFlight, unknown, other)
			if other > 0 {
				t.Errorf("%d workers got unexpected statuses", other)
			}
			if succeeded == 0 {
				t.Error("no worker observed success")
			}
		})
	}
}

// TestConcurrencyDistinctKeys runs N workers with DISTINCT idempotency
// keys — each must dispatch exactly once and commit independently.
func TestConcurrencyDistinctKeys(t *testing.T) {
	const workers = 25
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)

	var calls atomic.Int32
	p := &simProvider{
		effect: true,
		respond: func(n int32) Response {
			calls.Add(1)
			return Response{Status: StatusSucceeded, Result: json.RawMessage(`{"ok":true}`)}
		},
	}
	exec := NewDispatchExecutor(p, store)

	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := crashRequest("alice@example.com", fmt.Sprintf("distinct-%d-%d", i, time.Now().UnixNano()))
			if resp := exec.ExecuteWithIdempotency(context.Background(), req, crashDesc); resp.Status != StatusSucceeded {
				errs[i] = fmt.Errorf("worker %d: %s", i, resp.Status)
			}
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := calls.Load(); got != workers {
		t.Errorf("provider dispatch count = %d, want %d", got, workers)
	}
}
