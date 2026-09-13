package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/reconcile"
)

// fakeGitHub is an httptest server implementing the minimal GitHub
// issue API the adapter needs: POST /repos/o/r/issues and GET
// /repos/o/r/issues. Fault modes model each crash boundary.
type fakeGitHub struct {
	mu     sync.Mutex
	issues []map[string]any
	mode   string // "normal" | "hang" | "drop"
	sawOps []string
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	mode := f.mode
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
		var in struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		n := len(f.issues) + 1
		htmlURL := fmt.Sprintf("https://github.test%s/%d", r.URL.Path, n)
		f.issues = append(f.issues, map[string]any{
			"number":   n,
			"title":    in.Title,
			"body":     in.Body,
			"html_url": htmlURL,
		})
		f.sawOps = append(f.sawOps, r.Header.Get("X-Crabex-Operation"))
		f.mu.Unlock()
		switch mode {
		case "hang":
			// Effect exists; response never arrives.
			<-r.Context().Done()
			return
		case "drop":
			// Effect exists; connection drops before the response.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"number":%d,"id":%d,"html_url":%q}`, n, n, htmlURL)
		}
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
		f.mu.Lock()
		list := make([]map[string]any, len(f.issues))
		copy(list, f.issues)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeGitHub) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issues)
}

func (f *fakeGitHub) lastOp() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sawOps) == 0 {
		return ""
	}
	return f.sawOps[len(f.sawOps)-1]
}

func liveStore(t *testing.T, lease time.Duration) (*idempotency.Store, *sql.DB) {
	t.Helper()
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	store, err := idempotency.NewStoreWithConfig(db, idempotency.LeaseConfig{
		DefaultDuration: lease,
		MaxDuration:     10 * time.Second,
		RenewalWindow:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	return store, db
}

func reopenStore(t *testing.T, lease time.Duration) (*idempotency.Store, *sql.DB) {
	return liveStore(t, lease)
}

func githubDispatch(t *testing.T, exec *DispatchExecutor, key string) Response {
	t.Helper()
	return exec.ExecuteWithIdempotency(context.Background(), Request{
		Capability: "github.issue.create",
		Arguments:  json.RawMessage(`{"repo":"octo/repo","title":"hello","body":"world"}`),
		Authority: RequestAuthority{
			Principal:    "alice@example.com",
			AuthorityRef: "grant_gh",
		},
		IdempotencyKey: key,
	}, capability.ResolvedDescriptor{
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "github",
	})
}

// reconcileUnknownRecord runs the crash-recovery + reconciliation path
// for one record: expired lease → UNKNOWN (via recoverCrashed) →
// claimed UNKNOWN → resolver → terminal state.
func reconcileUnknownRecord(t *testing.T, store *idempotency.Store, resolver *GitHubIssueHandler, execID string) *idempotency.Record {
	t.Helper()
	ctx := context.Background()

	w := reconcile.NewWorker(store, reconcile.NoopResolver{}, 0)
	w.SetWorkerID("fault-worker")
	w.SetClaimDuration(2 * time.Second)
	w.RegisterResolver("github.issue.create", resolver)

	// Recover expired lease → UNKNOWN (IN_FLIGHT case).
	expired, err := store.ClaimExpiredBatch(ctx, "fault-worker", 50, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range expired {
		if rec.ExecutionID == execID {
			if err := w.RecoverCrashedForTest(ctx, rec); err != nil {
				t.Fatalf("crash recovery failed: %v", err)
			}
		}
	}

	// Claim UNKNOWN and resolve.
	claimed, err := store.ClaimUnknownBatch(ctx, "fault-worker", 50, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range claimed {
		if rec.ExecutionID == execID {
			if err := w.ReconcileOneForTest(ctx, rec); err != nil {
				t.Fatalf("reconciliation failed: %v", err)
			}
		}
	}
	rec, err := store.Lookup(ctx, execID)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestLiveGitHubIssueAtMostOnce exercises the github.issue.create
// adapter against every crash boundary: the durable effect must occur
// at most once and recovery must return the ORIGINAL provider run ID.
func TestLiveGitHubIssueAtMostOnce(t *testing.T) {
	dbURL := os.Getenv("CRABBOX_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CRABBOX_TEST_DATABASE_URL not set; skipping live PostgreSQL test")
	}
	ctx := context.Background()

	newSetup := func(t *testing.T, mode string) (*fakeGitHub, *idempotency.Store, *sql.DB, *DispatchExecutor, *GitHubIssueHandler, string) {
		fake := &fakeGitHub{mode: mode}
		srv := httptest.NewServer(fake)
		t.Cleanup(srv.Close)

		store, db := liveStore(t, 250*time.Millisecond)
		t.Cleanup(func() { db.Close() })

		gh := NewGitHubIssueHandler(srv.URL, "test-token")
		gh.SetHTTPClient(&http.Client{Timeout: 300 * time.Millisecond})
		multi := NewMultiHandler(map[string]Handler{"github": gh})
		exec := NewDispatchExecutor(multi, store)

		key := fmt.Sprintf("test-gh-%s-%d", mode, time.Now().UnixNano())
		db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
		t.Cleanup(func() {
			db.ExecContext(ctx, `DELETE FROM execution_requests WHERE idempotency_key = $1`, key)
		})
		return fake, store, db, exec, gh, key
	}

	t.Run("normal_dispatch_commits_once", func(t *testing.T) {
		fake, store, _, exec, _, key := newSetup(t, "normal")
		resp := githubDispatch(t, exec, key)
		if resp.Status != StatusSucceeded {
			t.Fatalf("expected SUCCEEDED, got %s: %s", resp.Status, resp.Error)
		}
		if fake.count() != 1 {
			t.Fatalf("expected 1 issue, got %d", fake.count())
		}
		// Same-token invariant: the operation token the provider saw
		// must embed the durable execution ID — proving the token
		// persisted in the locator is the one sent externally. (The
		// locator itself is cleared on terminal state, by design.)
		rec, _ := store.LookupByKey(ctx, "alice@example.com", "github.issue.create", key)
		if !strings.Contains(fake.lastOp(), rec.ExecutionID) {
			t.Errorf("provider operation token %q does not embed execution_id %s", fake.lastOp(), rec.ExecutionID)
		}
		// Replay: same key → terminal replay, no second issue.
		resp2 := githubDispatch(t, exec, key)
		if resp2.Status != StatusSucceeded {
			t.Errorf("expected replay SUCCEEDED, got %s", resp2.Status)
		}
		if fake.count() != 1 {
			t.Errorf("replay created a second issue: count=%d", fake.count())
		}
	})

	t.Run("timeout_after_request_commits_once", func(t *testing.T) {
		fake, store, _, exec, gh, key := newSetup(t, "hang")
		resp := githubDispatch(t, exec, key)
		if resp.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN after provider timeout, got %s: %s", resp.Status, resp.Error)
		}
		rec := reconcileUnknownRecord(t, store, gh, lookupExecID(t, store, ctx, key))
		if rec.State != idempotency.StateCommitted {
			t.Fatalf("expected COMMITTED after reconcile, got %s", rec.State)
		}
		if rec.ProviderRunID != "https://github.test/repos/octo/repo/issues/1" {
			t.Errorf("expected original provider run ID, got %q", rec.ProviderRunID)
		}
		if fake.count() != 1 {
			t.Errorf("expected 1 issue, got %d", fake.count())
		}
	})

	t.Run("response_dropped_commits_once", func(t *testing.T) {
		fake, store, _, exec, gh, key := newSetup(t, "drop")
		resp := githubDispatch(t, exec, key)
		if resp.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN after dropped response, got %s: %s", resp.Status, resp.Error)
		}
		rec := reconcileUnknownRecord(t, store, gh, lookupExecID(t, store, ctx, key))
		if rec.State != idempotency.StateCommitted {
			t.Fatalf("expected COMMITTED after reconcile, got %s", rec.State)
		}
		if fake.count() != 1 {
			t.Errorf("expected 1 issue, got %d", fake.count())
		}
	})

	t.Run("crash_before_observation_recovers", func(t *testing.T) {
		fake, _, db, exec, gh, key := newSetup(t, "normal")
		// Crash the database right between provider return and the
		// observation write — the response existed but nothing durable.
		exec.postDispatchHook = func() { db.Close() }
		resp := githubDispatch(t, exec, key)
		if resp.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN after crash, got %s: %s", resp.Status, resp.Error)
		}
		// Reconnect and reconcile: lease expires (heartbeat dead with
		// the DB), crash recovery marks UNKNOWN, resolver finds marker.
		store2, db2 := reopenStore(t, 250*time.Millisecond)
		defer db2.Close()
		time.Sleep(400 * time.Millisecond) // let the 250ms lease expire
		rec := reconcileUnknownRecord(t, store2, gh, lookupExecID(t, store2, ctx, key))
		if rec.State != idempotency.StateCommitted {
			t.Fatalf("expected COMMITTED after reconcile, got %s", rec.State)
		}
		if rec.ProviderRunID != "https://github.test/repos/octo/repo/issues/1" {
			t.Errorf("expected original provider run ID, got %q", rec.ProviderRunID)
		}
		if fake.count() != 1 {
			t.Errorf("expected 1 issue, got %d", fake.count())
		}
	})

	t.Run("crash_during_finalize_recovers", func(t *testing.T) {
		fake, _, db, exec, gh, key := newSetup(t, "normal")
		// Observation persisted, then the DB dies during Finalize.
		exec.preFinalizeHook = func() { db.Close() }
		resp := githubDispatch(t, exec, key)
		if resp.Status != StatusUnknown {
			t.Fatalf("expected UNKNOWN after finalize crash, got %s: %s", resp.Status, resp.Error)
		}
		store2, db2 := reopenStore(t, 250*time.Millisecond)
		defer db2.Close()
		time.Sleep(400 * time.Millisecond)
		rec := reconcileUnknownRecord(t, store2, gh, lookupExecID(t, store2, ctx, key))
		if rec.State != idempotency.StateCommitted {
			t.Fatalf("expected COMMITTED after reconcile, got %s", rec.State)
		}
		// The observation written before the crash must be durable.
		if rec.ProviderObservedAt == nil {
			t.Error("provider observation was not durable across the finalize crash")
		}
		if fake.count() != 1 {
			t.Errorf("expected 1 issue, got %d", fake.count())
		}
	})

	t.Run("refused_before_request_no_effect", func(t *testing.T) {
		fake, store, _, _, _, key := newSetup(t, "normal")
		// Point the handler at a dead port — connection refused before
		// any bytes are written is a provable no-effect failure.
		dead := NewGitHubIssueHandler("http://127.0.0.1:1", "test-token")
		dead.SetHTTPClient(&http.Client{Timeout: 200 * time.Millisecond})
		multi := NewMultiHandler(map[string]Handler{"github": dead})
		exec2 := NewDispatchExecutor(multi, store)
		resp := githubDispatch(t, exec2, key)
		if resp.Status != StatusFailed {
			t.Fatalf("expected definitive FAILED for refused connection, got %s: %s", resp.Status, resp.Error)
		}
		rec := lookupRecord(t, store, ctx, key)
		if rec.State != idempotency.StateFailed {
			t.Errorf("expected FAILED, got %s", rec.State)
		}
		if fake.count() != 0 {
			t.Errorf("no issue should exist, got %d", fake.count())
		}
	})
}

func lookupExecID(t *testing.T, store *idempotency.Store, ctx context.Context, key string) string {
	t.Helper()
	rec := lookupRecord(t, store, ctx, key)
	return rec.ExecutionID
}

func lookupRecord(t *testing.T, store *idempotency.Store, ctx context.Context, key string) *idempotency.Record {
	t.Helper()
	rec, err := store.LookupByKey(ctx, "alice@example.com", "github.issue.create", key)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	return rec
}
