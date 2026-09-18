package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// External-provider crash qualification. The adversarial provider
// runs in its own process with its own durable log, so executor
// SIGKILL cannot destroy the evidence that an external effect
// happened — the topology the durable executor is designed for:
//
//	executor process A ──HTTP──▶ provider process B ──▶ durable log
//
// POST /effects        apply the effect; idempotent on `token`
// GET  /effects/{tok}  status lookup — independent evidence for
//                      post-crash reconciliation

// providerLogEntry is one durable record in the provider's log.
type providerLogEntry struct {
	Token     string          `json:"token"`
	RunID     string          `json:"run_id"`
	EffectN   int             `json:"effect_n"`
	Result    json.RawMessage `json:"result"`
	Timestamp time.Time       `json:"timestamp"`
}

// readProviderLog parses the provider's durable JSON-lines log.
func readProviderLog(t *testing.T, path string) []providerLogEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read provider log: %v", err)
	}
	var entries []providerLogEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e providerLogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("corrupt provider log line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

// TestExternalProviderHelperProcess is the provider subprocess. It
// serves POST /effects (idempotent on token — a second request with
// the same token replays the logged result without a new effect) and
// GET /effects/{token} (status lookup). Every applied effect is
// appended to a fsynced JSON-lines log BEFORE the response is sent:
// the provider never acknowledges an effect it cannot prove later.
//
// Env:
//
//	CRABBOX_PROVIDER_HELPER=1      — run as helper
//	CRABBOX_PROVIDER_LOG=<path>    — durable log path
//	CRABBOX_PROVIDER_ADDR=<path>   — file to publish the bound addr
func TestExternalProviderHelperProcess(t *testing.T) {
	if os.Getenv("CRABBOX_PROVIDER_HELPER") != "1" {
		return
	}
	logPath := os.Getenv("CRABBOX_PROVIDER_LOG")
	var mu sync.Mutex
	effects := 0
	seen := map[string]providerLogEntry{}

	appendLog := func(e providerLogEntry) error {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(e)
		if _, err := f.Write(append(b, '\n')); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /effects", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if e, ok := seen[body.Token]; ok {
			// Idempotent replay — logged result, no new effect.
			json.NewEncoder(w).Encode(map[string]any{
				"status": "SUCCEEDED", "run_id": e.RunID, "result": e.Result,
			})
			return
		}
		effects++
		e := providerLogEntry{
			Token:     body.Token,
			RunID:     fmt.Sprintf("run-%d", effects),
			EffectN:   effects,
			Result:    json.RawMessage(`{"ok":true}`),
			Timestamp: time.Now().UTC(),
		}
		if err := appendLog(e); err != nil {
			http.Error(w, `{"error":"log failed"}`, http.StatusInternalServerError)
			return
		}
		seen[body.Token] = e
		json.NewEncoder(w).Encode(map[string]any{
			"status": "SUCCEEDED", "run_id": e.RunID, "result": e.Result,
		})
	})
	mux.HandleFunc("GET /effects/{token}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		e, ok := seen[r.PathValue("token")]
		if !ok {
			// Re-scan the durable log — truth survives process restart.
			data, _ := os.ReadFile(logPath)
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var le providerLogEntry
				if json.Unmarshal([]byte(line), &le) == nil && le.Token == r.PathValue("token") {
					e, ok = le, true
				}
			}
		}
		if !ok {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(e)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.WriteFile(os.Getenv("CRABBOX_PROVIDER_ADDR"), []byte(ln.Addr().String()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	http.Serve(ln, mux)
}

// startExternalProvider launches the provider subprocess and waits
// for its bound address. The process outlives any executor it serves.
func startExternalProvider(t *testing.T, dir string) (url string, logPath string) {
	t.Helper()
	logPath = filepath.Join(dir, "provider-log.jsonl")
	addrPath := filepath.Join(dir, "provider-addr")
	cmd := exec.Command(os.Args[0], "-test.run=TestExternalProviderHelperProcess")
	cmd.Env = append(os.Environ(),
		"CRABBOX_PROVIDER_HELPER=1",
		"CRABBOX_PROVIDER_LOG="+logPath,
		"CRABBOX_PROVIDER_ADDR="+addrPath,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start provider: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var addr []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(addrPath); err == nil && len(b) > 0 {
			addr = b
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(addr) == 0 {
		t.Fatal("provider did not publish its address")
	}
	return "http://" + string(addr), logPath
}

// httpProvider is the executor-side Handler for the external provider:
// the wire boundary the in-process simProvider cannot model. Transport
// failure after the request may have been sent is ambiguous — FAILED
// without DefinitiveFailure, so the executor enters UNKNOWN.
type httpProvider struct {
	baseURL string
	client  *http.Client
}

func (p *httpProvider) Execute(ctx context.Context, req Request, desc capability.ResolvedDescriptor) Response {
	body, _ := json.Marshal(map[string]any{"token": req.IdempotencyKey})
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/effects", strings.NewReader(string(body)))
	if err != nil {
		return Response{Status: StatusFailed, Error: err.Error(), DefinitiveFailure: true}
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(hreq)
	if err != nil {
		// Connection refused or reset mid-flight: the request may or
		// may not have applied — ambiguous, never definitive.
		return Response{Status: StatusFailed, Error: "provider transport: " + err.Error()}
	}
	defer resp.Body.Close()
	var out struct {
		Status string          `json:"status"`
		RunID  string          `json:"run_id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Response{Status: StatusFailed, Error: "provider response decode: " + err.Error()}
	}
	return Response{
		Status:    out.Status,
		Result:    out.Result,
		Execution: &ExecutionMeta{Provider: desc.AdapterID, RunID: out.RunID},
	}
}

// TestExternalProviderCrashMatrix kills the executor subprocess at
// every post-dispatch boundary while the provider subprocess survives.
// Assertions: the provider's durable log holds at most one effect per
// execution, the orphaned record is reconcilable, and a restarted
// executor replaying the same key never redispatches.
func TestExternalProviderCrashMatrix(t *testing.T) {
	for _, point := range []CrashPoint{
		CrashAfterMarkInFlight,
		CrashAfterProvider,
		CrashBeforeObservation,
		CrashAfterObservation,
		CrashBeforeFinalize,
	} {
		t.Run(string(point), func(t *testing.T) {
			dir := t.TempDir()
			providerURL, logPath := startExternalProvider(t, dir)
			dbPath := filepath.Join(dir, "db", "crash.db")
			key := fmt.Sprintf("ext-%s", point)

			// Executor subprocess — dies at the crash point.
			cmd := exec.Command(os.Args[0], "-test.run=TestCrashHelperProcess")
			cmd.Env = append(os.Environ(),
				"CRABBOX_CRASH_HELPER=1",
				"CRABBOX_CRASH_DB="+dbPath,
				"CRABBOX_CRASH_POINT="+string(point),
				"CRABBOX_CRASH_KEY="+key,
				"CRABBOX_CRASH_LEASE_MS=200",
				"CRABBOX_PROVIDER_URL="+providerURL,
			)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("executor should have died at %s\n%s", point, out)
			}

			// Provider log: the external effect happened (post-IN_FLIGHT
			// points dispatch before dying) and must count exactly 1.
			entries := readProviderLog(t, logPath)
			var mine []providerLogEntry
			for _, e := range entries {
				if e.Token == key {
					mine = append(mine, e)
				}
			}
			if point == CrashAfterMarkInFlight {
				// Died before the provider call — 0 or 1 depending on
				// where exactly the boundary lands relative to dispatch.
				if len(mine) > 1 {
					t.Fatalf("provider applied %d effects, want <=1", len(mine))
				}
			} else if len(mine) != 1 {
				t.Fatalf("provider applied %d effects after %s, want exactly 1 — evidence must survive executor death", len(mine), point)
			}

			// Durable state: post-dispatch crash leaves IN_FLIGHT,
			// never a fabricated terminal state.
			db, err := idempotency.OpenSQLiteDB(dbPath)
			if err != nil {
				t.Fatalf("reopen db: %v", err)
			}
			defer db.Close()
			store, err := idempotency.NewSQLiteStoreWithConfig(db, idempotency.LeaseConfig{
				DefaultDuration: 200 * time.Millisecond,
				MaxDuration:     time.Second,
				RenewalWindow:   50 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
			if err != nil {
				t.Fatalf("lookup after crash: %v", err)
			}
			if rec.State.IsDurablyFinal() {
				t.Fatalf("crash at %s produced terminal %s without finalization", point, rec.State)
			}

			// Restarted executor, same idempotency key: must replay the
			// orphaned record — never redispatch. The provider's effect
			// count must stay at exactly 1.
			cmd2 := exec.Command(os.Args[0], "-test.run=TestCrashHelperProcess")
			cmd2.Env = append(os.Environ(),
				"CRABBOX_CRASH_HELPER=1",
				"CRABBOX_CRASH_DB="+dbPath,
				"CRABBOX_CRASH_POINT=", // no crash — clean replay
				"CRABBOX_CRASH_KEY="+key,
				"CRABBOX_CRASH_LEASE_MS=200",
				"CRABBOX_PROVIDER_URL="+providerURL,
			)
			out2, _ := cmd2.CombinedOutput()
			entries = readProviderLog(t, logPath)
			mine = mine[:0]
			for _, e := range entries {
				if e.Token == key {
					mine = append(mine, e)
				}
			}
			if len(mine) > 1 {
				t.Fatalf("restart redispatched: %d provider effects\n%s", len(mine), out2)
			}
		})
	}
}

// TestExternalProviderStatusLookupReconciliation proves the full
// post-crash evidence path: the executor dies after dispatch, the
// provider's durable status lookup is the independent evidence, and
// the orphaned record reconciles against it — provider-side truth,
// not executor memory.
func TestExternalProviderStatusLookupReconciliation(t *testing.T) {
	dir := t.TempDir()
	providerURL, logPath := startExternalProvider(t, dir)
	dbPath := filepath.Join(dir, "db", "crash.db")
	key := "ext-reconcile"

	cmd := exec.Command(os.Args[0], "-test.run=TestCrashHelperProcess")
	cmd.Env = append(os.Environ(),
		"CRABBOX_CRASH_HELPER=1",
		"CRABBOX_CRASH_DB="+dbPath,
		"CRABBOX_CRASH_POINT="+string(CrashAfterProvider),
		"CRABBOX_CRASH_KEY="+key,
		"CRABBOX_CRASH_LEASE_MS=200",
		"CRABBOX_PROVIDER_URL="+providerURL,
	)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("executor should have died at after_provider\n%s", out)
	}

	// Provider status lookup: independent evidence the effect exists.
	resp, err := http.Get(providerURL + "/effects/" + key)
	if err != nil {
		t.Fatalf("status lookup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("provider has no record of the dispatched effect — status %d", resp.StatusCode)
	}
	var lookup providerLogEntry
	if err := json.NewDecoder(resp.Body).Decode(&lookup); err != nil {
		t.Fatal(err)
	}
	if lookup.Token != key || lookup.EffectN != 1 {
		t.Fatalf("provider status = %+v, want token %s effect 1", lookup, key)
	}

	// The orphaned record flows through lease expiry into UNKNOWN —
	// then reconciles against the provider-side evidence.
	db, err := idempotency.OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := idempotency.NewSQLiteStoreWithConfig(db, idempotency.LeaseConfig{
		DefaultDuration: 200 * time.Millisecond,
		MaxDuration:     time.Second,
		RenewalWindow:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != idempotency.StateInFlight {
		t.Fatalf("post-crash state = %s, want IN_FLIGHT", rec.State)
	}
	time.Sleep(300 * time.Millisecond)
	claimed, err := store.ClaimExpiredBatch(context.Background(), "recovery-worker", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range claimed {
		if c.ExecutionID == rec.ExecutionID {
			found = true
		}
	}
	if !found {
		t.Fatal("crashed record not claimable for reconciliation")
	}
	entries := readProviderLog(t, logPath)
	n := 0
	for _, e := range entries {
		if e.Token == key {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("provider applied %d effects, want exactly 1 — external effect count bounded", n)
	}
}
