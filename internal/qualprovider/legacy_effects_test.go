package qualprovider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ─── Legacy /effects durability contract (F-002) ─────────────────────
//
// The legacy effects log is the provider's acknowledged-effect memory:
// every POST /effects record is fsynced before the response is sent, so
// a replayed token must replay the acknowledged response after any
// restart — and durable state the server cannot fully interpret must
// refuse startup rather than silently become an empty map.
//
// These tests encode the strict contract. On the permissive
// implementation (best-effort line scanning at startup and on GET)
// they fail: malformed lines are skipped, a missing read is an empty
// map, and a token's replay can mint a second durable effect.

// effectLogLine serializes one effects-log record exactly as the
// provider's commit path writes it.
func effectLogLine(t *testing.T, token string, n int) string {
	t.Helper()
	b, err := json.Marshal(LogEntry{
		Token:     token,
		RunID:     fmt.Sprintf("run-%d", n),
		EffectN:   n,
		Result:    json.RawMessage(`{"ok":true}`),
		Timestamp: time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeEffectsLog(t *testing.T, dir string, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "provider-log.jsonl"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func postEffect(t *testing.T, url, token string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url+"/effects", "application/json",
		strings.NewReader(fmt.Sprintf(`{"token":%q}`, token)))
	if err != nil {
		t.Fatalf("POST /effects: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func effectLogEntries(t *testing.T, dir string) []LogEntry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "provider-log.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []LogEntry
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("effects log line is not valid JSON: %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func getEffectStatus(t *testing.T, url, token string) int {
	t.Helper()
	resp, err := http.Get(url + "/effects/" + token)
	if err != nil {
		t.Fatalf("GET /effects/%s: %v", token, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestLegacyEffectsCorruptedStartupRejects proves startup refuses any
// effects log it cannot fully interpret — the acknowledged-state
// contract is only meaningful if every byte of it survives validation.
func TestLegacyEffectsCorruptedStartupRejects(t *testing.T) {
	valid1 := effectLogLine(t, "tok-a", 1)
	valid2 := effectLogLine(t, "tok-b", 2)
	torn := `{"token":"tok-b","run_id":"run-2","effect_n":2,"result":{"ok":true},"timestamp":"2026` // never completed, never acknowledged
	dupToken := effectLogLine(t, "tok-a", 2)
	dupN := effectLogLine(t, "tok-c", 1)
	backwards := effectLogLine(t, "tok-c", 1)
	mismatched := `{"token":"tok-m","run_id":"run-7","effect_n":3,"result":{"ok":true},"timestamp":"2026-10-09T08:00:00Z"}`
	missingToken := `{"run_id":"run-1","effect_n":1,"result":{"ok":true},"timestamp":"2026-10-09T08:00:00Z"}`
	zeroN := `{"token":"tok-z","run_id":"run-0","effect_n":0,"result":{"ok":true},"timestamp":"2026-10-09T08:00:00Z"}`
	badTime := `{"token":"tok-t","run_id":"run-1","effect_n":1,"result":{"ok":true},"timestamp":"not-a-time"}`
	nullResult := `{"token":"tok-r","run_id":"run-1","effect_n":1,"result":null,"timestamp":"2026-10-09T08:00:00Z"}`
	unknownField := `{"token":"tok-u","run_id":"run-1","effect_n":1,"result":{"ok":true},"timestamp":"2026-10-09T08:00:00Z","surprise":true}`

	cases := map[string]string{
		"invalid JSON mid-file":        valid1 + "\n" + "not json at all\n" + valid2 + "\n",
		"invalid JSON tail":            valid1 + "\n" + "not json at all\n",
		"torn tail":                    valid1 + "\n" + torn,
		"blank line mid-file":          valid1 + "\n" + "\n" + valid2 + "\n",
		"non-record JSON":              `{"hello":"world"}` + "\n",
		"missing token":                missingToken + "\n",
		"zero effect number":           zeroN + "\n",
		"run/effect mismatch":          mismatched + "\n",
		"invalid timestamp":            badTime + "\n",
		"null result":                  nullResult + "\n",
		"unknown field":                unknownField + "\n",
		"duplicate token":              valid1 + "\n" + dupToken + "\n",
		"duplicate effect number":      valid1 + "\n" + dupN + "\n",
		"non-increasing effect number": valid2 + "\n" + backwards + "\n",
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			dir := privateStateDir(t)
			writeEffectsLog(t, dir, contents)
			if _, err := New(dir, ""); err == nil {
				t.Fatalf("startup with a corrupt effects log (%s) must refuse, not serve from a partial map", name)
			}
		})
	}

	t.Run("symlinked log", func(t *testing.T) {
		dir := privateStateDir(t)
		real := filepath.Join(t.TempDir(), "real-log.jsonl")
		if err := os.WriteFile(real, []byte(valid1+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(dir, "provider-log.jsonl")); err != nil {
			t.Fatal(err)
		}
		if _, err := New(dir, ""); err == nil {
			t.Fatal("a symlinked effects log must refuse startup — the durable state path is never followed")
		}
	})

	t.Run("non-regular log", func(t *testing.T) {
		dir := privateStateDir(t)
		if err := os.Mkdir(filepath.Join(dir, "provider-log.jsonl"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := New(dir, ""); err == nil {
			t.Fatal("a non-regular effects log must refuse startup")
		}
	})

	t.Run("unreadable log", func(t *testing.T) {
		dir := privateStateDir(t)
		writeEffectsLog(t, dir, valid1+"\n")
		if _, err := newServer(dir, "", &faultFS{inner: osDurableFS{}, target: "read", at: 1, pathSuffix: "provider-log.jsonl", err: syscall.EIO}); err == nil {
			t.Fatal("an unreadable effects log must refuse startup — an EIO cannot become an empty acknowledged-state map")
		}
	})

	// Positive control: a clean first initialization and a clean log
	// both start.
	t.Run("absent log is first init", func(t *testing.T) {
		if _, err := New(privateStateDir(t), ""); err != nil {
			t.Fatalf("first init: %v", err)
		}
	})
	t.Run("clean log starts", func(t *testing.T) {
		dir := privateStateDir(t)
		writeEffectsLog(t, dir, valid1+"\n"+valid2+"\n")
		if _, err := New(dir, ""); err != nil {
			t.Fatalf("clean log refused: %v", err)
		}
	})
}

// TestLegacyEffectsAcknowledgedReplayAfterCrash proves an acknowledged
// effect survives every restart the durable contract covers: a clean
// restart replays the recorded response; a restart over damaged state
// fails closed instead of forgetting the acknowledgement and minting a
// second effect.
func TestLegacyEffectsAcknowledgedReplayAfterCrash(t *testing.T) {
	// The clean path — green on every correct implementation and the
	// permanent regression for acknowledged replay.
	t.Run("clean restart replays the recorded response", func(t *testing.T) {
		dir := privateStateDir(t)
		_, srv1 := newTestServer(t, dir)
		resp, body := postEffect(t, srv1.URL, "tok-ack")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first effect: %d (%s)", resp.StatusCode, body)
		}
		var first map[string]any
		if err := json.Unmarshal(body, &first); err != nil {
			t.Fatalf("decode: %v", err)
		}
		srv1.Close()

		_, srv2 := newTestServer(t, dir)
		resp2, body2 := postEffect(t, srv2.URL, "tok-ack")
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("replay after restart: %d (%s)", resp2.StatusCode, body2)
		}
		var replay map[string]any
		if err := json.Unmarshal(body2, &replay); err != nil {
			t.Fatal(err)
		}
		if replay["run_id"] != first["run_id"] {
			t.Fatalf("replay minted a new run: %v vs acknowledged %v", replay["run_id"], first["run_id"])
		}
		if entries := effectLogEntries(t, dir); len(entries) != 1 {
			t.Fatalf("the acknowledged effect must stay exactly one durable record, got %d", len(entries))
		}
	})

	// The crash boundary: a process died mid-append of a LATER effect,
	// leaving the acknowledged record followed by a torn line. The only
	// safe answers are refusing startup (fail closed) or an explicit,
	// operator-visible recovery — never silently dropping bytes from an
	// acknowledged-state ledger.
	t.Run("torn tail after an acknowledged record fails closed", func(t *testing.T) {
		dir := privateStateDir(t)
		_, srv1 := newTestServer(t, dir)
		resp, body := postEffect(t, srv1.URL, "tok-ack")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first effect: %d (%s)", resp.StatusCode, body)
		}
		var first map[string]any
		if err := json.Unmarshal(body, &first); err != nil {
			t.Fatal(err)
		}
		srv1.Close()

		// The crash boundary: a second append was torn mid-write — bytes
		// were written, the record was never completed or acknowledged.
		f, err := os.OpenFile(filepath.Join(dir, "provider-log.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(`{"token":"tok-b","run_id":"run-2","effect_n":2,"result":{"ok":true},"timesta`); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := New(dir, ""); err == nil {
			t.Fatal("a torn durable tail after an acknowledged record must refuse startup — the ledger cannot decide whether the torn effect happened, so it must not guess")
		}
	})

	// The forgetting path the strict contract exists for: a restart
	// that cannot read the acknowledged ledger must refuse — not open
	// with an empty map that re-acknowledges the same token as a
	// second durable effect.
	t.Run("unreadable acknowledged ledger cannot mint a second effect", func(t *testing.T) {
		dir := privateStateDir(t)
		_, srv1 := newTestServer(t, dir)
		resp, body := postEffect(t, srv1.URL, "tok-ack")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first effect: %d (%s)", resp.StatusCode, body)
		}
		srv1.Close()

		// Restart where reading the log fails (EIO — a damaged device).
		s2, err := newServer(dir, "", &faultFS{inner: osDurableFS{}, target: "read", at: 1, pathSuffix: "provider-log.jsonl", err: syscall.EIO})
		if err != nil {
			return // strict behavior: startup refuses unreadable acknowledged state
		}
		srv2 := httptest.NewServer(s2.Handler())
		defer srv2.Close()

		resp2, _ := postEffect(t, srv2.URL, "tok-ack")
		resp2.Body.Close()
		if entries := effectLogEntries(t, dir); len(entries) != 1 {
			t.Fatalf("a restart that could not read the acknowledged ledger minted a second effect record (%d entries) — the acknowledgement was forgotten", len(entries))
		}
	})
}

// TestLegacyEffectsGetRejectsCorruptState proves the status lookup is
// served only from fully validated acknowledged state: a record that
// appears on disk without passing through the server's commit path is
// never presented as truth, and a lookup of a missing token can never
// be a scan artifact of corrupt bytes.
func TestLegacyEffectsGetRejectsCorruptState(t *testing.T) {
	dir := privateStateDir(t)
	_, srv := newTestServer(t, dir)

	resp, body := postEffect(t, srv.URL, "tok-real")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acknowledged effect: %d (%s)", resp.StatusCode, body)
	}

	// A well-formed record appended out-of-band — the server never
	// committed it, so it is not acknowledged state whatever the bytes
	// say. A lookup that rescans the log would serve it as truth.
	logPath := filepath.Join(dir, "provider-log.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(effectLogLine(t, "tok-ghost", 7) + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	code := getEffectStatus(t, srv.URL, "tok-ghost")
	if code == http.StatusOK {
		t.Fatal("GET /effects served a record the provider never acknowledged — an out-of-band write must not become provider truth")
	}
	if code != http.StatusNotFound && code != http.StatusServiceUnavailable {
		t.Fatalf("unacknowledged on-disk record: status = %d, want a definitive 404 or a fail-closed 503", code)
	}

	// The validated acknowledged record is still the truth.
	if code := getEffectStatus(t, srv.URL, "tok-real"); code != http.StatusOK {
		t.Fatalf("acknowledged record after out-of-band append: %d, want 200", code)
	}
	// A token that was never acknowledged is a definitive negative.
	if code := getEffectStatus(t, srv.URL, "tok-never"); code != http.StatusNotFound {
		t.Fatalf("never-acknowledged token: %d, want 404", code)
	}

	// Corrupt the log entirely out-of-band: the in-memory validated
	// state is unaffected, and no lookup may be answered by parsing
	// those bytes.
	if err := os.WriteFile(logPath, []byte("garbage not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := getEffectStatus(t, srv.URL, "tok-real"); code != http.StatusOK {
		t.Fatalf("acknowledged record with corrupt on-disk state: %d, want the validated state (200)", code)
	}
	if code := getEffectStatus(t, srv.URL, "tok-never"); code == http.StatusOK {
		t.Fatal("corrupt on-disk state produced a lookup hit")
	}
}

// TestLegacyEffectsConcurrentSameToken proves the token check and the
// durable commit are one atomic step: every concurrent request with the
// same token gets the same acknowledged response, and the log holds
// exactly one record — no second effect, no divergent acknowledgement.
func TestLegacyEffectsConcurrentSameToken(t *testing.T) {
	dir := privateStateDir(t)
	_, srv := newTestServer(t, dir)

	const callers = 16
	runIDs := make(chan string, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, body := postEffect(t, srv.URL, "tok-race")
			if resp.StatusCode != http.StatusOK {
				t.Errorf("concurrent effect: %d (%s)", resp.StatusCode, body)
				return
			}
			var ack map[string]any
			if err := json.Unmarshal(body, &ack); err != nil {
				t.Errorf("decode: %v", err)
				return
			}
			runIDs <- fmt.Sprint(ack["run_id"])
		}()
	}
	wg.Wait()
	close(runIDs)

	var first string
	for id := range runIDs {
		if first == "" {
			first = id
		} else if id != first {
			t.Fatalf("same token acknowledged with two different runs: %q and %q", first, id)
		}
	}
	if entries := effectLogEntries(t, dir); len(entries) != 1 {
		t.Fatalf("concurrent same-token requests minted %d durable records, want exactly 1", len(entries))
	}
}

// TestLegacyEffectsSequentialAcks proves acknowledged-state accounting
// holds at the boundary, not just for one record: one hundred distinct
// effects commit durably, and after restart every token replays its own
// acknowledgement with no reordering, loss, or renumbering.
func TestLegacyEffectsSequentialAcks(t *testing.T) {
	dir := privateStateDir(t)
	_, srv1 := newTestServer(t, dir)

	const total = 100
	ackRunID := map[string]string{}
	for i := 1; i <= total; i++ {
		token := fmt.Sprintf("tok-seq-%d", i)
		resp, body := postEffect(t, srv1.URL, token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("effect %d: %d (%s)", i, resp.StatusCode, body)
		}
		var ack map[string]any
		if err := json.Unmarshal(body, &ack); err != nil {
			t.Fatal(err)
		}
		ackRunID[token] = fmt.Sprint(ack["run_id"])
	}
	srv1.Close()

	_, srv2 := newTestServer(t, dir)
	for i := 1; i <= total; i++ {
		token := fmt.Sprintf("tok-seq-%d", i)
		resp, body := postEffect(t, srv2.URL, token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("replay of effect %d after restart: %d (%s)", i, resp.StatusCode, body)
		}
		var ack map[string]any
		if err := json.Unmarshal(body, &ack); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(ack["run_id"]); got != ackRunID[token] {
			t.Fatalf("effect %d replayed as run %v, acknowledged as %v", i, got, ackRunID[token])
		}
	}
	entries := effectLogEntries(t, dir)
	if len(entries) != total {
		t.Fatalf("durable log holds %d records, want %d", len(entries), total)
	}
	for i, e := range entries {
		if e.EffectN != i+1 {
			t.Fatalf("record %d has effect number %d — the durable sequence must be gap-free and ordered", i+1, e.EffectN)
		}
	}
}

// TestLegacyEffectsDurableWriteFailureFailsClosed proves a failed
// append is never claimed as success and its ambiguous durable result
// is never quietly carried forward: the request fails as
// recovery-required, acknowledged truth keeps answering, new mutations
// stop, lookups for unacknowledged tokens fail closed — and the torn
// bytes the partial write left behind refuse the next startup, so the
// ambiguity is resolved by an operator, not by a guess.
func TestLegacyEffectsDurableWriteFailureFailsClosed(t *testing.T) {
	dir := privateStateDir(t)
	_, srv := newTestServer(t, dir)

	// One cleanly acknowledged effect, to prove acknowledged truth
	// keeps answering while the provider refuses new mutations.
	resp, body := postEffect(t, srv.URL, "tok-acked")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acknowledged effect: %d (%s)", resp.StatusCode, body)
	}
	srv.Close()

	// Restart on a filesystem whose second append to the effects log
	// leaves torn bytes then fails — a real partial write.
	fs := &faultFS{inner: osDurableFS{}, target: "append", at: 1, pathSuffix: "provider-log.jsonl", err: syscall.ENOSPC}
	s2, err := newServer(dir, "", fs)
	if err != nil {
		t.Fatalf("restart over a clean acknowledged log: %v", err)
	}
	srv2 := httptest.NewServer(s2.Handler())
	defer srv2.Close()

	resp, body = postEffect(t, srv2.URL, "tok-torn")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("failed durable write must not claim success: %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), ErrRecoveryRequired) {
		t.Fatalf("failed durable write must surface %s, got %s", ErrRecoveryRequired, body)
	}

	// A new token is refused — the provider no longer accepts mutations
	// whose durable result it cannot prove.
	resp, body = postEffect(t, srv2.URL, "tok-after-failure")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("mutation after ambiguous write: %d, want 503 (%s)", resp.StatusCode, body)
	}

	// Lookups: acknowledged truth answers, unacknowledged state fails
	// closed rather than guessing.
	if code := getEffectStatus(t, srv2.URL, "tok-acked"); code != http.StatusOK {
		t.Fatalf("acknowledged record while degraded: %d, want 200", code)
	}
	if code := getEffectStatus(t, srv2.URL, "tok-torn"); code != http.StatusServiceUnavailable {
		t.Fatalf("lookup of ambiguous token while degraded: %d, want fail-closed 503", code)
	}
	if code := getEffectStatus(t, srv2.URL, "tok-never"); code != http.StatusServiceUnavailable {
		t.Fatalf("lookup of unknown token while degraded: %d, want fail-closed 503", code)
	}
	srv2.Close()

	// The torn bytes are durable ambiguity: the next startup refuses
	// until an operator reconciles them — they are never truncated.
	if _, err := New(dir, ""); err == nil {
		t.Fatal("restart over the torn effects log must refuse startup — ambiguous bytes are operator-reconciled, never auto-dropped")
	}
	data, err := os.ReadFile(filepath.Join(dir, "provider-log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"token":"tok-torn"`) || !strings.HasSuffix(strings.TrimSpace(string(data)), `"timesta`) {
		// The partial write's bytes are still on disk for diagnosis.
		t.Logf("torn log contents: %q", data)
	}
}
