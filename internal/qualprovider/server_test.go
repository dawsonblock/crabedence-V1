package qualprovider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func postOperation(t *testing.T, url, token, payload, fault string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/operations",
		strings.NewReader(fmt.Sprintf(`{"token":%q,"payload":%s}`, token, payload)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if fault != "" {
		req.Header.Set("X-Qualification-Fault", fault)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /operations: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestOperationIdempotentReplay(t *testing.T) {
	s, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp1, body1 := postOperation(t, srv.URL, "tok-1", `{"operation":"a"}`, "")
	if resp1.StatusCode != http.StatusOK || body1["status"] != "COMMITTED" {
		t.Fatalf("first op: %d %v", resp1.StatusCode, body1)
	}
	resp2, body2 := postOperation(t, srv.URL, "tok-1", `{"operation":"a"}`, "")
	if resp2.StatusCode != http.StatusOK || body2["operation_id"] != body1["operation_id"] {
		t.Fatalf("replay returned a different operation: %v vs %v", body2, body1)
	}

	// The durable ledger must show exactly one execution.
	var stats struct {
		Operations int `json:"operations"`
		Executions int `json:"executions"`
	}
	resp, err := http.Get(srv.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&stats)
	resp.Body.Close()
	if stats.Operations != 1 || stats.Executions != 1 {
		t.Fatalf("stats = %+v, want 1 operation / 1 execution", stats)
	}
}

func TestOperationTokenCollisionRejected(t *testing.T) {
	s, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	postOperation(t, srv.URL, "tok-1", `{"operation":"a"}`, "")
	resp, _ := postOperation(t, srv.URL, "tok-1", `{"operation":"different"}`, "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for token/payload collision, got %d", resp.StatusCode)
	}
}

func TestLedgerSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	srv1 := httptest.NewServer(s1.Handler())
	postOperation(t, srv1.URL, "tok-persist", `{"operation":"a"}`, "")
	srv1.Close()

	// A new Server over the same directory — provider truth must
	// survive process restart.
	s2, err := New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewServer(s2.Handler())
	defer srv2.Close()

	resp, err := http.Get(srv2.URL + "/operations/tok-persist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var op Operation
	if err := json.NewDecoder(resp.Body).Decode(&op); err != nil {
		t.Fatal(err)
	}
	if op.Token != "tok-persist" || op.Status != "COMMITTED" {
		t.Fatalf("reloaded operation = %+v", op)
	}
}

func TestFaultInjection(t *testing.T) {
	s, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// FAIL_BEFORE_ACCEPT: nothing is durably accepted.
	resp, _ := postOperation(t, srv.URL, "tok-fail", `{"operation":"a"}`, FaultFailBeforeAccept)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	lookup, err := http.Get(srv.URL + "/operations/tok-fail")
	if err != nil {
		t.Fatal(err)
	}
	lookup.Body.Close()
	if lookup.StatusCode != http.StatusNotFound {
		t.Fatalf("rejected op must not exist in the ledger, got %d", lookup.StatusCode)
	}

	// DEFINITIVE_REJECTION: durable REJECTED record, zero executions.
	resp, body := postOperation(t, srv.URL, "tok-rej", `{"operation":"a"}`, FaultDefinitiveReject)
	if resp.StatusCode != http.StatusOK || body["status"] != "REJECTED" {
		t.Fatalf("expected REJECTED, got %d %v", resp.StatusCode, body)
	}
	var stats struct {
		Executions int `json:"executions"`
	}
	sresp, _ := http.Get(srv.URL + "/stats")
	json.NewDecoder(sresp.Body).Decode(&stats)
	sresp.Body.Close()
	if stats.Executions != 0 {
		t.Fatalf("rejected op must count 0 executions, got %d", stats.Executions)
	}
}

func TestEffectsLogSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	srv1 := httptest.NewServer(s1.Handler())
	resp, err := http.Post(srv1.URL+"/effects", "application/json", strings.NewReader(`{"token":"fx-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	json.NewDecoder(resp.Body).Decode(&first)
	resp.Body.Close()
	srv1.Close()

	// A new Server over the same directory must keep the effect
	// idempotent: a replayed token replays the logged result instead
	// of appending a second effect.
	s2, err := New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewServer(s2.Handler())
	defer srv2.Close()
	resp2, err := http.Post(srv2.URL+"/effects", "application/json", strings.NewReader(`{"token":"fx-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	var replay map[string]any
	json.NewDecoder(resp2.Body).Decode(&replay)
	resp2.Body.Close()
	if replay["run_id"] != first["run_id"] {
		t.Fatalf("replayed effect minted a new run after restart: %v vs %v", replay, first)
	}

	data, err := os.ReadFile(s2.LogPath())
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; n != 1 {
		t.Fatalf("effects log holds %d entries after replay, want 1", n)
	}
}

func TestArtifactEndpoint(t *testing.T) {
	s, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	_, body := postOperation(t, srv.URL, "tok-art", `{"operation":"a"}`, "")
	resp, err := http.Get(srv.URL + "/artifacts/" + body["artifact_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("artifact fetch: %d", resp.StatusCode)
	}
	var artifact map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&artifact); err != nil {
		t.Fatalf("artifact is not the recorded JSON: %v", err)
	}
	if artifact["operation_id"] != body["operation_id"] {
		t.Fatalf("artifact %v does not match operation %v", artifact, body)
	}
}
