package qualprovider

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func newTestServer(t *testing.T, dir string) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(dir, "")
	if err != nil {
		t.Fatalf("New(%s): %v", dir, err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, srv
}

// postRaw posts one /operations body with an optional fault header and
// returns the response with its body read.
func postRaw(t *testing.T, url, body, fault string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/operations", strings.NewReader(body))
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
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

// readLedger parses every record of the operation ledger. It fails the
// test on a line that is not valid JSON — the ledger must always be a
// complete sequence of records.
func readLedger(t *testing.T, dir string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "operations.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("ledger line is not valid JSON: %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func writeLedger(t *testing.T, dir string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "operations.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// legacyLedgerLine builds one pre-two-phase ledger record exactly as the
// original provider wrote it, and returns the artifact bytes the record
// commits to. Recovery must read these records and repair the artifact
// state without inventing a second execution.
func legacyLedgerLine(token string, seq int, payload string) (string, []byte) {
	opID := fmt.Sprintf("op-%d", seq)
	artifact := []byte(fmt.Sprintf(`{"operation_id":%q,"token":%q,"outcome":"COMMITTED"}`, opID, token))
	artifactSum := sha256.Sum256(artifact)
	payloadSum := sha256.Sum256([]byte(payload))
	rec := map[string]any{
		"token":           token,
		"payload_digest":  fmt.Sprintf("%x", payloadSum),
		"operation_id":    opID,
		"artifact_id":     fmt.Sprintf("art-%d", seq),
		"artifact_digest": fmt.Sprintf("%x", artifactSum),
		"status":          "COMMITTED",
		"result":          map[string]any{"operation_id": opID},
		"executions":      1,
		"timestamp":       "2026-10-01T00:00:00Z",
	}
	b, err := json.Marshal(rec)
	if err != nil {
		panic(err)
	}
	return string(b), artifact
}

func getJSON(t *testing.T, url string, out any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", url, err)
		}
	}
	return resp.StatusCode
}

func getBytes(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type providerStats struct {
	Operations int `json:"operations"`
	Executions int `json:"executions"`
}

func getStats(t *testing.T, url string) providerStats {
	t.Helper()
	var stats providerStats
	if code := getJSON(t, url+"/stats", &stats); code != http.StatusOK {
		t.Fatalf("GET /stats: %d", code)
	}
	return stats
}

// TestCrashAfterPreparedRecoversToSingleCommit proves the crash window
// between the durable acceptance record and the artifact/commit records
// is recoverable: the response is never sent without a durable commit,
// and a restart completes the commit exactly once.
func TestCrashAfterPreparedRecoversToSingleCommit(t *testing.T) {
	dir := privateStateDir(t)
	_, srv1 := newTestServer(t, dir)

	resp, body := postRaw(t, srv1.URL, `{"token":"tok-prep","payload":{"operation":"a"}}`, FaultFailAfterPrepared)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("crash after PREPARED: status = %d (%s), want 500 — no acknowledgement may be sent before COMMITTED is durable", resp.StatusCode, body)
	}
	srv1.Close()

	// Restart over the same directory: recovery completes the commit.
	_, srv2 := newTestServer(t, dir)
	var op Operation
	if code := getJSON(t, srv2.URL+"/operations/tok-prep", &op); code != http.StatusOK {
		t.Fatalf("recovered operation lookup: %d, want 200", code)
	}
	if op.Status != "COMMITTED" || op.Executions != 1 {
		t.Fatalf("recovered operation = %+v, want one COMMITTED execution", op)
	}
	artifact := getBytes(t, srv2.URL+"/artifacts/"+op.ArtifactID)
	if sum := fmt.Sprintf("%x", sha256.Sum256(artifact)); sum != op.ArtifactDigest {
		t.Fatal("recovered artifact does not match the recorded digest")
	}

	// A retry of the same token replays the same operation.
	resp2, body2 := postRaw(t, srv2.URL, `{"token":"tok-prep","payload":{"operation":"a"}}`, "")
	var replay map[string]any
	if err := json.Unmarshal(body2, &replay); err != nil {
		t.Fatalf("decode replay: %v (%s)", err, body2)
	}
	if resp2.StatusCode != http.StatusOK || replay["operation_id"] != op.OperationID {
		t.Fatalf("retry after recovery = %d %v, want replay of %s", resp2.StatusCode, replay, op.OperationID)
	}
	if stats := getStats(t, srv2.URL); stats.Operations != 1 || stats.Executions != 1 {
		t.Fatalf("stats = %+v, want 1 operation / 1 execution", stats)
	}
}

// TestCrashAfterArtifactRecoversWithoutRewritingEvidence proves the
// window after the artifact write is recoverable and that recovery
// verifies the existing bytes instead of rewriting them.
func TestCrashAfterArtifactRecoversWithoutRewritingEvidence(t *testing.T) {
	dir := privateStateDir(t)
	_, srv1 := newTestServer(t, dir)

	resp, body := postRaw(t, srv1.URL, `{"token":"tok-art-phase","payload":{"operation":"a"}}`, FaultFailAfterArtifact)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("crash after artifact: status = %d (%s), want 500", resp.StatusCode, body)
	}
	srv1.Close()

	records := readLedger(t, dir)
	if len(records) != 1 {
		t.Fatalf("ledger holds %d records after the artifact phase, want the single PREPARED record", len(records))
	}
	artifactID, _ := records[0]["artifact_id"].(string)
	before, err := os.ReadFile(filepath.Join(dir, "artifacts", artifactID))
	if err != nil {
		t.Fatalf("artifact must be durable before the fault: %v", err)
	}

	_, srv2 := newTestServer(t, dir)
	var op Operation
	if code := getJSON(t, srv2.URL+"/operations/tok-art-phase", &op); code != http.StatusOK || op.Status != "COMMITTED" {
		t.Fatalf("recovered lookup = %d %+v, want COMMITTED", code, op)
	}
	after, err := os.ReadFile(filepath.Join(dir, "artifacts", artifactID))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("recovery rewrote an intact artifact instead of verifying it")
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256(after)); sum != op.ArtifactDigest {
		t.Fatal("recovered artifact does not match the recorded digest")
	}
}

// TestCrashAfterCommittedReplaysWithoutDuplication proves a crash after
// the commit record produces neither a duplicate commit record nor a
// second execution on retry.
func TestCrashAfterCommittedReplaysWithoutDuplication(t *testing.T) {
	dir := privateStateDir(t)
	_, srv1 := newTestServer(t, dir)

	resp, body := postRaw(t, srv1.URL, `{"token":"tok-commit","payload":{"operation":"a"}}`, FaultFailAfterCommitted)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("crash after COMMITTED: status = %d (%s), want 500", resp.StatusCode, body)
	}
	srv1.Close()

	_, srv2 := newTestServer(t, dir)
	var op Operation
	if code := getJSON(t, srv2.URL+"/operations/tok-commit", &op); code != http.StatusOK || op.Status != "COMMITTED" {
		t.Fatalf("recovered lookup = %d %+v, want COMMITTED", code, op)
	}

	resp2, body2 := postRaw(t, srv2.URL, `{"token":"tok-commit","payload":{"operation":"a"}}`, "")
	var replay map[string]any
	if err := json.Unmarshal(body2, &replay); err != nil {
		t.Fatalf("decode replay: %v (%s)", err, body2)
	}
	if resp2.StatusCode != http.StatusOK || replay["operation_id"] != op.OperationID {
		t.Fatalf("retry = %d %v, want replay of %s", resp2.StatusCode, replay, op.OperationID)
	}

	// Exactly one PREPARED and one COMMITTED record for the token.
	prepared, committed := 0, 0
	for _, rec := range readLedger(t, dir) {
		if rec["token"] != "tok-commit" {
			continue
		}
		switch rec["phase"] {
		case "PREPARED":
			prepared++
		case "COMMITTED":
			committed++
		}
	}
	if prepared != 1 || committed != 1 {
		t.Fatalf("ledger holds %d PREPARED / %d COMMITTED records for the token, want 1/1", prepared, committed)
	}
}

// TestStartupRejectsCorruptLedgerLine proves a ledger corrupted outside
// the crash-torn tail is a startup error, not a silently skipped line.
func TestStartupRejectsCorruptLedgerLine(t *testing.T) {
	dir := privateStateDir(t)
	first, _ := legacyLedgerLine("tok-a", 1, `{"operation":"a"}`)
	third, _ := legacyLedgerLine("tok-b", 3, `{"operation":"b"}`)
	writeLedger(t, dir, first, "not json at all", third)

	if _, err := New(dir, ""); err == nil {
		t.Fatal("a corrupt mid-file ledger line must refuse startup, not be skipped")
	}
}

// TestStartupRejectsCompleteButInvalidLedgerLine proves a line that
// parses as JSON but is not an operation record is refused even in the
// tail position: only a torn (incomplete) tail is recoverable.
func TestStartupRejectsCompleteButInvalidLedgerLine(t *testing.T) {
	dir := privateStateDir(t)
	writeLedger(t, dir, `{"hello":"world"}`)

	if _, err := New(dir, ""); err == nil {
		t.Fatal("a complete JSON line that is not an operation record must refuse startup")
	}
}

// TestStartupRecoversTornTailLine proves the one documented recovery:
// a crash-torn final line (never acknowledged, since the append never
// completed) is dropped so the ledger stays a sequence of complete
// records, and the token it half-names executes exactly once on retry.
func TestStartupRecoversTornTailLine(t *testing.T) {
	dir := privateStateDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	first, _ := legacyLedgerLine("tok-tail", 1, `{"operation":"a"}`)
	// A torn append: valid JSON prefix, no newline, truncated mid-record.
	torn := `{"token":"tok-torn","payload_digest":"deadbeef`
	content := first + "\n" + torn
	if err := os.WriteFile(filepath.Join(dir, "operations.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, srv := newTestServer(t, dir)

	// The torn fragment must be gone from the ledger.
	data, err := os.ReadFile(filepath.Join(dir, "operations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "tok-torn") {
		t.Fatalf("the torn tail record must be dropped; ledger still holds it:\n%s", data)
	}
	if recs := readLedger(t, dir); len(recs) == 0 {
		t.Fatal("the complete record before the torn tail must survive")
	}

	// The half-named token was never acknowledged: a retry executes once.
	resp, body := postRaw(t, srv.URL, `{"token":"tok-torn","payload":{"operation":"a"}}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry of the torn token: %d (%s), want 200", resp.StatusCode, body)
	}
	if stats := getStats(t, srv.URL); stats.Executions != 2 {
		t.Fatalf("executions = %d, want 2 (the surviving legacy op + the retried one)", stats.Executions)
	}
}

// TestStartupRejectsTokenPayloadConflict proves a token bound to two
// different payloads is a startup error: the ledger cannot decide which
// execution is the real one, so it must refuse rather than guess.
func TestStartupRejectsTokenPayloadConflict(t *testing.T) {
	dir := privateStateDir(t)
	first, _ := legacyLedgerLine("tok-conflict", 1, `{"operation":"a"}`)
	second, _ := legacyLedgerLine("tok-conflict", 2, `{"operation":"different"}`)
	writeLedger(t, dir, first, second)

	if _, err := New(dir, ""); err == nil {
		t.Fatal("a token bound to two payloads must refuse startup")
	}
}

// TestStartupRepairsLegacyMissingArtifact proves the historical
// ledger-before-artifact order is repaired, not inherited: the artifact
// is reconstructed from the durable record, verified against the
// recorded digest, and only then served.
func TestStartupRepairsLegacyMissingArtifact(t *testing.T) {
	dir := privateStateDir(t)
	line, artifact := legacyLedgerLine("tok-legacy", 1, `{"operation":"a"}`)
	writeLedger(t, dir, line)

	_, srv := newTestServer(t, dir)

	var op Operation
	if code := getJSON(t, srv.URL+"/operations/tok-legacy", &op); code != http.StatusOK || op.Status != "COMMITTED" {
		t.Fatalf("legacy operation lookup = %d %+v, want COMMITTED", code, op)
	}
	got := getBytes(t, srv.URL+"/artifacts/art-1")
	if string(got) != string(artifact) {
		t.Fatalf("reconstructed artifact = %q, want %q", got, artifact)
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256(got)); sum != op.ArtifactDigest {
		t.Fatal("reconstructed artifact does not match the recorded digest")
	}
	committed := 0
	for _, rec := range readLedger(t, dir) {
		if rec["token"] == "tok-legacy" && rec["phase"] == "COMMITTED" {
			committed++
		}
	}
	if committed != 1 {
		t.Fatalf("repair must record exactly one COMMITTED marker, got %d", committed)
	}
}

// TestStartupRejectsArtifactDigestMismatch proves an artifact whose
// bytes do not match the recorded digest refuses startup: corruption
// must never be overwritten or served.
func TestStartupRejectsArtifactDigestMismatch(t *testing.T) {
	dir := privateStateDir(t)
	line, _ := legacyLedgerLine("tok-mismatch", 1, `{"operation":"a"}`)
	writeLedger(t, dir, line)
	if err := os.WriteFile(filepath.Join(dir, "artifacts", "art-1"), []byte("corrupted bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := New(dir, ""); err == nil {
		t.Fatal("an artifact that does not match its recorded digest must refuse startup")
	}
}

// TestStartupRejectsSymlinkedArtifact proves artifact paths never
// follow links: a symlink where an artifact belongs is refused, not
// resolved to whatever it points at.
func TestStartupRejectsSymlinkedArtifact(t *testing.T) {
	dir := privateStateDir(t)
	line, artifact := legacyLedgerLine("tok-link", 1, `{"operation":"a"}`)
	writeLedger(t, dir, line)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "artifacts", "art-1")); err != nil {
		t.Fatal(err)
	}

	if _, err := New(dir, ""); err == nil {
		t.Fatal("a symlinked artifact must refuse startup")
	}
}

// TestArtifactFetchRefusesSymlink proves the fetch path itself refuses
// a link planted after startup instead of serving the link target.
func TestArtifactFetchRefusesSymlink(t *testing.T) {
	dir := privateStateDir(t)
	_, srv := newTestServer(t, dir)

	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("do-not-serve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "artifacts", "art-9")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.URL + "/artifacts/art-9")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || strings.Contains(string(data), "do-not-serve") {
		t.Fatalf("artifact fetch followed a symlink: %d %q", resp.StatusCode, data)
	}

	// Paths outside the artifact namespace are refused outright.
	for _, id := range []string{"..", "operations.jsonl", "art-1/../../operations.jsonl"} {
		resp, err := http.Get(srv.URL + "/artifacts/" + id)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || strings.Contains(string(body), "payload_digest") {
			t.Fatalf("GET /artifacts/%s escaped the artifact namespace: %d %q", id, resp.StatusCode, body)
		}
	}
}

// TestStartupPreservesOrphanArtifactsWithoutIDCollision proves an
// artifact file with no ledger record (a legacy crash leftover) is
// preserved and never overwritten: new operation IDs continue past it.
func TestStartupPreservesOrphanArtifactsWithoutIDCollision(t *testing.T) {
	dir := privateStateDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(dir, "artifacts", "art-1")
	if err := os.WriteFile(orphan, []byte("orphan evidence"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, srv := newTestServer(t, dir)
	resp, body := postRaw(t, srv.URL, `{"token":"tok-new","payload":{"operation":"a"}}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post: %d (%s)", resp.StatusCode, body)
	}
	var op map[string]any
	if err := json.Unmarshal(body, &op); err != nil {
		t.Fatal(err)
	}
	if op["operation_id"] == "op-1" || op["artifact_id"] == "art-1" {
		t.Fatalf("a new operation reused an existing artifact identity: %v", op)
	}
	after, err := os.ReadFile(orphan)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "orphan evidence" {
		t.Fatalf("the orphan artifact was overwritten: %q", after)
	}
}

// TestStartupRemovesStaleTempFiles proves scratch files from an
// interrupted atomic write are cleaned up so they cannot be mistaken
// for artifacts.
func TestStartupRemovesStaleTempFiles(t *testing.T) {
	dir := privateStateDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "artifacts", ".tmp-art-9-leftover")
	if err := os.WriteFile(stale, []byte("partial write"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, srv := newTestServer(t, dir)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temp file survived startup: %v", err)
	}
	if stats := getStats(t, srv.URL); stats.Operations != 0 {
		t.Fatalf("stats = %+v, want none", stats)
	}
}

// TestOperationBodyLimit proves an oversized request body is refused
// before any durable state is touched.
func TestOperationBodyLimit(t *testing.T) {
	dir := privateStateDir(t)
	_, srv := newTestServer(t, dir)

	big := strings.Repeat("x", 2<<20)
	resp, body := postRaw(t, srv.URL, fmt.Sprintf(`{"token":"tok-big","payload":{"operation":%q}}`, big), "")
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status = %d (%s), want 413", resp.StatusCode, body)
	}
	if stats := getStats(t, srv.URL); stats.Operations != 0 || stats.Executions != 0 {
		t.Fatalf("oversized body created durable state: %+v", stats)
	}
}

// faultFS fails one named durable primitive on its Nth call with a
// synthetic errno, delegating everything else to the real filesystem. A
// failed append models a real torn write: the bytes a partial write left
// behind are written before the error is returned.
type faultFS struct {
	inner  durableFS
	target string
	at     int
	calls  int
	err    error
	// pathSuffix, when non-empty, scopes the injection to calls whose
	// path ends with it — an operation-ledger append and an effects-log
	// append reach the same primitive, so targeting one ledger's call
	// needs a path match, not just a call count.
	pathSuffix string
}

func (f *faultFS) hit(step, path string) bool {
	if step != f.target {
		return false
	}
	if f.pathSuffix != "" && !strings.HasSuffix(path, f.pathSuffix) {
		return false
	}
	f.calls++
	return f.calls == f.at
}

func (f *faultFS) AppendLine(path string, payload []byte) error {
	if f.hit("append", path) {
		if len(payload) > 1 {
			_ = f.inner.AppendLine(path, payload[:len(payload)/2])
		}
		return f.err
	}
	return f.inner.AppendLine(path, payload)
}

func (f *faultFS) ReadFile(path string) ([]byte, error) {
	if f.hit("read", path) {
		return nil, f.err
	}
	return f.inner.ReadFile(path)
}

func (f *faultFS) WriteFileAtomic(path string, data []byte) error {
	if f.hit("rewrite", path) {
		return f.err
	}
	return f.inner.WriteFileAtomic(path, data)
}

func (f *faultFS) WriteTemp(dir, name string, data []byte) (string, error) {
	if f.hit("write-temp", filepath.Join(dir, name)) {
		return "", f.err
	}
	return f.inner.WriteTemp(dir, name, data)
}

func (f *faultFS) Rename(oldpath, newpath string) error {
	if f.hit("rename", newpath) {
		return f.err
	}
	return f.inner.Rename(oldpath, newpath)
}

func (f *faultFS) SyncDir(dir string) error {
	if f.hit("sync-dir", dir) {
		return f.err
	}
	return f.inner.SyncDir(dir)
}

func (f *faultFS) ReadArtifact(dir, name string) ([]byte, error) {
	return f.inner.ReadArtifact(dir, name)
}

func (f *faultFS) ReadDirNames(dir string) ([]string, error) { return f.inner.ReadDirNames(dir) }
func (f *faultFS) Remove(path string) error                  { return f.inner.Remove(path) }
func (f *faultFS) Lstat(path string) (os.FileInfo, error)    { return f.inner.Lstat(path) }

// TestInjectedDurableFailureAtEachStep injects an ENOSPC/EIO at every
// durable step of the operation commit — the acceptance append, the
// artifact temp write, the rename, the parent-directory fsync, and the
// commit append — and proves each one yields the same guarantee: the
// request is not acknowledged, a restart recovers deterministically,
// and the token executes exactly once.
func TestInjectedDurableFailureAtEachStep(t *testing.T) {
	steps := []struct {
		name     string
		target   string
		at       int
		accepted bool
	}{
		// The acceptance append failed: nothing durable was promised,
		// so the token is unknown after restart and executes once on
		// retry.
		{"prepared-append", "append", 1, false},
		{"artifact-temp-write", "write-temp", 1, true},
		{"artifact-rename", "rename", 1, true},
		{"artifact-dir-fsync", "sync-dir", 1, true},
		{"committed-append", "append", 2, true},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			dir := privateStateDir(t)
			s1, err := newServer(dir, "", &faultFS{inner: osDurableFS{}, target: step.target, at: step.at, err: syscall.ENOSPC})
			if err != nil {
				t.Fatalf("newServer: %v", err)
			}
			srv1 := httptest.NewServer(s1.Handler())
			resp, body := postRaw(t, srv1.URL, `{"token":"tok-step","payload":{"operation":"a"}}`, "")
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("injected %s failure: status = %d (%s), want 500", step.name, resp.StatusCode, body)
			}
			srv1.Close()

			// Restart over the same directory with a healthy filesystem.
			_, srv2 := newTestServer(t, dir)

			var op Operation
			code := getJSON(t, srv2.URL+"/operations/tok-step", &op)
			if step.accepted {
				if code != http.StatusOK || op.Status != "COMMITTED" || op.Executions != 1 {
					t.Fatalf("recovered lookup = %d %+v, want one COMMITTED operation", code, op)
				}
				artifact := getBytes(t, srv2.URL+"/artifacts/"+op.ArtifactID)
				if sum := fmt.Sprintf("%x", sha256.Sum256(artifact)); sum != op.ArtifactDigest {
					t.Fatal("recovered artifact does not match the recorded digest")
				}
			} else if code != http.StatusNotFound {
				t.Fatalf("lookup after an unacknowledged attempt = %d, want 404", code)
			}

			// The retry either replays the recovered operation or
			// executes the unacknowledged one — never both.
			resp2, body2 := postRaw(t, srv2.URL, `{"token":"tok-step","payload":{"operation":"a"}}`, "")
			if resp2.StatusCode != http.StatusOK {
				t.Fatalf("retry after recovery: %d (%s)", resp2.StatusCode, body2)
			}
			var replay map[string]any
			if err := json.Unmarshal(body2, &replay); err != nil {
				t.Fatalf("decode retry: %v (%s)", err, body2)
			}
			if step.accepted && replay["operation_id"] != op.OperationID {
				t.Fatalf("retry minted a new operation %v, want replay of %s", replay["operation_id"], op.OperationID)
			}
			if stats := getStats(t, srv2.URL); stats.Operations != 1 || stats.Executions != 1 {
				t.Fatalf("stats = %+v, want 1 operation / 1 execution", stats)
			}
			committed := 0
			for _, rec := range readLedger(t, dir) {
				if rec["token"] == "tok-step" && rec["phase"] == "COMMITTED" {
					committed++
				}
			}
			if committed != 1 {
				t.Fatalf("COMMITTED markers = %d, want exactly 1", committed)
			}
		})
	}
}

// TestRecoveryRewriteFailureRefusesStartup proves the torn-tail repair
// is itself fail-closed: if the rewrite cannot be made durable, startup
// refuses rather than serving a ledger it could not repair.
func TestRecoveryRewriteFailureRefusesStartup(t *testing.T) {
	dir := privateStateDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := `{"token":"a"}` + "\n" + `{"token":"torn`
	if err := os.WriteFile(filepath.Join(dir, "operations.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newServer(dir, "", &faultFS{inner: osDurableFS{}, target: "rewrite", at: 1, err: syscall.EIO}); err == nil {
		t.Fatal("a failed torn-tail rewrite must refuse startup")
	}
}
