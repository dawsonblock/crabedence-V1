package history

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func openContent(t *testing.T) *ContentStore {
	t.Helper()
	cs, err := OpenContentStore(filepath.Join(t.TempDir(), "cs"))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// A Claude Code transcript ingests as per-message conversation
// events with speaker, tool uses, and file references preserved —
// and appending to the transcript re-ingests only the new tail.
func TestIngestConversationsIncremental(t *testing.T) {
	s := openStore(t)
	cs := openContent(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	line1 := `{"type":"user","uuid":"m1","sessionId":"sess-1","timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":[{"type":"text","text":"the custody ack is forged"}]}}`
	line2 := `{"type":"assistant","uuid":"m2","sessionId":"sess-1","timestamp":"2026-01-01T00:01:00Z","message":{"role":"assistant","content":[{"type":"text","text":"checking"},{"type":"tool_use","name":"Read","input":{"file_path":"/src/ack.go"}}]}}`
	if err := os.WriteFile(path, []byte(line1+"\n"+line2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := s.IngestConversations(dir, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("ingested %d messages, want 2", n)
	}
	evs, err := s.Query(QueryOpts{Kinds: []string{KindConversation}})
	if err != nil {
		t.Fatal(err)
	}
	var assistant conversationRecord
	for _, e := range evs {
		var rec conversationRecord
		if err := json.Unmarshal(e.Payload, &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Role == "assistant" {
			assistant = rec
		}
	}
	if assistant.Role != "assistant" {
		t.Fatal("assistant message not ingested")
	}
	if len(assistant.ToolUses) != 1 || assistant.ToolUses[0] != "Read" {
		t.Fatalf("tool uses lost: %+v", assistant.ToolUses)
	}
	if len(assistant.FileRefs) != 1 || assistant.FileRefs[0] != "/src/ack.go" {
		t.Fatalf("file refs lost: %+v", assistant.FileRefs)
	}
	if assistant.SourceSHA == "" || !cs.Has(assistant.SourceSHA) {
		t.Fatal("transcript bytes not held in the content store")
	}
	// Append a third message — re-ingest adds only the tail.
	line3 := `{"type":"user","uuid":"m3","sessionId":"sess-1","timestamp":"2026-01-01T00:02:00Z","message":{"role":"user","content":[{"type":"text","text":"verify the signature"}]}}`
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(f, line3)
	f.Close()
	n, err = s.IngestConversations(dir, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("incremental ingest added %d messages, want 1", n)
	}
}

// A torn transcript refuses whole — guessing at corrupt rows would
// fabricate the reasoning record.
func TestIngestConversationsRefusesTorn(t *testing.T) {
	s := openStore(t)
	cs := openContent(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.jsonl"),
		[]byte(`{"role":"user","content":"ok"}`+"\n"+`{"role":"assistant"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestConversations(dir, cs); err == nil {
		t.Fatal("torn transcript ingested without refusal")
	}
}

// Traces ingest per action; a record naming no tool cannot say what
// was done and refuses.
func TestIngestTraces(t *testing.T) {
	s := openStore(t)
	cs := openContent(t)
	dir := t.TempDir()
	lines := `{"ts":"2026-01-01T00:00:00Z","run":"r-1","tool":"go_test","args":{"pkg":"./x"},"output":{"ok":true},"ok":true,"duration_ms":1200}` + "\n" +
		`{"ts":"2026-01-01T00:00:01Z","run":"r-1","tool":"edit","args":{"file":"a.go"}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "run.jsonl"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := s.IngestTraces(dir, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("ingested %d traces, want 2", n)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.jsonl"),
		[]byte(`{"ts":"2026-01-01T00:00:00Z","note":"no tool"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestTraces(filepath.Join(dir, "empty.jsonl"), cs); err == nil {
		t.Fatal("trace record naming no tool ingested")
	}
}

// The archive's detected identity comes from the content, never the
// filename: a misnamed archive is recorded as a conflict, both
// identities preserved.
func TestIngestArchiveDetectsConflict(t *testing.T) {
	s := openStore(t)
	cs := openContent(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "release-0.54.0-rc.7.1.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("VERSION")
	w.Write([]byte("0.54.0-rc.7.3\n"))
	w2, _ := zw.Create("src/main.go")
	w2.Write([]byte("package main\n"))
	zw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := s.IngestArchive(path, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ingested %d archives, want 1", n)
	}
	evs, err := s.Query(QueryOpts{Kinds: []string{KindArchive}})
	if err != nil {
		t.Fatal(err)
	}
	var rec archiveRecord
	if err := json.Unmarshal(evs[0].Payload, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.DetectedVersion != "0.54.0-rc.7.3" {
		t.Fatalf("detected version %q, want rc.7.3 from VERSION", rec.DetectedVersion)
	}
	if rec.SuppliedVersion != "0.54.0-rc.7.1" {
		t.Fatalf("supplied version %q, want rc.7.1 from the filename", rec.SuppliedVersion)
	}
	if !rec.VersionConflict {
		t.Fatal("filename/content version disagreement not recorded as conflict")
	}
	if rec.MemberCount != 2 || rec.ManifestSHA256 == "" {
		t.Fatalf("manifest incomplete: %+v", rec)
	}
}

// Experiment records ingest keyed on content — a corrected record
// lands beside the original, never rewriting it.
func TestIngestExperiments(t *testing.T) {
	s := openStore(t)
	cs := openContent(t)
	dir := t.TempDir()
	exp := `{"experiment_id":"exp-1","hypothesis":"smaller arm suffices","arm":"small","outcome":"pass","metrics":{"wall_ms":900},"timestamp":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "exp-1.json"), []byte(exp), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := s.IngestExperiments(dir, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ingested %d experiments, want 1", n)
	}
	// A corrected record (different outcome) is a second observation.
	exp2 := `{"experiment_id":"exp-1","hypothesis":"smaller arm suffices","arm":"small","outcome":"fail","timestamp":"2026-01-02T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "exp-1.json"), []byte(exp2), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err = s.IngestExperiments(dir, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("corrected experiment not preserved as new observation: %d", n)
	}
	evs, _ := s.Query(QueryOpts{Kinds: []string{KindExperiment}, Subject: "exp-1"})
	if len(evs) != 2 {
		t.Fatalf("expected both observations kept, got %d", len(evs))
	}
}

// Content objects that fail their own address are findings — held
// evidence is verified, not assumed.
func TestContentStoreDetectsTamper(t *testing.T) {
	cs := openContent(t)
	sha, _, err := cs.Put(bytes.NewReader([]byte("held bytes")))
	if err != nil {
		t.Fatal(err)
	}
	if findings := cs.Verify(); len(findings) != 0 {
		t.Fatalf("clean store reported: %v", findings)
	}
	// Rewrite the object under its address — the store must refuse
	// to serve it and verify must report it.
	if err := os.WriteFile(filepath.Join(cs.dir, sha), []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Read(sha); err == nil {
		t.Fatal("tampered object served by digest")
	}
	if findings := cs.Verify(); len(findings) == 0 {
		t.Fatal("tampered object passed verify")
	}
}
