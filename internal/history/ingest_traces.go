package history

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// traceRecord is the canonical payload a trace event commits to:
// one agent action — the tool invoked, digests of its input and
// output (full bytes live in the content store), its duration, and
// the run it belongs to. Digests, not payloads, so memory carries
// what was done without duplicating megabytes of tool output.
type traceRecord struct {
	Run          string `json:"run"`           // session/run identity the action belongs to
	Tool         string `json:"tool"`          // tool name as recorded
	Action       string `json:"action"`        // action kind if distinct from tool
	InputSHA256  string `json:"input_sha256"`  // digest of the recorded input
	OutputSHA256 string `json:"output_sha256"` // digest of the recorded output/result
	DurationMS   int64  `json:"duration_ms"`
	Ok           *bool  `json:"ok,omitempty"` // recorded success, when the trace asserts one
	SourceSHA    string `json:"source_sha256"`
	Line         int    `json:"line"`
	Timestamp    string `json:"timestamp"`
}

// IngestTraces reads agent action traces — JSONL files where each
// line records one tool call — into trace events. Accepted shapes
// are lenient on field names (tool|name|action, ts|timestamp,
// run|session, duration_ms|elapsed_ms) but strict on structure: a
// line that is not valid JSON, or an object naming no tool, refuses
// the ingest — a trace with invented structure is not a trace.
// Trace bytes are committed to the content store first.
func (s *Store) IngestTraces(path string, cs *ContentStore) (int, error) {
	var files []string
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return 0, err
		}
		for _, e := range entries {
			if !e.IsDir() && (filepath.Ext(e.Name()) == ".jsonl" || filepath.Ext(e.Name()) == ".json") {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	var events []*Event
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return 0, err
		}
		srcSHA, _, err := cs.Put(fh)
		fh.Close()
		if err != nil {
			return 0, fmt.Errorf("store trace %s: %w", f, err)
		}
		raw, err := cs.Read(srcSHA)
		if err != nil {
			return 0, err
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		line := 0
		run := filepath.Base(f)
		for sc.Scan() {
			line++
			b := sc.Bytes()
			if len(b) == 0 {
				continue
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(b, &obj); err != nil {
				return 0, fmt.Errorf("trace %s line %d: %w", f, line, err)
			}
			tool := firstField(obj, "tool", "name", "tool_name")
			if tool == "" {
				return 0, fmt.Errorf("trace %s line %d names no tool — the record cannot say what was done", f, line)
			}
			rec := traceRecord{
				Tool:      tool,
				Action:    firstField(obj, "action", "op"),
				SourceSHA: srcSHA,
				Line:      line,
				Timestamp: firstField(obj, "timestamp", "ts", "time"),
			}
			if r := firstField(obj, "run", "session", "session_id", "run_id"); r != "" {
				run = r
			}
			rec.Run = run
			rec.DurationMS = intField(obj, "duration_ms", "elapsed_ms", "duration")
			for k, dst := range map[string]*string{
				"input":  &rec.InputSHA256,
				"args":   &rec.InputSHA256,
				"output": &rec.OutputSHA256,
				"result": &rec.OutputSHA256,
			} {
				if v, ok := obj[k]; ok && *dst == "" {
					sum := sha256.Sum256(v)
					*dst = hex.EncodeToString(sum[:])
				}
			}
			if v, ok := obj["ok"]; ok {
				var b bool
				if json.Unmarshal(v, &b) == nil {
					rec.Ok = &b
				}
			} else if v, ok := obj["success"]; ok {
				var b bool
				if json.Unmarshal(v, &b) == nil {
					rec.Ok = &b
				}
			}
			payload, err := json.Marshal(rec)
			if err != nil {
				return 0, err
			}
			sum := sha256.Sum256(payload)
			events = append(events, &Event{
				DedupeKey:   "trace:" + hex.EncodeToString(sum[:]),
				Kind:        KindTrace,
				Subject:     run,
				Correlation: srcSHA,
				Source:      "traces:" + f,
				OccurredAt:  receiptTime(rec.Timestamp),
				Payload:     payload,
			})
		}
		if err := sc.Err(); err != nil {
			return 0, err
		}
	}
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}

// firstField returns the first non-empty string among aliases.
func firstField(obj map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := strField(obj, k); s != "" {
			return s
		}
	}
	return ""
}

// intField reads an integer-ish field leniently.
func intField(obj map[string]json.RawMessage, keys ...string) int64 {
	for _, k := range keys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		var n int64
		if json.Unmarshal(v, &n) == nil {
			return n
		}
		var f float64
		if json.Unmarshal(v, &f) == nil {
			return int64(f)
		}
	}
	return 0
}
