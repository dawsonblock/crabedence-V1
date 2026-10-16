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

// conversationRecord is the canonical payload a conversation event
// commits to: one message's speaker, text, time, and the tool calls
// and file references it made. The message is recorded as observed —
// memory keeps the reasoning record intact, including the parts that
// were wrong.
type conversationRecord struct {
	Format    string   `json:"format"`              // detected transcript format
	Role      string   `json:"role"`                // speaker attribution, verbatim
	SessionID string   `json:"session_id"`          // transcript's own session identity
	MessageID string   `json:"message_id"`          // transcript's own message identity
	Text      string   `json:"text"`                // the message body
	ToolUses  []string `json:"tool_uses,omitempty"` // tool names invoked in this message
	FileRefs  []string `json:"file_refs,omitempty"` // paths tool calls touched
	Timestamp string   `json:"timestamp"`
	SourceSHA string   `json:"source_sha256"` // transcript bytes in the content store
	Line      int      `json:"line"`          // 1-based position in the transcript
	Supplied  string   `json:"supplied_name"` // the file's own name — a claim, not identity
}

// IngestConversations reads development transcripts — the reasoning
// record — into conversation events. Path may be one .jsonl/.json
// transcript or a directory of them. Transcript bytes are committed
// to the content store so every message event links to held evidence;
// each message dedupes on its own content digest, so appending to a
// live transcript and re-ingesting adds only the new tail.
//
// Recognized shapes, detected per line:
//   - Claude Code transcript rows: {"type","timestamp","sessionId",
//     "message":{"role","content":[{type,text|tool_use|tool_result}]}}
//   - generic message rows: {"role","content","timestamp"|"ts"}
//   - a JSON array of either, in a .json file.
//
// Lines that are not messages (summaries, markers) are skipped;
// a line that is not valid JSON refuses the ingest — a transcript
// with torn rows is evidence of corruption, not material to guess at.
func (s *Store) IngestConversations(path string, cs *ContentStore) (int, error) {
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
			if e.IsDir() {
				continue
			}
			ext := filepath.Ext(e.Name())
			if ext == ".jsonl" || ext == ".json" {
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
		srcSHA, size, err := cs.Put(fh)
		fh.Close()
		if err != nil {
			return 0, fmt.Errorf("store transcript %s: %w", f, err)
		}
		if size == 0 {
			continue
		}
		raw, err := cs.Read(srcSHA)
		if err != nil {
			return 0, err
		}
		msgs, err := parseTranscript(raw)
		if err != nil {
			return 0, fmt.Errorf("transcript %s: %w", f, err)
		}
		session := filepath.Base(f)
		for i, m := range msgs {
			if m.Session != "" {
				session = m.Session
			}
			rec := conversationRecord{
				Format:    m.Format,
				Role:      m.Role,
				SessionID: m.Session,
				MessageID: m.ID,
				Text:      m.Text,
				ToolUses:  m.ToolUses,
				FileRefs:  m.FileRefs,
				Timestamp: m.Timestamp,
				SourceSHA: srcSHA,
				Line:      i + 1,
				Supplied:  filepath.Base(f),
			}
			payload, err := json.Marshal(rec)
			if err != nil {
				return 0, err
			}
			// The dedupe key commits to the message's position and
			// content, NOT the transcript's whole digest: appending
			// to a live transcript re-keys nothing that was already
			// seen, while a rewritten file produces different message
			// digests at the same positions — both kept, provenance
			// intact. The transcript's own bytes stay bound through
			// source_sha256 and the correlation key.
			msgKey, _ := json.Marshal(m)
			msgSHA := sha256.Sum256(msgKey)
			key := fmt.Sprintf("conv:%s:%d:%s", f, i+1, hex.EncodeToString(msgSHA[:])[:16])
			events = append(events, &Event{
				DedupeKey:   key,
				Kind:        KindConversation,
				Subject:     session,
				Correlation: srcSHA,
				Source:      "conversations:" + f,
				OccurredAt:  receiptTime(m.Timestamp),
				Payload:     payload,
			})
		}
	}
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}

// transcriptMessage is one normalized message — the superset shape
// every detected format maps into.
type transcriptMessage struct {
	Format    string
	Role      string
	Session   string
	ID        string
	Text      string
	ToolUses  []string
	FileRefs  []string
	Timestamp string
}

// parseTranscript normalizes raw transcript bytes: a JSON array first,
// else line-delimited objects.
func parseTranscript(raw []byte) ([]*transcriptMessage, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		var out []*transcriptMessage
		for _, el := range arr {
			if m := parseMessageRow(el); m != nil {
				out = append(out, m)
			}
		}
		return out, nil
	}
	var out []*transcriptMessage
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		if !json.Valid(b) {
			return nil, fmt.Errorf("line %d is not valid JSON — a torn transcript is refused whole", line)
		}
		if m := parseMessageRow(b); m != nil {
			out = append(out, m)
		}
	}
	return out, sc.Err()
}

// parseMessageRow detects the row's shape and normalizes it, or
// returns nil for rows that carry no message.
func parseMessageRow(raw json.RawMessage) *transcriptMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	// Claude Code transcript shape: top-level type + message object.
	if msgRaw, ok := obj["message"]; ok {
		var msg struct {
			Role    string            `json:"role"`
			Content []json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(msgRaw, &msg); err == nil && msg.Role != "" {
			m := &transcriptMessage{Format: "claude-code", Role: msg.Role}
			if v, ok := obj["type"]; ok {
				var t string
				if json.Unmarshal(v, &t) == nil {
					m.Format = "claude-code/" + t
				}
			}
			m.Session = strField(obj, "sessionId")
			m.ID = strField(obj, "uuid")
			m.Timestamp = strField(obj, "timestamp")
			for _, c := range msg.Content {
				parseContentPart(c, m)
			}
			return m
		}
	}
	// Generic message row.
	var gen struct {
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		Timestamp string          `json:"timestamp"`
		Ts        string          `json:"ts"`
		Session   string          `json:"session"`
	}
	if err := json.Unmarshal(raw, &gen); err == nil && gen.Role != "" {
		m := &transcriptMessage{Format: "generic", Role: gen.Role, Session: gen.Session}
		m.Timestamp = gen.Timestamp
		if m.Timestamp == "" {
			m.Timestamp = gen.Ts
		}
		var text string
		if json.Unmarshal(gen.Content, &text) == nil {
			m.Text = text
		} else {
			var parts []json.RawMessage
			if json.Unmarshal(gen.Content, &parts) == nil {
				for _, c := range parts {
					parseContentPart(c, m)
				}
			}
		}
		return m
	}
	return nil
}

// parseContentPart folds one content element into the message: text
// accumulates; tool_use contributes its name and touched paths;
// tool_result contributes its file references.
func parseContentPart(c json.RawMessage, m *transcriptMessage) {
	var part map[string]json.RawMessage
	if err := json.Unmarshal(c, &part); err != nil {
		return
	}
	if t := strField(part, "type"); t == "tool_use" {
		if name := strField(part, "name"); name != "" {
			m.ToolUses = append(m.ToolUses, name)
		}
		if in, ok := part["input"]; ok {
			var input map[string]json.RawMessage
			if json.Unmarshal(in, &input) == nil {
				for _, k := range []string{"file_path", "path", "filePath"} {
					if p := strField(input, k); p != "" {
						m.FileRefs = append(m.FileRefs, p)
					}
				}
			}
		}
		return
	}
	if txt := strField(part, "text"); txt != "" {
		if m.Text != "" {
			m.Text += "\n"
		}
		m.Text += txt
	}
}

// strField reads a string field leniently — absent or wrong-typed
// fields are empty, never guessed.
func strField(obj map[string]json.RawMessage, key string) string {
	v, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return ""
	}
	return s
}
