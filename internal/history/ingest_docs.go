package history

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxDocumentBytes bounds one ingested document — memory indexes the
// record and a bounded extract, not an archive of every byte.
const maxDocumentBytes = 4 << 20

// docRecord is the canonical payload a document event commits to.
type docRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	// Heading is the document's first markdown heading, when it has
	// one — the record's human-readable identity.
	Heading string `json:"heading,omitempty"`
	// Body is the full document text under maxDocumentBytes, else a
	// bounded prefix — memory keeps enough to learn from, keyed to
	// the digest for the rest.
	Body      string `json:"body"`
	Truncated bool   `json:"truncated"`
}

// IngestDocuments records files as document events, keyed on their
// content digest: re-ingesting an unchanged file dedupes, a changed
// file appends a new event — the store keeps the document's own
// evolution as history.
func (s *Store) IngestDocuments(paths ...string) (int, error) {
	var events []*Event
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return 0, fmt.Errorf("document %s: %w", p, err)
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("document %s is not a regular file", p)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return 0, fmt.Errorf("read document %s: %w", p, err)
		}
		sum := sha256.Sum256(raw)
		rec := docRecord{
			Path:   filepath.Clean(p),
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(raw)),
		}
		body := raw
		if len(body) > maxDocumentBytes {
			body = body[:maxDocumentBytes]
			rec.Truncated = true
		}
		rec.Body = string(body)
		for _, line := range strings.Split(rec.Body, "\n") {
			if h := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#")); h != strings.TrimSpace(line) && h != "" {
				rec.Heading = h
				break
			}
		}
		payload, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		events = append(events, &Event{
			DedupeKey:   "doc:" + rec.Path + ":" + rec.SHA256,
			Kind:        KindDocument,
			Subject:     rec.Path,
			Correlation: rec.SHA256,
			Source:      "document",
			OccurredAt:  info.ModTime().UnixMilli(),
			Payload:     payload,
		})
	}
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}
