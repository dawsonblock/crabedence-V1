package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

// experimentRecord is the canonical payload an experiment event
// commits to: what was hypothesized, what was tried (arm/params),
// and what was observed — recorded, never judged at ingest time.
type experimentRecord struct {
	ExperimentID string          `json:"experiment_id"`
	Hypothesis   string          `json:"hypothesis,omitempty"`
	Arm          string          `json:"arm,omitempty"`
	Params       json.RawMessage `json:"params,omitempty"`
	Outcome      string          `json:"outcome,omitempty"`
	Metrics      json.RawMessage `json:"metrics,omitempty"`
	Timestamp    string          `json:"timestamp"`
	SourceSHA    string          `json:"source_sha256"`
	File         string          `json:"file"`
}

// IngestExperiments reads a directory (or single file) of experiment
// records — JSON objects carrying id/hypothesis/arm/outcome/metrics —
// into experiment events. Each file's bytes go to the content store;
// the event dedupes on its record digest, so a corrected record is a
// new observation beside the original, never a rewrite.
func (s *Store) IngestExperiments(path string, cs *ContentStore) (int, error) {
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
			if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	var events []*Event
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return 0, err
		}
		var rec experimentRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return 0, fmt.Errorf("experiment %s: %w", f, err)
		}
		if rec.ExperimentID == "" {
			rec.ExperimentID = firstFieldRaw(raw, "id", "name", "experiment")
		}
		if rec.ExperimentID == "" {
			return 0, fmt.Errorf("experiment %s names no experiment identity", f)
		}
		if rec.Timestamp == "" {
			rec.Timestamp = firstFieldRaw(raw, "ts", "time", "created_at")
		}
		srcSHA, _, err := cs.Put(bytes.NewReader(raw))
		if err != nil {
			return 0, fmt.Errorf("store experiment %s: %w", f, err)
		}
		rec.SourceSHA = srcSHA
		rec.File = filepath.Base(f)
		payload, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		sum := sha256.Sum256(payload)
		events = append(events, &Event{
			DedupeKey:   "experiment:" + hex.EncodeToString(sum[:]),
			Kind:        KindExperiment,
			Subject:     rec.ExperimentID,
			Correlation: srcSHA,
			Source:      "experiments:" + f,
			OccurredAt:  receiptTime(rec.Timestamp),
			Payload:     payload,
		})
	}
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}

// firstFieldRaw reads a string field from a raw JSON object.
func firstFieldRaw(raw []byte, keys ...string) string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	return firstField(obj, keys...)
}

// recoveryRecord is the canonical payload a recovery event commits
// to — the executor's own durable trail, imported as memory.
type recoveryRecord struct {
	Seq     int64  `json:"seq"`
	Kind    string `json:"recovery_kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	AtMS    int64  `json:"at_ms"`
	Ledger  string `json:"ledger"`
}

// IngestRecovery imports the executor ledger's durable recovery
// trail as recovery events — what the maintenance loop claimed,
// marked, terminated, or escalated is part of the development record,
// not just daemon bookkeeping.
func (s *Store) IngestRecovery(ledger *sandboxexecutor.Ledger, ledgerPath string) (int, error) {
	events, err := ledger.RecoveryEvents(0)
	if err != nil {
		return 0, err
	}
	var out []*Event
	for _, e := range events {
		rec := recoveryRecord{
			Seq:     e.Seq,
			Kind:    e.Kind,
			Subject: e.Subject,
			Detail:  e.Detail,
			AtMS:    e.AtMS,
			Ledger:  filepath.Base(ledgerPath),
		}
		payload, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		out = append(out, &Event{
			DedupeKey:   fmt.Sprintf("recovery:%s:%d", filepath.Base(ledgerPath), e.Seq),
			Kind:        KindRecovery,
			Subject:     e.Subject,
			Correlation: e.Kind,
			Source:      "recovery:" + ledgerPath,
			OccurredAt:  e.AtMS,
			Payload:     payload,
		})
	}
	appended, err := s.Append(out...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}
