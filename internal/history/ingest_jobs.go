package history

import (
	"encoding/json"

	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

// jobRecord is the canonical payload an execution event commits to:
// the durable registry row plus the contract fields memory learns
// from — the task's shape and the parameters it ran under. The full
// contract JSON is bound by contract_hash, so memory carries the
// parts queries need without duplicating it.
type jobRecord struct {
	JobID           string                         `json:"job_id"`
	ContractHash    string                         `json:"contract_hash"`
	State           string                         `json:"state"`
	DispatchClass   string                         `json:"dispatch_class"`
	Principal       string                         `json:"principal"`
	Submitter       string                         `json:"submitter"`
	Image           string                         `json:"image"`
	ImageDigest     string                         `json:"image_digest"`
	Argv            []string                       `json:"argv,omitempty"`
	Resources       sandboxexecutor.ResourceBudget `json:"resources"`
	Security        string                         `json:"security"`
	NetworkMode     string                         `json:"network_mode"`
	ExitCode        *int64                         `json:"exit_code,omitempty"`
	TerminalSeq     int64                          `json:"terminal_seq"`
	ReceiptSHA256   string                         `json:"receipt_sha256,omitempty"`
	BackendID       string                         `json:"backend_id,omitempty"`
	Archived        bool                           `json:"archived"`
	ReceivedAtMS    int64                          `json:"received_at_ms"`
	UpdatedAtMS     int64                          `json:"updated_at_ms"`
	DurationMS      int64                          `json:"duration_ms"`
	RuntimeIdentity string                         `json:"runtime_identity,omitempty"`
}

// IngestJobs records executor jobs as execution events — active
// registry rows and archived terminal history alike, since Ledger.List
// already unions them. Dedupe is permanent by contract hash: a job is
// one historical fact, and re-ingesting sees it once. A job's record
// is re-ingestable on change (its dedupe key includes the contract
// hash AND the terminal state, so a row observed mid-flight is
// refreshed when it settles — the durable record replaces the
// in-flight note, never duplicates it).
//
// Jobs are a memory subject, not evidence in themselves: the receipt
// chain they reference is ingested by IngestEvidenceDir.
func (s *Store) IngestJobs(ledger *sandboxexecutor.Ledger) (int, error) {
	jobs, err := ledger.List()
	if err != nil {
		return 0, err
	}
	var events []*Event
	for _, j := range jobs {
		rec := jobRecord{
			JobID:           j.JobID,
			ContractHash:    j.ContractHash,
			State:           j.State,
			DispatchClass:   j.DispatchClass,
			Principal:       j.Principal,
			Submitter:       j.Submitter,
			Image:           j.Image,
			ImageDigest:     j.ImageDigest,
			BackendID:       j.BackendID,
			ExitCode:        j.ExitCode,
			TerminalSeq:     j.TerminalSeq,
			ReceiptSHA256:   j.ReceiptSHA256,
			Archived:        j.Archived,
			ReceivedAtMS:    j.ReceivedAt.UnixMilli(),
			UpdatedAtMS:     j.UpdatedAt.UnixMilli(),
			DurationMS:      j.UpdatedAt.Sub(j.ReceivedAt).Milliseconds(),
			RuntimeIdentity: j.RuntimeIdentity,
		}
		// Contract fields come from the durable contract JSON, not a
		// re-parse of the submitter's request — what the executor
		// verified is what memory records.
		if c, err := sandboxexecutor.ParseContract(json.RawMessage(j.ContractJSON)); err == nil {
			rec.Argv = c.Argv
			rec.Resources = c.Resources
			rec.Security = c.Security
			rec.NetworkMode = c.Network.Mode
		}
		payload, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		at := j.ReceivedAt.UnixMilli()
		if j.TerminalSeq != 0 {
			at = j.UpdatedAt.UnixMilli()
		}
		events = append(events, &Event{
			DedupeKey:   "job:" + j.ContractHash + ":" + j.State,
			Kind:        KindExecution,
			Subject:     j.JobID,
			Correlation: j.ContractHash,
			Source:      "ledger",
			OccurredAt:  at,
			Payload:     payload,
		})
	}
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}
