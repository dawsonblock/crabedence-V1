package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RunEvidenceV1 is a provider-neutral, versioned, machine-verifiable record of
// a single run's outcome. It normalizes RunResult + TimingReport into a
// portable format that can be stored, compared, and audited across the CLI,
// the coordinator, and provider qualification pipelines.
//
// The record uses snake_case JSON keys to match TerminalRunReceipt and the
// AWS qualification contract conventions. The digest covers all fields except
// the digest itself, so any tampering is detectable.
type RunEvidenceV1 struct {
	SchemaVersion int    `json:"schema_version"`
	EvidenceType  string `json:"evidence_type"`
	Provider      string `json:"provider"`
	LeaseID       string `json:"lease_id,omitempty"`
	Slug          string `json:"slug,omitempty"`
	RunID         string `json:"run_id,omitempty"`
	Label         string `json:"label,omitempty"`
	MachineType   string `json:"machine_type,omitempty"`

	// Outcome
	ExitCode    int          `json:"exit_code"`
	RunStatus   RunStatus    `json:"run_status"`
	ErrorKind   RunErrorKind `json:"error_kind,omitempty"`
	CommandText string       `json:"command_text,omitempty"`

	// Timing (milliseconds)
	TotalMs       int64 `json:"total_ms"`
	CommandMs     int64 `json:"command_ms"`
	SyncMs        int64 `json:"sync_ms"`
	RunnerTotalMs int64 `json:"runner_total_ms,omitempty"`
	EndToEndMs    int64 `json:"end_to_end_ms,omitempty"`
	LeaseMs       int64 `json:"lease_ms,omitempty"`
	BootstrapMs   int64 `json:"bootstrap_ms,omitempty"`
	HydrateMs     int64 `json:"hydrate_ms,omitempty"`
	ProbeMs       int64 `json:"probe_ms,omitempty"`

	// Sync metadata
	SyncDelegated      bool   `json:"sync_delegated,omitempty"`
	SyncSkipped        bool   `json:"sync_skipped,omitempty"`
	SyncMode           string `json:"sync_mode,omitempty"`
	SyncTransferFiles  int    `json:"sync_transfer_files,omitempty"`
	SyncTransferBytes  int64  `json:"sync_transfer_bytes,omitempty"`
	SyncFallbackReason string `json:"sync_fallback_reason,omitempty"`

	// Phases
	RunnerPhases  []RunnerPhase `json:"runner_phases,omitempty"`
	SyncPhases    []TimingPhase `json:"sync_phases,omitempty"`
	CommandPhases []TimingPhase `json:"command_phases,omitempty"`

	// Failure classification
	BlockedStage       string                   `json:"blocked_stage,omitempty"`
	ResourceExhaustion ResourceExhaustionReason `json:"resource_exhaustion,omitempty"`
	RetryLikely        string                   `json:"retry_likely,omitempty"`
	FailureHint        string                   `json:"failure_hint,omitempty"`

	// Artifacts
	Artifacts []RunEvidenceArtifact `json:"artifacts,omitempty"`

	// Integrity
	StartedAt string `json:"started_at,omitempty"`
	EndedAt   string `json:"ended_at,omitempty"`
	Digest    string `json:"digest"`
}

// RunEvidenceArtifact is the normalized artifact entry in RunEvidenceV1.
type RunEvidenceArtifact struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Bytes  int    `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

const runEvidenceSchemaVersion = 1
const runEvidenceType = "run"

// RunEvidenceInput is the provider-neutral input from which RunEvidenceV1 is
// constructed. Both the SSH lease path and delegated run providers produce
// these fields.
type RunEvidenceInput struct {
	Provider    string
	LeaseID     string
	Slug        string
	RunID       string
	Label       string
	MachineType string
	CommandText string

	ExitCode  int
	RunStatus RunStatus
	ErrorKind RunErrorKind

	TotalMs       int64
	CommandMs     int64
	SyncMs        int64
	RunnerTotalMs int64
	EndToEndMs    int64
	LeaseMs       int64
	BootstrapMs   int64
	HydrateMs     int64
	ProbeMs       int64

	SyncDelegated      bool
	SyncSkipped        bool
	SyncMode           string
	SyncTransferFiles  int
	SyncTransferBytes  int64
	SyncFallbackReason string

	RunnerPhases  []RunnerPhase
	SyncPhases    []TimingPhase
	CommandPhases []TimingPhase

	BlockedStage       string
	ResourceExhaustion ResourceExhaustionReason
	RetryLikely        string
	FailureHint        string

	Artifacts []RunEvidenceArtifact

	StartedAt time.Time
	EndedAt   time.Time
}

// NewRunEvidence constructs a RunEvidenceV1 from the input, normalizing
// status/error if they are unset, and computing the integrity digest.
func NewRunEvidence(input RunEvidenceInput) RunEvidenceV1 {
	if input.RunStatus == "" || input.ErrorKind == "" {
		finalized := FinalizeRunResult(RunResult{
			ExitCode:  input.ExitCode,
			Status:    input.RunStatus,
			ErrorKind: input.ErrorKind,
		}, nil)
		if input.RunStatus == "" {
			input.RunStatus = finalized.Status
		}
		if input.ErrorKind == "" {
			input.ErrorKind = finalized.ErrorKind
		}
	}

	ev := RunEvidenceV1{
		SchemaVersion:      runEvidenceSchemaVersion,
		EvidenceType:       runEvidenceType,
		Provider:           input.Provider,
		LeaseID:            input.LeaseID,
		Slug:               input.Slug,
		RunID:              input.RunID,
		Label:              input.Label,
		MachineType:        input.MachineType,
		ExitCode:           input.ExitCode,
		RunStatus:          input.RunStatus,
		ErrorKind:          input.ErrorKind,
		CommandText:        input.CommandText,
		TotalMs:            input.TotalMs,
		CommandMs:          input.CommandMs,
		SyncMs:             input.SyncMs,
		RunnerTotalMs:      input.RunnerTotalMs,
		EndToEndMs:         input.EndToEndMs,
		LeaseMs:            input.LeaseMs,
		BootstrapMs:        input.BootstrapMs,
		HydrateMs:          input.HydrateMs,
		ProbeMs:            input.ProbeMs,
		SyncDelegated:      input.SyncDelegated,
		SyncSkipped:        input.SyncSkipped,
		SyncMode:           input.SyncMode,
		SyncTransferFiles:  input.SyncTransferFiles,
		SyncTransferBytes:  input.SyncTransferBytes,
		SyncFallbackReason: input.SyncFallbackReason,
		RunnerPhases:       input.RunnerPhases,
		SyncPhases:         input.SyncPhases,
		CommandPhases:      input.CommandPhases,
		BlockedStage:       input.BlockedStage,
		ResourceExhaustion: input.ResourceExhaustion,
		RetryLikely:        input.RetryLikely,
		FailureHint:        input.FailureHint,
		Artifacts:          input.Artifacts,
	}
	if !input.StartedAt.IsZero() {
		ev.StartedAt = input.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	if !input.EndedAt.IsZero() {
		ev.EndedAt = input.EndedAt.UTC().Format(time.RFC3339Nano)
	}
	ev.Digest = runEvidenceDigest(ev)
	return ev
}

// runEvidenceDigest computes a SHA-256 over the canonical JSON encoding of the
// evidence record, excluding the digest field itself. Uses a type alias to
// avoid recursing into MarshalJSON.
func runEvidenceDigest(ev RunEvidenceV1) string {
	clone := ev
	clone.Digest = ""
	type alias RunEvidenceV1
	data, err := json.Marshal(alias(clone))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// VerifyRunEvidenceDigest returns true if the evidence's digest matches a
// freshly computed digest over its content (excluding the digest field).
func VerifyRunEvidenceDigest(ev RunEvidenceV1) bool {
	expected := runEvidenceDigest(ev)
	return ev.Digest == expected && ev.Digest != ""
}

// RunEvidenceFromTimingReport constructs RunEvidenceV1 from a TimingReport,
// which is the broadest existing JSON envelope for run outcomes.
func RunEvidenceFromTimingReport(report TimingReport) RunEvidenceV1 {
	artifacts := make([]RunEvidenceArtifact, 0, len(report.Artifacts))
	for _, a := range report.Artifacts {
		artifacts = append(artifacts, RunEvidenceArtifact{
			Kind:  a.Kind,
			Path:  a.Path,
			Bytes: a.Bytes,
		})
	}
	return NewRunEvidence(RunEvidenceInput{
		Provider:           report.Provider,
		LeaseID:            report.LeaseID,
		Slug:               report.Slug,
		RunID:              report.RunID,
		Label:              report.Label,
		MachineType:        report.MachineType,
		ExitCode:           report.ExitCode,
		RunStatus:          report.RunStatus,
		ErrorKind:          report.ErrorKind,
		TotalMs:            report.TotalMs,
		CommandMs:          report.CommandMs,
		SyncMs:             report.SyncMs,
		RunnerTotalMs:      report.RunnerTotalMs,
		EndToEndMs:         report.EndToEndMs,
		LeaseMs:            report.LeaseMs,
		BootstrapMs:        report.BootstrapMs,
		HydrateMs:          report.HydrateMs,
		ProbeMs:            report.ProbeMs,
		SyncDelegated:      report.SyncDelegated,
		SyncSkipped:        report.SyncSkipped,
		SyncMode:           report.SyncMode,
		SyncTransferFiles:  report.SyncTransferFiles,
		SyncTransferBytes:  report.SyncTransferBytes,
		SyncFallbackReason: report.SyncFallbackReason,
		RunnerPhases:       report.RunnerPhases,
		SyncPhases:         report.SyncPhases,
		CommandPhases:      report.CommandPhases,
		BlockedStage:       report.BlockedStage,
		ResourceExhaustion: report.ResourceExhaustion,
		RetryLikely:        report.RetryLikely,
		Artifacts:          artifacts,
	})
}

// RunEvidenceFromRunResult constructs RunEvidenceV1 from a RunResult, suitable
// for delegated providers that return RunResult directly.
func RunEvidenceFromRunResult(result RunResult) RunEvidenceV1 {
	artifacts := make([]RunEvidenceArtifact, 0, len(result.Artifacts))
	for _, a := range result.Artifacts {
		artifacts = append(artifacts, RunEvidenceArtifact{
			Kind:  a.Kind,
			Path:  a.Path,
			Bytes: a.Bytes,
		})
	}
	input := RunEvidenceInput{
		Provider:      result.Provider,
		LeaseID:       result.LeaseID,
		Slug:          result.Slug,
		CommandText:   result.CommandText,
		ExitCode:      result.ExitCode,
		RunStatus:     result.Status,
		ErrorKind:     result.ErrorKind,
		TotalMs:       result.Total.Milliseconds(),
		CommandMs:     result.Command.Milliseconds(),
		SyncDelegated: result.SyncDelegated,
		Artifacts:     artifacts,
	}
	if result.Session != nil {
		input.RunID = result.Session.RunID
	}
	return NewRunEvidence(input)
}

// MarshalJSON ensures the digest is always consistent when the evidence is
// serialized. If the digest is empty or stale, it is recomputed.
func (ev RunEvidenceV1) MarshalJSON() ([]byte, error) {
	if ev.Digest == "" || !VerifyRunEvidenceDigest(ev) {
		ev.Digest = runEvidenceDigest(ev)
	}
	type alias RunEvidenceV1
	return json.Marshal(alias(ev))
}

// RunEvidenceSummary returns a one-line human-readable summary of the evidence.
func (ev RunEvidenceV1) Summary() string {
	parts := []string{
		fmt.Sprintf("provider=%s", ev.Provider),
		fmt.Sprintf("status=%s", ev.RunStatus),
		fmt.Sprintf("exit=%d", ev.ExitCode),
		fmt.Sprintf("total=%dms", ev.TotalMs),
	}
	if ev.LeaseID != "" {
		parts = append(parts, fmt.Sprintf("lease=%s", ev.LeaseID))
	}
	if ev.BlockedStage != "" {
		parts = append(parts, fmt.Sprintf("blocked=%s", ev.BlockedStage))
	}
	if ev.RetryLikely != "" {
		parts = append(parts, fmt.Sprintf("retry=%s", ev.RetryLikely))
	}
	return strings.Join(parts, " ")
}
