package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// RunEvidenceV1 is a provider-neutral, versioned run outcome record. It
// normalizes RunResult + TimingReport into a portable format that can be
// stored, compared, and audited across the CLI, the coordinator, and
// provider qualification pipelines.
//
// The record uses snake_case JSON keys to match TerminalRunReceipt and the
// AWS qualification contract conventions. The digest covers all fields except
// the digest itself (SHA-256 over canonical JSON with digest set to "").
//
// The digest is an integrity checksum, NOT a cryptographic signature.
// Authenticity is established by binding the evidence digest into the
// Ed25519-signed TerminalRunReceipt (evidence_sha256 field in receipt v3+),
// which the coordinator verifies.
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

	// Startup confirmation result (provider qualification evidence)
	StartupConfirm *StartupConfirmSummary `json:"startup_confirm,omitempty"`

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

	StartupConfirm *StartupConfirmSummary

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
		StartupConfirm:     input.StartupConfirm,
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
// evidence record, excluding the digest field itself. Canonicalization uses
// lexicographic code-point key ordering (matching the TypeScript coordinator's
// stableJSONValue) to ensure both implementations produce identical bytes.
func runEvidenceDigest(ev RunEvidenceV1) string {
	b, err := runEvidenceDigestBytes(ev)
	if err != nil {
		return ""
	}
	return string(b)
}

// runEvidenceDigestBytes returns the lowercase hex SHA-256 digest of the
// canonical JSON encoding of the evidence record (with digest set to "").
func runEvidenceDigestBytes(ev RunEvidenceV1) ([]byte, error) {
	clone := ev
	clone.Digest = ""
	data, err := canonicalEvidenceJSON(clone)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return []byte(hex.EncodeToString(sum[:])), nil
}

// canonicalEvidenceJSON serializes the evidence as JSON with keys sorted by
// Unicode code point order (lexicographic), matching the TypeScript
// stableJSONValue implementation. This is NOT RFC 8785, but it is a
// well-defined, portable, locale-independent canonicalization that both
// implementations share. The digest field is set to "" before serialization.
//
// String contents are serialized without HTML escaping: Go's default
// json.Marshal escapes '<', '>', and '&' as \u003c, \u003e, and \u0026,
// while JavaScript's JSON.stringify emits them raw. Since the digest is
// computed over these exact bytes on both sides, the encoders must agree.
func canonicalEvidenceJSON(ev RunEvidenceV1) ([]byte, error) {
	return marshalNoEscape(evidenceToOrderedMap(ev))
}

// marshalNoEscape serializes v as JSON with HTML escaping disabled,
// byte-for-byte matching JavaScript's JSON.stringify for the value shapes
// evidence uses (valid UTF-8 strings, booleans, integers within the
// IEEE-754 safe range, arrays, and objects). With SetEscapeHTML(false),
// Go also stops escaping U+2028/U+2029, matching JSON.stringify.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a trailing newline; trim it.
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// orderedMap is a map that preserves insertion order for JSON serialization.
type orderedMap struct {
	keys   []string
	values map[string]any
}

func newOrderedMap() *orderedMap {
	return &orderedMap{values: make(map[string]any)}
}

func (m *orderedMap) set(key string, value any) {
	if _, exists := m.values[key]; !exists {
		m.keys = append(m.keys, key)
	}
	m.values[key] = value
}

func (m *orderedMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, err := marshalNoEscape(key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')
		valBytes, err := marshalNoEscape(m.values[key])
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// evidenceToOrderedMap converts RunEvidenceV1 to an ordered map with keys
// sorted by Unicode code point order, matching the TypeScript
// stableJSONValue canonicalization.
func evidenceToOrderedMap(ev RunEvidenceV1) *orderedMap {
	// Collect all non-omitted fields into a map, then sort keys.
	raw := map[string]any{}
	raw["schema_version"] = ev.SchemaVersion
	raw["evidence_type"] = ev.EvidenceType
	raw["provider"] = ev.Provider
	if ev.LeaseID != "" {
		raw["lease_id"] = ev.LeaseID
	}
	if ev.Slug != "" {
		raw["slug"] = ev.Slug
	}
	if ev.RunID != "" {
		raw["run_id"] = ev.RunID
	}
	if ev.Label != "" {
		raw["label"] = ev.Label
	}
	if ev.MachineType != "" {
		raw["machine_type"] = ev.MachineType
	}
	raw["exit_code"] = ev.ExitCode
	raw["run_status"] = ev.RunStatus
	if ev.ErrorKind != "" {
		raw["error_kind"] = ev.ErrorKind
	}
	if ev.CommandText != "" {
		raw["command_text"] = ev.CommandText
	}
	raw["total_ms"] = ev.TotalMs
	raw["command_ms"] = ev.CommandMs
	raw["sync_ms"] = ev.SyncMs
	if ev.RunnerTotalMs != 0 {
		raw["runner_total_ms"] = ev.RunnerTotalMs
	}
	if ev.EndToEndMs != 0 {
		raw["end_to_end_ms"] = ev.EndToEndMs
	}
	if ev.LeaseMs != 0 {
		raw["lease_ms"] = ev.LeaseMs
	}
	if ev.BootstrapMs != 0 {
		raw["bootstrap_ms"] = ev.BootstrapMs
	}
	if ev.HydrateMs != 0 {
		raw["hydrate_ms"] = ev.HydrateMs
	}
	if ev.ProbeMs != 0 {
		raw["probe_ms"] = ev.ProbeMs
	}
	if ev.SyncDelegated {
		raw["sync_delegated"] = ev.SyncDelegated
	}
	if ev.SyncSkipped {
		raw["sync_skipped"] = ev.SyncSkipped
	}
	if ev.SyncMode != "" {
		raw["sync_mode"] = ev.SyncMode
	}
	if ev.SyncTransferFiles != 0 {
		raw["sync_transfer_files"] = ev.SyncTransferFiles
	}
	if ev.SyncTransferBytes != 0 {
		raw["sync_transfer_bytes"] = ev.SyncTransferBytes
	}
	if ev.SyncFallbackReason != "" {
		raw["sync_fallback_reason"] = ev.SyncFallbackReason
	}
	if len(ev.RunnerPhases) > 0 {
		raw["runner_phases"] = runnerPhasesCanonical(ev.RunnerPhases)
	}
	if len(ev.SyncPhases) > 0 {
		raw["sync_phases"] = timingPhasesCanonical(ev.SyncPhases)
	}
	if len(ev.CommandPhases) > 0 {
		raw["command_phases"] = timingPhasesCanonical(ev.CommandPhases)
	}
	if ev.BlockedStage != "" {
		raw["blocked_stage"] = ev.BlockedStage
	}
	if ev.ResourceExhaustion != "" {
		raw["resource_exhaustion"] = ev.ResourceExhaustion
	}
	if ev.RetryLikely != "" {
		raw["retry_likely"] = ev.RetryLikely
	}
	if ev.FailureHint != "" {
		raw["failure_hint"] = ev.FailureHint
	}
	if len(ev.Artifacts) > 0 {
		raw["artifacts"] = runEvidenceArtifactsCanonical(ev.Artifacts)
	}
	if ev.StartupConfirm != nil {
		raw["startup_confirm"] = startupConfirmCanonical(ev.StartupConfirm)
	}
	if ev.StartedAt != "" {
		raw["started_at"] = ev.StartedAt
	}
	if ev.EndedAt != "" {
		raw["ended_at"] = ev.EndedAt
	}
	raw["digest"] = ev.Digest

	return sortedOrderedMap(raw)
}

// sortedOrderedMap builds an orderedMap from entries with keys sorted by
// Unicode code point order, matching the TypeScript stableJSONValue
// canonicalization. Nested objects (phases, artifacts) must use this too:
// the TypeScript side sorts keys recursively at every level, while Go's
// default struct marshaling preserves field-declaration order, which
// differs from sorted order (e.g. "ms" sorts before "name").
func sortedOrderedMap(entries map[string]any) *orderedMap {
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m := newOrderedMap()
	for _, k := range keys {
		m.set(k, entries[k])
	}
	return m
}

// runnerPhasesCanonical converts runner phases to sorted-key ordered maps,
// preserving each field's omitempty wire semantics.
func runnerPhasesCanonical(phases []RunnerPhase) []any {
	out := make([]any, len(phases))
	for i, p := range phases {
		entries := map[string]any{
			"name": p.Name,
			"ms":   p.Ms,
		}
		if p.Opaque {
			entries["opaque"] = p.Opaque
		}
		if p.Reason != "" {
			entries["reason"] = p.Reason
		}
		if p.Provider != "" {
			entries["provider"] = p.Provider
		}
		if p.LeaseID != "" {
			entries["leaseId"] = p.LeaseID
		}
		if p.Slug != "" {
			entries["slug"] = p.Slug
		}
		if p.RunID != "" {
			entries["runId"] = p.RunID
		}
		if p.MachineType != "" {
			entries["machineType"] = p.MachineType
		}
		if p.TransferCount != 0 {
			entries["transferCount"] = p.TransferCount
		}
		if p.TransferBytes != 0 {
			entries["transferBytes"] = p.TransferBytes
		}
		out[i] = sortedOrderedMap(entries)
	}
	return out
}

// timingPhasesCanonical converts timing phases to sorted-key ordered maps,
// preserving each field's omitempty wire semantics.
func timingPhasesCanonical(phases []TimingPhase) []any {
	out := make([]any, len(phases))
	for i, p := range phases {
		entries := map[string]any{
			"name": p.Name,
		}
		if p.Ms != 0 {
			entries["ms"] = p.Ms
		}
		if p.Skipped {
			entries["skipped"] = p.Skipped
		}
		if p.Reason != "" {
			entries["reason"] = p.Reason
		}
		out[i] = sortedOrderedMap(entries)
	}
	return out
}

// runEvidenceArtifactsCanonical converts artifacts to sorted-key ordered
// maps, preserving each field's omitempty wire semantics.
func runEvidenceArtifactsCanonical(artifacts []RunEvidenceArtifact) []any {
	out := make([]any, len(artifacts))
	for i, a := range artifacts {
		entries := map[string]any{
			"kind": a.Kind,
			"path": a.Path,
		}
		if a.Bytes != 0 {
			entries["bytes"] = a.Bytes
		}
		if a.SHA256 != "" {
			entries["sha256"] = a.SHA256
		}
		out[i] = sortedOrderedMap(entries)
	}
	return out
}

// startupConfirmCanonical converts a StartupConfirmSummary to a canonical
// (sorted-key) ordered map for JSON serialization. Keys are sorted by Unicode
// code point order to match the TypeScript stableJSONValue canonicalization.
func startupConfirmCanonical(sc *StartupConfirmSummary) *orderedMap {
	entries := map[string]any{
		"stage":       sc.Stage,
		"duration_ms": sc.DurationMs,
		"ready":       sc.Ready,
	}
	if sc.ProcessExited {
		entries["process_exited"] = sc.ProcessExited
	}
	if sc.Retryable {
		entries["retryable"] = sc.Retryable
	}
	return sortedOrderedMap(entries)
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
		CommandText:        report.CommandText,
		StartedAt:          report.StartedAt,
		EndedAt:            report.EndedAt,
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
		StartupConfirm:     report.StartupConfirm,
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
		Provider:       result.Provider,
		LeaseID:        result.LeaseID,
		Slug:           result.Slug,
		CommandText:    result.CommandText,
		ExitCode:       result.ExitCode,
		RunStatus:      result.Status,
		ErrorKind:      result.ErrorKind,
		TotalMs:        result.Total.Milliseconds(),
		CommandMs:      result.Command.Milliseconds(),
		SyncDelegated:  result.SyncDelegated,
		Artifacts:      artifacts,
		StartupConfirm: result.StartupConfirm,
	}
	if result.Session != nil {
		input.RunID = result.Session.RunID
	}
	return NewRunEvidence(input)
}

// MarshalJSON serializes the evidence using canonical (sorted-key) JSON.
// The digest is computed only if it has not been set yet (first
// serialization after construction). If the digest is already set but
// stale relative to the fields, it is preserved as-is so that tampering
// is detectable by the coordinator's validator rather than silently
// repaired.
func (ev RunEvidenceV1) MarshalJSON() ([]byte, error) {
	if ev.Digest == "" {
		ev.Digest = runEvidenceDigest(ev)
	}
	return canonicalEvidenceJSON(ev)
}

// WriteEvidenceJSON writes the evidence as a single JSON object to w. It is
// the evidence analogue of writeTimingJSON.
func WriteEvidenceJSON(w io.Writer, ev RunEvidenceV1) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(ev)
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
