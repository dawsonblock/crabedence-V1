package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// FinalRunOutcome is the immutable snapshot of a completed run's execution
// state. Once created, no logging, JSON-output, filesystem, coordinator, or
// client-side error may alter it. The outcome captures what happened during
// execution; auxiliary failures (local file writes, coordinator commits) are
// reported separately and cannot retroactively change a successful remote
// execution into a failed signed execution.
//
// The outcome is created after all post-execution collection (artifacts,
// JUnit results, failure downloads) is complete. The ExitCode reflects the
// final interpreted exit code including local-output policies (JUnit failure
// detection, artifact validation). After the outcome is captured, no
// subsequent error can change it.
type FinalRunOutcome struct {
	// ExitCode is the final interpreted exit code. This is the code that
	// the evidence and receipt will bind. It includes the remote command's
	// exit code plus any local-output policy adjustments (JUnit, artifacts).
	ExitCode int

	// RunStatus is the finalized run status (succeeded/failed/timed-out/canceled).
	RunStatus RunStatus

	// ErrorKind is the finalized error classification.
	ErrorKind RunErrorKind

	// Command is the executed command as a string slice (for receipt binding).
	Command []string

	// CommandText is the display form of the executed command.
	CommandText string

	// Timing is the finalized timing report.
	Timing TimingReport

	// Classification is the failure classification (if any).
	Classification FailureClassification

	// Results is the test result summary (if any).
	Results *TestResultSummary

	// Artifacts is the collected run artifacts.
	Artifacts []runArtifact

	// TerminalLog is the captured terminal log snapshot.
	TerminalLog runLogSnapshot

	// StartedAt is when the run started.
	StartedAt time.Time

	// EndedAt is when the run ended.
	EndedAt time.Time

	// Provider is the provider name.
	Provider string

	// LeaseID is the lease identifier.
	LeaseID string

	// Slug is the server slug.
	Slug string

	// RunID is the run identifier.
	RunID string

	// ActionsURL is the optional actions URL.
	ActionsURL string
}

// TerminalBundleV1 is the atomic terminal record: evidence, receipt, and
// terminal log bound together as a single unit. The bundle is self-verified
// before being sent to the coordinator. The coordinator atomically persists
// all parts in a single transaction.
//
// The bundle replaces the previous pattern of sending evidence and receipt
// as separate fields that could be independently accepted or rejected. With
// TerminalBundleV1, either the entire bundle is accepted or it is rejected.
type TerminalBundleV1 struct {
	// Evidence is the RunEvidenceV1 record.
	Evidence RunEvidenceV1

	// Receipt is the signed TerminalRunReceiptV3.
	Receipt terminalRunReceipt

	// TerminalLog is the log content (may be truncated).
	TerminalLog string

	// LogTruncated indicates whether the terminal log was truncated.
	LogTruncated bool

	// LogSHA256 is the SHA-256 of the full (untruncated) terminal log.
	LogSHA256 string

	// RetainedLogSHA256 is the SHA-256 of the retained (possibly truncated) log.
	RetainedLogSHA256 string

	// Results is the test result summary (if any).
	Results *TestResultSummary

	// Classification is the failure classification (if any).
	Classification FailureClassification

	// SyncMs is the sync phase duration in milliseconds.
	SyncMs int64

	// CommandMs is the command phase duration in milliseconds.
	CommandMs int64
}

// BuildTerminalBundle builds an immutable TerminalBundleV1 from a FinalRunOutcome.
// The bundle is self-verified before being returned. Once built, the bundle's
// evidence and receipt are immutable — no subsequent error can change them.
//
// This is the single finalization path. It replaces the previous
// prepareTerminalRun/finalizeTerminalRun closure pattern that allowed
// post-finalization errors to rebuild the receipt with a different exit code.
func BuildTerminalBundle(outcome FinalRunOutcome, key ed25519.PrivateKey) (TerminalBundleV1, error) {
	if key == nil {
		return TerminalBundleV1{}, fmt.Errorf("terminal bundle requires a signing key")
	}

	// Build evidence from the outcome.
	evidenceInput := RunEvidenceInput{
		Provider:       outcome.Provider,
		LeaseID:        outcome.LeaseID,
		Slug:           outcome.Slug,
		RunID:          outcome.RunID,
		CommandText:    outcome.CommandText,
		ExitCode:       outcome.ExitCode,
		RunStatus:      outcome.RunStatus,
		ErrorKind:      outcome.ErrorKind,
		TotalMs:        outcome.Timing.TotalMs,
		CommandMs:      outcome.Timing.CommandMs,
		SyncMs:         outcome.Timing.SyncMs,
		RunnerTotalMs:  outcome.Timing.RunnerTotalMs,
		EndToEndMs:     outcome.Timing.EndToEndMs,
		LeaseMs:        outcome.Timing.LeaseMs,
		BootstrapMs:    outcome.Timing.BootstrapMs,
		HydrateMs:      outcome.Timing.HydrateMs,
		ProbeMs:        outcome.Timing.ProbeMs,
		Artifacts:      artifactsFromRunArtifacts(outcome.Artifacts),
		StartupConfirm: StartupConfirmFromSummary(outcome.Timing.StartupConfirm),
		StartedAt:      outcome.StartedAt,
		EndedAt:        outcome.EndedAt,
	}
	evidence := NewRunEvidence(evidenceInput)

	// Build the receipt from the outcome.
	receipt, err := buildTerminalRunReceiptWithKey(key, terminalRunReceiptInput{
		Provider:          outcome.Provider,
		LeaseID:           outcome.LeaseID,
		Slug:              outcome.Slug,
		RunID:             outcome.RunID,
		Command:           outcome.Command,
		CommandDisplay:    outcome.CommandText,
		ExitCode:          outcome.ExitCode,
		SyncMs:            outcome.Timing.SyncMs,
		CommandMs:         outcome.Timing.CommandMs,
		StartedAt:         outcome.StartedAt,
		EndedAt:           outcome.EndedAt,
		LogSHA256:         outcome.TerminalLog.FullSHA256,
		RetainedLogSHA256: sha256Digest([]byte(outcome.TerminalLog.Log)),
		LogTruncated:      outcome.TerminalLog.Truncated,
		EvidenceSHA256:    evidence.Digest,
	})
	if err != nil {
		return TerminalBundleV1{}, fmt.Errorf("build terminal receipt: %w", err)
	}

	bundle := TerminalBundleV1{
		Evidence:          evidence,
		Receipt:           receipt,
		TerminalLog:       outcome.TerminalLog.Log,
		LogTruncated:      outcome.TerminalLog.Truncated,
		LogSHA256:         outcome.TerminalLog.FullSHA256,
		RetainedLogSHA256: sha256Digest([]byte(outcome.TerminalLog.Log)),
		Results:           outcome.Results,
		Classification:    outcome.Classification,
		SyncMs:            outcome.Timing.SyncMs,
		CommandMs:         outcome.Timing.CommandMs,
	}

	// Self-verify: confirm the signature is valid and the evidence binding
	// is correct. This catches signing bugs, key mismatches, and binding
	// errors before the bundle reaches the coordinator.
	if verifyErr := verifyTerminalRunReceiptSignature(receipt); verifyErr != nil {
		return TerminalBundleV1{}, fmt.Errorf("self-verify terminal receipt signature: %w", verifyErr)
	}
	if receipt.EvidenceSHA256 != evidence.Digest {
		return TerminalBundleV1{}, fmt.Errorf("self-verify evidence binding: receipt evidence_sha256 %s != evidence digest %s", receipt.EvidenceSHA256, evidence.Digest)
	}

	return bundle, nil
}

// CommitTerminalBundle sends the terminal bundle to the coordinator via the
// run recorder. If the coordinator commit fails, the error is returned but
// the bundle remains immutable — the caller reports it as an auxiliary error
// but does not rebuild the bundle.
//
// This replaces the previous pattern where a coordinator commit failure
// would rebuild the receipt with a failure exit code, retroactively turning
// a successful remote execution into a failed signed execution.
func CommitTerminalBundle(ctx context.Context, recorder *runRecorder, target SSHTarget, bundle TerminalBundleV1) error {
	if recorder == nil {
		return nil
	}
	return recorder.Finish(
		ctx,
		target,
		bundle.Receipt.ExitCode,
		time.Duration(bundle.SyncMs)*time.Millisecond,
		time.Duration(bundle.CommandMs)*time.Millisecond,
		bundle.TerminalLog,
		bundle.LogTruncated,
		bundle.Results,
		bundle.Classification,
		&bundle.Receipt,
		&bundle.Evidence,
	)
}

// AuxiliaryError represents a failure that occurred after the FinalRunOutcome
// was captured. Auxiliary errors cannot change the execution outcome — they
// are reported to the user and may affect the CLI exit code, but the signed
// execution record (evidence + receipt) remains immutable.
//
// Examples of auxiliary errors:
//   - --evidence-json file write failure
//   - --timing-json file write failure
//   - --attest receipt file write failure
//   - coordinator commit failure (the run may have succeeded remotely)
type AuxiliaryError struct {
	Op  string
	Err error
}

func (e *AuxiliaryError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *AuxiliaryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// auxiliaryErrors joins multiple auxiliary errors into a single error.
// Returns nil if no errors are provided.
func auxiliaryErrors(errs ...error) error {
	var filtered []error
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return errors.Join(filtered...)
}

// artifactsFromRunArtifacts converts internal runArtifact slice to the
// RunEvidenceArtifact slice used by RunEvidenceV1.
func artifactsFromRunArtifacts(artifacts []runArtifact) []RunEvidenceArtifact {
	if len(artifacts) == 0 {
		return nil
	}
	result := make([]RunEvidenceArtifact, len(artifacts))
	for i, a := range artifacts {
		result[i] = RunEvidenceArtifact{
			Kind:  a.Kind,
			Path:  a.Path,
			Bytes: a.Bytes,
		}
	}
	return result
}
