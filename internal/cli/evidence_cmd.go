package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// evidenceVerify verifies a RunEvidenceV1 JSON document: recomputes the digest,
// validates structural limits, and optionally cross-checks a signed v3 terminal
// receipt binding. It clearly distinguishes:
//
//   - digest verified (SHA-256 integrity)
//   - receipt binding verified (evidence_sha256 matches the receipt)
//   - receipt signature verified (Ed25519 authenticity)
//
// A digest alone does not prove authenticity; only the signed receipt binding
// does. Provider qualification or external authority is out of scope for this
// command.
func (a App) evidence(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return a.evidenceHelp()
	}
	switch args[0] {
	case "verify":
		return a.evidenceVerify(ctx, args[1:])
	case "-h", "--help", "help":
		return a.evidenceHelp()
	default:
		return exit(2, "unknown evidence subcommand %q; available: verify", args[0])
	}
}

func (a App) evidenceHelp() error {
	fmt.Fprintln(a.Stdout, `Usage:
  crabbox evidence verify <evidence.json> [--receipt <receipt.json>]

Verify a RunEvidenceV1 JSON document.

Checks:
  1. Schema and structural limits (size, nesting, array bounds)
  2. Digest integrity (recompute SHA-256 over canonical JSON)
  3. Receipt binding (if --receipt is provided):
     - Receipt must be schema version >= 3
     - receipt.evidence_sha256 must equal evidence.digest
     - Receipt Ed25519 signature must verify

Trust levels:
  digest-verified       SHA-256 integrity only; does not prove authenticity
  receipt-binding       evidence_sha256 matches the signed receipt field
  receipt-signed        Ed25519 signature on the receipt verifies

A digest alone does NOT prove authenticity. Only a valid v3 receipt
binding + signature establishes authenticity. Provider qualification
or external authority is out of scope for this command.`)
	return nil
}

func (a App) evidenceVerify(ctx context.Context, args []string) error {
	fs := newFlagSet("evidence verify", a.Stderr)
	receiptPath := fs.String("receipt", "", "path to a signed terminal run receipt JSON for binding + signature verification")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return exit(2, "usage: crabbox evidence verify <evidence.json> [--receipt <receipt.json>]")
	}

	evidencePath := fs.Arg(0)
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		return exit(2, "read evidence: %v", err)
	}

	// Use the strict parser: rejects unknown fields, duplicate keys, trailing
	// data, and incorrect JSON types. This is the cryptographic boundary — a
	// lenient parser could silently accept a malformed record that produces
	// different canonical bytes and therefore a wrong digest.
	ev, err := ParseRunEvidenceV1(data)
	if err != nil {
		fmt.Fprintf(a.Stdout, "FAIL %s parse: %v\n", evidencePath, err)
		return ExitError{Code: 1}
	}

	// Check 1: schema, structural limits, and semantic invariants.
	if err := ValidateRunEvidenceV1(ev); err != nil {
		fmt.Fprintf(a.Stdout, "FAIL %s structural_validation: %v\n", evidencePath, err)
		return ExitError{Code: 1}
	}

	// Check 2: digest integrity.
	digestOK := VerifyRunEvidenceDigest(ev)
	if !digestOK {
		fmt.Fprintf(a.Stdout, "FAIL %s digest: mismatch (expected %s, recomputed does not match)\n", evidencePath, ev.Digest)
		return ExitError{Code: 1}
	}

	fmt.Fprintf(a.Stdout, "PASS %s digest=verified sha256=%s\n", evidencePath, ev.Digest)

	// Check 3: receipt binding + signature (optional).
	if *receiptPath != "" {
		receiptData, err := os.ReadFile(*receiptPath)
		if err != nil {
			return exit(2, "read receipt: %v", err)
		}
		var envelope struct {
			SchemaVersion int `json:"schema_version"`
		}
		if err := json.Unmarshal(receiptData, &envelope); err != nil {
			return exit(2, "malformed receipt: %v", err)
		}
		if envelope.SchemaVersion < terminalReceiptSchemaVersion {
			fmt.Fprintf(a.Stdout, "FAIL %s receipt_binding: schema version %d < %d (evidence binding requires v3+)\n",
				*receiptPath, envelope.SchemaVersion, terminalReceiptSchemaVersion)
			return ExitError{Code: 1}
		}
		receipt, err := decodeTerminalRunReceipt(receiptData)
		if err != nil {
			fmt.Fprintf(a.Stdout, "FAIL %s receipt: %v\n", *receiptPath, err)
			return ExitError{Code: 1}
		}

		// Receipt binding: evidence_sha256 must match evidence digest.
		if receipt.EvidenceSHA256 == "" {
			fmt.Fprintf(a.Stdout, "FAIL %s receipt_binding: receipt has no evidence_sha256 field\n", *receiptPath)
			return ExitError{Code: 1}
		}
		if receipt.EvidenceSHA256 != ev.Digest {
			fmt.Fprintf(a.Stdout, "FAIL %s receipt_binding: evidence_sha256 mismatch (receipt=%s, evidence=%s)\n",
				*receiptPath, receipt.EvidenceSHA256, ev.Digest)
			return ExitError{Code: 1}
		}
		fmt.Fprintf(a.Stdout, "PASS %s receipt_binding=verified evidence_sha256=%s\n", *receiptPath, receipt.EvidenceSHA256)

		// Receipt signature: Ed25519 verification.
		if err := verifyTerminalRunReceiptSignature(receipt); err != nil {
			fmt.Fprintf(a.Stdout, "FAIL %s receipt_signature: %v\n", *receiptPath, err)
			return ExitError{Code: 1}
		}
		signer := strings.TrimSpace(receipt.Signer)
		fmt.Fprintf(a.Stdout, "PASS %s receipt_signature=verified signer=%s\n", *receiptPath, signer)
	}

	return nil
}

// validateRunEvidenceStructure checks the structural limits documented in
// docs/spec/run-evidence.md: bounded body size, string lengths, phase/artifact
// array bounds, and nesting depth. It does NOT verify the digest.
func validateRunEvidenceStructure(ev RunEvidenceV1) error {
	if ev.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1, got %d", ev.SchemaVersion)
	}
	if ev.EvidenceType != "run" {
		return fmt.Errorf("evidence_type must be \"run\", got %q", ev.EvidenceType)
	}
	if ev.Digest != "" && !validHexDigest(ev.Digest, 32) {
		return fmt.Errorf("digest must be a 64-character lowercase hex string")
	}
	if len(ev.Provider) == 0 {
		return fmt.Errorf("provider is required")
	}
	if len(ev.Provider) > 256 {
		return fmt.Errorf("provider exceeds 256 characters")
	}
	if len(ev.LeaseID) > 256 {
		return fmt.Errorf("lease_id exceeds 256 characters")
	}
	if len(ev.RunID) > 256 {
		return fmt.Errorf("run_id exceeds 256 characters")
	}
	if len(ev.Slug) > 256 {
		return fmt.Errorf("slug exceeds 256 characters")
	}
	if len(ev.Label) > 256 {
		return fmt.Errorf("label exceeds 256 characters")
	}
	if len(ev.MachineType) > 256 {
		return fmt.Errorf("machine_type exceeds 256 characters")
	}
	if len(ev.CommandText) > 4096 {
		return fmt.Errorf("command_text exceeds 4096 characters")
	}
	if len(ev.RunStatus) > 64 {
		return fmt.Errorf("run_status exceeds 64 characters")
	}
	if len(ev.ErrorKind) > 64 {
		return fmt.Errorf("error_kind exceeds 64 characters")
	}
	if len(ev.BlockedStage) > 64 {
		return fmt.Errorf("blocked_stage exceeds 64 characters")
	}
	if len(ev.RunnerPhases) > 64 {
		return fmt.Errorf("runner_phases exceeds 64 entries")
	}
	if len(ev.SyncPhases) > 64 {
		return fmt.Errorf("sync_phases exceeds 64 entries")
	}
	if len(ev.CommandPhases) > 64 {
		return fmt.Errorf("command_phases exceeds 64 entries")
	}
	if len(ev.Artifacts) > 64 {
		return fmt.Errorf("artifacts exceeds 64 entries")
	}
	for i, phase := range ev.RunnerPhases {
		if len(phase.Name) > 256 {
			return fmt.Errorf("runner_phases[%d].name exceeds 256 characters", i)
		}
	}
	for i, phase := range ev.SyncPhases {
		if len(phase.Name) > 256 {
			return fmt.Errorf("sync_phases[%d].name exceeds 256 characters", i)
		}
	}
	for i, phase := range ev.CommandPhases {
		if len(phase.Name) > 256 {
			return fmt.Errorf("command_phases[%d].name exceeds 256 characters", i)
		}
	}
	for i, artifact := range ev.Artifacts {
		if len(artifact.Kind) > 64 {
			return fmt.Errorf("artifacts[%d].kind exceeds 64 characters", i)
		}
		if len(artifact.Path) > 1024 {
			return fmt.Errorf("artifacts[%d].path exceeds 1024 characters", i)
		}
	}
	return nil
}
