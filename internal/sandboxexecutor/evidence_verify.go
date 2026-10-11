package sandboxexecutor

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openclaw/crabbox/internal/evidence"
)

// VerifyReport is the outcome of an independent evidence check: every
// failure is a distinct finding, never a collapsed error — a verifier
// reports everything wrong, not just the first thing.
type VerifyReport struct {
	// Failures lists every detected problem; empty means verified.
	Failures []string
	// Receipts counts attestation lines checked.
	Receipts int
	// TerminalRows counts durable terminal records enumerated.
	TerminalRows int
	// Artifacts counts artifact files re-hashed.
	Artifacts int
	// CheckpointCount is the covered-record count of the verified
	// checkpoint (−1 when none existed to check).
	CheckpointCount int

	trusted map[string]bool
}

// VerifyEvidenceDir independently verifies an executor's evidence
// chain against its ledger — the same logic the sandbox-evidence-verify
// tool runs, exported so tests exercise the real path. The ledger
// opens read-only (InspectLedger): no flock, no epoch bump, no
// reconcile — verification must never mutate the store it checks.
// checkpointPath empty selects the highest record_count checkpoint.
func VerifyEvidenceDir(ledgerPath, evidenceDir, checkpointPath string, trusted map[string]bool) *VerifyReport {
	r := &VerifyReport{CheckpointCount: -1, trusted: trusted}
	if len(trusted) == 0 {
		r.fail("no trusted evidence signers supplied — verification cannot fail closed without a trust anchor")
		return r
	}
	ledger, err := InspectLedger(ledgerPath)
	if err != nil {
		r.fail("open ledger: %v", err)
		return r
	}
	defer ledger.Close()
	jobs, err := ledger.List()
	if err != nil {
		r.fail("enumerate ledger: %v", err)
		return r
	}
	refs, err := ledger.TerminalRefs()
	if err != nil {
		r.fail("enumerate terminal records: %v", err)
		return r
	}
	r.TerminalRows = len(refs)

	byID := map[string]*LedgerJob{}
	for _, j := range jobs {
		byID[j.JobID] = j
	}
	r.verifyReceipts(filepath.Join(evidenceDir, "receipts.jsonl"), byID, refs)
	r.verifyCheckpoint(evidenceDir, checkpointPath, refs)
	r.verifyArtifacts(jobs)
	return r
}

func (r *VerifyReport) fail(format string, args ...any) {
	r.Failures = append(r.Failures, fmt.Sprintf(format, args...))
}

// expectedOutcome derives the attested outcome from the durable state:
// SUCCEEDED/FAILED mean the workload demonstrably ran (COMPLETED);
// DISPATCH_FAILED means it provably did not (NO_EFFECT).
func expectedOutcome(state string) string {
	switch state {
	case JobStateDispatchFailed:
		return evidence.OutcomeNoEffect
	default:
		return evidence.OutcomeCompleted
	}
}

// providerRunIdentity is the run identity receipts bind to: the
// runtime-owned run id when the backend reported one, the backend's
// handle otherwise. Both identify the same run — the run id is the
// one the runtime itself can reconcile after a restart.
func providerRunIdentity(job *LedgerJob) string {
	if job.BackendJobID != "" {
		return job.BackendJobID
	}
	return job.BackendHandle
}

func (r *VerifyReport) verifyReceipts(path string, byID map[string]*LedgerJob, refs []evidence.TerminalRef) {
	f, err := os.Open(path)
	if err != nil {
		if len(refs) == 0 {
			return // no terminal rows and no receipts — consistent
		}
		r.fail("receipts log unreadable but %d terminal records exist: %v", len(refs), err)
		return
	}
	defer f.Close()

	seen := map[string]bool{}
	terminalIDs := map[string]bool{}
	for _, ref := range refs {
		terminalIDs[ref.ExecutionID] = true
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 128*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		r.Receipts++
		sum := sha256.Sum256(raw)
		receiptSHA := hex.EncodeToString(sum[:])

		rcpt, err := evidence.ParseReceipt(json.RawMessage(raw))
		if err != nil {
			r.fail("receipt %d: %v", line, err)
			continue
		}
		if err := evidence.VerifySignature(rcpt); err != nil {
			r.fail("receipt %d (%s): %v", line, rcpt.ExecutionID, err)
			continue
		}
		if !r.trusted[rcpt.Signer] {
			r.fail("receipt %d (%s): signer %s is not trusted", line, rcpt.ExecutionID, rcpt.Signer)
			continue
		}
		if seen[rcpt.ExecutionID] {
			r.fail("receipt %d: duplicate attestation for %s", line, rcpt.ExecutionID)
			continue
		}
		seen[rcpt.ExecutionID] = true

		job, ok := byID[rcpt.ExecutionID]
		if !ok {
			r.fail("receipt %d: attests job %s which the ledger does not record", line, rcpt.ExecutionID)
			continue
		}
		if !terminalIDs[rcpt.ExecutionID] {
			r.fail("receipt %d: job %s is %s — a receipt exists for a non-terminal job", line, rcpt.ExecutionID, job.State)
			continue
		}
		want := evidence.Binding{
			ExecutionID:    job.JobID,
			Capability:     EvidenceCapability,
			Principal:      job.Principal,
			RequestDigest:  job.ContractHash,
			ProviderID:     job.BackendID,
			ProviderRunID:  providerRunIdentity(job),
			Outcome:        expectedOutcome(job.State),
			EvidenceSHA256: job.ArtifactSHA256,
		}
		if want.EvidenceSHA256 == "" {
			sum := sha256.Sum256(nil)
			want.EvidenceSHA256 = hex.EncodeToString(sum[:])
		}
		if rcpt.Capability != want.Capability || rcpt.Principal != want.Principal ||
			rcpt.RequestDigest != want.RequestDigest || rcpt.ProviderID != want.ProviderID ||
			rcpt.ProviderRunID != want.ProviderRunID || rcpt.Outcome != want.Outcome ||
			rcpt.EvidenceSHA256 != want.EvidenceSHA256 {
			r.fail("receipt %d (%s): binding mismatch — the receipt attests a different job than the ledger records", line, rcpt.ExecutionID)
			continue
		}
		if job.ReceiptSHA256 != receiptSHA {
			r.fail("receipt %d (%s): ledger receipt_sha256 %s does not match the presented receipt %s",
				line, rcpt.ExecutionID, job.ReceiptSHA256, receiptSHA)
		}
	}
	if err := sc.Err(); err != nil {
		r.fail("read receipts: %v", err)
	}
	for id := range terminalIDs {
		if !seen[id] {
			r.fail("terminal job %s has no receipt — evidence gap", id)
		}
	}
}

func (r *VerifyReport) verifyCheckpoint(evidenceDir, arg string, refs []evidence.TerminalRef) {
	path := arg
	if path == "" {
		entries, err := os.ReadDir(filepath.Join(evidenceDir, "checkpoints"))
		if err != nil {
			if len(refs) > 0 {
				r.fail("no checkpoints but %d terminal records exist", len(refs))
			}
			return
		}
		var names []string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "checkpoint-") {
				names = append(names, e.Name())
			}
		}
		if len(names) == 0 {
			if len(refs) > 0 {
				r.fail("no checkpoints but %d terminal records exist", len(refs))
			}
			return
		}
		sort.Strings(names)
		path = filepath.Join(evidenceDir, "checkpoints", names[len(names)-1])
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		r.fail("read checkpoint %s: %v", path, err)
		return
	}
	var cp evidence.Checkpoint
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cp); err != nil {
		r.fail("parse checkpoint %s: %v", path, err)
		return
	}
	// A checkpoint file is emitter bytes, not merely parseable claims:
	// case-insensitive JSON field matching means "public_kEy" would
	// decode to the untouched checkpoint, so non-canonical bytes are a
	// byte-level rewrite even when the decoded claims are identical.
	if canon, err := json.Marshal(&cp); err != nil || !bytes.Equal(bytes.TrimSpace(raw), canon) {
		r.fail("checkpoint %s is not in canonical emitter form — a byte-level rewrite of signed evidence", path)
		return
	}
	r.CheckpointCount = cp.RecordCount
	if err := evidence.VerifyCheckpoint(&cp, refs, r.trusted); err != nil {
		r.fail("checkpoint %s: %v", path, err)
		return
	}
	// Only the latest checkpoint owes current coverage — an explicit
	// older checkpoint is asked "is your prefix still intact", which
	// VerifyCheckpoint already answered.
	if arg == "" && cp.RecordCount < len(refs) {
		r.fail("latest checkpoint covers %d records but %d terminal rows exist — the last %d were never checkpointed",
			cp.RecordCount, len(refs), len(refs)-cp.RecordCount)
	}
}

func (r *VerifyReport) verifyArtifacts(jobs []*LedgerJob) {
	for _, j := range jobs {
		if j.ArtifactSHA256 == "" || j.ResultJSON == "" {
			continue
		}
		var res ExecResult
		if err := json.Unmarshal([]byte(j.ResultJSON), &res); err != nil {
			r.fail("job %s: result_json unparseable: %v", j.JobID, err)
			continue
		}
		if res.OutputPath == "" {
			continue
		}
		r.Artifacts++
		got, err := hashFileSHA256(res.OutputPath)
		if err != nil {
			r.fail("job %s: artifact %s unreadable: %v", j.JobID, res.OutputPath, err)
			continue
		}
		if got != j.ArtifactSHA256 {
			r.fail("job %s: artifact %s digest changed — recorded %s, found %s",
				j.JobID, res.OutputPath, j.ArtifactSHA256, got)
		}
		// The artifact must also agree with the result's own size
		// and with the bound the authority signed: bytes beyond the
		// contract's max_output_bytes, or a truncation flag that
		// disagrees with the stored size, is an integrity failure
		// even when the digest matches.
		info, serr := os.Stat(res.OutputPath)
		if serr != nil {
			r.fail("job %s: artifact %s stat failed: %v", j.JobID, res.OutputPath, serr)
			continue
		}
		if info.Size() != res.OutputBytes {
			r.fail("job %s: artifact %s holds %d bytes but the result reports %d",
				j.JobID, res.OutputPath, info.Size(), res.OutputBytes)
		}
		if c, cerr := ParseContract(json.RawMessage(j.ContractJSON)); cerr == nil && c.Resources.MaxOutputBytes > 0 {
			if uint64(info.Size()) > c.Resources.MaxOutputBytes {
				r.fail("job %s: artifact %s is %d bytes, beyond the contract's %d-byte bound",
					j.JobID, res.OutputPath, info.Size(), c.Resources.MaxOutputBytes)
			} else if res.Truncated && uint64(info.Size()) != c.Resources.MaxOutputBytes {
				r.fail("job %s: artifact %s reports truncation but holds %d of the %d-byte bound",
					j.JobID, res.OutputPath, info.Size(), c.Resources.MaxOutputBytes)
			}
		}
	}
}

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
