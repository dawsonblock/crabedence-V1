package sandboxexecutor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// ─── Execution evidence log ──────────────────────────────────────────
//
// The ledger records what the executor claims happened; the evidence
// log is what lets anyone else check the claim. Every terminal job
// produces a signed ReceiptV3 before its ledger transition commits —
// evidence precedes the claim it supports — and every terminal write
// re-issues a signed checkpoint over the ledger's terminal
// enumeration, so a verifier holding any checkpoint + the signer
// fingerprint can detect records deleted, rewritten, reordered, or
// rolled back wholesale.
//
// Custody: receipts.jsonl and checkpoints/ are ordinary files meant
// to be copied OFF the executor host. Verification needs only the
// files, the ledger (read-only), and a trusted signer fingerprint —
// the executor's own word is not part of the trust chain.
//
// The evidence signer is NOT an authority key: it attests that work
// ran, never that work was permitted. It lives in the evidence dir
// via evidence.LoadOrCreateSigner (durable no-clobber PKCS8).

const (
	// EvidenceCapability is the receipt capability for sandbox jobs —
	// the action class the signer attests, versioned with the
	// contract it reports on. A V2 contract's receipt can never be
	// presented as evidence for a V1 job, and vice versa.
	EvidenceCapability = "sandbox-job-v2"

	receiptsFile  = "receipts.jsonl"
	checkpointDir = "checkpoints"
	signerFile    = "executor-evidence.pem"
)

// EvidenceLog is the executor's append-only execution-evidence chain.
type EvidenceLog struct {
	dir     string
	signer  *evidence.Signer
	backend string // ProviderID attested in receipts
	now     func() time.Time
	// mu serializes emissions: the live monitor, the refusal path and
	// the reconcile pass all append receipts, and the chain's ordering
	// and fsync guarantees only hold if one writer at a time owns the
	// file.
	mu sync.Mutex
	f  *os.File
	// appended counts receipts written this lifetime — informational
	// for shutdown auditing.
	appended int
}

// DefaultEvidenceKeyPath is where the evidence signer lives inside
// the evidence directory.
func DefaultEvidenceKeyPath(evidenceDir string) string {
	return filepath.Join(evidenceDir, signerFile)
}

// OpenEvidenceLog creates (if needed) the evidence directory and
// opens receipts.jsonl for append. The file lands 0600 — receipts
// are public-verifiable artifacts but the local copy stays owner-only
// like everything else the executor writes.
func OpenEvidenceLog(dir string, signer *evidence.Signer, backendName string) (*EvidenceLog, error) {
	if signer == nil {
		return nil, fmt.Errorf("evidence log requires a signer")
	}
	if strings.TrimSpace(backendName) == "" {
		return nil, fmt.Errorf("evidence log requires a backend identity")
	}
	if err := os.MkdirAll(filepath.Join(dir, checkpointDir), 0o700); err != nil {
		return nil, fmt.Errorf("create evidence dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure evidence dir %s: %w", dir, err)
	}
	f, err := os.OpenFile(filepath.Join(dir, receiptsFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open receipts log: %w", err)
	}
	_ = os.Chmod(f.Name(), 0o600)
	return &EvidenceLog{
		dir:     dir,
		signer:  signer,
		backend: backendName,
		now:     func() time.Time { return time.Now().UTC() },
		f:       f,
	}, nil
}

// SignerFingerprint is the evidence signer's fingerprint — the trust
// anchor an operator publishes for verifiers.
func (e *EvidenceLog) SignerFingerprint() string { return e.signer.Fingerprint() }

// Signer exposes the executor's evidence signer for signing recovery
// checkpoints — the same key that attests receipts and checkpoints,
// so recovery attestations authenticate under the established trust
// root rather than a parallel identity.
func (e *EvidenceLog) Signer() *evidence.Signer { return e.signer }

// emptyEvidenceDigest is the SHA-256 of zero bytes — the evidence
// digest for outcomes that legitimately produced no artifact
// (NO_EFFECT dispatch refusals, monitor errors before capture).
var emptyEvidenceDigest = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

// EmitForJob signs, appends and durably commits one terminal receipt.
// The caller then commits the matching ledger transition (binding
// the returned digest) and issues Checkpoint over the post-transition
// enumeration — receipt first, claim second, checkpoint last. A crash
// between steps leaves an honest gap a verifier flags, never a false
// attestation.
func (e *EvidenceLog) EmitForJob(job *LedgerJob, outcome, artifactSHA, runID string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if artifactSHA == "" {
		artifactSHA = emptyEvidenceDigest
	}
	raw, err := e.signer.Sign(evidence.Binding{
		ExecutionID:    job.JobID,
		Capability:     EvidenceCapability,
		Principal:      job.Principal,
		RequestDigest:  job.ContractHash,
		ProviderID:     e.backend,
		ProviderRunID:  runID,
		Outcome:        outcome,
		EvidenceSHA256: artifactSHA,
	})
	if err != nil {
		return "", fmt.Errorf("sign execution receipt for %s: %w", job.JobID, err)
	}
	sum := sha256.Sum256(raw)
	receiptSHA := hex.EncodeToString(sum[:])
	if _, err := e.f.Write(append(raw, '\n')); err != nil {
		return "", fmt.Errorf("append execution receipt for %s: %w", job.JobID, err)
	}
	// fsync before returning: the receipt must be durable before the
	// ledger records its digest, or a crash could leave a bound
	// digest pointing at a receipt that never existed.
	if err := e.f.Sync(); err != nil {
		return "", fmt.Errorf("commit execution receipt for %s: %w", job.JobID, err)
	}
	e.appended++
	return receiptSHA, nil
}

// Checkpoint signs and durably publishes a checkpoint over refs —
// one file per covered-record count, so each terminal write adds a
// checkpoint without rewriting history. Checkpoint N stays valid
// even as N+k arrive: the prefix property is the point.
func (e *EvidenceLog) Checkpoint(refs []evidence.TerminalRef) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.checkpointLocked(refs)
}

// checkpointLocked is Checkpoint's body for callers that already hold
// the log's lock (Close emits its final checkpoint under the same
// critical section).
func (e *EvidenceLog) checkpointLocked(refs []evidence.TerminalRef) error {
	cp := e.signer.SignCheckpoint(int64(len(refs)), refs)
	raw, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	name := filepath.Join(e.dir, checkpointDir,
		fmt.Sprintf("checkpoint-%08d.json", cp.RecordCount))
	// Atomic publish: temp + fsync + rename + dir fsync — a crash
	// never leaves a truncated checkpoint under the final name, and
	// an existing checkpoint is only ever replaced by one covering
	// the same count (identical content) since counts are unique.
	tmp, err := os.CreateTemp(filepath.Join(e.dir, checkpointDir), ".ckpt-*.tmp")
	if err != nil {
		return fmt.Errorf("publish checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("publish checkpoint: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("publish checkpoint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("publish checkpoint: %w", err)
	}
	if err := os.Rename(tmpName, name); err != nil {
		return fmt.Errorf("publish checkpoint: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("secure checkpoint: %w", err)
	}
	d, err := os.Open(filepath.Join(e.dir, checkpointDir))
	if err != nil {
		return fmt.Errorf("commit checkpoint dir: %w", err)
	}
	derr := d.Sync()
	cerr := d.Close()
	if derr != nil {
		return fmt.Errorf("commit checkpoint dir: %w", derr)
	}
	return cerr
}

// Close issues a final checkpoint (if refs are supplied), syncs and
// closes the receipts file.
func (e *EvidenceLog) Close(refs []evidence.TerminalRef) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var err error
	if refs != nil && e.appended > 0 {
		if cerr := e.checkpointLocked(refs); cerr != nil {
			err = cerr
		}
	}
	if cerr := e.f.Close(); err == nil {
		err = cerr
	}
	return err
}
