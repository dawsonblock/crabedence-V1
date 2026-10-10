package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// ─── Checkpoints ─────────────────────────────────────────────────────
//
// A receipt proves one execution; a checkpoint proves the *set*. It
// commits to a canonical enumeration of terminal executions, so an
// operator who holds a sequence of checkpoints independently can prove
// that the store still contains everything each checkpoint covered —
// the property receipts alone cannot give: a receipt left in the same
// store as the record it describes is rewritten or deleted with it, and
// a store rolled back to an earlier snapshot silently loses the
// executions that happened after it.
//
// The chain digest covers the length-prefixed canonical fields of every
// covered record, in terminalization-commit order — the durable
// terminal_seq assigned transactionally with each terminal write, so
// the enumeration is append-only by construction. Verification
// recomputes the chain over the first RecordCount records of the
// current store: if any covered record was deleted, reordered or
// rewritten, the digest differs; if the store now holds fewer records,
// the checkpoint's count no longer fits. Records appended after the
// checkpoint do not affect either check — the prefix property is what
// makes a monotonic sequence of checkpoints meaningful.
//
// Schema v1 checkpoints (execution_id order, no terminal_seq in the
// canon) remain verifiable under their own ordering for stores that
// issued them; v1 cannot promise append-only semantics — a late
// terminalization legitimately reorders the v1 enumeration — so v1
// verification answers "the covered records still exist, unchanged" and
// nothing more. Issue a fresh v2 baseline after upgrading.

// CheckpointSchemaVersion is the current checkpoint schema version.
const CheckpointSchemaVersion = 2

// CheckpointType identifies the checkpoint schema in serialized form.
const CheckpointType = "evidence-checkpoint-v2"

// checkpointSigningDomain separates checkpoint signatures from every
// other message the signer produces (receipts use signingDomain).
const checkpointSigningDomain = "crabbox-evidence-checkpoint-v2\x00"

// Legacy v1 identifiers, kept so checkpoints issued before the
// terminal-seq ledger upgrade remain verifiable under v1 semantics.
const checkpointSchemaVersionV1 = 1
const checkpointTypeV1 = "evidence-checkpoint-v1"
const checkpointSigningDomainV1 = "crabbox-evidence-checkpoint-v1\x00"

// TerminalRef is one terminal execution as a checkpoint commits to it:
// the durable terminalization sequence, the execution identity, the
// terminal state, the request digest, the immutable terminal
// result/evidence/receipt digests, the provider operation identity, and
// the terminalization timestamp.
type TerminalRef struct {
	Seq                    int64  `json:"terminal_seq"`
	ExecutionID            string `json:"execution_id"`
	State                  string `json:"state"`
	RequestDigest          string `json:"request_digest"`
	TerminalResultDigest   string `json:"terminal_result_digest"`
	TerminalEvidenceDigest string `json:"terminal_evidence_digest"`
	TerminalReceiptDigest  string `json:"terminal_receipt_digest"`
	ProviderID             string `json:"provider_id"`
	ProviderRunID          string `json:"provider_run_id"`
	UpdatedAt              string `json:"updated_at"`
}

// Checkpoint commits to the first RecordCount records of the canonical
// terminal enumeration. The signature covers every field except itself.
type Checkpoint struct {
	SchemaVersion  int    `json:"schema_version"`
	CheckpointType string `json:"checkpoint_type"`
	Sequence       int64  `json:"sequence"`
	IssuedAt       string `json:"issued_at"`
	RecordCount    int    `json:"record_count"`
	ChainDigest    string `json:"chain_digest"`
	PublicKey      string `json:"public_key"`
	Signer         string `json:"signer"`
	Signature      string `json:"signature"`
}

// CheckpointChainDigest computes the canonical chain digest over refs —
// a SHA-256 over the length-prefixed canonical fields, in enumeration
// order. The same refs always produce the same digest, on both engines.
// The durable terminal_seq is committed first: a checkpoint binds not
// only the record content but its position in the ledger, so
// renumbering the ledger is itself detected.
func CheckpointChainDigest(refs []TerminalRef) string {
	h := sha256.New()
	var length [4]byte
	for _, ref := range refs {
		for _, value := range []string{
			strconv.FormatInt(ref.Seq, 10),
			ref.ExecutionID,
			ref.State,
			ref.RequestDigest,
			ref.TerminalResultDigest,
			ref.TerminalEvidenceDigest,
			ref.TerminalReceiptDigest,
			ref.ProviderID,
			ref.ProviderRunID,
			ref.UpdatedAt,
		} {
			binary.BigEndian.PutUint32(length[:], uint32(len(value)))
			h.Write(length[:])
			h.Write([]byte(value))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// checkpointChainDigestV1 is the legacy v1 canon: the same nine fields
// as CheckpointChainDigest minus the terminal_seq, computed over the
// execution_id-ordered enumeration. It exists so checkpoints issued
// before the ledger upgrade can still be answered.
func checkpointChainDigestV1(refs []TerminalRef) string {
	h := sha256.New()
	var length [4]byte
	for _, ref := range refs {
		for _, value := range []string{
			ref.ExecutionID,
			ref.State,
			ref.RequestDigest,
			ref.TerminalResultDigest,
			ref.TerminalEvidenceDigest,
			ref.TerminalReceiptDigest,
			ref.ProviderID,
			ref.ProviderRunID,
			ref.UpdatedAt,
		} {
			binary.BigEndian.PutUint32(length[:], uint32(len(value)))
			h.Write(length[:])
			h.Write([]byte(value))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SignCheckpoint produces a checkpoint covering refs, signed by the
// evidence signer. The sequence is supplied by the emitter so an operator
// holding the sequence can detect missing checkpoints.
func (s *Signer) SignCheckpoint(sequence int64, refs []TerminalRef) *Checkpoint {
	pub := s.key.Public().(ed25519.PublicKey)
	cp := &Checkpoint{
		SchemaVersion:  CheckpointSchemaVersion,
		CheckpointType: CheckpointType,
		Sequence:       sequence,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		RecordCount:    len(refs),
		ChainDigest:    CheckpointChainDigest(refs),
		PublicKey:      base64.StdEncoding.EncodeToString(pub),
		Signer:         Fingerprint(pub),
	}
	cp.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(s.key, checkpointSigningBytes(*cp)))
	return cp
}

// checkpointSigningBytes builds the canonical signing payload — the same
// domain-separated length-prefixed construction as receipt
// signingBytes, under the checkpoint domain for the schema version.
func checkpointSigningBytes(cp Checkpoint) []byte {
	domain := checkpointSigningDomain
	if cp.CheckpointType == checkpointTypeV1 {
		domain = checkpointSigningDomainV1
	}
	values := []string{
		cp.CheckpointType,
		strconv.FormatInt(cp.Sequence, 10),
		cp.IssuedAt,
		strconv.Itoa(cp.RecordCount),
		cp.ChainDigest,
		cp.PublicKey,
		cp.Signer,
	}
	var payload bytes.Buffer
	payload.WriteString(domain)
	var length [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		payload.Write(length[:])
		payload.WriteString(value)
	}
	return payload.Bytes()
}

// VerifyCheckpoint verifies a checkpoint against the store's current
// terminal enumeration:
//
//   - the checkpoint is well-formed and signed by a trusted signer;
//   - the store still holds at least the covered records
//     (RecordCount ≤ len(current));
//   - the first RecordCount records recompute to the checkpoint's chain
//     digest — deleting, reordering or rewriting any covered record
//     fails verification.
//
// current must be the store's terminal enumeration in terminal_seq
// order. A legacy v1 checkpoint is verified under its own semantics —
// the covered prefix of the execution_id-ordered enumeration — which
// detects deletion, rewrite and rollback of covered records but cannot
// assert append-only ordering. Only v2 checkpoints carry that
// guarantee.
func VerifyCheckpoint(cp *Checkpoint, current []TerminalRef, trustedSigners map[string]bool) error {
	legacy, err := verifyCheckpointShape(cp, trustedSigners)
	if err != nil {
		return err
	}
	return verifyCheckpointAgainstStore(cp, current, legacy)
}

// verifyCheckpointShape carries the checkpoint's intrinsic checks:
// schema identity, plausible field shapes, a signer fingerprint bound
// to the presented public key and present in the trusted set, and an
// ed25519 signature over the canonical payload. It answers "this is a
// genuine checkpoint from a trusted signer" without consulting the
// store, and reports whether the checkpoint carries v1 semantics so the
// caller can verify the chain under the matching canon.
func verifyCheckpointShape(cp *Checkpoint, trustedSigners map[string]bool) (bool, error) {
	if cp == nil {
		return false, errors.New("checkpoint is nil")
	}
	legacy := false
	switch {
	case cp.CheckpointType == CheckpointType && cp.SchemaVersion == CheckpointSchemaVersion:
	case cp.CheckpointType == checkpointTypeV1 && cp.SchemaVersion == checkpointSchemaVersionV1:
		legacy = true
	default:
		return false, fmt.Errorf("unsupported checkpoint schema %q version %d", cp.CheckpointType, cp.SchemaVersion)
	}
	if cp.Sequence < 0 {
		return false, fmt.Errorf("invalid sequence %d", cp.Sequence)
	}
	if cp.RecordCount < 0 {
		return false, fmt.Errorf("invalid record_count %d", cp.RecordCount)
	}
	if _, err := time.Parse(time.RFC3339Nano, cp.IssuedAt); err != nil {
		return false, fmt.Errorf("invalid issued_at")
	}
	if _, err := hex.DecodeString(cp.ChainDigest); err != nil || len(cp.ChainDigest) != 2*sha256.Size {
		return false, fmt.Errorf("invalid chain_digest")
	}
	pub, err := base64.StdEncoding.DecodeString(cp.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public_key")
	}
	if cp.Signer != Fingerprint(pub) {
		return false, fmt.Errorf("signer fingerprint does not match public_key")
	}
	if !trustedSigners[cp.Signer] {
		return false, fmt.Errorf("signer %s not trusted", cp.Signer)
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature")
	}
	if !ed25519.Verify(pub, checkpointSigningBytes(*cp), sig) {
		return false, fmt.Errorf("invalid signature")
	}
	return legacy, nil
}

// verifyCheckpointAgainstStore carries the coverage checks: the store
// must still hold at least the committed records and the covered prefix
// must recompute to the committed chain digest, under the schema's own
// enumeration semantics.
func verifyCheckpointAgainstStore(cp *Checkpoint, current []TerminalRef, legacy bool) error {
	if len(current) < cp.RecordCount {
		return fmt.Errorf("store holds %d terminal records but the checkpoint commits to %d — records deleted or the store rolled back",
			len(current), cp.RecordCount)
	}
	if legacy {
		ordered := make([]TerminalRef, len(current))
		copy(ordered, current)
		sort.SliceStable(ordered, func(i, j int) bool {
			return ordered[i].ExecutionID < ordered[j].ExecutionID
		})
		if got := checkpointChainDigestV1(ordered[:cp.RecordCount]); got != cp.ChainDigest {
			return fmt.Errorf("chain mismatch — a covered terminal record changed or moved since the checkpoint")
		}
		return nil
	}
	for i, ref := range current[:cp.RecordCount] {
		if i > 0 && ref.Seq <= current[i-1].Seq {
			return fmt.Errorf("terminal enumeration is not in commit order (seq %d after %d)", ref.Seq, current[i-1].Seq)
		}
	}
	if got := CheckpointChainDigest(current[:cp.RecordCount]); got != cp.ChainDigest {
		return fmt.Errorf("chain mismatch — a covered terminal record changed or moved since the checkpoint")
	}
	return nil
}
