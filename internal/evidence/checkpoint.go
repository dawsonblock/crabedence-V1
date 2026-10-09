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
// covered record, in execution_id order — an order the store controls
// (execution ids are time-ordered UUIDv7) and that never changes,
// because terminal records are immutable. Verification recomputes the
// chain over the first RecordCount records of the current store: if any
// covered record was deleted, reordered or rewritten, the digest
// differs; if the store now holds fewer records, the checkpoint's count
// no longer fits. Records appended after the checkpoint do not affect
// either check — the prefix property is what makes a monotonic sequence
// of checkpoints meaningful.

// CheckpointSchemaVersion is the only accepted checkpoint schema version.
const CheckpointSchemaVersion = 1

// CheckpointType identifies the checkpoint schema in serialized form.
const CheckpointType = "evidence-checkpoint-v1"

// checkpointSigningDomain separates checkpoint signatures from every
// other message the signer produces (receipts use signingDomain).
const checkpointSigningDomain = "crabbox-evidence-checkpoint-v1\x00"

// TerminalRef is one terminal execution as a checkpoint commits to it:
// the execution identity, the terminal state, the request digest, the
// immutable terminal result/evidence/receipt digests, the provider
// operation identity, and the terminalization timestamp.
type TerminalRef struct {
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
func CheckpointChainDigest(refs []TerminalRef) string {
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
// signingBytes, under the checkpoint domain.
func checkpointSigningBytes(cp Checkpoint) []byte {
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
	payload.WriteString(checkpointSigningDomain)
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
func VerifyCheckpoint(cp *Checkpoint, current []TerminalRef, trustedSigners map[string]bool) error {
	if cp == nil {
		return errors.New("checkpoint is nil")
	}
	if cp.CheckpointType != CheckpointType {
		return fmt.Errorf("unsupported checkpoint_type %q", cp.CheckpointType)
	}
	if cp.SchemaVersion != CheckpointSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", cp.SchemaVersion)
	}
	if cp.Sequence < 0 {
		return fmt.Errorf("invalid sequence %d", cp.Sequence)
	}
	if cp.RecordCount < 0 {
		return fmt.Errorf("invalid record_count %d", cp.RecordCount)
	}
	if _, err := time.Parse(time.RFC3339Nano, cp.IssuedAt); err != nil {
		return fmt.Errorf("invalid issued_at")
	}
	if _, err := hex.DecodeString(cp.ChainDigest); err != nil || len(cp.ChainDigest) != 2*sha256.Size {
		return fmt.Errorf("invalid chain_digest")
	}
	pub, err := base64.StdEncoding.DecodeString(cp.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public_key")
	}
	if cp.Signer != Fingerprint(pub) {
		return fmt.Errorf("signer fingerprint does not match public_key")
	}
	if !trustedSigners[cp.Signer] {
		return fmt.Errorf("signer %s not trusted", cp.Signer)
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature")
	}
	if !ed25519.Verify(pub, checkpointSigningBytes(*cp), sig) {
		return fmt.Errorf("invalid signature")
	}
	if len(current) < cp.RecordCount {
		return fmt.Errorf("store holds %d terminal records but the checkpoint commits to %d — records deleted or the store rolled back",
			len(current), cp.RecordCount)
	}
	if got := CheckpointChainDigest(current[:cp.RecordCount]); got != cp.ChainDigest {
		return fmt.Errorf("chain mismatch — a covered terminal record changed or moved since the checkpoint")
	}
	return nil
}
