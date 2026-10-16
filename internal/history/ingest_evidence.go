package history

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sandboxcustody"
)

// receiptRecord is the canonical payload a receipt event commits to.
// signature_valid records intrinsic verification — the signature
// covers the receipt's own declared key; trusted records whether the
// signer fingerprint is in the caller's trust set. Memory records
// what the evidence dir contains AND what it could establish about
// it — a receipt that fails intrinsic checks is ingested as a
// record of failure, never dropped silently.
type receiptRecord struct {
	ExecutionID    string          `json:"execution_id"`
	Outcome        string          `json:"outcome"`
	RequestDigest  string          `json:"request_digest"`
	ProviderID     string          `json:"provider_id"`
	ProviderRunID  string          `json:"provider_run_id"`
	EvidenceSHA256 string          `json:"evidence_sha256"`
	IssuedAt       string          `json:"issued_at"`
	Signer         string          `json:"signer"`
	SignatureValid bool            `json:"signature_valid"`
	Trusted        bool            `json:"trusted"`
	ReceiptSHA256  string          `json:"receipt_sha256"`
	Raw            json.RawMessage `json:"-"`
}

type checkpointRecord struct {
	Sequence    int64  `json:"sequence"`
	RecordCount int    `json:"record_count"`
	ChainDigest string `json:"chain_digest"`
	IssuedAt    string `json:"issued_at"`
	Signer      string `json:"signer"`
	// Verified records a full VerifyCheckpoint result — only
	// possible when the caller supplies the ledger's terminal
	// enumeration. No refs means recorded-but-not-proven, which is
	// stated, never implied.
	Verified *bool `json:"verified,omitempty"`
	Trusted  bool  `json:"trusted"`
}

// IngestEvidenceDir records an executor evidence directory:
// receipts.jsonl as receipt events and checkpoints/*.json as
// checkpoint events. trustedSigners is the caller's trust set — an
// empty set marks every signer untrusted (memory reports, it does
// not decide). refs, when non-nil, is the ledger's terminal
// enumeration and enables full checkpoint verification; nil records
// checkpoints as unverified-by-ingestion.
func (s *Store) IngestEvidenceDir(dir string, trustedSigners map[string]bool, refs []evidence.TerminalRef) (int, error) {
	var events []*Event

	// ── receipts.jsonl ───────────────────────────────────────────
	rf, err := os.Open(filepath.Join(dir, "receipts.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("open receipts: %w", err)
	}
	if err == nil {
		sc := bufio.NewScanner(rf)
		sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			raw := append([]byte(nil), sc.Bytes()...)
			if len(raw) == 0 {
				continue
			}
			r, perr := evidence.ParseReceipt(raw)
			if perr != nil {
				rf.Close()
				return 0, fmt.Errorf("receipts.jsonl line %d: %w", lineNo, perr)
			}
			sum := sha256.Sum256(raw)
			rec := receiptRecord{
				ExecutionID:    r.ExecutionID,
				Outcome:        r.Outcome,
				RequestDigest:  r.RequestDigest,
				ProviderID:     r.ProviderID,
				ProviderRunID:  r.ProviderRunID,
				EvidenceSHA256: r.EvidenceSHA256,
				IssuedAt:       r.IssuedAt,
				Signer:         r.Signer,
				Trusted:        trustedSigners[r.Signer],
				ReceiptSHA256:  hex.EncodeToString(sum[:]),
			}
			rec.SignatureValid = evidence.VerifySignature(r) == nil
			payload, err := json.Marshal(rec)
			if err != nil {
				rf.Close()
				return 0, err
			}
			at := receiptTime(r.IssuedAt)
			events = append(events, &Event{
				DedupeKey:   "receipt:" + rec.ReceiptSHA256,
				Kind:        KindReceipt,
				Subject:     r.ExecutionID,
				Correlation: r.RequestDigest,
				Source:      "evidence:" + dir,
				OccurredAt:  at,
				Payload:     payload,
			})
		}
		rf.Close()
		if err := sc.Err(); err != nil {
			return 0, fmt.Errorf("read receipts: %w", err)
		}
	}

	// ── checkpoints/ ─────────────────────────────────────────────
	cpDir := filepath.Join(dir, "checkpoints")
	entries, err := os.ReadDir(cpDir)
	if err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("read checkpoints: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(cpDir, e.Name()))
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		cp := &evidence.Checkpoint{}
		if err := json.Unmarshal(raw, cp); err != nil {
			return 0, fmt.Errorf("checkpoint %s malformed: %w", e.Name(), err)
		}
		rec := checkpointRecord{
			Sequence:    cp.Sequence,
			RecordCount: cp.RecordCount,
			ChainDigest: cp.ChainDigest,
			IssuedAt:    cp.IssuedAt,
			Signer:      cp.Signer,
			Trusted:     trustedSigners[cp.Signer],
		}
		if refs != nil {
			v := evidence.VerifyCheckpoint(cp, refs, trustedSigners) == nil
			rec.Verified = &v
		}
		payload, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		sum := sha256.Sum256(raw)
		events = append(events, &Event{
			DedupeKey:  "checkpoint:" + hex.EncodeToString(sum[:]),
			Kind:       KindCheckpoint,
			Subject:    fmt.Sprintf("checkpoint-%08d", cp.Sequence),
			Source:     "evidence:" + dir,
			OccurredAt: receiptTime(cp.IssuedAt),
			Payload:    payload,
		})
	}

	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}

// custodyAckRecord is the canonical payload a custody_ack event
// commits to — the witness's record plus the link-level checks the
// ingester re-derived from the raw chain bytes.
type custodyAckRecord struct {
	AckSeq           int64  `json:"ack_seq"`
	SegmentSeq       int64  `json:"segment_seq"`
	FirstTerminalSeq int64  `json:"first_terminal_seq"`
	LastTerminalSeq  int64  `json:"last_terminal_seq"`
	RowCount         int    `json:"row_count"`
	PayloadSHA256    string `json:"payload_sha256"`
	WitnessedAt      string `json:"witnessed_at"`
	Signer           string `json:"signer"`
	ChainLinkValid   bool   `json:"chain_link_valid"`
	SignatureValid   bool   `json:"signature_valid"`
	SegmentHeld      bool   `json:"segment_held"`
	Trusted          bool   `json:"trusted"`
}

// IngestCustodyDir records an external custody store's ack chain as
// custody_ack events, re-deriving each record's chain link, its
// signature under the declared key, and that the segment bytes it
// names are actually held — the same checks VerifyCustodyDir runs,
// so memory's custody record is the custody the store can prove.
func (s *Store) IngestCustodyDir(dir string, trustedSigners map[string]bool) (int, error) {
	f, err := os.Open(filepath.Join(dir, "acks.jsonl"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open custody chain: %w", err)
	}
	defer f.Close()

	var events []*Event
	var prevRaw []byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := append([]byte(nil), sc.Bytes()...)
		if len(raw) == 0 {
			continue
		}
		rec := &sandboxcustody.AckRecord{}
		if err := json.Unmarshal(raw, rec); err != nil {
			return 0, fmt.Errorf("custody ack line %d malformed: %w", lineNo, err)
		}
		var wantPrev string
		if len(prevRaw) > 0 {
			sum := sha256.Sum256(prevRaw)
			wantPrev = hex.EncodeToString(sum[:])
		}
		out := custodyAckRecord{
			AckSeq:           rec.AckSeq,
			SegmentSeq:       rec.SegmentSeq,
			FirstTerminalSeq: rec.FirstTerminalSeq,
			LastTerminalSeq:  rec.LastTerminalSeq,
			RowCount:         rec.RowCount,
			PayloadSHA256:    rec.PayloadSHA256,
			WitnessedAt:      rec.WitnessedAt,
			Signer:           rec.Signer,
			ChainLinkValid:   rec.PrevAckSHA256 == wantPrev,
			Trusted:          trustedSigners[rec.Signer],
		}
		if pub, err := base64.StdEncoding.DecodeString(rec.PublicKey); err == nil && len(pub) == ed25519.PublicKeySize {
			out.SignatureValid = evidence.VerifyRecordSignature(
				ed25519.PublicKey(pub), sandboxcustody.WitnessDomain, rec.Signature,
				rec.RecordType,
				fmt.Sprint(rec.AckSeq),
				fmt.Sprint(rec.SegmentSeq),
				fmt.Sprint(rec.FirstTerminalSeq),
				fmt.Sprint(rec.LastTerminalSeq),
				fmt.Sprint(rec.RowCount),
				rec.PayloadSHA256,
				rec.PrevAckSHA256,
				rec.WitnessedAt,
				rec.PublicKey,
				rec.Signer,
			) == nil && rec.Signer == evidence.Fingerprint(ed25519.PublicKey(pub))
		}
		if seg, err := os.ReadFile(filepath.Join(dir, "segments", rec.PayloadSHA256)); err == nil {
			sum := sha256.Sum256(seg)
			out.SegmentHeld = hex.EncodeToString(sum[:]) == rec.PayloadSHA256
		}
		payload, err := json.Marshal(out)
		if err != nil {
			return 0, err
		}
		sum := sha256.Sum256(raw)
		events = append(events, &Event{
			DedupeKey:   "custody:" + hex.EncodeToString(sum[:]),
			Kind:        KindCustodyAck,
			Subject:     fmt.Sprintf("segment-%d", rec.SegmentSeq),
			Correlation: rec.PayloadSHA256,
			Source:      "custody:" + dir,
			OccurredAt:  receiptTime(rec.WitnessedAt),
			Payload:     payload,
		})
		prevRaw = raw
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read custody chain: %w", err)
	}
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}

// receiptTime parses an RFC3339Nano timestamp to unix ms; a record
// whose time cannot be parsed lands at 0 rather than being
// fabricated — its chain position still orders it.
func receiptTime(s string) int64 {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}
