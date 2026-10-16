package sandboxcustody

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

	"github.com/openclaw/crabbox/internal/evidence"
)

// VerifyCustodyDir independently audits a custody directory — nothing
// the witness says is trusted. For every acknowledgement on the chain
// it re-derives: the chain link (each record's prev hash is the digest
// of the previous line's raw bytes), the signature (under the record's
// own declared key, over the domain-separated field vector), and the
// held payload (the file named by the digest must hash to it).
// A custody dir with no acks is empty but consistent — nothing was
// ever witnessed there.
func VerifyCustodyDir(dir string) []string {
	var findings []string
	chainPath := filepath.Join(dir, "acks.jsonl")
	f, err := os.Open(chainPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []string{fmt.Sprintf("custody chain unreadable: %v", err)}
	}
	defer f.Close()

	var prevRaw []byte
	var wantSeq int64 = 1
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := append([]byte(nil), sc.Bytes()...)
		rec := &AckRecord{}
		if err := json.Unmarshal(raw, rec); err != nil {
			findings = append(findings, fmt.Sprintf("ack %d malformed: %v", lineNo, err))
			prevRaw = nil
			continue
		}
		if rec.RecordType != "archive-custody-ack/v1" {
			findings = append(findings, fmt.Sprintf("ack %d record_type %q", lineNo, rec.RecordType))
		}
		if rec.AckSeq != wantSeq {
			findings = append(findings, fmt.Sprintf("ack %d seq %d — expected %d (gap or reorder)", lineNo, rec.AckSeq, wantSeq))
		}
		var wantPrev string
		if len(prevRaw) > 0 {
			sum := sha256.Sum256(prevRaw)
			wantPrev = hex.EncodeToString(sum[:])
		}
		if rec.PrevAckSHA256 != wantPrev {
			findings = append(findings, fmt.Sprintf("ack %d prev link %s does not match the previous record's digest %s — the chain was edited", lineNo, rec.PrevAckSHA256, wantPrev))
		}
		pub, perr := base64.StdEncoding.DecodeString(rec.PublicKey)
		if perr != nil || len(pub) != ed25519.PublicKeySize {
			findings = append(findings, fmt.Sprintf("ack %d carries an unusable public key", lineNo))
		} else {
			if rec.Signer != evidence.Fingerprint(ed25519.PublicKey(pub)) {
				findings = append(findings, fmt.Sprintf("ack %d signer %s does not match its public key", lineNo, rec.Signer))
			}
			if err := evidence.VerifyRecordSignature(ed25519.PublicKey(pub), WitnessDomain, rec.Signature, rec.ackFields()...); err != nil {
				findings = append(findings, fmt.Sprintf("ack %d signature invalid: %v", lineNo, err))
			}
		}
		// The held payload is the custody: the file must exist and
		// digest to the witnessed value.
		payload, perr := os.ReadFile(filepath.Join(dir, "segments", rec.PayloadSHA256))
		if perr != nil {
			findings = append(findings, fmt.Sprintf("ack %d payload %s missing from custody: %v", lineNo, rec.PayloadSHA256, perr))
		} else {
			sum := sha256.Sum256(payload)
			if hex.EncodeToString(sum[:]) != rec.PayloadSHA256 {
				findings = append(findings, fmt.Sprintf("ack %d payload %s digests differently — custody bytes were rewritten", lineNo, rec.PayloadSHA256))
			}
		}
		prevRaw = raw
		wantSeq++
	}
	if err := sc.Err(); err != nil {
		findings = append(findings, fmt.Sprintf("read custody chain: %v", err))
	}
	// Orphaned payloads: bytes held with no acknowledgement — the
	// executor never released their rows for these, so they are
	// unexplained rather than damaging, but they are worth surfacing.
	segDir := filepath.Join(dir, "segments")
	entries, derr := os.ReadDir(segDir)
	if derr == nil {
		acked := map[string]bool{}
		if _, err := f.Seek(0, 0); err == nil {
			sc2 := bufio.NewScanner(f)
			sc2.Buffer(make([]byte, 0, 1<<20), 16<<20)
			for sc2.Scan() {
				rec := &AckRecord{}
				if json.Unmarshal(sc2.Bytes(), rec) == nil {
					acked[rec.PayloadSHA256] = true
				}
			}
		}
		for _, e := range entries {
			if e.IsDir() || !acked[e.Name()] {
				findings = append(findings, fmt.Sprintf("custody holds %s with no acknowledgement on the chain", e.Name()))
			}
		}
	}
	return findings
}
