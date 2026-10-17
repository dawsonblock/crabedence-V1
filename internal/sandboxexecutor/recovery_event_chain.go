package sandboxexecutor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// Authenticated recovery history (RC7.5, INV-05).
//
// recovery_events was durable but not independently verifiable: a
// tampered row, a deleted range, or a wholesale rollback of the table
// left no detectable trace outside the database's own say-so. The
// chain closes that: every event commits its own digest over the
// canonical event and the digest of the event before it, inside the
// same transaction as the state change it records — a committed
// history that cannot be rewritten anywhere without breaking every
// later digest.
//
// A hash chain alone is not enough: an attacker rewriting the whole
// table could recompute every digest. The signed recovery checkpoint
// is the second half — the evidence signer commits to the chain head
// and covered sequence range, so an externally retained checkpoint
// detects a recomputed or rolled-back local history. The custody
// outbox carries those checkpoints to an independently controlled
// destination.

const (
	// recoveryEventDomain separates recovery-event digests from every
	// other SHA-256 commitment this system makes.
	recoveryEventDomain = "crabbox-recovery-event-v1\x00"
	// recoveryCheckpointDomain separates recovery checkpoint
	// signatures from receipts, evidence checkpoints and custody
	// acks — a signature valid here is valid nowhere else.
	recoveryCheckpointDomain = "crabbox-recovery-checkpoint-v1\x00"
	// RecoveryCheckpointType identifies the checkpoint schema in
	// serialized form.
	RecoveryCheckpointType = "recovery-checkpoint-v1"
	// recoveryCheckpointSchema is the current checkpoint schema.
	recoveryCheckpointSchema = 1
	// recoveryGenesisPrev is the previous-digest sentinel of the
	// chain's first event — the empty-chain head.
	recoveryGenesisPrev = ""
)

// recoveryEventHash computes one event's digest over its canonical
// form: domain separator plus the length-prefixed fields in schema
// order. The previous event's digest is a field, so an event can only
// stand where it was written — a modified, deleted, reordered or
// replayed predecessor changes every later digest.
func recoveryEventHash(seq int64, prevSHA, kind, subject, detail string, atMS, claimUID int64) string {
	h := sha256.New()
	h.Write([]byte(recoveryEventDomain))
	var length [4]byte
	for _, value := range []string{
		"1", // event schema version
		strconv.FormatInt(seq, 10),
		prevSHA,
		kind,
		subject,
		detail,
		strconv.FormatInt(atMS, 10),
		strconv.FormatInt(claimUID, 10),
	} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		h.Write(length[:])
		h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// recordRecoveryEventTx is the chain-aware mandatory-evidence write.
// The event's sequence is allocated by the insert; its digest — over
// the sequence and the chain head read inside the same transaction —
// lands in the same commit as whatever state change required the
// record. An event whose chain position cannot be durably bound never
// commits: the calling transaction rolls back with it.
func (l *Ledger) recordRecoveryEventTx(tx *sql.Tx, kind, subject, detail string, at time.Time, claimUID int64) error {
	var prev string
	err := tx.QueryRow(`SELECT event_sha256 FROM recovery_events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read recovery chain head: %w", err)
	}
	res, err := tx.Exec(`INSERT INTO recovery_events
		(at_ms, kind, subject, detail, claim_uid, authenticated)
		VALUES (?,?,?,?,?,1)`,
		at.UnixMilli(), kind, subject, detail, claimUID)
	if err != nil {
		return err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("read recovery event sequence: %w", err)
	}
	sha := recoveryEventHash(seq, prev, kind, subject, detail, at.UnixMilli(), claimUID)
	if _, err := tx.Exec(`UPDATE recovery_events SET prev_event_sha256 = ?, event_sha256 = ? WHERE seq = ?`,
		prev, sha, seq); err != nil {
		return fmt.Errorf("bind recovery event %d into the chain: %w", seq, err)
	}
	return nil
}

// recoveryChainHead reads the current chain tip — the digest a
// checkpoint commits to. hasAny reports whether the table holds any
// events at all.
func (l *Ledger) recoveryChainHeadTx(tx *sql.Tx) (head string, seq int64, err error) {
	err = tx.QueryRow(`SELECT event_sha256, seq FROM recovery_events ORDER BY seq DESC LIMIT 1`).Scan(&head, &seq)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	return head, seq, err
}

// RecoveryChainHead returns the durable chain tip (digest + sequence)
// for checkpoint emission and verification.
func (l *Ledger) RecoveryChainHead() (string, int64, error) {
	tx, err := l.db.BeginTx(context.Background(), nil)
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	return l.recoveryChainHeadTx(tx)
}

// RecoveryCheckpoint is a signed commitment to the recovery chain's
// head over a covered sequence range: an externally retained copy
// detects a rewritten, truncated or rolled-back local history that
// recomputing digests alone cannot reveal.
type RecoveryCheckpoint struct {
	SchemaVersion  int    `json:"schema_version"`
	CheckpointType string `json:"checkpoint_type"`
	// FirstSeq..LastSeq is the committed event range; EventCount is
	// the total event population the checkpoint covers, and
	// ChainHeadSHA256 is the chain tip at LastSeq.
	FirstSeq        int64  `json:"first_seq"`
	LastSeq         int64  `json:"last_seq"`
	EventCount      int64  `json:"event_count"`
	ChainHeadSHA256 string `json:"chain_head_sha256"`
	// Epoch names the ledger generation that issued the checkpoint —
	// the deployment identity this attestation belongs to.
	Epoch     uint64 `json:"epoch"`
	IssuedAt  string `json:"issued_at"`
	PublicKey string `json:"public_key"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

// checkpointFields is the canonical signing field order — the same
// order verification reconstructs.
func (c *RecoveryCheckpoint) checkpointFields() []string {
	return []string{
		c.CheckpointType,
		strconv.Itoa(c.SchemaVersion),
		strconv.FormatInt(c.FirstSeq, 10),
		strconv.FormatInt(c.LastSeq, 10),
		strconv.FormatInt(c.EventCount, 10),
		c.ChainHeadSHA256,
		strconv.FormatUint(c.Epoch, 10),
		c.IssuedAt,
		c.PublicKey,
		c.Signer,
	}
}

// signRecoveryCheckpoint issues a signed checkpoint over the current
// chain head. An empty chain signs a genesis checkpoint — attesting
// "no recovery history yet" is as honest a statement as any other.
func (l *Ledger) signRecoveryCheckpoint(signer *evidence.Signer, now time.Time) (*RecoveryCheckpoint, error) {
	head, seq, err := l.RecoveryChainHead()
	if err != nil {
		return nil, err
	}
	var first int64
	var count int64
	row := l.db.QueryRow(`SELECT COALESCE(MIN(seq),0), COUNT(*) FROM recovery_events`)
	if err := row.Scan(&first, &count); err != nil {
		return nil, fmt.Errorf("read recovery event range: %w", err)
	}
	pub := signer.PublicKey()
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	cp := &RecoveryCheckpoint{
		SchemaVersion:   recoveryCheckpointSchema,
		CheckpointType:  RecoveryCheckpointType,
		FirstSeq:        first,
		LastSeq:         seq,
		EventCount:      count,
		ChainHeadSHA256: head,
		Epoch:           l.epoch,
		IssuedAt:        now.UTC().Format(time.RFC3339Nano),
		PublicKey:       pubB64,
		Signer:          evidence.Fingerprint(pub),
	}
	sig, err := signer.SignRecord(recoveryCheckpointDomain, cp.checkpointFields()...)
	if err != nil {
		return nil, fmt.Errorf("sign recovery checkpoint: %w", err)
	}
	cp.Signature = sig
	return cp, nil
}

// VerifyRecoveryCheckpointSignature checks a checkpoint's intrinsic
// validity: schema identity, plausible fields, a signer fingerprint
// bound to the presented public key, and an ed25519 signature over
// the canonical record. trustedSigners is the caller's trust root.
func VerifyRecoveryCheckpointSignature(cp *RecoveryCheckpoint, trustedSigners map[string]bool) error {
	if cp == nil {
		return fmt.Errorf("recovery checkpoint is nil")
	}
	if cp.CheckpointType != RecoveryCheckpointType || cp.SchemaVersion != recoveryCheckpointSchema {
		return fmt.Errorf("unsupported recovery checkpoint schema %q version %d", cp.CheckpointType, cp.SchemaVersion)
	}
	if cp.LastSeq < 0 || cp.FirstSeq < 0 || cp.EventCount < 0 || cp.FirstSeq > cp.LastSeq && cp.EventCount > 0 {
		return fmt.Errorf("invalid committed range %d..%d over %d events", cp.FirstSeq, cp.LastSeq, cp.EventCount)
	}
	if _, err := time.Parse(time.RFC3339Nano, cp.IssuedAt); err != nil {
		return fmt.Errorf("invalid issued_at")
	}
	if _, err := hex.DecodeString(cp.ChainHeadSHA256); err != nil || (cp.EventCount > 0 && len(cp.ChainHeadSHA256) != 2*sha256.Size) {
		return fmt.Errorf("invalid chain_head_sha256")
	}
	pub, err := base64.StdEncoding.DecodeString(cp.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public_key")
	}
	if cp.Signer != evidence.Fingerprint(pub) {
		return fmt.Errorf("signer fingerprint does not match public_key")
	}
	if !trustedSigners[cp.Signer] {
		return fmt.Errorf("signer %s not trusted", cp.Signer)
	}
	if err := evidence.VerifyRecordSignature(pub, recoveryCheckpointDomain, cp.Signature, cp.checkpointFields()...); err != nil {
		return err
	}
	return nil
}

// EmitRecoveryCheckpoint signs a checkpoint over the current chain
// head and durably queues it for custody — one row per head: a head
// already queued carries nothing new, so emission is skipped rather
// than flooding the outbox with redundant attestations. Returns the
// outbox sequence and whether a checkpoint was actually emitted.
func (l *Ledger) EmitRecoveryCheckpoint(signer *evidence.Signer) (int64, bool, error) {
	if signer == nil {
		return 0, false, fmt.Errorf("recovery checkpoint emission requires a signer")
	}
	head, _, err := l.RecoveryChainHead()
	if err != nil {
		return 0, false, err
	}
	last, err := l.lastOutboxHead()
	if err != nil {
		return 0, false, fmt.Errorf("read custody outbox head: %w", err)
	}
	if head == last {
		return 0, false, nil
	}
	cp, err := l.signRecoveryCheckpoint(signer, time.Now().UTC())
	if err != nil {
		return 0, false, err
	}
	blob, err := json.Marshal(cp)
	if err != nil {
		return 0, false, fmt.Errorf("serialize recovery checkpoint: %w", err)
	}
	// The row's head column is the head the checkpoint actually
	// committed to — if the chain advanced between the skip check and
	// signing, the record names the signed tip, and the newer head
	// emits its own checkpoint on the next pass.
	seq, err := l.EnqueueRecoveryCheckpoint(cp.ChainHeadSHA256, blob)
	return seq, true, err
}

// VerifyRecoveryEvents recomputes the recovery chain over the
// ledger's current rows and reports every point it fails to hold:
// a modified field, a missing predecessor, a replayed or reordered
// sequence, a duplicate position, a forged digest. Legacy rows —
// written before the chain existed — are verified under the same
// recomputation: the chain binds them too, while their authenticated
// flag stays honestly false.
func (l *Ledger) VerifyRecoveryEvents() ([]string, error) {
	rows, err := l.db.Query(`SELECT seq, at_ms, kind, subject, detail, claim_uid, prev_event_sha256, event_sha256
		FROM recovery_events ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []string
	prev := recoveryGenesisPrev
	var expectedSeq int64 = -1
	count := int64(0)
	for rows.Next() {
		var seq, atMS, claimUID int64
		var kind, subject, detail, prevSHA, sha string
		if err := rows.Scan(&seq, &atMS, &kind, &subject, &detail, &claimUID, &prevSHA, &sha); err != nil {
			return nil, err
		}
		count++
		if expectedSeq >= 0 && seq <= expectedSeq {
			findings = append(findings,
				fmt.Sprintf("recovery event seq %d does not advance past %d — duplicate or reordered position", seq, expectedSeq))
		}
		expectedSeq = seq
		if prevSHA != prev {
			findings = append(findings,
				fmt.Sprintf("recovery event %d names prev digest %s but the chain carries %s — a deleted, reordered or forged predecessor", seq, shortSHA(prevSHA), shortSHA(prev)))
		}
		if want := recoveryEventHash(seq, prevSHA, kind, subject, detail, atMS, claimUID); want != sha {
			findings = append(findings,
				fmt.Sprintf("recovery event %d digest does not recompute — a field was modified after commit", seq))
		}
		prev = sha
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

// CheckRecoveryCheckpoint validates a retained checkpoint against the
// local chain: the signature and signer trust are verified, then the
// checkpoint's committed head must equal the chain's head at its
// committed tip — a store rolled back past the checkpoint, or one
// where any covered event changed, fails. Events appended after the
// checkpoint's tip do not affect it (the prefix property).
func (l *Ledger) CheckRecoveryCheckpoint(cp *RecoveryCheckpoint, trustedSigners map[string]bool) error {
	if err := VerifyRecoveryCheckpointSignature(cp, trustedSigners); err != nil {
		return err
	}
	if cp.EventCount == 0 {
		// A genesis checkpoint commits to an empty chain — nothing
		// further to check locally (later events are appends, which
		// the prefix property permits).
		return nil
	}
	var head string
	var n int64
	row := l.db.QueryRow(`SELECT event_sha256, (SELECT COUNT(*) FROM recovery_events WHERE seq <= ?) FROM recovery_events WHERE seq = ?`,
		cp.LastSeq, cp.LastSeq)
	if err := row.Scan(&head, &n); err == sql.ErrNoRows {
		return fmt.Errorf("recovery chain no longer holds event %d the checkpoint commits to — local history was rolled back or truncated", cp.LastSeq)
	} else if err != nil {
		return err
	}
	if head != cp.ChainHeadSHA256 {
		return fmt.Errorf("recovery chain head at event %d is %s but the checkpoint commits to %s — covered history was rewritten", cp.LastSeq, shortSHA(head), shortSHA(cp.ChainHeadSHA256))
	}
	if n != cp.EventCount {
		return fmt.Errorf("the chain holds %d events at seq %d but the checkpoint covers %d — history was inserted or deleted inside the covered range", n, cp.LastSeq, cp.EventCount)
	}
	// The retained checkpoint is honest about the tip; now prove the
	// local history up to it still recomputes — a tampered middle
	// changes the tip digest and already failed above, but a full
	// recompute also catches a digest column rewritten wholesale.
	findings, err := l.VerifyRecoveryEvents()
	if err != nil {
		return err
	}
	if len(findings) > 0 {
		return fmt.Errorf("local chain does not verify: %s", findings[0])
	}
	return nil
}

func shortSHA(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
