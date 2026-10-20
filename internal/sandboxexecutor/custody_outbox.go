package sandboxexecutor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/sandboxcustody"
)

// Recovery-checkpoint custody outbox (RC7.5, INV-05).
//
// A signed recovery checkpoint is only a local attestation until it
// reaches an independently controlled destination. The outbox makes
// the obligation durable: every emitted checkpoint is queued in the
// ledger before publication, so a crash after the commit cannot
// silently lose the duty to replicate. Delivery is idempotent — the
// same checkpoint re-offered to the same custodian must acknowledge
// identically — and retries never roll state back: a row acked stays
// acked, a row pending stays queued until a custodian proves it.
//
// Competing-head detection: the custodian's acknowledgement sequence
// must advance monotonically; an ack that reuses a sequence for a
// different payload, or regresses below the last acked sequence, is a
// contradictory checkpoint head and is escalated, never recorded as
// custody.

// RecoveryCustodian is the pluggable custody hook for signed recovery
// checkpoints. It is called after the checkpoint row lands in the
// outbox; the returned acknowledgement is independently verified by
// the recording boundary — not trusted from the adapter — and then
// persisted on the outbox row. Custody is recorded only when the
// custodian's own proof verifies at the boundary.
//
// The acknowledgement contract is fixed: the signed record must bind
// the offered checkpoint's bytes and outbox position — SegmentSeq,
// FirstTerminalSeq and LastTerminalSeq equal to the outbox sequence,
// RowCount 1, PayloadSHA256 equal to sha256(checkpointJSON) — under
// the custody ack signing protocol, verified against the trust root
// CustodyTrustRoot declares.
type RecoveryCustodian interface {
	// WitnessRecoveryCheckpoint hands one durable outbox row to the
	// custodian and returns its signed acknowledgement. The witness
	// request must bind the row's durable request instance — its
	// outbox position and committed created_ms — so the returned
	// acknowledgement can never be replayed against a different
	// request than the one the ledger queued. The implementation
	// must be idempotent: re-witnessing the same row must return an
	// acknowledgement that verifies.
	WitnessRecoveryCheckpoint(row *RecoveryOutboxRow) (*CustodyAck, error)
	// CustodyTrustRoot declares the witness trust under which this
	// custodian's acknowledgements must verify — controlled
	// configuration, never learned from an acknowledgement. An empty
	// root means no custody can be recorded: the boundary fails closed.
	CustodyTrustRoot() *sandboxcustody.TrustRoot
}

// EnqueueRecoveryCheckpoint durably records the obligation to
// replicate one signed checkpoint. Returns the outbox sequence the
// row was assigned — the position the custody trail acknowledges.
func (l *Ledger) EnqueueRecoveryCheckpoint(headSHA string, checkpointJSON []byte) (int64, error) {
	res, err := l.db.Exec(`INSERT INTO recovery_outbox (head_sha256, checkpoint_json, created_ms) VALUES (?,?,?)`,
		headSHA, string(checkpointJSON), time.Now().UTC().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("enqueue recovery checkpoint: %w", err)
	}
	return res.LastInsertId()
}

// lastOutboxHead returns the chain head the most recently queued
// checkpoint commits to — the emission skip check: a checkpoint for
// a head already queued carries nothing new.
func (l *Ledger) lastOutboxHead() (string, error) {
	var head string
	err := l.db.QueryRow(`SELECT head_sha256 FROM recovery_outbox ORDER BY seq DESC LIMIT 1`).Scan(&head)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return head, err
}

// PendingRecoveryCustody lists outbox rows whose custody never
// finished — the durable retry set a crash cannot lose.
func (l *Ledger) PendingRecoveryCustody(limit int) ([]*RecoveryOutboxRow, error) {
	if limit <= 0 {
		limit = 32
	}
	rows, err := l.db.Query(`SELECT seq, checkpoint_json, created_ms FROM recovery_outbox
		WHERE ack_json = '' ORDER BY seq LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RecoveryOutboxRow
	for rows.Next() {
		r := &RecoveryOutboxRow{}
		if err := rows.Scan(&r.Seq, &r.CheckpointJSON, &r.CreatedMS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecoveryOutboxRow is one queued custody obligation.
type RecoveryOutboxRow struct {
	Seq            int64
	CheckpointJSON string
	CreatedMS      int64
}

// ackRecoveryCustody records a verified acknowledgement on one outbox
// row — idempotently: re-acking an already-acked row is refused
// unless the ack is byte-identical, so a redelivery cannot silently
// rewrite what custody was recorded.
func (l *Ledger) ackRecoveryCustody(outboxSeq int64, ackJSON string) error {
	res, err := l.db.Exec(`UPDATE recovery_outbox SET ack_json = ?
		WHERE seq = ? AND (ack_json = '' OR ack_json = ?)`, ackJSON, outboxSeq, ackJSON)
	if err != nil {
		return fmt.Errorf("record recovery custody ack %d: %w", outboxSeq, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("recovery custody ack %d conflicts with the ack already recorded — a contradictory acknowledgement is escalated, never overwritten", outboxSeq)
	}
	return nil
}

// lastRecoveryAckSeq returns the highest acknowledgement sequence the
// outbox has recorded — the continuity floor a new ack must extend.
func (l *Ledger) lastRecoveryAckSeq() (int64, error) {
	var seq sql.NullInt64
	err := l.db.QueryRow(`SELECT MAX(CAST(json_extract(ack_json, '$.ack_seq') AS INTEGER))
		FROM recovery_outbox WHERE ack_json != ''`).Scan(&seq)
	if err != nil {
		return 0, err
	}
	if !seq.Valid {
		return 0, nil
	}
	return seq.Int64, nil
}

// DrainRecoveryCustody offers every pending outbox row to the
// custodian, in order, and records each verified acknowledgement. The
// sequence continuity check runs per row: an ack whose sequence does
// not advance past the last recorded one is a competing checkpoint
// head — reported and left pending for an operator, never silently
// accepted.
func (l *Ledger) DrainRecoveryCustody(c RecoveryCustodian, audit func(string, ...any)) error {
	if c == nil {
		return nil
	}
	// The verification root is resolved once from operator-administered
	// configuration when present — the ack-producing adapter's declared
	// root is only the weaker compatibility path (see custodyVerifyRoot).
	trust := l.custodyVerifyRoot(c.CustodyTrustRoot())
	pending, err := l.PendingRecoveryCustody(0)
	if err != nil {
		return fmt.Errorf("enumerate pending recovery custody: %w", err)
	}
	for _, row := range pending {
		ack, err := c.WitnessRecoveryCheckpoint(row)
		if err != nil {
			if audit != nil {
				audit("recovery custody: outbox %d not acknowledged: %v", row.Seq, err)
			}
			continue
		}
		ackJSON, err := json.Marshal(ack)
		if err != nil {
			if audit != nil {
				audit("recovery custody: outbox %d ack cannot be recorded: %v", row.Seq, err)
			}
			continue
		}
		// The boundary verifies — the adapter's own check is defense
		// in depth, never the enforcement point: the returned record
		// must be signed under the declared trust root and bind this
		// exact checkpoint payload and outbox position, or the row
		// stays pending and the failure is audited.
		if err := verifyRecoveryCustodyAck(row, ack, trust); err != nil {
			if audit != nil {
				audit("recovery custody: outbox %d acknowledgement failed boundary verification — not recorded as custody: %v", row.Seq, err)
			}
			continue
		}
		last, err := l.lastRecoveryAckSeq()
		if err != nil {
			if audit != nil {
				audit("recovery custody: cannot read ack continuity: %v", err)
			}
			continue
		}
		if ack.AckSeq <= last {
			if audit != nil {
				audit("recovery custody: outbox %d acknowledged at seq %d, not past the recorded head %d — a competing checkpoint head is escalated", row.Seq, ack.AckSeq, last)
			}
			continue
		}
		if err := l.ackRecoveryCustody(row.Seq, string(ackJSON)); err != nil {
			if audit != nil {
				audit("recovery custody: outbox %d: %v", row.Seq, err)
			}
			continue
		}
	}
	return nil
}

// parseCustodyAckRecord unpacks a returned acknowledgement's signed
// record and proves the summary fields the caller reported agree with
// what was actually signed — a wrapper that claims one seq or signer
// over a record that attests another is refused before verification
// is even attempted.
func parseCustodyAckRecord(ack *CustodyAck) (*sandboxcustody.AckRecord, error) {
	if ack == nil || ack.AckJSON == "" {
		return nil, fmt.Errorf("custodian returned no signed acknowledgement record")
	}
	rec := &sandboxcustody.AckRecord{}
	if err := json.Unmarshal([]byte(ack.AckJSON), rec); err != nil {
		return nil, fmt.Errorf("custody acknowledgement does not parse: %w", err)
	}
	if ack.AckSeq != rec.AckSeq || ack.Signer != rec.Signer || ack.PayloadSHA256 != rec.PayloadSHA256 {
		return nil, fmt.Errorf("custody acknowledgement summary contradicts its signed record")
	}
	return rec, nil
}

// verifyArchiveCustodyAck is the recording boundary's own check on a
// witnessed archive segment — independent of the adapter's internal
// verification. The signed record must bind the segment's exact
// identity and verify under the custodian's declared trust root; the
// request-instance field is reconstructed from the durable segment
// (the request derives from it), so a replayed or foreign ack fails.
func verifyArchiveCustodyAck(seg *ArchiveSegment, ack *CustodyAck, trust *sandboxcustody.TrustRoot) error {
	if trust.Empty() {
		return fmt.Errorf("no custody trust root declared — a self-declared acknowledgement is not evidence")
	}
	rec, err := parseCustodyAckRecord(ack)
	if err != nil {
		return err
	}
	want := &sandboxcustody.AckBinding{
		SegmentSeq:       seg.Seq,
		FirstTerminalSeq: seg.FirstTerminalSeq,
		LastTerminalSeq:  seg.LastTerminalSeq,
		RowCount:         seg.RowCount,
		PayloadSHA256:    seg.SHA256,
		RequestCreatedAt: seg.CreatedAt.UnixMilli(),
	}
	return sandboxcustody.VerifyWitnessAck(rec, want, trust)
}

// verifyRecoveryCustodyAck is the recording boundary's own check on
// one returned acknowledgement — independent of whatever the
// custodian adapter already did. The acknowledgement must carry a
// parseable signed record whose summary fields agree with it, bind
// this exact outbox position and checkpoint payload, attest the
// durable request instance the ledger committed (the outbox row's
// own created_ms, never a timestamp the acknowledgement itself
// declares), and verify under the resolved trust root. Anything less
// is not custody.
func verifyRecoveryCustodyAck(row *RecoveryOutboxRow, ack *CustodyAck, trust *sandboxcustody.TrustRoot) error {
	if trust.Empty() {
		return fmt.Errorf("no custody trust root declared — a self-declared acknowledgement is not evidence")
	}
	rec, err := parseCustodyAckRecord(ack)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(row.CheckpointJSON))
	want := &sandboxcustody.AckBinding{
		SegmentSeq:       row.Seq,
		FirstTerminalSeq: row.Seq,
		LastTerminalSeq:  row.Seq,
		RowCount:         1,
		PayloadSHA256:    hex.EncodeToString(sum[:]),
		RequestCreatedAt: row.CreatedMS,
	}
	return sandboxcustody.VerifyWitnessAck(rec, want, trust)
}

// handed to the custody daemon as a witnessed payload — the same
// verified-acknowledgement protocol archive custody uses, bound to
// this checkpoint's bytes and to the durable request instance the
// outbox row committed when it was queued. The daemon's
// acknowledgement is proof the checkpoint reached custody outside
// the executor's own storage — and a v2 ack attests the request
// instance the ledger recorded, so an acknowledgement minted for
// some other request cannot be replayed here.
func (c *SocketCustodian) WitnessRecoveryCheckpoint(row *RecoveryOutboxRow) (*CustodyAck, error) {
	trust := c.trust()
	if trust.Empty() {
		return nil, fmt.Errorf("custody witness trust not configured — refusing self-declared custody")
	}
	sumRaw := sha256.Sum256([]byte(row.CheckpointJSON))
	sum := hex.EncodeToString(sumRaw[:])
	cli := &sandboxcustody.Client{Socket: c.Socket, Timeout: c.Timeout, Token: c.Token}
	req := &sandboxcustody.WitnessRequest{
		Op:               sandboxcustody.OpWitnessArchive,
		SegmentSeq:       row.Seq,
		FirstTerminalSeq: row.Seq,
		LastTerminalSeq:  row.Seq,
		RowCount:         1,
		SHA256:           sum,
		CreatedAt:        row.CreatedMS,
		PayloadB64:       base64.StdEncoding.EncodeToString([]byte(row.CheckpointJSON)),
	}
	resp, err := cli.Witness(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("custody witness refused recovery checkpoint %d: %s", row.Seq, resp.Error)
	}
	if err := sandboxcustody.VerifyWitnessAck(resp.Ack, sandboxcustody.BindingFor(req), trust); err != nil {
		return nil, fmt.Errorf("custody acknowledgement for recovery checkpoint %d failed verification: %w", row.Seq, err)
	}
	ackJSON, err := json.Marshal(resp.Ack)
	if err != nil {
		return nil, fmt.Errorf("marshal verified custody ack: %w", err)
	}
	return &CustodyAck{
		AckSeq:           resp.Ack.AckSeq,
		Signer:           resp.Ack.Signer,
		PayloadSHA256:    resp.Ack.PayloadSHA256,
		AckJSON:          string(ackJSON),
		RequestCreatedAt: req.CreatedAt,
	}, nil
}
