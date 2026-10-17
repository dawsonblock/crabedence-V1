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
// outbox; the returned acknowledgement is independently verified and
// then persisted on the outbox row — custody is recorded only when
// the custodian's own proof verifies.
type RecoveryCustodian interface {
	// WitnessRecoveryCheckpoint hands one serialized checkpoint to
	// the custodian and returns its signed acknowledgement. The
	// implementation must be idempotent: re-witnessing the same
	// checkpoint must return an acknowledgement that verifies.
	WitnessRecoveryCheckpoint(outboxSeq int64, checkpointJSON []byte) (*CustodyAck, error)
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
	pending, err := l.PendingRecoveryCustody(0)
	if err != nil {
		return fmt.Errorf("enumerate pending recovery custody: %w", err)
	}
	for _, row := range pending {
		ack, err := c.WitnessRecoveryCheckpoint(row.Seq, []byte(row.CheckpointJSON))
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

// SocketCustodian's recovery witness: a signed recovery checkpoint is
// handed to the custody daemon as a witnessed payload — the same
// verified-acknowledgement protocol archive custody uses, bound to
// this checkpoint's bytes. The daemon's acknowledgement is proof the
// checkpoint reached custody outside the executor's own storage.
func (c *SocketCustodian) WitnessRecoveryCheckpoint(outboxSeq int64, checkpointJSON []byte) (*CustodyAck, error) {
	trust := c.trust()
	if trust.Empty() {
		return nil, fmt.Errorf("custody witness trust not configured — refusing self-declared custody")
	}
	sumRaw := sha256.Sum256(checkpointJSON)
	sum := hex.EncodeToString(sumRaw[:])
	cli := &sandboxcustody.Client{Socket: c.Socket, Timeout: c.Timeout, Token: c.Token}
	req := &sandboxcustody.WitnessRequest{
		Op:               sandboxcustody.OpWitnessArchive,
		SegmentSeq:       outboxSeq,
		FirstTerminalSeq: outboxSeq,
		LastTerminalSeq:  outboxSeq,
		RowCount:         1,
		SHA256:           sum,
		CreatedAt:        time.Now().UTC().UnixMilli(),
		PayloadB64:       base64.StdEncoding.EncodeToString(checkpointJSON),
	}
	resp, err := cli.Witness(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("custody witness refused recovery checkpoint %d: %s", outboxSeq, resp.Error)
	}
	if err := sandboxcustody.VerifyWitnessAck(resp.Ack, sandboxcustody.BindingFor(req), trust); err != nil {
		return nil, fmt.Errorf("custody acknowledgement for recovery checkpoint %d failed verification: %w", outboxSeq, err)
	}
	ackJSON, err := json.Marshal(resp.Ack)
	if err != nil {
		return nil, fmt.Errorf("marshal verified custody ack: %w", err)
	}
	return &CustodyAck{
		AckSeq:        resp.Ack.AckSeq,
		Signer:        resp.Ack.Signer,
		PayloadSHA256: resp.Ack.PayloadSHA256,
		AckJSON:       string(ackJSON),
	}, nil
}
