// Package sandboxcustody is the external evidence-custody witness:
// a daemon independent of the executor that durably holds the bytes
// an archive segment commits to, acknowledges custody with its own
// signing key in an append-only chain, and refuses to attest bytes it
// did not verify.
//
// The executor's archive custodian hands over each segment's canonical
// payload; the witness stores it content-addressed under its digest
// and signs an acknowledgement only after the payload's digest, row
// count and terminal range all check out. Custody is idempotent on the
// digest: a retried handoff returns the original acknowledgement, so a
// crash between the executor's archive commit and the release is
// resumed without double-witnessing.
package sandboxcustody

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// The operations the witness speaks. Both witness opaque payload
// bytes bound by digest; they differ only in the structural claim the
// witness checks before attesting: an archive segment is a canonical
// row array whose terminal sequences land inside the declared range;
// a recovery checkpoint is a single signed record whose declared
// position is one outbox row (first == last == segment seq, one row).
const OpWitnessArchive = "witness_archive"
const OpWitnessCheckpoint = "witness_checkpoint"

// witnessDomain separates custody signatures from every other signed
// record — a custody acknowledgement can never be presented as a
// receipt or a checkpoint.
const WitnessDomain = "crabedence-archive-custody-v1\x00"

// WitnessRequest hands one archive segment to the witness. The payload
// is the canonical segment bytes: sha256(payload) must equal SHA256.
type WitnessRequest struct {
	Op               string `json:"op"`
	SegmentSeq       int64  `json:"segment_seq"`
	FirstTerminalSeq int64  `json:"first_terminal_seq"`
	LastTerminalSeq  int64  `json:"last_terminal_seq"`
	RowCount         int    `json:"row_count"`
	SHA256           string `json:"sha256"`
	CreatedAt        int64  `json:"created_at"`
	// DeploymentID is the requesting ledger's durable deployment scope.
	// The witness signs it into v3 acknowledgements so a record minted
	// for one deployment can never be replayed as custody for another —
	// two ledgers sharing a witness still hold disjoint evidence.
	DeploymentID string `json:"deployment_id,omitempty"`
	PayloadB64   string `json:"payload_b64"`
	Token        string `json:"token,omitempty"`
}

// WitnessResponse is the custody acknowledgement: ok means the bytes
// are durably held under their digest and the acknowledgement is
// chained and signed. Ack carries the complete signed record — the
// only form of the acknowledgement an independent verifier can check:
// the flat fields above it are a convenience echo of what Ack commits
// to, never evidence in their own right.
type WitnessResponse struct {
	OK              bool       `json:"ok"`
	AckSeq          int64      `json:"ack_seq,omitempty"`
	WitnessedSHA256 string     `json:"witnessed_sha256,omitempty"`
	Signer          string     `json:"signer,omitempty"`
	Signature       string     `json:"signature,omitempty"`
	Ack             *AckRecord `json:"ack,omitempty"`
	Error           string     `json:"error,omitempty"`
}

// Client speaks to the witness over its unix socket — one request, one
// response, one connection.
type Client struct {
	Socket  string
	Timeout time.Duration
	Token   string
}

// Witness submits one archive segment and returns the witness's
// verdict. An unreachable or refusing witness is an error — the caller
// must not release the operational rows.
func (c *Client) Witness(ctx context.Context, req *WitnessRequest) (*WitnessResponse, error) {
	if c.Socket == "" {
		return nil, fmt.Errorf("custody socket not configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("custody dial %s: %w", c.Socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if c.Token != "" {
		req.Token = c.Token
	}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal custody request: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("custody write: %w", err)
	}
	resp := &WitnessResponse{}
	reader := bufio.NewReaderSize(conn, 4<<20)
	respLine, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("custody read: %w", err)
	}
	if err := json.Unmarshal(respLine, resp); err != nil {
		return nil, fmt.Errorf("custody response malformed: %w", err)
	}
	return resp, nil
}
