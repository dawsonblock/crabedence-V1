package sandboxexecutor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/sandboxcustody"
)

// SocketCustodian is the ArchiveCustodian that hands archive segments
// to an external custody witness over its unix socket. The executor
// releases the operational rows only when the witness has stored the
// payload and its acknowledgement independently verifies: bound to
// this exact segment and request, signed under the witness's key, and
// issued by a witness the configured trust root approves — custody of
// the archive's contents then lives outside the executor's own
// storage and outside the witness's say-so.
type SocketCustodian struct {
	// Socket is the custody daemon's socket path.
	Socket string
	// Timeout bounds one witness call; zero uses the client's default.
	Timeout time.Duration
	// Token is the optional shared secret the daemon requires.
	Token string
	// Trust is the approved-witness root — public keys the operator
	// explicitly configured through controlled configuration. When
	// set it is the authority on which witness may vouch.
	Trust *sandboxcustody.TrustRoot
	// ExpectedSigner pins the custody daemon's witness fingerprint —
	// a response signed under a key with a different fingerprint is
	// not the custody the operator configured. It is a trust input,
	// never a substitute for signature verification: the ack's
	// embedded public key and signature must still verify.
	ExpectedSigner string
}

// trust resolves the effective witness trust root. A fingerprint pin
// becomes a fingerprint-scoped root; an explicitly configured root is
// used as-is. No configured trust is no trust — every acknowledgement
// then fails closed as self-declared custody.
func (c *SocketCustodian) trust() *sandboxcustody.TrustRoot {
	if c.Trust != nil && !c.Trust.Empty() {
		return c.Trust
	}
	if c.ExpectedSigner != "" {
		return sandboxcustody.NewFingerprintTrust(c.ExpectedSigner)
	}
	return nil
}

// CustodyTrustRoot declares the witness trust root this custodian's
// acknowledgements must verify under — the recording boundary
// re-verifies every ack against it, so an adapter-level check is
// additional defense, never the sole enforcement point.
func (c *SocketCustodian) CustodyTrustRoot() *sandboxcustody.TrustRoot {
	return c.trust()
}

// WitnessArchive hands the segment to the custody daemon and
// independently verifies the signed acknowledgement — digest and
// fingerprint comparisons are not custody evidence. deployment is
// the ledger's durable custody scope, passed through verbatim into
// the request: the boundary re-verifies the acknowledgement binds
// it, so an adapter substituting another scope refuses itself. A
// verified acknowledgement is returned for the ledger to persist
// before the operational rows may release.
func (c *SocketCustodian) WitnessArchive(seg *ArchiveSegment, payload []byte, deployment string) (*CustodyAck, error) {
	trust := c.trust()
	if trust.Empty() {
		return nil, fmt.Errorf("custody witness trust not configured — refusing self-declared custody")
	}
	cli := &sandboxcustody.Client{Socket: c.Socket, Timeout: c.Timeout, Token: c.Token}
	req := &sandboxcustody.WitnessRequest{
		Op:               sandboxcustody.OpWitnessArchive,
		SegmentSeq:       seg.Seq,
		FirstTerminalSeq: seg.FirstTerminalSeq,
		LastTerminalSeq:  seg.LastTerminalSeq,
		RowCount:         seg.RowCount,
		SHA256:           seg.SHA256,
		CreatedAt:        seg.CreatedAt.UnixMilli(),
		DeploymentID:     deployment,
		PayloadB64:       base64.StdEncoding.EncodeToString(payload),
	}
	resp, err := cli.Witness(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("custody witness refused segment %d: %s", seg.Seq, resp.Error)
	}
	if err := sandboxcustody.VerifyWitnessAck(resp.Ack, sandboxcustody.BindingFor(req), trust); err != nil {
		return nil, fmt.Errorf("custody acknowledgement for segment %d failed verification: %w", seg.Seq, err)
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
