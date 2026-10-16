package sandboxexecutor

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/sandboxcustody"
)

// SocketCustodian is the ArchiveCustodian that hands archive segments
// to an external custody witness over its unix socket. The executor
// releases the operational rows only when the witness has stored the
// payload and signed its acknowledgement — custody of the archive's
// contents then lives outside the executor's own storage.
type SocketCustodian struct {
	// Socket is the custody daemon's socket path.
	Socket string
	// Timeout bounds one witness call; zero uses the client's default.
	Timeout time.Duration
	// Token is the optional shared secret the daemon requires.
	Token string
	// ExpectedSigner pins the custody daemon's witness fingerprint —
	// a response signed under a different key is not the custody the
	// operator configured. Empty accepts any signer (the chain is
	// still verifiable, but the witness's identity is unpinned).
	ExpectedSigner string
}

// WitnessArchive hands the segment to the custody daemon and insists
// the acknowledgement names this segment's digest — a response that
// attests a different digest is not custody of this archive.
func (c *SocketCustodian) WitnessArchive(seg *ArchiveSegment, payload []byte) error {
	cli := &sandboxcustody.Client{Socket: c.Socket, Timeout: c.Timeout, Token: c.Token}
	resp, err := cli.Witness(context.Background(), &sandboxcustody.WitnessRequest{
		Op:               sandboxcustody.OpWitnessArchive,
		SegmentSeq:       seg.Seq,
		FirstTerminalSeq: seg.FirstTerminalSeq,
		LastTerminalSeq:  seg.LastTerminalSeq,
		RowCount:         seg.RowCount,
		SHA256:           seg.SHA256,
		CreatedAt:        seg.CreatedAt.UnixMilli(),
		PayloadB64:       base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("custody witness refused segment %d: %s", seg.Seq, resp.Error)
	}
	if resp.WitnessedSHA256 != seg.SHA256 {
		return fmt.Errorf("custody witness acknowledged %s, not the segment's %s", resp.WitnessedSHA256, seg.SHA256)
	}
	if c.ExpectedSigner != "" && resp.Signer != c.ExpectedSigner {
		return fmt.Errorf("custody acknowledged by signer %s, not the pinned witness %s", resp.Signer, c.ExpectedSigner)
	}
	return nil
}
