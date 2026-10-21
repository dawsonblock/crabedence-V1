package sandboxexecutor

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sandboxcustody"
)

// The custody adversary: anything answering at the configured socket —
// a forged response, a substituted signer, a replayed acknowledgement.
// The custodian's job is that only a verified, trusted, request-bound
// acknowledgement can authorize releasing the executor's own copy of
// execution evidence.

// fakeWitness runs a one-shot unix-socket server whose handler sees
// the real request and fabricates the response — the wire-level
// adversary surface SocketCustodian defends.
type fakeWitness struct {
	socket string
	done   chan *sandboxcustody.WitnessRequest
	ln     *net.UnixListener
}

func startFakeWitness(t *testing.T, respond func(*sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse) *fakeWitness {
	t.Helper()
	dir, err := os.MkdirTemp("", "fkw-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "custody.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	fw := &fakeWitness{socket: socket, done: make(chan *sandboxcustody.WitnessRequest, 1), ln: ln}
	go func() {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReaderSize(conn, 16<<20)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		req := &sandboxcustody.WitnessRequest{}
		if json.Unmarshal(line, req) != nil {
			return
		}
		fw.done <- req
		resp := respond(req)
		out, _ := json.Marshal(resp)
		_, _ = conn.Write(append(out, '\n'))
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return fw
}

func custodyTestSegment() (*ArchiveSegment, []byte) {
	payload, _ := json.Marshal([]map[string]any{
		{"job_id": "j1", "terminal_seq": int64(1)},
	})
	sum := sha256.Sum256(payload)
	return &ArchiveSegment{
		Seq:              5,
		FirstTerminalSeq: 1,
		LastTerminalSeq:  1,
		RowCount:         1,
		SHA256:           hex.EncodeToString(sum[:]),
		CreatedAt:        time.Now().UTC().Truncate(time.Millisecond),
	}, payload
}

// daemonAck builds an acknowledgement exactly as the custody daemon
// signs it — the honest response every forgery is measured against.
func daemonAck(t *testing.T, signer *evidence.Signer, req *sandboxcustody.WitnessRequest, ackSeq int64) *sandboxcustody.AckRecord {
	t.Helper()
	pub := signer.PublicKey()
	ack := &sandboxcustody.AckRecord{
		RecordType:       sandboxcustody.AckRecordTypeV3,
		AckSeq:           ackSeq,
		SegmentSeq:       req.SegmentSeq,
		FirstTerminalSeq: req.FirstTerminalSeq,
		LastTerminalSeq:  req.LastTerminalSeq,
		RowCount:         req.RowCount,
		PayloadSHA256:    req.SHA256,
		RequestCreatedAt: req.CreatedAt,
		DeploymentID:     req.DeploymentID,
		WitnessedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey:        base64.StdEncoding.EncodeToString(pub),
		Signer:           evidence.Fingerprint(pub),
	}
	fields, err := ack.SigningFields()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignRecord(sandboxcustody.WitnessDomain, fields...)
	if err != nil {
		t.Fatal(err)
	}
	ack.Signature = sig
	return ack
}

func witnessSeg(t *testing.T, c *SocketCustodian, seg *ArchiveSegment, payload []byte) error {
	t.Helper()
	_, err := c.WitnessArchive(seg, payload, "test-deployment")
	return err
}

// A response that merely claims success — the forged shape the old
// fingerprint check could not see through. No signed record is no
// acknowledgement.
func TestCustodyRejectsForgedSuccess(t *testing.T) {
	seg, payload := custodyTestSegment()
	fw := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		return &sandboxcustody.WitnessResponse{
			OK:              true,
			AckSeq:          1,
			WitnessedSHA256: req.SHA256,
			Signer:          strings.Repeat("a", 64),
			Signature:       base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		}
	})
	c := &SocketCustodian{Socket: fw.socket, ExpectedSigner: strings.Repeat("a", 64)}
	if err := witnessSeg(t, c, seg, payload); err == nil {
		t.Fatal("a forged self-declared success released custody")
	}
}

// A complete-looking record whose signature is garbage — matching
// digest, invalid signature.
func TestCustodyRejectsBadSignature(t *testing.T) {
	seg, payload := custodyTestSegment()
	rogue, _ := evidence.GenerateSigner()
	fw := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		ack := daemonAck(t, rogue, req, 1)
		raw, _ := base64.StdEncoding.DecodeString(ack.Signature)
		raw[3] ^= 0x80
		ack.Signature = base64.StdEncoding.EncodeToString(raw)
		return &sandboxcustody.WitnessResponse{OK: true, Ack: ack}
	})
	c := &SocketCustodian{Socket: fw.socket, Trust: sandboxcustody.NewTrustRoot(rogue.PublicKey())}
	if err := witnessSeg(t, c, seg, payload); err == nil {
		t.Fatal("a corrupted signature was accepted as custody")
	}
}

// A genuinely signed acknowledgement under a key the trust root never
// approved — the substituted-witness case.
func TestCustodyRejectsSubstitutedSigner(t *testing.T) {
	seg, payload := custodyTestSegment()
	real, _ := evidence.GenerateSigner()
	rogue, _ := evidence.GenerateSigner()
	fw := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		return &sandboxcustody.WitnessResponse{OK: true, Ack: daemonAck(t, rogue, req, 1)}
	})
	c := &SocketCustodian{Socket: fw.socket, Trust: sandboxcustody.NewTrustRoot(real.PublicKey())}
	if err := witnessSeg(t, c, seg, payload); err == nil {
		t.Fatal("an unapproved witness's genuine signature was accepted")
	}
	// The same attack through the fingerprint pin path.
	fw2 := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		return &sandboxcustody.WitnessResponse{OK: true, Ack: daemonAck(t, rogue, req, 1)}
	})
	c2 := &SocketCustodian{Socket: fw2.socket, ExpectedSigner: real.Fingerprint()}
	if err := witnessSeg(t, c2, seg, payload); err == nil {
		t.Fatal("a foreign signer satisfied the fingerprint pin without verification")
	}
}

// A valid signed ack minted for another segment — the replay case.
// The witness is honest; the response simply answers a different ask.
func TestCustodyRejectsAckForWrongSegment(t *testing.T) {
	seg, payload := custodyTestSegment()
	witness, _ := evidence.GenerateSigner()
	fw := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		// Rebind the request to a different segment identity — the
		// honest signature then attests the wrong custody event.
		other := *req
		other.SegmentSeq = 99
		return &sandboxcustody.WitnessResponse{OK: true, Ack: daemonAck(t, witness, &other, 1)}
	})
	c := &SocketCustodian{Socket: fw.socket, Trust: sandboxcustody.NewTrustRoot(witness.PublicKey())}
	if err := witnessSeg(t, c, seg, payload); err == nil {
		t.Fatal("an ack for another segment satisfied this custody request")
	}
}

// No trust configured — even a daemon that answers perfectly is
// self-declared, so the custodian refuses before believing anything.
func TestCustodyFailsClosedWithoutTrust(t *testing.T) {
	seg, payload := custodyTestSegment()
	witness, _ := evidence.GenerateSigner()
	fw := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		return &sandboxcustody.WitnessResponse{OK: true, Ack: daemonAck(t, witness, req, 1)}
	})
	c := &SocketCustodian{Socket: fw.socket}
	if err := witnessSeg(t, c, seg, payload); err == nil {
		t.Fatal("unpinned custody was accepted")
	}
}

// The happy path under the new contract: a verified ack, and the
// ledger persists the acknowledgement reference when it releases.
func TestCustodyAckPersistedWithWitnessedSegment(t *testing.T) {
	l, _ := openLedger(t)
	witness, _ := evidence.GenerateSigner()
	fw := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		return &sandboxcustody.WitnessResponse{
			OK:              true,
			AckSeq:          1,
			WitnessedSHA256: req.SHA256,
			Signer:          "",
			Ack:             daemonAck(t, witness, req, 1),
		}
	})
	c := &SocketCustodian{Socket: fw.socket, Trust: sandboxcustody.NewTrustRoot(witness.PublicKey())}
	if err := l.SetArchiveCustodian(c); err != nil {
		t.Fatal(err)
	}
	settleJob(t, l, "ack-1", "h-ack-1")
	seg, err := l.ArchiveCompleted(0)
	if err != nil {
		t.Fatalf("custodial archive: %v", err)
	}
	if seg == nil || seg.Custody != "witnessed" {
		t.Fatalf("custody = %+v", seg)
	}
	// The verified acknowledgement reference is durably on the
	// segment — the release is auditable against the witness's chain.
	var ackJSON string
	if err := l.db.QueryRow(
		`SELECT custody_ack FROM archive_segments WHERE segment_seq = ?`, seg.Seq).
		Scan(&ackJSON); err != nil {
		t.Fatal(err)
	}
	if ackJSON == "" {
		t.Fatal("custody release recorded no acknowledgement reference")
	}
	stored := &CustodyAck{}
	if err := json.Unmarshal([]byte(ackJSON), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Signer != witness.Fingerprint() || stored.AckJSON == "" {
		t.Fatalf("stored ack reference = %+v", stored)
	}
	// And it re-verifies as evidence, not just as stored text.
	rec := &sandboxcustody.AckRecord{}
	if err := json.Unmarshal([]byte(stored.AckJSON), rec); err != nil {
		t.Fatal(err)
	}
	if stored.PayloadSHA256 != seg.SHA256 || rec.PayloadSHA256 != seg.SHA256 {
		t.Fatal("stored ack does not bind the segment digest")
	}
	// The stored record must still stand on its own as a verified
	// acknowledgement — persisting it was the point of the release.
	verr := sandboxcustody.VerifyWitnessAck(rec, nil, sandboxcustody.NewTrustRoot(witness.PublicKey()))
	if verr != nil {
		t.Fatalf("persisted ack fails independent verification: %v", verr)
	}
}

// End-to-end forgery through the ledger: a malicious witness socket
// must never get the operational rows deleted.
func TestArchiveHoldsRowsAgainstForgedAck(t *testing.T) {
	l, _ := openLedger(t)
	fw := startFakeWitness(t, func(req *sandboxcustody.WitnessRequest) *sandboxcustody.WitnessResponse {
		return &sandboxcustody.WitnessResponse{OK: true, WitnessedSHA256: req.SHA256}
	})
	c := &SocketCustodian{Socket: fw.socket, ExpectedSigner: strings.Repeat("a", 64)}
	if err := l.SetArchiveCustodian(c); err != nil {
		t.Fatal(err)
	}
	settleJob(t, l, "forge-1", "h-forge-1")
	if _, err := l.ArchiveCompleted(0); err == nil {
		t.Fatal("a forged acknowledgement released the archive")
	}
	if n, _ := l.Count(); n != 1 {
		t.Fatalf("operational row released on forged custody: %d", n)
	}
	segs, _ := l.ArchiveSegments()
	if len(segs) != 1 || segs[0].Custody != "pending" {
		t.Fatalf("custody = %+v", segs)
	}
}
