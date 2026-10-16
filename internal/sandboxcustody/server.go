package sandboxcustody

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// The custody daemon is the witness the executor's archive custodian
// hands settled history to. It holds the canonical segment bytes under
// their digest (segments/<sha256>), and every acknowledgement it issues
// is appended to a signed, hash-chained log (acks.jsonl) under a key
// only this daemon holds — custody is an independent attestor, not a
// copy of the executor's records.
//
// Verification is by construction: the daemon writes a payload file
// only after re-deriving its digest from the bytes it received, so a
// file named by digest always contains exactly those bytes; and the
// ack chain is verified record-by-record by VerifyCustodyDir.

// Config carries the custody daemon's parameters.
type Config struct {
	// SocketDir is an owner-only directory the custody socket is
	// bound inside — the directory mode is the socket's boundary.
	SocketDir string
	// CustodyDir holds the witnessed payloads and the ack chain.
	CustodyDir string
	// KeyPath is the witness's signer (PKCS8 PEM, created if absent).
	KeyPath string
	// Token is an optional shared secret the request must carry.
	Token string
	// Audit receives operator-visible lines; nil discards.
	Audit func(format string, args ...any)
}

// Server is the running custody daemon.
type Server struct {
	cfg    Config
	socket string

	signer *evidence.Signer

	mu         sync.Mutex // serializes store+chain writes
	stopped    bool
	started    bool
	listener   *net.UnixListener
	closed     chan struct{}
	acceptWg   sync.WaitGroup
	shutdown   context.Context
	shutdownFn context.CancelFunc
}

// NewServer validates the configuration and opens the witness signer.
func NewServer(cfg Config) (*Server, error) {
	if cfg.SocketDir == "" {
		return nil, fmt.Errorf("custody socket dir is required")
	}
	if cfg.CustodyDir == "" {
		return nil, fmt.Errorf("custody dir is required")
	}
	signer, err := evidence.LoadOrCreateSigner(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("custody signer: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:        cfg,
		socket:     filepath.Join(cfg.SocketDir, "custody.sock"),
		signer:     signer,
		closed:     make(chan struct{}),
		shutdown:   ctx,
		shutdownFn: cancel,
	}, nil
}

// SocketPath reports where the daemon is listening.
func (s *Server) SocketPath() string { return s.socket }

// SignerFingerprint names the witness's key — the identity custody
// acknowledgements carry.
func (s *Server) SignerFingerprint() string { return s.signer.Fingerprint() }

// Done closes when Stop has fully drained.
func (s *Server) Done() <-chan struct{} { return s.closed }

func (s *Server) audit(format string, args ...any) {
	if s.cfg.Audit != nil {
		s.cfg.Audit(format, args...)
	}
}

// Start binds the custody socket and begins accepting witnesses.
func (s *Server) Start() error {
	if s.started {
		return fmt.Errorf("custody server already started")
	}
	if err := os.MkdirAll(s.cfg.SocketDir, 0o700); err != nil {
		return fmt.Errorf("custody socket dir: %w", err)
	}
	if err := os.MkdirAll(s.cfg.CustodyDir, 0o700); err != nil {
		return fmt.Errorf("custody dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(s.cfg.CustodyDir, "segments"), 0o700); err != nil {
		return fmt.Errorf("custody segments dir: %w", err)
	}
	if _, err := os.Lstat(s.socket); err == nil {
		if rmErr := os.Remove(s.socket); rmErr != nil {
			return fmt.Errorf("remove stale custody socket: %w", rmErr)
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socket, Net: "unix"})
	if err != nil {
		return fmt.Errorf("bind custody socket %s: %w", s.socket, err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(s.socket, 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("secure custody socket %s: %w", s.socket, err)
	}
	s.listener, s.started = listener, true
	s.acceptWg.Add(1)
	go s.acceptLoop()
	s.audit("sandbox-custodyd listening on %s (custody=%s signer=%s)",
		s.socket, s.cfg.CustodyDir, s.signer.Fingerprint())
	return nil
}

// Stop drains in-flight witnesses, closes the socket and removes it.
func (s *Server) Stop() error {
	s.mu.Lock()
	if s.stopped || !s.started {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	listener := s.listener
	s.mu.Unlock()

	s.shutdownFn()
	err := listener.Close()
	s.acceptWg.Wait()
	_ = os.Remove(s.socket)
	close(s.closed)
	return err
}

func (s *Server) acceptLoop() {
	defer s.acceptWg.Done()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if s.shutdown.Err() != nil {
				return
			}
			s.audit("custody accept: %v", err)
			continue
		}
		s.acceptWg.Add(1)
		go s.serve(conn)
	}
}

// serve handles one witness request — one request, one response,
// then the connection closes.
func (s *Server) serve(conn *net.UnixConn) {
	defer s.acceptWg.Done()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	resp := s.handle(conn)
	line, _ := json.Marshal(resp)
	_, _ = conn.Write(append(line, '\n'))
}

func (s *Server) handle(conn *net.UnixConn) *WitnessResponse {
	reader := bufio.NewReaderSize(conn, 16<<20)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return &WitnessResponse{Error: fmt.Sprintf("read request: %v", err)}
	}
	req := &WitnessRequest{}
	if err := json.Unmarshal(line, req); err != nil {
		return &WitnessResponse{Error: fmt.Sprintf("malformed request: %v", err)}
	}
	if s.cfg.Token != "" &&
		subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.cfg.Token)) != 1 {
		return &WitnessResponse{Error: "custody token refused"}
	}
	if req.Op != OpWitnessArchive {
		return &WitnessResponse{Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
	ack, err := s.witness(req)
	if err != nil {
		return &WitnessResponse{Error: err.Error()}
	}
	return ack
}

// payloadRow is the one field the witness reads from the archived
// payload — the terminal sequence must land inside the segment's
// claimed range. Everything else is bound by the digest, not by the
// witness's opinion of the row shape.
type payloadRow struct {
	TerminalSeq int64 `json:"terminal_seq"`
}

// witness validates, stores and acknowledges one archive segment.
func (s *Server) witness(req *WitnessRequest) (*WitnessResponse, error) {
	if req.RowCount <= 0 {
		return nil, fmt.Errorf("segment %d carries no rows", req.SegmentSeq)
	}
	if req.FirstTerminalSeq <= 0 || req.LastTerminalSeq < req.FirstTerminalSeq {
		return nil, fmt.Errorf("segment %d terminal range %d..%d is invalid",
			req.SegmentSeq, req.FirstTerminalSeq, req.LastTerminalSeq)
	}
	if len(req.SHA256) != 64 || !isHex(req.SHA256) {
		return nil, fmt.Errorf("segment %d digest %q is not sha256", req.SegmentSeq, req.SHA256)
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		return nil, fmt.Errorf("segment %d payload is not base64: %w", req.SegmentSeq, err)
	}
	sum := sha256.Sum256(payload)
	gotSHA := hex.EncodeToString(sum[:])
	if gotSHA != req.SHA256 {
		// The witness attests the bytes it holds — a payload whose
		// digest disagrees with the claim is refused outright.
		return nil, fmt.Errorf("segment %d payload digests to %s, not the claimed %s — refusing to witness", req.SegmentSeq, gotSHA, req.SHA256)
	}
	var rows []payloadRow
	if err := json.Unmarshal(payload, &rows); err != nil {
		return nil, fmt.Errorf("segment %d payload is not the canonical row array: %w", req.SegmentSeq, err)
	}
	if len(rows) != req.RowCount {
		return nil, fmt.Errorf("segment %d claims %d rows but carries %d", req.SegmentSeq, req.RowCount, len(rows))
	}
	for i, r := range rows {
		if r.TerminalSeq < req.FirstTerminalSeq || r.TerminalSeq > req.LastTerminalSeq {
			return nil, fmt.Errorf("segment %d row %d terminal_seq %d outside %d..%d",
				req.SegmentSeq, i, r.TerminalSeq, req.FirstTerminalSeq, req.LastTerminalSeq)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	segPath := filepath.Join(s.cfg.CustodyDir, "segments", req.SHA256)
	if _, err := os.Stat(segPath); err == nil {
		// Idempotent custody: the digest is already held. Re-verify
		// the held bytes before re-acknowledging — custody never
		// re-attests content it did not re-check.
		held, err := os.ReadFile(segPath)
		if err != nil {
			return nil, fmt.Errorf("held segment %s unreadable: %w", req.SHA256, err)
		}
		heldSum := sha256.Sum256(held)
		if hex.EncodeToString(heldSum[:]) != req.SHA256 {
			return nil, fmt.Errorf("held segment %s digests to %s — custody store tampered", req.SHA256, hex.EncodeToString(heldSum[:]))
		}
		ack, err := s.findAck(req.SHA256)
		if err != nil {
			return nil, err
		}
		if ack == nil {
			return nil, fmt.Errorf("segment %s held but no acknowledgement is on the chain — custody store inconsistent", req.SHA256)
		}
		return ack, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("custody stat %s: %w", req.SHA256, err)
	}

	if err := writeFileAtomic(segPath, payload, 0o444); err != nil {
		return nil, fmt.Errorf("custody store %s: %w", req.SHA256, err)
	}
	ack, err := s.appendAck(req)
	if err != nil {
		return nil, err
	}
	s.audit("witnessed archive segment %d (%s, %d rows, terminal %d..%d)",
		req.SegmentSeq, req.SHA256[:12], req.RowCount, req.FirstTerminalSeq, req.LastTerminalSeq)
	return ack, nil
}

// AckRecord is one link of the custody chain — the signed
// acknowledgement that a segment's bytes are durably held.
type AckRecord struct {
	RecordType       string `json:"record_type"`
	AckSeq           int64  `json:"ack_seq"`
	SegmentSeq       int64  `json:"segment_seq"`
	FirstTerminalSeq int64  `json:"first_terminal_seq"`
	LastTerminalSeq  int64  `json:"last_terminal_seq"`
	RowCount         int    `json:"row_count"`
	PayloadSHA256    string `json:"payload_sha256"`
	PrevAckSHA256    string `json:"prev_ack_sha256"`
	WitnessedAt      string `json:"witnessed_at"`
	PublicKey        string `json:"public_key"`
	Signer           string `json:"signer"`
	Signature        string `json:"signature"`
}

// ackFields is the signing vector — every field the signature commits
// to, in declared order.
func (a *AckRecord) ackFields() []string {
	return []string{
		a.RecordType,
		fmt.Sprint(a.AckSeq),
		fmt.Sprint(a.SegmentSeq),
		fmt.Sprint(a.FirstTerminalSeq),
		fmt.Sprint(a.LastTerminalSeq),
		fmt.Sprint(a.RowCount),
		a.PayloadSHA256,
		a.PrevAckSHA256,
		a.WitnessedAt,
		a.PublicKey,
		a.Signer,
	}
}

// appendAck signs and appends the acknowledgement — the caller holds
// the store lock, so the chain grows one link at a time.
func (s *Server) appendAck(req *WitnessRequest) (*WitnessResponse, error) {
	chainPath := filepath.Join(s.cfg.CustodyDir, "acks.jsonl")
	prevSHA, nextSeq, err := chainTail(chainPath)
	if err != nil {
		return nil, err
	}
	pub := s.signer.PublicKey()
	ack := &AckRecord{
		RecordType:       "archive-custody-ack/v1",
		AckSeq:           nextSeq,
		SegmentSeq:       req.SegmentSeq,
		FirstTerminalSeq: req.FirstTerminalSeq,
		LastTerminalSeq:  req.LastTerminalSeq,
		RowCount:         req.RowCount,
		PayloadSHA256:    req.SHA256,
		PrevAckSHA256:    prevSHA,
		WitnessedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey:        base64.StdEncoding.EncodeToString(pub),
		Signer:           evidence.Fingerprint(pub),
	}
	sig, err := s.signer.SignRecord(WitnessDomain, ack.ackFields()...)
	if err != nil {
		return nil, fmt.Errorf("sign custody ack: %w", err)
	}
	ack.Signature = sig
	line, err := json.Marshal(ack)
	if err != nil {
		return nil, fmt.Errorf("marshal custody ack: %w", err)
	}
	f, err := os.OpenFile(chainPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open custody chain: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("append custody ack: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync custody chain: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close custody chain: %w", err)
	}
	return &WitnessResponse{
		OK:              true,
		AckSeq:          ack.AckSeq,
		WitnessedSHA256: req.SHA256,
		Signer:          ack.Signer,
		Signature:       ack.Signature,
	}, nil
}

// findAck locates the prior acknowledgement for a digest — the
// idempotent-custody lookup. The chain is the source of truth: an ack
// that never made the chain does not count as custody.
func (s *Server) findAck(sha string) (*WitnessResponse, error) {
	chainPath := filepath.Join(s.cfg.CustodyDir, "acks.jsonl")
	f, err := os.Open(chainPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open custody chain: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		rec := &AckRecord{}
		if err := json.Unmarshal(sc.Bytes(), rec); err != nil {
			return nil, fmt.Errorf("custody chain malformed: %w", err)
		}
		if rec.PayloadSHA256 == sha {
			return &WitnessResponse{
				OK:              true,
				AckSeq:          rec.AckSeq,
				WitnessedSHA256: rec.PayloadSHA256,
				Signer:          rec.Signer,
				Signature:       rec.Signature,
			}, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read custody chain: %w", err)
	}
	return nil, nil
}

// chainTail reads the last chain entry: its raw bytes' digest becomes
// the next record's prev link, and its seq + 1 is the next ack seq.
func chainTail(chainPath string) (prevSHA string, nextSeq int64, err error) {
	f, err := os.Open(chainPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", 1, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("open custody chain: %w", err)
	}
	defer f.Close()
	var lastRaw []byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		lastRaw = append([]byte(nil), sc.Bytes()...)
	}
	if err := sc.Err(); err != nil {
		return "", 0, fmt.Errorf("read custody chain: %w", err)
	}
	if len(lastRaw) == 0 {
		return "", 1, nil
	}
	prev := &AckRecord{}
	if err := json.Unmarshal(lastRaw, prev); err != nil {
		return "", 0, fmt.Errorf("custody chain tail malformed: %w", err)
	}
	sum := sha256.Sum256(lastRaw)
	return hex.EncodeToString(sum[:]), prev.AckSeq + 1, nil
}

// writeFileAtomic writes a custody file: temp file, sync, rename —
// a crash leaves the pre-image or the post-image, never a torn file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// isHex reports whether s is a lowercase hex string.
func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
