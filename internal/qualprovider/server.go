// Package qualprovider implements the external qualification provider:
// an HTTP server with its own durable state that models a real external
// effect provider for Crabedence qualification.
//
// The provider runs in its own process with its own durable log, so
// executor death cannot destroy the evidence that an external effect
// happened — the topology the durable executor is designed for:
//
//	executor process A ──HTTP──▶ provider process B ──▶ durable log
//
// API surface:
//
//	POST /effects            apply an effect; idempotent on `token`
//	GET  /effects/{token}    status lookup — independent evidence for
//	                         post-crash reconciliation
//	POST /operations         CRITICAL operation ledger + immutable
//	                         artifact, deterministic fault injection
//	GET  /operations/{token} completion / non-effect proof lookup
//	GET  /artifacts/{id}     immutable artifact bytes
//	GET  /stats              operation/execution counts
//
// Every applied effect and operation is appended to fsynced JSON-lines
// ledgers BEFORE the response is sent: the provider never acknowledges
// work it cannot prove later. This package is shared by the test
// harness helper process and the deployed qualification binary — the
// same code serves both, so harness results carry over to deployed
// qualification.
package qualprovider

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Fault names, injected deterministically per request via the
// X-Qualification-Fault header (or ?fault= for lookups).
const (
	FaultFailBeforeAccept  = "FAIL_BEFORE_ACCEPT"
	FaultCommitThenTimeout = "COMMIT_THEN_TIMEOUT"
	FaultCommitThenReset   = "COMMIT_THEN_RESET"
	FaultLookupUnavailable = "LOOKUP_TEMPORARILY_UNAVAILABLE"
	FaultDefinitiveReject  = "DEFINITIVE_REJECTION"
	FaultWrongArtifactDig  = "WRONG_ARTIFACT_DIGEST"
	FaultCorruptArtifact   = "CORRUPT_ARTIFACT"
)

// LogEntry is one durable record in the provider's effects log.
type LogEntry struct {
	Token     string          `json:"token"`
	RunID     string          `json:"run_id"`
	EffectN   int             `json:"effect_n"`
	Result    json.RawMessage `json:"result"`
	Timestamp time.Time       `json:"timestamp"`
}

// Operation is one durable record in the provider's operation ledger
// (operations.jsonl, fsynced before the response is sent). The ledger
// is the provider's independent knowledge of whether the external
// operation happened: killing Crabedence cannot erase it.
type Operation struct {
	Token          string          `json:"token"`
	PayloadDigest  string          `json:"payload_digest"`
	OperationID    string          `json:"operation_id"`
	ArtifactID     string          `json:"artifact_id"`
	ArtifactDigest string          `json:"artifact_digest"`
	Status         string          `json:"status"` // COMMITTED | REJECTED
	Result         json.RawMessage `json:"result,omitempty"`
	Executions     int             `json:"executions"`
	Timestamp      time.Time       `json:"timestamp"`
}

// Server is the qualification provider HTTP service bound to a state
// directory (durable ledgers + immutable artifacts).
type Server struct {
	dir         string
	logPath     string
	opLedger    string
	artifactDir string

	mu              sync.Mutex
	effects         int
	seen            map[string]LogEntry
	opsByToken      map[string]Operation
	opSeq           int
	totalExecutions int
}

// New creates the provider server rooted at dir. The directory holds
// the effects log, the operation ledger (operations.jsonl), and
// artifacts/; all are created with owner-only permissions. Durable
// state is reloaded from the ledger so a restarted provider remembers
// every operation it ever accepted.
func New(dir, logName string) (*Server, error) {
	if dir == "" {
		return nil, fmt.Errorf("qualprovider: state directory required")
	}
	if logName == "" {
		logName = "provider-log.jsonl"
	}
	s := &Server{
		dir:         dir,
		logPath:     filepath.Join(dir, logName),
		opLedger:    filepath.Join(dir, "operations.jsonl"),
		artifactDir: filepath.Join(dir, "artifacts"),
		seen:        map[string]LogEntry{},
		opsByToken:  map[string]Operation{},
	}
	if err := os.MkdirAll(s.artifactDir, 0o700); err != nil {
		return nil, err
	}
	// Reload the operation ledger — provider truth survives restarts.
	if data, err := os.ReadFile(s.opLedger); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var op Operation
			if json.Unmarshal([]byte(line), &op) == nil && op.Token != "" {
				s.opsByToken[op.Token] = op
				s.opSeq++
				s.totalExecutions += op.Executions
			}
		}
	}
	return s, nil
}

// Handler returns the provider's HTTP handler surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /effects", s.postEffects)
	mux.HandleFunc("GET /effects/{token}", s.getEffect)
	mux.HandleFunc("POST /operations", s.postOperation)
	mux.HandleFunc("GET /operations/{token}", s.getOperation)
	mux.HandleFunc("GET /artifacts/{id}", s.getArtifact)
	mux.HandleFunc("GET /stats", s.getStats)
	return mux
}

// LogPath returns the durable effects log path.
func (s *Server) LogPath() string { return s.logPath }

func appendLine(path string, v any) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(v)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Server) writeArtifact(id string, data []byte) error {
	path := filepath.Join(s.artifactDir, id)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Server) readArtifact(id string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.artifactDir, id))
}

func (s *Server) postEffects(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	respond := func(e LogEntry) {
		// Completion evidence: the durable log entry bytes ARE the
		// artifact; the digest is SHA-256 over them — Crabedence
		// recomputes it before attesting, never trusts the claim.
		artifact, _ := json.Marshal(e)
		sum := sha256.Sum256(artifact)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "SUCCEEDED", "run_id": e.RunID, "result": e.Result,
			"evidence": map[string]any{
				// RawMessage embeds the entry bytes — a []byte
				// would marshal as base64 and the executor would
				// attest a digest of the wrong bytes.
				"artifact": json.RawMessage(artifact),
				"digest":   fmt.Sprintf("%x", sum),
			},
		})
	}
	if e, ok := s.seen[body.Token]; ok {
		// Idempotent replay — logged result, no new effect.
		respond(e)
		return
	}
	s.effects++
	e := LogEntry{
		Token:     body.Token,
		RunID:     fmt.Sprintf("run-%d", s.effects),
		EffectN:   s.effects,
		Result:    json.RawMessage(`{"ok":true}`),
		Timestamp: time.Now().UTC(),
	}
	if err := appendLine(s.logPath, e); err != nil {
		http.Error(w, `{"error":"log failed"}`, http.StatusInternalServerError)
		return
	}
	s.seen[body.Token] = e
	respond(e)
}

func (s *Server) getEffect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.seen[r.PathValue("token")]
	if !ok {
		// Re-scan the durable log — truth survives process restart.
		data, _ := os.ReadFile(s.logPath)
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var le LogEntry
			if json.Unmarshal([]byte(line), &le) == nil && le.Token == r.PathValue("token") {
				e, ok = le, true
			}
		}
	}
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(e)
}

func (s *Server) respondOperation(w http.ResponseWriter, op Operation, fault string) {
	artifact, err := s.readArtifact(op.ArtifactID)
	if err != nil {
		http.Error(w, `{"error":"artifact missing"}`, http.StatusInternalServerError)
		return
	}
	declared := op.ArtifactDigest
	if fault == FaultWrongArtifactDig {
		// Claim a valid-looking digest that does not cover the bytes.
		declared = strings.Repeat("0", 64)
	}
	if fault == FaultCorruptArtifact {
		// Corrupt the bytes in transit; the durable artifact file is
		// untouched, so the provider's ledger remains the truth.
		corrupted := append([]byte(nil), artifact...)
		corrupted[len(corrupted)-1] ^= 0x01
		artifact = corrupted
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status":       op.Status,
		"operation_id": op.OperationID,
		"run_id":       op.OperationID,
		"artifact_id":  op.ArtifactID,
		"digest":       declared,
		"result":       op.Result,
		"artifact":     json.RawMessage(artifact),
	})
}

func (s *Server) postOperation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token   string          `json:"token"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	fault := r.Header.Get("X-Qualification-Fault")
	payloadSum := sha256.Sum256(body.Payload)
	payloadDigest := fmt.Sprintf("%x", payloadSum)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.opsByToken[body.Token]; ok {
		if existing.PayloadDigest != payloadDigest {
			// Same token, different payload: an idempotency collision,
			// never a second effect.
			http.Error(w, `{"error":"operation token bound to a different payload"}`, http.StatusConflict)
			return
		}
		// Duplicate token with the same payload: replay the original
		// operation. No new effect.
		s.respondOperation(w, existing, fault)
		return
	}

	if fault == FaultFailBeforeAccept {
		http.Error(w, `{"error":"rejected before accept"}`, http.StatusInternalServerError)
		return
	}

	s.opSeq++
	op := Operation{
		Token:         body.Token,
		PayloadDigest: payloadDigest,
		OperationID:   fmt.Sprintf("op-%d", s.opSeq),
		ArtifactID:    fmt.Sprintf("art-%d", s.opSeq),
		Status:        "COMMITTED",
		Executions:    1,
		Result:        json.RawMessage(fmt.Sprintf(`{"operation_id":"op-%d"}`, s.opSeq)),
		Timestamp:     time.Now().UTC(),
	}
	var artifact []byte
	if fault == FaultDefinitiveReject {
		// A definitive rejection: no external effect occurred, and the
		// provider can prove it with an artifact.
		op.Status = "REJECTED"
		op.Executions = 0
		op.Result = nil
		artifact = []byte(fmt.Sprintf(`{"operation_id":%q,"outcome":"REJECTED","reason":"deterministic rejection"}`, op.OperationID))
	} else {
		artifact = []byte(fmt.Sprintf(`{"operation_id":%q,"token":%q,"outcome":"COMMITTED"}`, op.OperationID, op.Token))
	}
	artifactSum := sha256.Sum256(artifact)
	op.ArtifactDigest = fmt.Sprintf("%x", artifactSum)
	if err := appendLine(s.opLedger, op); err != nil {
		http.Error(w, `{"error":"ledger failed"}`, http.StatusInternalServerError)
		return
	}
	if err := s.writeArtifact(op.ArtifactID, artifact); err != nil {
		http.Error(w, `{"error":"artifact failed"}`, http.StatusInternalServerError)
		return
	}
	s.opsByToken[op.Token] = op
	s.totalExecutions += op.Executions

	switch fault {
	case FaultCommitThenTimeout:
		// The operation is durable; the response never arrives. The
		// state mutex is released first so the lookup endpoint keeps
		// serving while this connection hangs.
		s.mu.Unlock()
		time.Sleep(30 * time.Second)
		s.mu.Lock()
		return
	case FaultCommitThenReset:
		// The operation is durable; the connection dies without a
		// response (a reset, not a clean close).
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return
			}
		}
		return
	}
	s.respondOperation(w, op, fault)
}

func (s *Server) getOperation(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("fault") == FaultLookupUnavailable {
		http.Error(w, `{"error":"temporarily unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.opsByToken[r.PathValue("token")]
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(op)
}

func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.readArtifact(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *Server) getStats(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]int{
		"operations": len(s.opsByToken),
		"executions": s.totalExecutions,
	})
}
