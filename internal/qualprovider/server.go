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
//	                         (legacy-effects-v2 compatibility mode —
//	                         see "Legacy effects endpoint" below)
//	GET  /effects/{token}    status lookup — independent evidence for
//	                         post-crash reconciliation
//	POST /operations         CRITICAL operation ledger + immutable
//	                         artifact, deterministic fault injection
//	GET  /operations/{token} completion / non-effect proof lookup
//	GET  /artifacts/{id}     immutable artifact bytes
//	GET  /stats              operation/execution counts
//
// # Legacy effects endpoint
//
// /effects is retained for the external-provider crash-qualification
// harness (internal/execution's external provider tests dispatch
// through it and reconcile against GET /effects/{token}). It carries
// strict durable semantics identical in kind to the operation ledger:
// the log is fully validated before the server serves anything, an
// acknowledged effect survives restart, and any byte of durable state
// the provider cannot interpret fails startup closed. New
// qualification flows should use /operations; /effects is documented
// for removal once the crash-qualification harness is migrated.
//
// # Two-phase operation commit
//
// An operation is durably accepted only when its PREPARED record is
// fsynced; the acknowledgement is sent only after the artifact and the
// COMMITTED record are durable. The phases are ordered so every crash
// boundary is recoverable:
//
//	PREPARED record (fsync)   acceptance — a retry replays, never re-executes
//	artifact (temp, fsync, atomic rename, parent fsync)
//	COMMITTED record (fsync)  the acknowledgement point
//
// Every applied effect and operation is appended to fsynced JSON-lines
// ledgers BEFORE the response is sent: the provider never acknowledges
// work it cannot prove later. This package is shared by the test
// harness helper process and the deployed qualification binary — the
// same code serves both, so harness results carry over to deployed
// qualification.
//
// # Startup recovery
//
// New() refuses to start on a ledger or artifact store it cannot
// interpret: a corrupt line outside a crash-torn tail, a token bound to
// two payloads, a COMMITTED marker without its PREPARED record, an
// artifact that does not match its recorded digest, or an artifact path
// that is not a regular file (symlinks are never followed). The one
// documented recovery is the crash-torn final line — an append that
// never completed and was therefore never acknowledged — which is
// dropped so the ledger stays a sequence of complete records. Records
// written before the two-phase protocol (a bare Operation line) are
// read as PREPARED records, and a missing artifact is reconstructed
// from the record and verified against the recorded digest before it is
// ever served.
package qualprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

	// Phase-boundary crash faults: the named phase completes durably,
	// then the response is never sent — the observable equivalent of
	// the process dying at that boundary. A restart (or a retry) must
	// recover to exactly one committed operation.
	FaultFailAfterPrepared  = "FAIL_AFTER_PREPARED"
	FaultFailAfterArtifact  = "FAIL_AFTER_ARTIFACT"
	FaultFailAfterCommitted = "FAIL_AFTER_COMMITTED"
)

// Ledger record phases.
const (
	phasePrepared  = "PREPARED"
	phaseCommitted = "COMMITTED"
)

// maxRequestBodyBytes bounds any request body the provider will read.
const maxRequestBodyBytes = 1 << 20

// Legacy-effects durability error identifiers — surfaced verbatim in
// startup errors and HTTP error bodies so the qualification harness
// classifies them rather than guessing from status codes.
const (
	// ErrCorruptEffectLog: the durable effects log failed validation —
	// malformed record, torn tail, duplicate/conflicting identity, or
	// an unsafe file type at the ledger path.
	ErrCorruptEffectLog = "ERR_CORRUPT_EFFECT_LOG"
	// ErrEffectLogUnreadable: the ledger exists but could not be read
	// (EIO, EACCES, …). Unreadable acknowledged state can never be
	// treated as empty acknowledged state.
	ErrEffectLogUnreadable = "ERR_EFFECT_LOG_UNREADABLE"
	// ErrDuplicateTokenConflict: one token is bound to two records.
	ErrDuplicateTokenConflict = "ERR_DUPLICATE_TOKEN_CONFLICT"
	// ErrRecoveryRequired: a durable write's completion is ambiguous —
	// the provider no longer accepts new mutations until the state is
	// re-verified by a restart (or explicit operator reconciliation).
	ErrRecoveryRequired = "ERR_RECOVERY_REQUIRED"
)

// Durable effects-log bounds: the ledger is small by design; anything
// larger is corruption or abuse, not workload.
const (
	maxEffectsLogBytes   = 256 << 20
	maxEffectsLogRecords = 1 << 20
	maxEffectTokenBytes  = 4096
)

var (
	opIDPattern   = regexp.MustCompile(`^op-([0-9]+)$`)
	artIDPattern  = regexp.MustCompile(`^art-([0-9]+)$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// LogEntry is one durable record in the provider's effects log.
type LogEntry struct {
	Token     string          `json:"token"`
	RunID     string          `json:"run_id"`
	EffectN   int             `json:"effect_n"`
	Result    json.RawMessage `json:"result"`
	Timestamp time.Time       `json:"timestamp"`
}

// Operation is one durable operation, served by GET /operations/{token}.
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

// ledgerRecord is one line of operations.jsonl. A PREPARED record
// carries the complete operation; a COMMITTED record is the marker that
// names the operation whose artifact and commit are both durable. A
// record written before the two-phase protocol has no phase field and
// is read as PREPARED.
type ledgerRecord struct {
	Phase          string          `json:"phase"`
	Token          string          `json:"token"`
	PayloadDigest  string          `json:"payload_digest,omitempty"`
	OperationID    string          `json:"operation_id"`
	ArtifactID     string          `json:"artifact_id,omitempty"`
	ArtifactDigest string          `json:"artifact_digest"`
	Status         string          `json:"status,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	Executions     int             `json:"executions,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
}

// Server is the qualification provider HTTP service bound to a state
// directory (durable ledgers + immutable artifacts).
type Server struct {
	dir         string
	logPath     string
	opLedger    string
	artifactDir string
	fs          durableFS

	mu      sync.Mutex
	effects int
	seen    map[string]LogEntry
	// degraded is non-nil once a durable write's completion is
	// ambiguous: a failed append may have left torn bytes, so the
	// provider stops accepting NEW mutations until the state is
	// re-verified by restart. Acknowledged records keep answering —
	// they are durable truth — but nothing uncertain is served.
	degraded   error
	opsByToken map[string]Operation
	// prepared holds operations whose PREPARED record is durable but
	// whose commit has not completed; a retry completes the commit
	// rather than executing again.
	prepared map[string]Operation
	// committed marks tokens whose COMMITTED marker is durable.
	committed       map[string]bool
	opSeq           int
	totalExecutions int
}

// New creates the provider server rooted at dir. The directory holds
// the effects log, the operation ledger (operations.jsonl), and
// artifacts/; all are created with owner-only permissions. Durable
// state is reloaded — and repaired where a crash interrupted a commit —
// before the server serves anything.
func New(dir, logName string) (*Server, error) {
	return newServer(dir, logName, osDurableFS{})
}

func newServer(dir, logName string, fs durableFS) (*Server, error) {
	if dir == "" {
		return nil, fmt.Errorf("qualprovider: state directory required")
	}
	if logName == "" {
		logName = "provider-log.jsonl"
	}
	// The ledger always lives inside the state directory — a caller
	// naming anything else is a defect, not a configuration.
	logName = filepath.Base(logName)
	s := &Server{
		dir:         dir,
		logPath:     filepath.Join(dir, logName),
		opLedger:    filepath.Join(dir, "operations.jsonl"),
		artifactDir: filepath.Join(dir, "artifacts"),
		fs:          fs,
		seen:        map[string]LogEntry{},
		opsByToken:  map[string]Operation{},
		prepared:    map[string]Operation{},
		committed:   map[string]bool{},
	}
	// The state directory is private by contract — the ledgers in it
	// are the provider's acknowledged truth, so a directory another
	// principal can read or write is refused before anything opens.
	if err := ensurePrivateStateDir(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.artifactDir, 0o700); err != nil {
		return nil, err
	}
	// Artifact scan first: it validates that every artifact-shaped entry
	// is a regular file (never a link), removes scratch files from an
	// interrupted atomic write, and advances the operation sequence past
	// any orphan so a new operation can never overwrite existing bytes.
	if err := s.scanArtifacts(); err != nil {
		return nil, err
	}
	// Reload (and repair) the operation ledger — provider truth survives
	// restarts, and an interrupted commit is completed, never repeated.
	if err := s.recoverLedger(); err != nil {
		return nil, err
	}
	// Reload the effects log under the same contract as the operation
	// ledger: the whole file validates before any of it becomes live
	// state, a replayed token stays idempotent across restarts, and
	// EffectN never repeats. Any state the provider cannot interpret —
	// corrupt, torn, conflicting, unreadable — refuses startup rather
	// than silently becoming an empty map.
	seen, maxN, err := s.loadEffectsLog()
	if err != nil {
		return nil, err
	}
	s.seen = seen
	s.effects = maxN
	return s, nil
}

// loadEffectsLog strictly validates the durable effects log and returns
// the recovered acknowledged-state map and the highest durable effect
// number. The map is populated only when every byte of the log is
// accounted for — a partially parsed ledger never becomes live state.
//
// An absent file is a first initialization; anything else that is not
// a complete newline-terminated sequence of well-formed records fails
// closed: a torn final line is an append that may or may not have been
// acknowledged before the process died, and guessing either way can
// mint a second effect or forget one that happened. The bytes are left
// in place for diagnosis; recovery is an explicit operator action, not
// an automatic rewrite.
func (s *Server) loadEffectsLog() (map[string]LogEntry, int, error) {
	seen := map[string]LogEntry{}
	info, err := s.fs.Lstat(s.logPath)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("%s: %s is not a regular file (%s)", ErrCorruptEffectLog, s.logPath, info.Mode())
		}
		if info.Size() > maxEffectsLogBytes {
			return nil, 0, fmt.Errorf("%s: %s is %d bytes, exceeding the %d-byte ledger bound", ErrCorruptEffectLog, s.logPath, info.Size(), maxEffectsLogBytes)
		}
	case os.IsNotExist(err):
		return seen, 0, nil // first initialization — no acknowledged state yet
	default:
		return nil, 0, fmt.Errorf("%s: stat %s: %w", ErrEffectLogUnreadable, s.logPath, err)
	}
	data, err := s.fs.ReadFile(s.logPath)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: read %s: %w", ErrEffectLogUnreadable, s.logPath, err)
	}
	if len(data) == 0 {
		return seen, 0, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, 0, fmt.Errorf("%s: %s ends in a torn record — an append interrupted before acknowledgement; preserve the bytes and reconcile before restarting", ErrCorruptEffectLog, s.logPath)
	}
	lines := bytes.Split(data[:len(data)-1], []byte("\n"))
	if len(lines) > maxEffectsLogRecords {
		return nil, 0, fmt.Errorf("%s: %s holds %d records, exceeding the %d-record bound", ErrCorruptEffectLog, s.logPath, len(lines), maxEffectsLogRecords)
	}
	maxN := 0
	for i, line := range lines {
		if len(line) == 0 {
			return nil, 0, fmt.Errorf("%s: %s line %d is empty — a missing record boundary", ErrCorruptEffectLog, s.logPath, i+1)
		}
		e, err := parseEffectRecord(line)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %s line %d: %w", ErrCorruptEffectLog, s.logPath, i+1, err)
		}
		if e.EffectN <= maxN {
			return nil, 0, fmt.Errorf("%s: %s line %d: effect number %d does not strictly increase (previous %d) — the durable sequence order is violated", ErrCorruptEffectLog, s.logPath, i+1, e.EffectN, maxN)
		}
		if _, dup := seen[e.Token]; dup {
			return nil, 0, fmt.Errorf("%s: %s line %d: token %q is bound to two records", ErrDuplicateTokenConflict, s.logPath, i+1, e.Token)
		}
		seen[e.Token] = e
		maxN = e.EffectN
	}
	return seen, maxN, nil
}

// parseEffectRecord validates one effects-log line: exactly one
// complete JSON object in the committed schema, with a non-empty
// bounded token, a positive effect number that matches the canonical
// run identity, a real timestamp and a real JSON result. Unknown
// fields are refused — the durable schema is owned by this provider
// and a field it does not know is not a record it wrote.
func parseEffectRecord(line []byte) (LogEntry, error) {
	var e LogEntry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return e, fmt.Errorf("trailing data after the record")
	}
	if e.Token == "" {
		return e, fmt.Errorf("record has no token")
	}
	if len(e.Token) > maxEffectTokenBytes {
		return e, fmt.Errorf("token exceeds the %d-byte bound", maxEffectTokenBytes)
	}
	if e.EffectN <= 0 {
		return e, fmt.Errorf("record for token %q has non-positive effect number %d", e.Token, e.EffectN)
	}
	if want := fmt.Sprintf("run-%d", e.EffectN); e.RunID != want {
		return e, fmt.Errorf("record for token %q binds run %q to effect %d — the canonical run identity is %q", e.Token, e.RunID, e.EffectN, want)
	}
	if e.Timestamp.IsZero() {
		return e, fmt.Errorf("record for token %q has no timestamp", e.Token)
	}
	if len(e.Result) == 0 || string(e.Result) == "null" {
		return e, fmt.Errorf("record for token %q has no result", e.Token)
	}
	return e, nil
}

// ensurePrivateStateDir makes the provider's state directory if absent
// and refuses one it cannot prove private: the durable ledgers inside
// are acknowledged truth, so a shared, world-readable or foreign-owned
// directory is a deployment defect, not a preference.
func ensurePrivateStateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dir, 0o700)
		}
		return fmt.Errorf("state directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state directory %s is a symlink — the durable state path is never followed", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("state path %s is not a directory (%s)", dir, info.Mode())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("state directory %s is not private (mode %o grants group/other access)", dir, perm)
	}
	return privateDirOwner(dir, info)
}

// scanArtifacts validates the artifact directory and advances the
// operation sequence past every existing artifact identity.
func (s *Server) scanArtifacts() error {
	names, err := s.fs.ReadDirNames(s.artifactDir)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, ".tmp-") {
			// Scratch from an interrupted atomic write: never referenced
			// by a ledger record, never served, safe to remove.
			if err := s.fs.Remove(filepath.Join(s.artifactDir, name)); err != nil {
				return err
			}
			continue
		}
		n, ok := artifactNumber(name)
		if !ok {
			// Not an artifact identity this provider mints; it is never
			// served and never deleted.
			continue
		}
		info, err := s.fs.Lstat(filepath.Join(s.artifactDir, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact %s is not a regular file (%s) — refusing to serve or overwrite it", name, info.Mode())
		}
		if n > s.opSeq {
			s.opSeq = n
		}
	}
	return nil
}

// recoverLedger parses the operation ledger, refusing any state it
// cannot interpret, and completes an interrupted commit exactly once.
func (s *Server) recoverLedger() error {
	data, err := s.fs.ReadFile(s.opLedger)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read operation ledger: %w", err)
	}
	lines, droppedTornTail := splitCompleteLines(data)
	if droppedTornTail {
		// The torn tail was never acknowledged (the response follows the
		// completed, fsynced append), so dropping it loses no promise —
		// and keeping it would corrupt the next append.
		kept := bytes.Join(lines, []byte("\n"))
		if len(kept) > 0 {
			kept = append(kept, '\n')
		}
		if err := s.fs.WriteFileAtomic(s.opLedger, kept); err != nil {
			return fmt.Errorf("drop torn ledger tail: %w", err)
		}
	}
	var order []string
	byToken := map[string]*tokenRecords{}
	for i, line := range lines {
		rec, err := parseLedgerRecord(line)
		if err != nil {
			return fmt.Errorf("operations ledger line %d: %w", i+1, err)
		}
		if n := opNumber(rec.OperationID); n > s.opSeq {
			s.opSeq = n
		}
		tr, ok := byToken[rec.Token]
		if !ok {
			tr = &tokenRecords{token: rec.Token}
			byToken[rec.Token] = tr
			order = append(order, rec.Token)
		}
		tr.add(rec)
	}
	seenOps := map[string]string{}
	seenArtifacts := map[string]string{}
	for _, token := range order {
		tr := byToken[token]
		canonical, err := tr.resolve()
		if err != nil {
			return err
		}
		if prev, dup := seenOps[canonical.OperationID]; dup {
			return fmt.Errorf("operation %s is bound to two tokens (%s and %s)", canonical.OperationID, prev, token)
		}
		seenOps[canonical.OperationID] = token
		if prev, dup := seenArtifacts[canonical.ArtifactID]; dup {
			return fmt.Errorf("artifact %s is bound to two tokens (%s and %s)", canonical.ArtifactID, prev, token)
		}
		seenArtifacts[canonical.ArtifactID] = token

		op := canonical.operation()
		if err := s.ensureArtifact(op); err != nil {
			return err
		}
		if len(tr.committed) == 0 {
			if err := s.appendRecord(s.opLedger, committedRecord(op)); err != nil {
				return fmt.Errorf("complete commit for token %s: %w", token, err)
			}
		}
		s.opsByToken[token] = op
		s.committed[token] = true
		s.totalExecutions += op.Executions
	}
	return nil
}

// tokenRecords groups one token's ledger records for resolution.
type tokenRecords struct {
	token     string
	prepared  []ledgerRecord
	committed []ledgerRecord
}

func (tr *tokenRecords) add(rec ledgerRecord) {
	switch rec.Phase {
	case phasePrepared:
		tr.prepared = append(tr.prepared, rec)
	case phaseCommitted:
		tr.committed = append(tr.committed, rec)
	}
}

// resolve picks the canonical operation for a token. A token may appear
// in more than one PREPARED record only in ledgers written before the
// two-phase protocol (where a failed artifact write followed by a retry
// appended twice); the last attempt is the one that can have been
// acknowledged, so the highest operation number wins and the others are
// treated as unreferenced history. Conflicting payload bindings and
// ambiguous markers are refused.
func (tr *tokenRecords) resolve() (ledgerRecord, error) {
	if len(tr.prepared) == 0 {
		return ledgerRecord{}, fmt.Errorf("token %q has a COMMITTED record with no PREPARED record", tr.token)
	}
	if len(tr.committed) > 1 {
		return ledgerRecord{}, fmt.Errorf("token %q has %d COMMITTED records", tr.token, len(tr.committed))
	}
	digest := tr.prepared[0].PayloadDigest
	canonical := tr.prepared[0]
	seen := map[string]bool{canonical.OperationID: true}
	for _, rec := range tr.prepared[1:] {
		if rec.PayloadDigest != digest {
			return ledgerRecord{}, fmt.Errorf("token %q is bound to two payloads (%s and %s)", tr.token, digest, rec.PayloadDigest)
		}
		if seen[rec.OperationID] {
			return ledgerRecord{}, fmt.Errorf("token %q repeats operation %s", tr.token, rec.OperationID)
		}
		seen[rec.OperationID] = true
		if opNumber(rec.OperationID) > opNumber(canonical.OperationID) {
			canonical = rec
		}
	}
	if len(tr.committed) == 1 {
		marker := tr.committed[0]
		if marker.OperationID != canonical.OperationID || marker.ArtifactDigest != canonical.ArtifactDigest {
			return ledgerRecord{}, fmt.Errorf("token %q COMMITTED marker does not match its PREPARED record", tr.token)
		}
	}
	return canonical, nil
}

// parseLedgerRecord parses and validates one ledger line.
func parseLedgerRecord(line []byte) (ledgerRecord, error) {
	var rec ledgerRecord
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return rec, fmt.Errorf("trailing data after the record")
	}
	if rec.Token == "" {
		return rec, fmt.Errorf("record has no token")
	}
	if !opIDPattern.MatchString(rec.OperationID) {
		return rec, fmt.Errorf("record for token %q has invalid operation id %q", rec.Token, rec.OperationID)
	}
	if !sha256Pattern.MatchString(rec.ArtifactDigest) {
		return rec, fmt.Errorf("record for token %q has invalid artifact digest %q", rec.Token, rec.ArtifactDigest)
	}
	if rec.Phase == "" {
		rec.Phase = phasePrepared
	}
	switch rec.Phase {
	case phasePrepared:
		if !sha256Pattern.MatchString(rec.PayloadDigest) {
			return rec, fmt.Errorf("record for token %q has invalid payload digest %q", rec.Token, rec.PayloadDigest)
		}
		if !artIDPattern.MatchString(rec.ArtifactID) {
			return rec, fmt.Errorf("record for token %q has invalid artifact id %q", rec.Token, rec.ArtifactID)
		}
		artifactN, _ := artifactNumber(rec.ArtifactID)
		if opNumber(rec.OperationID) != artifactN {
			return rec, fmt.Errorf("record for token %q pairs operation %s with artifact %s", rec.Token, rec.OperationID, rec.ArtifactID)
		}
		if rec.Status != "COMMITTED" && rec.Status != "REJECTED" {
			return rec, fmt.Errorf("record for token %q has unknown status %q", rec.Token, rec.Status)
		}
	case phaseCommitted:
	default:
		return rec, fmt.Errorf("record for token %q has unknown phase %q", rec.Token, rec.Phase)
	}
	return rec, nil
}

// splitCompleteLines splits a ledger into complete lines. A file that
// does not end in a newline ends in a torn append (the process died
// mid-write, before the fsync that precedes the acknowledgement); that
// fragment is dropped. Blank lines are skipped.
func splitCompleteLines(data []byte) (lines [][]byte, droppedTornTail bool) {
	if len(data) == 0 {
		return nil, false
	}
	complete := data
	if data[len(data)-1] != '\n' {
		idx := bytes.LastIndexByte(data, '\n')
		if idx < 0 {
			return nil, true
		}
		complete = data[:idx+1]
		droppedTornTail = true
	}
	for _, line := range bytes.Split(bytes.TrimSuffix(complete, []byte("\n")), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		lines = append(lines, line)
	}
	return lines, droppedTornTail
}

// ensureArtifact makes sure the artifact for an operation exists and
// matches the recorded digest. A missing artifact is reconstructed from
// the record — the derivation is deterministic — and verified before it
// is written. A mismatched artifact is refused, never overwritten.
func (s *Server) ensureArtifact(op Operation) error {
	data, err := s.fs.ReadArtifact(s.artifactDir, op.ArtifactID)
	if err == nil {
		if sum := sha256.Sum256(data); fmt.Sprintf("%x", sum) != op.ArtifactDigest {
			return fmt.Errorf("artifact %s does not match the recorded digest — refusing to overwrite evidence", op.ArtifactID)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("artifact %s: %w", op.ArtifactID, err)
	}
	want := artifactFor(op)
	if sum := sha256.Sum256(want); fmt.Sprintf("%x", sum) != op.ArtifactDigest {
		return fmt.Errorf("artifact %s: recorded digest does not cover the reconstructed artifact", op.ArtifactID)
	}
	return s.writeArtifactAtomic(op.ArtifactID, want)
}

// writeArtifactAtomic writes one artifact without ever truncating or
// replacing existing bytes: a fresh identity is chosen at acceptance, so
// an existing file here is evidence this write must not destroy.
func (s *Server) writeArtifactAtomic(id string, data []byte) error {
	target := filepath.Join(s.artifactDir, id)
	if _, err := s.fs.Lstat(target); err == nil {
		return fmt.Errorf("artifact %s already exists — refusing to overwrite evidence", id)
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := s.fs.WriteTemp(s.artifactDir, id, data)
	if err != nil {
		return err
	}
	if err := s.fs.Rename(tmp, target); err != nil {
		s.fs.Remove(tmp)
		return err
	}
	return s.fs.SyncDir(s.artifactDir)
}

// artifactFor derives the artifact bytes an operation commits to. The
// derivation is deterministic over the durable record, which is what
// makes an interrupted artifact write recoverable: the bytes can always
// be reconstructed and checked against the recorded digest.
func artifactFor(op Operation) []byte {
	if op.Status == "REJECTED" {
		return []byte(fmt.Sprintf(`{"operation_id":%q,"outcome":"REJECTED","reason":"deterministic rejection"}`, op.OperationID))
	}
	return []byte(fmt.Sprintf(`{"operation_id":%q,"token":%q,"outcome":"COMMITTED"}`, op.OperationID, op.Token))
}

func preparedRecord(op Operation) ledgerRecord {
	return ledgerRecord{
		Phase:          phasePrepared,
		Token:          op.Token,
		PayloadDigest:  op.PayloadDigest,
		OperationID:    op.OperationID,
		ArtifactID:     op.ArtifactID,
		ArtifactDigest: op.ArtifactDigest,
		Status:         op.Status,
		Result:         op.Result,
		Executions:     op.Executions,
		Timestamp:      op.Timestamp,
	}
}

func committedRecord(op Operation) ledgerRecord {
	return ledgerRecord{
		Phase:          phaseCommitted,
		Token:          op.Token,
		OperationID:    op.OperationID,
		ArtifactDigest: op.ArtifactDigest,
		Timestamp:      time.Now().UTC(),
	}
}

func (rec ledgerRecord) operation() Operation {
	return Operation{
		Token:          rec.Token,
		PayloadDigest:  rec.PayloadDigest,
		OperationID:    rec.OperationID,
		ArtifactID:     rec.ArtifactID,
		ArtifactDigest: rec.ArtifactDigest,
		Status:         rec.Status,
		Result:         rec.Result,
		Executions:     rec.Executions,
		Timestamp:      rec.Timestamp,
	}
}

func (s *Server) appendRecord(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.fs.AppendLine(path, append(b, '\n'))
}

// completeCommit finishes an operation whose PREPARED record is durable
// but whose commit was interrupted: the artifact is verified (or
// reconstructed), the COMMITTED marker is appended once, and the
// operation becomes servable. It never executes anything again.
func (s *Server) completeCommit(op Operation) error {
	if err := s.ensureArtifact(op); err != nil {
		return err
	}
	if !s.committed[op.Token] {
		if err := s.appendRecord(s.opLedger, committedRecord(op)); err != nil {
			return err
		}
		s.committed[op.Token] = true
	}
	s.finishCommit(op)
	return nil
}

func (s *Server) finishCommit(op Operation) {
	s.opsByToken[op.Token] = op
	delete(s.prepared, op.Token)
	s.totalExecutions += op.Executions
}

func opNumber(id string) int {
	m := opIDPattern.FindStringSubmatch(id)
	n, _ := strconv.Atoi(m[1])
	return n
}

func artifactNumber(name string) (int, bool) {
	m := artIDPattern.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

func validArtifactName(name string) bool {
	_, ok := artifactNumber(name)
	return ok
}

func writeError(w http.ResponseWriter, status int, msg string) {
	payload, _ := json.Marshal(map[string]string{"error": msg})
	http.Error(w, string(payload), status)
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

func (s *Server) postEffects(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
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
		// Idempotent replay — logged result, no new effect. Acknowledged
		// truth keeps answering even while the provider is degraded.
		respond(e)
		return
	}
	// A never-acknowledged token is a mutation. Once a durable write
	// has failed ambiguously the provider refuses further mutations —
	// an append that may have committed torn bytes cannot be followed
	// by more appends, and uncertain state is never claimed empty.
	if s.degraded != nil {
		writeError(w, http.StatusServiceUnavailable, ErrRecoveryRequired+": "+s.degraded.Error())
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
	if err := s.appendRecord(s.logPath, e); err != nil {
		s.degraded = fmt.Errorf("effects append for token %q: %w", body.Token, err)
		writeError(w, http.StatusServiceUnavailable, ErrRecoveryRequired+": "+s.degraded.Error())
		return
	}
	s.seen[body.Token] = e
	respond(e)
}

// getEffect is the out-of-band reconciliation surface: after a crash a
// caller asks the provider, not the executor, whether a token ever ran.
// It answers only from the acknowledged-state map, which is populated
// exclusively by a strictly validated durable log or a fully committed
// append — the log is never re-scanned at query time, so state the
// provider did not durably establish can never be served.
func (s *Server) getEffect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.seen[r.PathValue("token")]
	if !ok {
		if s.degraded != nil {
			writeError(w, http.StatusServiceUnavailable, ErrRecoveryRequired+": "+s.degraded.Error())
			return
		}
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(e)
}

func (s *Server) respondOperation(w http.ResponseWriter, op Operation, fault string) {
	artifact, err := s.fs.ReadArtifact(s.artifactDir, op.ArtifactID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "artifact missing: "+err.Error())
		return
	}
	if sum := sha256.Sum256(artifact); fmt.Sprintf("%x", sum) != op.ArtifactDigest {
		writeError(w, http.StatusInternalServerError, "artifact does not match the recorded digest")
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
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var body struct {
		Token   string          `json:"token"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds the provider's bound")
			return
		}
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if body.Token == "" {
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

	if pending, ok := s.prepared[body.Token]; ok {
		if pending.PayloadDigest != payloadDigest {
			http.Error(w, `{"error":"operation token bound to a different payload"}`, http.StatusConflict)
			return
		}
		// The commit was interrupted after the durable acceptance
		// record: complete it rather than execute a second time.
		if err := s.completeCommit(pending); err != nil {
			writeError(w, http.StatusInternalServerError, "commit recovery failed: "+err.Error())
			return
		}
		s.respondOperation(w, s.opsByToken[body.Token], fault)
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
	}
	artifact = artifactFor(op)
	artifactSum := sha256.Sum256(artifact)
	op.ArtifactDigest = fmt.Sprintf("%x", artifactSum)

	// Phase 1 — durable acceptance. From here a retry replays this
	// operation; it can never execute a second time.
	if err := s.appendRecord(s.opLedger, preparedRecord(op)); err != nil {
		http.Error(w, `{"error":"ledger failed"}`, http.StatusInternalServerError)
		return
	}
	s.prepared[op.Token] = op
	if fault == FaultFailAfterPrepared {
		http.Error(w, `{"error":"interrupted after the acceptance record"}`, http.StatusInternalServerError)
		return
	}

	// Phase 2 — the artifact, atomically: temp write, fsync, rename,
	// parent-directory fsync.
	if err := s.writeArtifactAtomic(op.ArtifactID, artifact); err != nil {
		http.Error(w, `{"error":"artifact failed"}`, http.StatusInternalServerError)
		return
	}
	if fault == FaultFailAfterArtifact {
		http.Error(w, `{"error":"interrupted after the artifact"}`, http.StatusInternalServerError)
		return
	}

	// Phase 3 — the durable commit. The acknowledgement follows only
	// after this record is fsynced.
	if err := s.appendRecord(s.opLedger, committedRecord(op)); err != nil {
		http.Error(w, `{"error":"commit failed"}`, http.StatusInternalServerError)
		return
	}
	s.committed[op.Token] = true
	if fault == FaultFailAfterCommitted {
		http.Error(w, `{"error":"interrupted after the commit record"}`, http.StatusInternalServerError)
		return
	}

	s.finishCommit(op)

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
	token := r.PathValue("token")
	op, ok := s.opsByToken[token]
	if !ok {
		if pending, isPending := s.prepared[token]; isPending {
			// A lookup of an interrupted commit completes it, so the
			// answer the caller receives is backed by durable bytes.
			if err := s.completeCommit(pending); err != nil {
				writeError(w, http.StatusInternalServerError, "operation recovery failed: "+err.Error())
				return
			}
			op, ok = s.opsByToken[token]
		}
	}
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(op)
}

func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.fs.ReadArtifact(s.artifactDir, r.PathValue("id"))
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
