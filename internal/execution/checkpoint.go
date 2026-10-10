package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// ─── Evidence checkpoint emission ────────────────────────────────────
//
// A receipt proves one execution; a checkpoint proves the set. The
// service (the signer holder) periodically commits the canonical
// terminal-evidence enumeration to a signed sequence: every emission is
// appended to an append-only retained log and mirrored on the configured
// custody path — which only counts as independent custody when its
// storage lives outside this host's failure domain. An operator can
// then prove — with cmd/evidence-checkpoint — that the store still
// contains everything a held checkpoint covered. Deleting, rewriting or
// reordering a covered record breaks the chain digest; deleting all of
// them, or rolling the store back, breaks the count.
//
// The retained log is itself evidence: before extending it the emitter
// verifies the entire history — signature, contiguous sequence,
// monotonic coverage, single signing identity — so tampering with any
// historical entry stops the stream visibly instead of quietly
// inheriting a forged prefix. Writers serialize on an advisory lock so
// overlapping services cannot interleave sequence allocation with
// appends. Verification cost stays bounded with a verified-position
// cursor: an untouched log is re-anchored by the digest of its boundary
// line, while any change to the log — or the first scan in a process,
// or every checkpointFullRescanInterval emissions — pays the full scan
// that arbitrates.

// checkpointFullRescanInterval bounds how many incremental scans may
// run before the whole retained log is verified again — a corrupted
// cursor or a rewrite strictly inside the verified prefix is caught at
// the next full scan instead of persisting indefinitely.
const checkpointFullRescanInterval = 64

// runCheckpointLoop emits a signed checkpoint on the configured interval
// until ctx ends.
func runCheckpointLoop(ctx context.Context, store idempotency.EffectStore, signer *evidence.Signer, path, custodyPath string, interval time.Duration) {
	emitCheckpoint(ctx, store, signer, path, custodyPath)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emitCheckpoint(ctx, store, signer, path, custodyPath)
		}
	}
}

// emitCheckpoint enumerates the terminal evidence, signs it, appends it
// to the retained sequence log, and refreshes the latest file — locally,
// and on the configured custody path when one is set. Emission failures
// are logged, never fatal: a checkpoint that could not be written must
// not take the authority down with it — the absence of a fresh
// checkpoint is the operator-visible signal.
func emitCheckpoint(ctx context.Context, store idempotency.EffectStore, signer *evidence.Signer, path, custodyPath string) {
	logPath := retainedCheckpointLogPath(path)
	// The verify-then-append critical section is atomic across writers:
	// without the lock two emitters can read the same tail sequence and
	// interleave appends, which the next verification rightly refuses
	// as duplicated history.
	unlock, err := lockCheckpointWriter(logPath + ".lock")
	if err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot take writer lock: %v\n", err)
		return
	}
	defer func() {
		if err := unlock(); err != nil {
			fmt.Fprintf(os.Stderr, "evidence checkpoint: writer lock release failed: %v\n", err)
		}
	}()
	refs, err := store.TerminalEvidence(ctx)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot enumerate terminal evidence: %v\n", err)
		}
		return
	}
	seq, journal, err := nextCheckpointSequence(path, logPath, signer.Fingerprint())
	if err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: %v\n", err)
		return
	}
	cp := signer.SignCheckpoint(seq, refs)
	payload, err := json.Marshal(cp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot marshal checkpoint: %v\n", err)
		return
	}
	// The retained sequence is the record custody depends on: every
	// emission lands in the append-only log before the latest-file
	// pointer moves, so a torn write is a visibly corrupt tail the next
	// read refuses — never a silently lost emission. When the retained
	// log cannot record the emission the latest file must not advance
	// either: a latest checkpoint with no retained entry would break
	// the every-emission-is-retained invariant.
	if err := appendCheckpointLine(logPath, payload); err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot append to retained log %s — emission %d not recorded: %v\n", logPath, seq, err)
		return
	}
	line := append(payload, '\n')
	if err := advanceCheckpointCursor(logPath, journal, cp, line); err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot persist verified cursor for %s: %v\n", logPath, err)
	}
	if err := writeFileAtomic(path, line, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot write %s: %v\n", path, err)
	}
	if custodyPath != "" {
		mirrorCheckpointCustody(custodyPath, logPath, payload, seq)
	}
}

// mirrorCheckpointCustody carries one emission to the custody path. The
// custody log must verify under the same stream invariants as the local
// journal, so a custody copy that fell behind is first backfilled with
// the missing retained entries rather than left with a sequence gap it
// could never honestly explain. A custody log that is corrupt, forked
// or ahead of the local stream is refused loudly — appending over
// divergent custody would launder the divergence.
func mirrorCheckpointCustody(custodyPath, localLogPath string, payload []byte, seq int64) {
	custodyLog := retainedCheckpointLogPath(custodyPath)
	custodySeq, err := custodyTailSequence(custodyLog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: custody log %s is unreadable — refusing to extend possible divergent custody: %v\n", custodyLog, err)
		return
	}
	if custodySeq >= seq {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: custody log %s is at sequence %d, emission %d not appended — divergent custody needs an operator\n", custodyLog, custodySeq, seq)
		return
	}
	if custodySeq < seq-1 {
		backfill, err := retainedLinesAfter(localLogPath, custodySeq, seq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot read backfill for custody log %s: %v\n", custodyLog, err)
			return
		}
		for _, line := range backfill {
			if err := appendCheckpointLine(custodyLog, line); err != nil {
				fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot backfill custody log %s — custody mirror not updated: %v\n", custodyLog, err)
				return
			}
		}
	}
	if err := appendCheckpointLine(custodyLog, payload); err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot append to custody log %s — custody mirror not updated: %v\n", custodyLog, err)
		return
	}
	if err := writeFileAtomic(custodyPath, append(payload, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot write custody checkpoint %s: %v\n", custodyPath, err)
	}
}

// custodyTailSequence returns the sequence of the custody log's last
// retained entry, or 0 when no usable log exists. An existing log whose
// tail cannot be parsed is reported so the caller can refuse to extend
// possibly divergent custody.
func custodyTailSequence(custodyLog string) (int64, error) {
	line, err := lastLogLine(custodyLog)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(line) == 0 {
		return 0, nil
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(line, &cp); err != nil {
		return 0, fmt.Errorf("last entry not parseable: %w", err)
	}
	return cp.Sequence, nil
}

// retainedLinesAfter reads the retained entries in (after, before) out
// of the local journal, in order, so a lagging custody log can be
// caught up without a sequence gap — and without re-copying the entry
// the caller appends itself. Lines are returned without their newline
// terminators.
func retainedLinesAfter(logPath string, after, before int64) ([][]byte, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var cp evidence.Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			return nil, fmt.Errorf("cannot replay local journal %s: entry not parseable: %w", logPath, err)
		}
		if cp.Sequence > after && cp.Sequence < before {
			out = append(out, line)
		}
	}
	return out, nil
}

// retainedCheckpointLogPath names the append-only sequence log beside
// the latest-checkpoint file.
func retainedCheckpointLogPath(path string) string {
	return path + ".jsonl"
}

// appendCheckpointLine appends one complete JSON line to the retained
// sequence log and flushes it durable before returning. Each line is
// self-contained and independently signed, so a torn final line is
// visible corruption the next read refuses — never silently lost
// history.
func appendCheckpointLine(logPath string, payload []byte) error {
	fh, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	line := append(payload, '\n')
	n, err := fh.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return fh.Sync()
}

// checkpointJournal is the verified state of the retained log as the
// next emission inherits it.
type checkpointJournal struct {
	entries         int64
	lastSequence    int64
	lastRecordCount int
	lastIssuedAt    string
	lastLineOffset  int64 // byte offset where the final verified line begins
	lastLine        []byte
	scansSinceFull  int64 // incremental scans since the last full verification
}

// checkpointCursor is the persisted verified-position cursor: a
// previous pass's results pinned to the log's exact size and mtime, and
// anchored by the digest of its boundary line. It is only ever a hint —
// the log growing, shrinking or being touched by anyone since the
// cursor was written routes verification down the full path, the
// boundary digest must still match before the prefix is trusted, and a
// mandatory full scan bounds the whole mechanism periodically.
type checkpointCursor struct {
	Entries         int64  `json:"entries"`
	LastSequence    int64  `json:"last_sequence"`
	LastRecordCount int    `json:"last_record_count"`
	LastIssuedAt    string `json:"last_issued_at"`
	LastLineOffset  int64  `json:"last_line_offset"`
	LastLineSHA256  string `json:"last_line_sha256"`
	LogSize         int64  `json:"log_size"`
	LogMTimeNs      int64  `json:"log_mtime_ns"`
	ScansSinceFull  int64  `json:"scans_since_full"`
}

func checkpointCursorPath(logPath string) string {
	return logPath + ".cursor"
}

// nextCheckpointSequence returns the sequence the next emission must
// carry. The retained append-only log is the authority when it exists:
// it holds the sequence history the single latest file cannot, so a
// lost latest file cannot restart the numbering. The whole retained
// history must verify under the emitter's own signer before it is
// extended — a malformed, gap-carrying, duplicated, reordered,
// coverage-regressing or foreign-signed entry anywhere in the log is
// refused, because extending a corrupted log could quietly hide
// destroyed evidence. When no log exists the latest file's sequence
// continues, and an existing latest file that cannot be parsed is
// likewise refused: silently overwriting an unreadable checkpoint could
// destroy evidence an operator expects to keep.
//
// The journal and the latest file are reconciled: a latest file behind
// the journal is a crash between append and latest-write and is simply
// rewritten; a latest file ahead of the journal, or carrying the
// journal's tail sequence under different bytes, is a forked chain no
// emission may extend.
func nextCheckpointSequence(latestPath, logPath, signerFP string) (int64, *checkpointJournal, error) {
	journal, err := verifyRetainedJournal(logPath, signerFP)
	if err != nil {
		return 0, nil, err
	}
	if journal != nil {
		if err := reconcileLatestCheckpoint(latestPath, journal); err != nil {
			return 0, nil, err
		}
		return journal.lastSequence + 1, journal, nil
	}
	data, err := os.ReadFile(latestPath)
	if errors.Is(err, os.ErrNotExist) {
		return 1, nil, nil
	}
	if err != nil {
		return 0, nil, fmt.Errorf("cannot read existing checkpoint: %w", err)
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(bytes.TrimSpace(data), &cp); err != nil {
		return 0, nil, fmt.Errorf("existing checkpoint at %s is unreadable — refusing to overwrite possible evidence: %w", latestPath, err)
	}
	return cp.Sequence + 1, nil, nil
}

// journalFullScans records the logs this process has already full-
// scanned: the first verification a process performs is always a full
// scan, because a cursor written before this writer existed cannot
// vouch for what happened while it was away.
var journalFullScans sync.Map

// verifyRetainedJournal verifies the whole retained log and returns its
// inherited state, or nil when no usable log exists. The verified-
// position cursor bounds the common case — an untouched log re-anchors
// by the stored digest of its boundary line — but the cursor is a hint,
// never authority: the first scan in any process is full, a log shorter
// than the cursor's coverage is truncated history and refuses outright,
// any size or mtime change routes to the full path, a boundary digest
// that no longer matches is arbitrated by the full scan, and every
// checkpointFullRescanInterval emissions the full history is verified
// regardless.
func verifyRetainedJournal(logPath, signerFP string) (*checkpointJournal, error) {
	info, err := os.Stat(logPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot stat retained checkpoint log: %w", err)
	}
	if info.Size() == 0 {
		return nil, nil
	}
	trusted := map[string]bool{signerFP: true}
	_, scanned := journalFullScans.LoadOrStore(logPath, struct{}{})
	if cur, ok := readCheckpointCursor(checkpointCursorPath(logPath)); ok && scanned &&
		cur.LogSize > 0 && cur.ScansSinceFull < checkpointFullRescanInterval {
		if info.Size() < cur.LogSize {
			return nil, fmt.Errorf("retained checkpoint log at %s is %d bytes but %d were previously verified — history was truncated", logPath, info.Size(), cur.LogSize)
		}
		if info.Size() == cur.LogSize && info.ModTime().UnixNano() == cur.LogMTimeNs {
			if journal, ok := anchorCheckpointCursor(logPath, cur); ok {
				return journal, nil
			}
		}
		// Any other change to the log — a peer writer's append, an
		// operator's edit, a failed anchor — is arbitrated below.
	}
	fh, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read retained checkpoint log: %w", err)
	}
	defer fh.Close()
	summary, err := evidence.VerifyCheckpointHistory(fh, evidence.CheckpointHistoryOptions{
		TrustedSigners: trusted,
		ExpectedSigner: signerFP,
	})
	if err != nil {
		return nil, fmt.Errorf("retained checkpoint log at %s is corrupt — refusing to extend possible evidence: %w", logPath, err)
	}
	offset, lastLine, err := journalLastLine(fh, info.Size())
	if err != nil {
		return nil, fmt.Errorf("cannot anchor retained checkpoint log %s: %w", logPath, err)
	}
	return &checkpointJournal{
		entries:         summary.Entries,
		lastSequence:    summary.LastSequence,
		lastRecordCount: summary.LastRecordCount,
		lastIssuedAt:    summary.LastIssuedAt,
		lastLineOffset:  offset,
		lastLine:        lastLine,
	}, nil
}

// anchorCheckpointCursor re-anchors a verified prefix by the stored
// digest of its boundary line: the log's size and mtime already matched
// the cursor, so the only way the prefix could still differ is a
// rewrite inside mtime granularity that also kept the boundary line —
// the digest is the second barrier. False means the anchor did not
// hold and the caller falls back to the full scan.
func anchorCheckpointCursor(logPath string, cur *checkpointCursor) (*checkpointJournal, bool) {
	// A cursor is a hint, never trusted input: a forged or torn one
	// must degrade to the full scan, never a panic or a shortcut.
	if cur.Entries <= 0 || cur.LastSequence <= 0 ||
		cur.LastLineOffset < 0 || cur.LastLineOffset >= cur.LogSize {
		return nil, false
	}
	anchorDigest, err := hex.DecodeString(cur.LastLineSHA256)
	if err != nil || len(anchorDigest) != sha256.Size {
		return nil, false
	}
	fh, err := os.Open(logPath)
	if err != nil {
		return nil, false
	}
	defer fh.Close()
	anchor, err := readFileSpan(fh, cur.LastLineOffset, cur.LogSize-cur.LastLineOffset)
	if err != nil || !bytes.Equal(sum256(anchor), anchorDigest) {
		return nil, false
	}
	return &checkpointJournal{
		entries:         cur.Entries,
		lastSequence:    cur.LastSequence,
		lastRecordCount: cur.LastRecordCount,
		lastIssuedAt:    cur.LastIssuedAt,
		lastLineOffset:  cur.LastLineOffset,
		lastLine:        anchor,
		scansSinceFull:  cur.ScansSinceFull + 1,
	}, true
}

// reconcileLatestCheckpoint checks the latest-file pointer against the
// verified journal tail. Behind is a crash-torn pointer the next
// emission rewrites; ahead, or the same sequence under different bytes,
// is a fork the stream must not extend.
func reconcileLatestCheckpoint(latestPath string, journal *checkpointJournal) error {
	data, err := os.ReadFile(latestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read existing checkpoint: %w", err)
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(bytes.TrimSpace(data), &cp); err != nil {
		return fmt.Errorf("existing checkpoint at %s is unreadable — refusing to overwrite possible evidence: %w", latestPath, err)
	}
	if cp.Sequence > journal.lastSequence {
		return fmt.Errorf("latest checkpoint %s is at sequence %d but the retained log ends at %d — a checkpoint exists with no retained entry",
			latestPath, cp.Sequence, journal.lastSequence)
	}
	if cp.Sequence == journal.lastSequence && !bytes.Equal(bytes.TrimSpace(data), bytes.TrimSpace(journal.lastLine)) {
		return fmt.Errorf("latest checkpoint %s and the retained log carry different bytes at sequence %d — a forked chain",
			latestPath, cp.Sequence)
	}
	return nil
}

// advanceCheckpointCursor persists the verified-position cursor after
// a successful append: the newly written line is verified by
// construction — the emitter just produced and signed it — so coverage
// extends to the new log end, pinned to the post-append size and mtime.
// line is the appended bytes, newline included.
func advanceCheckpointCursor(logPath string, journal *checkpointJournal, cp *evidence.Checkpoint, line []byte) error {
	info, err := os.Stat(logPath)
	if err != nil {
		return err
	}
	var entries, scans int64
	if journal != nil {
		entries = journal.entries
		scans = journal.scansSinceFull
	}
	cursor := checkpointCursor{
		Entries:         entries + 1,
		LastSequence:    cp.Sequence,
		LastRecordCount: cp.RecordCount,
		LastIssuedAt:    cp.IssuedAt,
		LastLineOffset:  info.Size() - int64(len(line)),
		LastLineSHA256:  hex.EncodeToString(sum256(line)),
		LogSize:         info.Size(),
		LogMTimeNs:      info.ModTime().UnixNano(),
		ScansSinceFull:  scans,
	}
	data, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	return writeFileAtomic(checkpointCursorPath(logPath), append(data, '\n'), 0o600)
}

func sum256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// readFileSpan returns exactly length bytes at offset.
func readFileSpan(fh *os.File, offset, length int64) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := fh.ReadAt(buf, offset); err != nil {
		return nil, err
	}
	return buf, nil
}

// journalLastLine locates the final newline-terminated line of an open
// log known to end at size: it reads back only the bounded tail a valid
// final line can span and returns the line's offset and raw bytes,
// newline included. The caller has already verified every line is
// newline-terminated and within the line bound.
func journalLastLine(fh *os.File, size int64) (int64, []byte, error) {
	if size == 0 {
		return 0, nil, errors.New("empty log")
	}
	window := int64(evidence.DefaultMaxCheckpointLineBytes + 1)
	if window > size {
		window = size
	}
	buf, err := readFileSpan(fh, size-window, window)
	if err != nil {
		return 0, nil, err
	}
	if buf[len(buf)-1] != '\n' {
		return 0, nil, errors.New("log does not end on a line boundary")
	}
	idx := bytes.LastIndexByte(buf[:len(buf)-1], '\n')
	offset := size - window
	if idx >= 0 {
		offset += int64(idx) + 1
	}
	return offset, buf[offset-(size-window):], nil
}

// lastLogLine reads the final newline-terminated line of a log file,
// tolerating a missing file.
func lastLogLine(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		return nil, nil
	}
	_, line, err := journalLastLine(fh, info.Size())
	return line, err
}

// readCheckpointCursor loads the persisted cursor; a missing or
// unparseable cursor is simply absent — it is a hint, never evidence.
func readCheckpointCursor(path string) (*checkpointCursor, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cur checkpointCursor
	if err := json.Unmarshal(data, &cur); err != nil {
		return nil, false
	}
	return &cur, true
}
