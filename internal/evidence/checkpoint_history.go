package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ─── Retained checkpoint history ─────────────────────────────────────
//
// One checkpoint proves the store still covers what it committed to;
// the retained sequence proves the custody story itself was not edited.
// The emitter appends every emission to an append-only JSONL log, and
// the sequence is only meaningful when every line in it verifies: a
// single forged, reordered, duplicated or deleted entry breaks the
// continuity the custody claim rests on. VerifyCheckpointHistory is the
// streaming verifier both sides share — the emitter runs it before it
// will extend a log, and cmd/evidence-checkpoint runs it over a held
// journal.
//
// The stream invariants, applied per line in order:
//
//   - the line is a complete, newline-terminated, parseable checkpoint
//     — an unterminated tail is a torn write, not history;
//   - the checkpoint is well-formed and signed under a trusted signer
//     (verifyCheckpointShape);
//   - sequences are strictly contiguous from the expected first
//     sequence — a gap is a deleted entry, a repeat is a duplication;
//   - record_count is monotonically non-decreasing — a decrease is a
//     coverage rollback a checkpoint cannot legitimately express;
//   - issued_at is non-decreasing — the signed timestamps must order
//     plausibly;
//   - every entry is signed by the same signer — one log is one
//     signing identity's stream; a rotation or substitution starts a
//     new log rather than mixing identities inside this one.
//
// With Current set, each entry's chain is additionally verified against
// the store's covered prefix — the full rigor pass the independent
// verifier applies.

// DefaultMaxCheckpointLineBytes bounds one serialized checkpoint line.
// A real checkpoint line is well under a kilobyte; the bound exists so
// a corrupt or hostile log cannot make the verifier buffer unbounded
// input.
const DefaultMaxCheckpointLineBytes = 1 << 20

// CheckpointHistoryOptions configures VerifyCheckpointHistory.
type CheckpointHistoryOptions struct {
	// TrustedSigners is the required trusted fingerprint set: every
	// entry must verify under one member.
	TrustedSigners map[string]bool
	// ExpectedSigner, when set, additionally pins every entry to this
	// fingerprint. The emitter sets it to its own signer so a log that
	// drifted to another identity — even a trusted one — is refused
	// rather than extended.
	ExpectedSigner string
	// FirstSequence is the sequence the first entry must carry;
	// defaults to 1.
	FirstSequence int64
	// MinRecordCount is the floor for the first entry's record count.
	// Incremental verification passes the count at the verified prefix
	// so the monotonicity check continues seamlessly.
	MinRecordCount int
	// MinIssuedAt is the floor for the first entry's issued_at, for the
	// same reason.
	MinIssuedAt string
	// Current, when non-nil, additionally verifies each entry's chain
	// against the store's covered prefix — the independent verifier's
	// pass. nil skips the store check (signature and continuity only).
	Current []TerminalRef
	// MaxLineBytes bounds one line; defaults to
	// DefaultMaxCheckpointLineBytes.
	MaxLineBytes int64
}

// CheckpointHistorySummary describes a verified retained log.
type CheckpointHistorySummary struct {
	// Entries is the number of verified entries.
	Entries int64
	// LastSequence is the sequence of the last verified entry — the
	// next emission carries LastSequence+1.
	LastSequence int64
	// LastRecordCount is the record count of the last verified entry.
	LastRecordCount int
	// LastIssuedAt is the issued_at of the last verified entry.
	LastIssuedAt string
	// Signer is the stream's single signing identity (empty when the
	// log was empty).
	Signer string
	// Last is the last verified checkpoint (nil for an empty log).
	Last *Checkpoint
}

// VerifyCheckpointHistory verifies a retained checkpoint log
// end-to-end under the stream invariants. The reader is consumed
// sequentially, so arbitrarily long histories verify in bounded memory.
// An empty log verifies to an empty summary — the first emission
// legitimately starts the stream. Any violation fails with the entry
// number and reason.
func VerifyCheckpointHistory(r io.Reader, opts CheckpointHistoryOptions) (*CheckpointHistorySummary, error) {
	if len(opts.TrustedSigners) == 0 {
		return nil, errors.New("no trusted signers configured")
	}
	maxLine := opts.MaxLineBytes
	if maxLine <= 0 {
		maxLine = DefaultMaxCheckpointLineBytes
	}
	expectedSeq := opts.FirstSequence
	if expectedSeq <= 0 {
		expectedSeq = 1
	}
	// Timestamps compare as instants, never strings: RFC3339Nano trims
	// trailing zeros, so "22.506425Z" sorts before "22.506Z"
	// lexicographically while being the later instant — a fast emitter
	// legitimately produces that pair.
	var minIssuedAt time.Time
	if opts.MinIssuedAt != "" {
		var err error
		minIssuedAt, err = time.Parse(time.RFC3339Nano, opts.MinIssuedAt)
		if err != nil {
			return nil, fmt.Errorf("invalid MinIssuedAt %q: %w", opts.MinIssuedAt, err)
		}
	}
	var prevIssuedAt time.Time
	summary := &CheckpointHistorySummary{}
	br := bufio.NewReaderSize(r, 64*1024)
	var offset int64
	for {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				return nil, fmt.Errorf("entry %d at byte %d is not newline-terminated — torn write or truncated log",
					summary.Entries+1, offset)
			}
			return summary, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read retained log: %w", err)
		}
		offset += int64(len(line))
		if int64(len(line)) > maxLine {
			return nil, fmt.Errorf("entry %d exceeds the %d-byte line bound", summary.Entries+1, maxLine)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, fmt.Errorf("entry %d is empty", summary.Entries+1)
		}
		var cp Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			return nil, fmt.Errorf("entry %d is not parseable: %w", summary.Entries+1, err)
		}
		legacy, err := verifyCheckpointShape(&cp, opts.TrustedSigners)
		if err != nil {
			return nil, fmt.Errorf("entry %d (sequence %d): %w", summary.Entries+1, cp.Sequence, err)
		}
		if cp.Sequence != expectedSeq {
			return nil, fmt.Errorf("entry %d carries sequence %d, expected %d — a deleted, duplicated or reordered entry",
				summary.Entries+1, cp.Sequence, expectedSeq)
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, cp.IssuedAt)
		if err != nil {
			return nil, fmt.Errorf("entry %d (sequence %d): invalid issued_at", summary.Entries+1, cp.Sequence)
		}
		if summary.Entries == 0 {
			if cp.RecordCount < opts.MinRecordCount {
				return nil, fmt.Errorf("entry %d record_count %d regresses below verified prefix %d",
					summary.Entries+1, cp.RecordCount, opts.MinRecordCount)
			}
			if !minIssuedAt.IsZero() && issuedAt.Before(minIssuedAt) {
				return nil, fmt.Errorf("entry %d issued_at %s predates verified prefix %s",
					summary.Entries+1, cp.IssuedAt, opts.MinIssuedAt)
			}
		} else {
			if cp.Signer != summary.Signer {
				return nil, fmt.Errorf("entry %d switches signer from %s to %s — one log is one signing identity",
					summary.Entries+1, summary.Signer, cp.Signer)
			}
			if cp.RecordCount < summary.LastRecordCount {
				return nil, fmt.Errorf("entry %d record_count %d regresses below previous %d — a coverage rollback",
					summary.Entries+1, cp.RecordCount, summary.LastRecordCount)
			}
			if issuedAt.Before(prevIssuedAt) {
				return nil, fmt.Errorf("entry %d issued_at %s precedes previous %s — implausible timestamp ordering",
					summary.Entries+1, cp.IssuedAt, summary.LastIssuedAt)
			}
		}
		if opts.ExpectedSigner != "" && cp.Signer != opts.ExpectedSigner {
			return nil, fmt.Errorf("entry %d is signed by %s, not the expected signer %s",
				summary.Entries+1, cp.Signer, opts.ExpectedSigner)
		}
		if opts.Current != nil {
			if err := verifyCheckpointAgainstStore(&cp, opts.Current, legacy); err != nil {
				return nil, fmt.Errorf("entry %d (sequence %d): %w", summary.Entries+1, cp.Sequence, err)
			}
		}
		prevIssuedAt = issuedAt
		summary.Entries++
		summary.LastSequence = cp.Sequence
		summary.LastRecordCount = cp.RecordCount
		summary.LastIssuedAt = cp.IssuedAt
		if summary.Entries == 1 {
			summary.Signer = cp.Signer
		}
		cpCopy := cp
		summary.Last = &cpCopy
		expectedSeq++
	}
}
