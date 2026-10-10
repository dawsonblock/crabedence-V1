package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	refs, err := store.TerminalEvidence(ctx)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot enumerate terminal evidence: %v\n", err)
		}
		return
	}
	logPath := retainedCheckpointLogPath(path)
	seq, err := nextCheckpointSequence(path, logPath)
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
	if err := writeFileAtomic(path, append(payload, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot write %s: %v\n", path, err)
	}
	if custodyPath != "" {
		custodyLog := retainedCheckpointLogPath(custodyPath)
		if err := appendCheckpointLine(custodyLog, payload); err != nil {
			fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot append to custody log %s — custody mirror not updated: %v\n", custodyLog, err)
		} else if err := writeFileAtomic(custodyPath, append(payload, '\n'), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot write custody checkpoint %s: %v\n", custodyPath, err)
		}
	}
}

// retainedCheckpointLogPath names the append-only sequence log beside
// the latest-checkpoint file.
func retainedCheckpointLogPath(path string) string {
	return path + ".jsonl"
}

// appendCheckpointLine appends one complete JSON line to the retained
// sequence log. Each line is self-contained and independently signed,
// so a torn final line is visible corruption the next read refuses —
// never silently lost history.
func appendCheckpointLine(logPath string, payload []byte) error {
	fh, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := fh.Write(append(payload, '\n')); err != nil {
		return err
	}
	return fh.Sync()
}

// nextCheckpointSequence returns the sequence the next emission must
// carry. The retained append-only log is the authority when it exists:
// it holds the sequence history the single latest file cannot, so a
// lost latest file cannot restart the numbering. A retained log whose
// last line cannot be parsed is refused — extending a corrupted log
// could quietly hide destroyed evidence. When no log exists the latest
// file's sequence continues, and an existing latest file that cannot be
// parsed is likewise refused: silently overwriting an unreadable
// checkpoint could destroy evidence an operator expects to keep.
func nextCheckpointSequence(latestPath, logPath string) (int64, error) {
	if data, err := os.ReadFile(logPath); err == nil {
		if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 {
			last := trimmed[bytes.LastIndexByte(trimmed, '\n')+1:]
			var cp evidence.Checkpoint
			if err := json.Unmarshal(last, &cp); err != nil {
				return 0, fmt.Errorf("retained checkpoint log at %s is unreadable — refusing to extend possible evidence: %w", logPath, err)
			}
			return cp.Sequence + 1, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("cannot read retained checkpoint log: %w", err)
	}
	data, err := os.ReadFile(latestPath)
	if errors.Is(err, os.ErrNotExist) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cannot read existing checkpoint: %w", err)
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return 0, fmt.Errorf("existing checkpoint at %s is unreadable — refusing to overwrite possible evidence: %w", latestPath, err)
	}
	return cp.Sequence + 1, nil
}
