package execution

import (
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
// terminal-evidence enumeration to a signed file next to the socket, so
// an operator can archive the sequence on an independent medium and
// later prove — with cmd/evidence-checkpoint — that the store still
// contains everything a held checkpoint covered. Deleting, rewriting or
// reordering a covered record breaks the chain digest; deleting all of
// them, or rolling the store back, breaks the count.

// runCheckpointLoop emits a signed checkpoint on the configured interval
// until ctx ends.
func runCheckpointLoop(ctx context.Context, store idempotency.EffectStore, signer *evidence.Signer, path string, interval time.Duration) {
	emitCheckpoint(ctx, store, signer, path)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emitCheckpoint(ctx, store, signer, path)
		}
	}
}

// emitCheckpoint enumerates the terminal evidence, signs it, and writes
// the checkpoint atomically. Emission failures are logged, never fatal:
// a checkpoint that could not be written must not take the authority
// down with it — the absence of a fresh checkpoint is the
// operator-visible signal.
func emitCheckpoint(ctx context.Context, store idempotency.EffectStore, signer *evidence.Signer, path string) {
	refs, err := store.TerminalEvidence(ctx)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot enumerate terminal evidence: %v\n", err)
		}
		return
	}
	seq, err := nextCheckpointSequence(path)
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
	if err := writeFileAtomic(path, append(payload, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "evidence checkpoint: cannot write %s: %v\n", path, err)
	}
}

// nextCheckpointSequence reads the existing checkpoint file (when one
// exists) and returns the next sequence number. An existing file that
// cannot be parsed is refused: silently overwriting an unreadable
// checkpoint could destroy evidence an operator expects to keep.
func nextCheckpointSequence(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cannot read existing checkpoint: %w", err)
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return 0, fmt.Errorf("existing checkpoint at %s is unreadable — refusing to overwrite possible evidence: %w", path, err)
	}
	return cp.Sequence + 1, nil
}
