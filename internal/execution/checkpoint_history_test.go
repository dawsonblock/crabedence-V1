package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// checkpointTestRig wires a store, a signer and a checkpoint path the
// way serve.go wires the real emission loop.
type checkpointTestRig struct {
	store  idempotency.EffectStore
	signer *evidence.Signer
	path   string
}

func newCheckpointTestRig(t *testing.T) *checkpointTestRig {
	t.Helper()
	db, err := idempotency.OpenSQLiteDB(filepath.Join(t.TempDir(), "db", "cp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return &checkpointTestRig{
		store:  store,
		signer: signer,
		path:   filepath.Join(t.TempDir(), "evidence-checkpoint.json"),
	}
}

func (r *checkpointTestRig) emit() {
	emitCheckpoint(context.Background(), r.store, r.signer, r.path, "")
}

// journalBytes returns the raw retained log.
func (r *checkpointTestRig) journalBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(r.path + ".jsonl")
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	return data
}

func (r *checkpointTestRig) writeJournal(t *testing.T, data []byte) {
	t.Helper()
	if err := os.WriteFile(r.path+".jsonl", data, 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	// A rewritten prefix invalidates the verified-byte cursor's
	// boundary anchor — remove it so each case starts from a full scan.
	os.Remove(r.path + ".jsonl.cursor")
}

func (r *checkpointTestRig) journalLines(t *testing.T) [][]byte {
	t.Helper()
	var lines [][]byte
	for _, line := range bytes.Split(r.journalBytes(t), []byte{'\n'}) {
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

func rejoinJournal(lines [][]byte) []byte {
	var buf bytes.Buffer
	for _, line := range lines {
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// latestSequence reads the latest-file sequence, or -1 when absent.
func (r *checkpointTestRig) latestSequence(t *testing.T) int64 {
	t.Helper()
	data, err := os.ReadFile(r.path)
	if err != nil {
		return -1
	}
	var cp evidence.Checkpoint
	if err := json.Unmarshal(bytes.TrimSpace(data), &cp); err != nil {
		t.Fatalf("latest not parseable: %v", err)
	}
	return cp.Sequence
}

// The retained log is evidence, not scratch: tampering with any entry —
// not just the tail the old code read — must stop the stream. Each case
// mutates a healthy five-entry journal, then asserts the next emission
// leaves the journal and the latest file untouched.
func TestEmitCheckpointRefusesTamperedRetainedHistory(t *testing.T) {
	cases := map[string]func(t *testing.T, r *checkpointTestRig) []byte{
		"corrupt middle entry": func(t *testing.T, r *checkpointTestRig) []byte {
			lines := r.journalLines(t)
			mut := append([]byte{}, lines[1]...)
			mut[len(mut)/2] ^= 0x20
			lines[1] = mut
			return rejoinJournal(lines)
		},
		"deleted middle entry": func(t *testing.T, r *checkpointTestRig) []byte {
			lines := r.journalLines(t)
			return rejoinJournal(append(lines[:1:1], lines[2:]...))
		},
		"reordered entries": func(t *testing.T, r *checkpointTestRig) []byte {
			lines := r.journalLines(t)
			lines[1], lines[2] = lines[2], lines[1]
			return rejoinJournal(lines)
		},
		"duplicated tail entry": func(t *testing.T, r *checkpointTestRig) []byte {
			lines := r.journalLines(t)
			return rejoinJournal(append(lines, lines[len(lines)-1]))
		},
		"truncated tail": func(t *testing.T, r *checkpointTestRig) []byte {
			raw := r.journalBytes(t)
			return raw[:len(raw)-30]
		},
		"foreign-signed splice": func(t *testing.T, r *checkpointTestRig) []byte {
			other, _ := evidence.GenerateSigner()
			forged, _ := json.Marshal(other.SignCheckpoint(3, nil))
			lines := r.journalLines(t)
			lines[2] = forged
			return rejoinJournal(lines)
		},
		"sequence gap": func(t *testing.T, r *checkpointTestRig) []byte {
			lines := r.journalLines(t)
			return rejoinJournal(lines[:3])
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rig := newCheckpointTestRig(t)
			for i := 0; i < 5; i++ {
				rig.emit()
			}
			latestBefore := rig.latestSequence(t)
			mutated := mutate(t, rig)
			rig.writeJournal(t, mutated)
			rig.emit()
			if !bytes.Equal(rig.journalBytes(t), mutated) {
				t.Fatalf("%s: emission extended a tampered journal", name)
			}
			if got := rig.latestSequence(t); got != latestBefore {
				t.Fatalf("%s: latest advanced to %d over tampered history", name, got)
			}
		})
	}
}

// The honest incremental path is the common one — and it must still
// refuse a rewrite. With the cursor left in place, a same-size tamper
// changes the log's mtime, which routes verification down the full
// path where the corruption is caught.
func TestEmitCheckpointIntactCursorStillCatchesTamper(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 5; i++ {
		rig.emit()
	}
	lines := rig.journalLines(t)
	mut := append([]byte{}, lines[1]...)
	mut[len(mut)/2] ^= 0x20
	lines[1] = mut
	mutated := rejoinJournal(lines)
	if err := os.WriteFile(rig.path+".jsonl", mutated, 0o600); err != nil {
		t.Fatalf("tamper journal: %v", err)
	}
	latestBefore := rig.latestSequence(t)
	rig.emit()
	if !bytes.Equal(rig.journalBytes(t), mutated) {
		t.Fatal("emission extended a tampered journal under an intact cursor")
	}
	if got := rig.latestSequence(t); got != latestBefore {
		t.Fatalf("latest advanced to %d over tampered history", got)
	}
}

// A "sequence gap" is also what deleting the journal tail looks like —
// covered above via truncation to three entries, which the contiguous-
// sequence check refuses as missing entries 4-5 only when re-extended.
// The case above truncates and the next emission expects sequence 4 and
// finds the log ends at 3 — that is legitimate continuation, so the gap
// case is the inverse: a missing middle entry, already covered. Here we
// verify the distinct rule: a latest file ahead of its own journal is a
// checkpoint with no retained entry, which must refuse.
func TestEmitCheckpointRefusesLatestAheadOfJournal(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 3; i++ {
		rig.emit()
	}
	// Forge a latest file two sequences beyond the journal tail, signed
	// by the real signer so shape checks pass — the fork is positional.
	forged, _ := json.Marshal(rig.signer.SignCheckpoint(5, nil))
	if err := os.WriteFile(rig.path, append(forged, '\n'), 0o600); err != nil {
		t.Fatalf("forge latest: %v", err)
	}
	journalBefore := rig.journalBytes(t)
	rig.emit()
	if !bytes.Equal(rig.journalBytes(t), journalBefore) {
		t.Fatal("emission extended a journal its latest file had raced ahead of")
	}
}

// The same sequence under different bytes in the latest file and the
// journal tail is a forked chain: the emission that produced the
// journal line cannot have also produced a different latest.
func TestEmitCheckpointRefusesForkedLatest(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 3; i++ {
		rig.emit()
	}
	// Sequence 3 again, over different content — validly signed, wrong
	// bytes.
	forged, _ := json.Marshal(rig.signer.SignCheckpoint(3, nil))
	if err := os.WriteFile(rig.path, append(forged, '\n'), 0o600); err != nil {
		t.Fatalf("forge latest: %v", err)
	}
	journalBefore := rig.journalBytes(t)
	rig.emit()
	if !bytes.Equal(rig.journalBytes(t), journalBefore) {
		t.Fatal("emission extended a forked chain")
	}
}

// A crash between the journal append and the latest-file write leaves
// latest one sequence behind — the normal torn-pointer case the stream
// must heal by continuing the sequence and rewriting latest.
func TestEmitCheckpointHealsTornLatestPointer(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 3; i++ {
		rig.emit()
	}
	// Simulate the crash: latest still carries sequence 2 while the
	// journal holds 3.
	lines := rig.journalLines(t)
	if err := os.WriteFile(rig.path, append(lines[1], '\n'), 0o600); err != nil {
		t.Fatalf("plant stale latest: %v", err)
	}
	rig.emit()
	if got := rig.latestSequence(t); got != 4 {
		t.Fatalf("latest after healing = %d, want 4", got)
	}
	entries := rig.journalLines(t)
	if len(entries) != 4 {
		t.Fatalf("journal holds %d entries, want 4", len(entries))
	}
}

// Two emitters on one path must serialize: the writer lock makes the
// verify-then-append critical section atomic, so interleaved emissions
// still produce one contiguous history.
func TestEmitCheckpointConcurrentWriters(t *testing.T) {
	rig := newCheckpointTestRig(t)
	const writers, emissions = 4, 5
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < emissions; i++ {
				rig.emit()
			}
		}()
	}
	wg.Wait()
	summary, err := evidence.VerifyCheckpointHistory(bytes.NewReader(rig.journalBytes(t)),
		evidence.CheckpointHistoryOptions{
			TrustedSigners: map[string]bool{rig.signer.Fingerprint(): true},
		})
	if err != nil {
		t.Fatalf("concurrent history does not verify: %v", err)
	}
	if summary.Entries != writers*emissions {
		t.Fatalf("journal holds %d entries, want %d", summary.Entries, writers*emissions)
	}
	if got := rig.latestSequence(t); got != writers*emissions {
		t.Fatalf("latest = %d, want %d", got, writers*emissions)
	}
}

// The verified-position cursor bounds re-verification: a cursor
// rewritten to claim coverage beyond the log's real size is a truncated
// history, not a hint to rescan — it refuses rather than silently
// re-verifying.
func TestEmitCheckpointRefusesCursorBeyondLogEnd(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 3; i++ {
		rig.emit()
	}
	cursorPath := rig.path + ".jsonl.cursor"
	data, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("cursor not written: %v", err)
	}
	var cur checkpointCursor
	if err := json.Unmarshal(data, &cur); err != nil {
		t.Fatalf("cursor not parseable: %v", err)
	}
	cur.LogSize += 4096
	forged, _ := json.Marshal(cur)
	if err := os.WriteFile(cursorPath, forged, 0o600); err != nil {
		t.Fatalf("forge cursor: %v", err)
	}
	journalBefore := rig.journalBytes(t)
	rig.emit()
	if !bytes.Equal(rig.journalBytes(t), journalBefore) {
		t.Fatal("emission proceeded over a truncated-history signal")
	}
}

// A forged or stale cursor that does not match the log's real boundary
// line cannot launder prefix tampering: the anchor digest fails, the
// full scan arbitrates, and the tampering is still refused.
func TestEmitCheckpointCursorAnchorFallsBackToFullScan(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 3; i++ {
		rig.emit()
	}
	// Rewrite the journal's first entry, then re-stamp the cursor so it
	// claims the tampered prefix is verified.
	lines := rig.journalLines(t)
	mut := append([]byte{}, lines[0]...)
	mut[len(mut)/2] ^= 0x20
	lines[0] = mut
	rig.writeJournal(t, rejoinJournal(lines)) // clears the cursor
	// Re-emit a cursor claiming the whole (now tampered) log is
	// verified — a forger who can write the cursor file's worst case.
	cur := checkpointCursor{
		Entries:         3,
		LastSequence:    3,
		LastRecordCount: 0,
		LastIssuedAt:    "9999-01-01T00:00:00.000Z",
		LastLineOffset:  0,
		LastLineSHA256:  "deadbeef",
		LogSize:         int64(len(rejoinJournal(lines))),
	}
	forged, _ := json.Marshal(cur)
	if err := os.WriteFile(rig.path+".jsonl.cursor", forged, 0o600); err != nil {
		t.Fatalf("forge cursor: %v", err)
	}
	journalBefore := rig.journalBytes(t)
	rig.emit()
	if !bytes.Equal(rig.journalBytes(t), journalBefore) {
		t.Fatal("tampered prefix accepted under a forged cursor")
	}
}

// Honest incremental verification: after the cursor is established, an
// emission extends the journal without re-reading the verified prefix —
// observable here because the cursor survives and keeps pointing at the
// grown tail.
func TestEmitCheckpointCursorTracksGrowth(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 3; i++ {
		rig.emit()
	}
	rig.emit()
	data, err := os.ReadFile(rig.path + ".jsonl.cursor")
	if err != nil {
		t.Fatalf("cursor not written: %v", err)
	}
	var cur checkpointCursor
	if err := json.Unmarshal(data, &cur); err != nil {
		t.Fatalf("cursor not parseable: %v", err)
	}
	if cur.Entries != 4 || cur.LastSequence != 4 {
		t.Fatalf("cursor entries/seq = %d/%d, want 4/4", cur.Entries, cur.LastSequence)
	}
	if size := int64(len(rig.journalBytes(t))); cur.LogSize != size {
		t.Fatalf("cursor covers %d bytes of a %d-byte journal", cur.LogSize, size)
	}
}

// Custody that fell behind is caught up with the missing retained
// entries, not left with a gap its own verification would refuse.
func TestEmitCheckpointBackfillsLaggingCustody(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 3; i++ {
		rig.emit() // local only — custody "missed" these
	}
	custody := filepath.Join(t.TempDir(), "evidence-checkpoint.json")
	for i := 0; i < 2; i++ {
		emitCheckpoint(context.Background(), rig.store, rig.signer, rig.path, custody)
	}
	custodyLog, err := os.ReadFile(custody + ".jsonl")
	if err != nil {
		t.Fatalf("read custody log: %v", err)
	}
	summary, err := evidence.VerifyCheckpointHistory(bytes.NewReader(custodyLog),
		evidence.CheckpointHistoryOptions{
			TrustedSigners: map[string]bool{rig.signer.Fingerprint(): true},
		})
	if err != nil {
		t.Fatalf("backfilled custody does not verify: %v", err)
	}
	if summary.Entries != 5 {
		t.Fatalf("custody holds %d entries, want 5", summary.Entries)
	}
	if !bytes.Equal(custodyLog, rig.journalBytes(t)) {
		t.Fatal("custody journal diverges from local journal")
	}
}

// Custody ahead of the local stream is divergence, not lag: the writer
// must not append over it — a restarted service whose local journal was
// lost must surface the mismatch, not paper over it.
func TestEmitCheckpointRefusesDivergentCustody(t *testing.T) {
	rig := newCheckpointTestRig(t)
	custody := filepath.Join(t.TempDir(), "evidence-checkpoint.json")
	for i := 0; i < 3; i++ {
		emitCheckpoint(context.Background(), rig.store, rig.signer, rig.path, custody)
	}
	custodyBefore, err := os.ReadFile(custody + ".jsonl")
	if err != nil {
		t.Fatalf("read custody: %v", err)
	}
	// The local journal is "lost": the stream restarts at sequence 1
	// while custody still holds entries through 3.
	os.Remove(rig.path + ".jsonl")
	os.Remove(rig.path + ".jsonl.cursor")
	os.Remove(rig.path)
	emitCheckpoint(context.Background(), rig.store, rig.signer, rig.path, custody)
	custodyAfter, err := os.ReadFile(custody + ".jsonl")
	if err != nil {
		t.Fatalf("read custody after: %v", err)
	}
	if !bytes.Equal(custodyAfter, custodyBefore) {
		t.Fatal("emission appended over divergent custody")
	}
}

// Every emission still lands before latest moves — the full-history
// verification does not weaken the crash-safe ordering, it enforces it.
func TestEmitCheckpointJournalIsContiguousAndComplete(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 7; i++ {
		rig.emit()
	}
	summary, err := evidence.VerifyCheckpointHistory(bytes.NewReader(rig.journalBytes(t)),
		evidence.CheckpointHistoryOptions{
			TrustedSigners: map[string]bool{rig.signer.Fingerprint(): true},
			ExpectedSigner: rig.signer.Fingerprint(),
		})
	if err != nil {
		t.Fatalf("emitted history does not verify: %v", err)
	}
	if summary.Entries != 7 || summary.LastSequence != 7 {
		t.Fatalf("journal summary wrong: %+v", summary)
	}
	if got := rig.latestSequence(t); got != 7 {
		t.Fatalf("latest = %d, want 7", got)
	}
}

// stderr silence check helper — the refusal paths above assert the
// journal and latest are untouched; this one pins that the refusal is
// also loud, so an operator sees the tamper rather than a quiet stall.
func TestEmitCheckpointRefusalIsObservable(t *testing.T) {
	rig := newCheckpointTestRig(t)
	for i := 0; i < 2; i++ {
		rig.emit()
	}
	rig.writeJournal(t, append(rig.journalBytes(t), []byte("forged entry\n")...))

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	stderr := os.Stderr
	os.Stderr = w
	rig.emit()
	w.Close()
	os.Stderr = stderr
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if !strings.Contains(buf.String(), "evidence checkpoint:") {
		t.Fatalf("refusal not reported on stderr: %q", buf.String())
	}
}
