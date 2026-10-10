package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// signCheckpointAt signs a checkpoint carrying an explicit issued_at —
// timestamp ordering is part of the stream contract, so the tests need
// control SignCheckpoint's wall clock does not give.
func signCheckpointAt(s *Signer, sequence int64, refs []TerminalRef, issuedAt string) *Checkpoint {
	cp := s.SignCheckpoint(sequence, refs)
	cp.IssuedAt = issuedAt
	cp.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(s.key, checkpointSigningBytes(*cp)))
	return cp
}

// journal builds the raw newline-terminated log bytes for a stream of
// checkpoints over monotonically growing prefixes of refs — the shape a
// healthy emitter leaves behind.
func journal(t *testing.T, s *Signer, seqs []int64, prefixLens []int, refs []TerminalRef) []byte {
	t.Helper()
	var buf bytes.Buffer
	for i, seq := range seqs {
		prefix := prefixLens[i]
		cp := signCheckpointAt(s, seq, refs[:prefix],
			"2026-10-09T05:00:0"+string(rune('0'+i))+".000Z")
		payload, err := json.Marshal(cp)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf.Write(payload)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// journalLines splits raw journal bytes into their line payloads.
func journalLines(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var lines [][]byte
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		t.Fatal("journal holds no lines")
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

func TestVerifyCheckpointHistoryAcceptsHealthyStream(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(5)
	raw := journal(t, signer, []int64{1, 2, 3, 4}, []int{1, 2, 3, 5}, refs)
	summary, err := VerifyCheckpointHistory(bytes.NewReader(raw), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
	})
	if err != nil {
		t.Fatalf("healthy stream refused: %v", err)
	}
	if summary.Entries != 4 || summary.LastSequence != 4 || summary.LastRecordCount != 5 {
		t.Fatalf("summary wrong: %+v", summary)
	}
	if summary.Signer != signer.Fingerprint() {
		t.Fatalf("stream signer = %s", summary.Signer)
	}
}

func TestVerifyCheckpointHistoryAcceptsEmptyStream(t *testing.T) {
	signer, _ := GenerateSigner()
	summary, err := VerifyCheckpointHistory(bytes.NewReader(nil), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
	})
	if err != nil {
		t.Fatalf("empty stream refused: %v", err)
	}
	if summary.Entries != 0 || summary.Last != nil {
		t.Fatalf("empty stream summary wrong: %+v", summary)
	}
}

// Every way to lie with the retained log fails closed — a forged,
// reordered, dropped, duplicated, truncated or coverage-regressing
// entry is refused before the stream can be extended over it.
func TestVerifyCheckpointHistoryRefusesTampering(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(6)
	healthy := journal(t, signer, []int64{1, 2, 3, 4, 5}, []int{1, 2, 3, 4, 5}, refs)

	cases := map[string]struct {
		mutate func(t *testing.T) []byte
		want   string
	}{
		"corrupt middle entry": {
			mutate: func(t *testing.T) []byte {
				lines := journalLines(t, healthy)
				mut := append([]byte{}, lines[1]...)
				mut[len(mut)/2] ^= 0x20
				lines[1] = mut
				return rejoinJournal(lines)
			},
			want: "entry 2",
		},
		"deleted middle entry": {
			mutate: func(t *testing.T) []byte {
				lines := journalLines(t, healthy)
				return rejoinJournal(append(lines[:1:1], lines[2:]...))
			},
			want: "expected 2",
		},
		"reordered entries": {
			mutate: func(t *testing.T) []byte {
				lines := journalLines(t, healthy)
				lines[1], lines[2] = lines[2], lines[1]
				return rejoinJournal(lines)
			},
			want: "expected 2",
		},
		"duplicated tail": {
			mutate: func(t *testing.T) []byte {
				lines := journalLines(t, healthy)
				return rejoinJournal(append(lines, lines[len(lines)-1]))
			},
			want: "expected 6",
		},
		"truncated final line": {
			mutate: func(t *testing.T) []byte {
				return append(append([]byte{}, healthy[:len(healthy)-40]...), '\n')
			},
			want: "entry 5",
		},
		"unterminated tail": {
			mutate: func(t *testing.T) []byte {
				return bytes.TrimRight(healthy, "\n")
			},
			want: "not newline-terminated",
		},
		"empty line inside": {
			mutate: func(t *testing.T) []byte {
				lines := journalLines(t, healthy)
				out := append([][]byte{lines[0]}, []byte("   "))
				out = append(out, lines[1:]...)
				return rejoinJournal(out)
			},
			want: "entry 2 is empty",
		},
		"unparseable entry": {
			mutate: func(t *testing.T) []byte {
				return append(healthy, []byte("not json\n")...)
			},
			want: "entry 6 is not parseable",
		},
		"signer substitution": {
			mutate: func(t *testing.T) []byte {
				other, _ := GenerateSigner()
				forged, _ := json.Marshal(other.SignCheckpoint(3, checkpointFixture(3)))
				lines := journalLines(t, healthy)
				lines[2] = forged
				return rejoinJournal(lines)
			},
			want: "not trusted",
		},
		"coverage regression": {
			mutate: func(t *testing.T) []byte {
				shrunk, _ := json.Marshal(signCheckpointAt(signer, 4, refs[:2], "2026-10-09T05:00:04.000Z"))
				lines := journalLines(t, healthy)
				lines[3] = shrunk
				return rejoinJournal(lines)
			},
			want: "coverage rollback",
		},
		"timestamp regression": {
			mutate: func(t *testing.T) []byte {
				rewound, _ := json.Marshal(signCheckpointAt(signer, 4, refs[:4], "2026-10-09T04:00:00.000Z"))
				lines := journalLines(t, healthy)
				lines[3] = rewound
				return rejoinJournal(lines)
			},
			want: "implausible timestamp",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyCheckpointHistory(bytes.NewReader(tc.mutate(t)), CheckpointHistoryOptions{
				TrustedSigners: map[string]bool{signer.Fingerprint(): true},
			})
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s failed for the wrong reason: %v", name, err)
			}
		})
	}
}

// A second trusted signer does not buy admission: one log carries one
// signing identity, so a stream that switches keys mid-way is refused
// even when both keys are individually trusted.
func TestVerifyCheckpointHistoryRefusesMidStreamSignerSwitch(t *testing.T) {
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	refs := checkpointFixture(4)
	var buf bytes.Buffer
	for i, seq := range []int64{1, 2, 3} {
		s := signer
		if i == 2 {
			s = other
		}
		payload, _ := json.Marshal(signCheckpointAt(s, seq, refs[:i+1], "2026-10-09T05:00:0"+string(rune('0'+i))+".000Z"))
		buf.Write(payload)
		buf.WriteByte('\n')
	}
	trusted := map[string]bool{signer.Fingerprint(): true, other.Fingerprint(): true}
	if _, err := VerifyCheckpointHistory(bytes.NewReader(buf.Bytes()), CheckpointHistoryOptions{
		TrustedSigners: trusted,
	}); err == nil || !strings.Contains(err.Error(), "switches signer") {
		t.Fatalf("mid-stream signer switch mishandled: %v", err)
	}
}

// The emitter pins the stream to its own key: a log of entirely
// foreign-signed entries — however well-formed — is not its history to
// extend.
func TestVerifyCheckpointHistoryRefusesForeignStream(t *testing.T) {
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	refs := checkpointFixture(3)
	raw := journal(t, other, []int64{1, 2}, []int{1, 3}, refs)
	trusted := map[string]bool{signer.Fingerprint(): true, other.Fingerprint(): true}
	if _, err := VerifyCheckpointHistory(bytes.NewReader(raw), CheckpointHistoryOptions{
		TrustedSigners: trusted,
		ExpectedSigner: signer.Fingerprint(),
	}); err == nil || !strings.Contains(err.Error(), "not the expected signer") {
		t.Fatalf("foreign stream mishandled: %v", err)
	}
}

// Incremental verification continues the invariants seamlessly: the
// suffix's first entry must pick the sequence, coverage and timestamp
// up where the verified prefix left them.
func TestVerifyCheckpointHistoryContinuation(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(6)
	var buf bytes.Buffer
	for _, cp := range []*Checkpoint{
		signCheckpointAt(signer, 4, refs[:4], "2026-10-09T05:00:03.000Z"),
		signCheckpointAt(signer, 5, refs[:6], "2026-10-09T05:00:04.000Z"),
	} {
		payload, _ := json.Marshal(cp)
		buf.Write(payload)
		buf.WriteByte('\n')
	}
	summary, err := VerifyCheckpointHistory(bytes.NewReader(buf.Bytes()), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
		FirstSequence:  4,
		MinRecordCount: 3,
		MinIssuedAt:    "2026-10-09T05:00:02.000Z",
	})
	if err != nil {
		t.Fatalf("continuation refused: %v", err)
	}
	if summary.Entries != 2 || summary.LastSequence != 5 {
		t.Fatalf("continuation summary wrong: %+v", summary)
	}
	// A suffix that regresses below the verified prefix's coverage is
	// refused even though it is internally consistent.
	regressing := journal(t, signer, []int64{4}, []int{2}, refs)
	if _, err := VerifyCheckpointHistory(bytes.NewReader(regressing), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
		FirstSequence:  4,
		MinRecordCount: 3,
	}); err == nil || !strings.Contains(err.Error(), "regresses below verified prefix") {
		t.Fatalf("regressing continuation mishandled: %v", err)
	}
}

// With a store enumeration the history also proves coverage: the head
// and every intermediate entry's committed prefix must still hold.
func TestVerifyCheckpointHistoryWithStore(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(5)
	raw := journal(t, signer, []int64{1, 2, 3}, []int{2, 3, 5}, refs)
	if _, err := VerifyCheckpointHistory(bytes.NewReader(raw), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
		Current:        refs,
	}); err != nil {
		t.Fatalf("store-backed stream refused: %v", err)
	}
	// Roll the store back below an intermediate entry's commitment and
	// the stream fails at that entry.
	if _, err := VerifyCheckpointHistory(bytes.NewReader(raw), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
		Current:        refs[:2],
	}); err == nil || !strings.Contains(err.Error(), "entry 2") {
		t.Fatalf("rolled-back store mishandled: %v", err)
	}
}

// The verifier is streaming by construction: a long retained history
// verifies in bounded memory and reasonable time — custody over ten
// thousand emissions must not degrade into an infeasible audit.
func TestVerifyCheckpointHistoryLongStream(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(2)
	var buf bytes.Buffer
	const n = 5000
	for i := 0; i < n; i++ {
		payload, _ := json.Marshal(signer.SignCheckpoint(int64(i+1), refs))
		buf.Write(payload)
		buf.WriteByte('\n')
	}
	summary, err := VerifyCheckpointHistory(bytes.NewReader(buf.Bytes()), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
	})
	if err != nil {
		t.Fatalf("long stream refused: %v", err)
	}
	if summary.Entries != n || summary.LastSequence != n {
		t.Fatalf("long stream summary wrong: entries=%d seq=%d", summary.Entries, summary.LastSequence)
	}
}

// The line bound is part of the containment story: an oversized entry
// refuses before it can exhaust the verifier.
func TestVerifyCheckpointHistoryLineBound(t *testing.T) {
	signer, _ := GenerateSigner()
	refs := checkpointFixture(2)
	raw := journal(t, signer, []int64{1}, []int{2}, refs)
	if _, err := VerifyCheckpointHistory(bytes.NewReader(raw), CheckpointHistoryOptions{
		TrustedSigners: trustedFp(t, signer),
		MaxLineBytes:   16,
	}); err == nil || !strings.Contains(err.Error(), "line bound") {
		t.Fatalf("oversized entry mishandled: %v", err)
	}
}
