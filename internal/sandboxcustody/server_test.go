package sandboxcustody

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The custody gates: a witness holds verified bytes under their
// digest, signs every acknowledgement onto an append-only chain, is
// idempotent on retry, and verifies independently — a tampered store
// or edited chain is a finding, not silent trust.

func startCustody(t *testing.T, dir string) *Server {
	t.Helper()
	// The socket lives in a short path — t.TempDir() names embed the
	// test name and can exceed the platform's sun_path bound.
	sockDir, err := os.MkdirTemp("", "cx-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	srv, err := NewServer(Config{
		SocketDir:  sockDir,
		CustodyDir: filepath.Join(dir, "custody"),
		KeyPath:    filepath.Join(dir, "custody", "witness.key"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv
}

// testPayload builds a canonical segment payload the witness accepts:
// an array of rows each carrying a terminal_seq inside the range.
func testPayload(t *testing.T, seqs ...int64) ([]byte, string) {
	t.Helper()
	rows := make([]map[string]any, 0, len(seqs))
	for _, s := range seqs {
		rows = append(rows, map[string]any{"job_id": "j", "terminal_seq": s})
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:])
}

func witnessReq(seq int64, first, last int64, payload []byte, sha string) *WitnessRequest {
	return witnessReqAt(seq, first, last, payload, sha, time.Now().UTC().UnixMilli())
}

// witnessReqAt builds a request with a fixed request identity — the
// shape production sends, where created_at is the durable segment's
// own timestamp, stable across every retry of the same handoff.
func witnessReqAt(seq int64, first, last int64, payload []byte, sha string, createdAt int64) *WitnessRequest {
	return &WitnessRequest{
		Op:               OpWitnessArchive,
		SegmentSeq:       seq,
		FirstTerminalSeq: first,
		LastTerminalSeq:  last,
		RowCount:         len(mustRows(payload)),
		SHA256:           sha,
		CreatedAt:        createdAt,
		PayloadB64:       base64.StdEncoding.EncodeToString(payload),
	}
}

func mustRows(payload []byte) []json.RawMessage {
	var rows []json.RawMessage
	_ = json.Unmarshal(payload, &rows)
	return rows
}

func TestCustodyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	srv := startCustody(t, dir)
	payload, sha := testPayload(t, 1, 2, 3)
	resp, err := (&Client{Socket: srv.SocketPath()}).Witness(
		context.Background(), witnessReq(1, 1, 3, payload, sha))
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if !resp.OK || resp.WitnessedSHA256 != sha || resp.Signature == "" {
		t.Fatalf("ack = %+v", resp)
	}
	// The bytes are held under their digest.
	held, err := os.ReadFile(filepath.Join(dir, "custody", "segments", sha))
	if err != nil {
		t.Fatalf("payload not stored: %v", err)
	}
	if string(held) != string(payload) {
		t.Fatal("held payload differs from witnessed bytes")
	}
	// And the chain verifies independently.
	if findings := VerifyCustodyDir(filepath.Join(dir, "custody")); len(findings) != 0 {
		t.Fatalf("custody verify: %v", findings)
	}
}

// A payload that does not digest to the claimed sha is refused — the
// witness must never attest bytes it did not verify.
func TestCustodyRefusesDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	srv := startCustody(t, dir)
	payload, _ := testPayload(t, 1)
	other := strings64('9')
	resp, err := (&Client{Socket: srv.SocketPath()}).Witness(
		context.Background(), witnessReq(1, 1, 1, payload, other))
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatal("a payload/digest mismatch was witnessed")
	}
	if _, err := os.Stat(filepath.Join(dir, "custody", "segments", other)); !os.IsNotExist(err) {
		t.Fatal("refused payload was stored")
	}
}

// Row-count and terminal-range lies are refused the same way.
func TestCustodyRefusesShapeMismatches(t *testing.T) {
	dir := t.TempDir()
	srv := startCustody(t, dir)
	payload, sha := testPayload(t, 5, 9)

	// Wrong row count.
	req := witnessReq(1, 5, 9, payload, sha)
	req.RowCount = 7
	resp, err := (&Client{Socket: srv.SocketPath()}).Witness(context.Background(), req)
	if err != nil || resp.OK {
		t.Fatalf("row-count lie witnessed: %v %+v", err, resp)
	}
	// Terminal range that does not cover the rows.
	req = witnessReq(1, 5, 8, payload, sha)
	resp, err = (&Client{Socket: srv.SocketPath()}).Witness(context.Background(), req)
	if err != nil || resp.OK {
		t.Fatalf("range lie witnessed: %v %+v", err, resp)
	}
	if _, err := os.Stat(filepath.Join(dir, "custody", "segments", sha)); !os.IsNotExist(err) {
		t.Fatal("refused payload was stored")
	}
}

// Re-witnessing the same digest returns the original acknowledgement —
// custody retries after a mid-handoff crash are idempotent.
func TestCustodyIdempotentRetry(t *testing.T) {
	dir := t.TempDir()
	srv := startCustody(t, dir)
	payload, sha := testPayload(t, 1)
	cli := &Client{Socket: srv.SocketPath()}
	created := time.Now().UTC().UnixMilli()
	r1, err := cli.Witness(context.Background(), witnessReqAt(1, 1, 1, payload, sha, created))
	if err != nil || !r1.OK {
		t.Fatalf("first witness: %v %+v", err, r1)
	}
	r2, err := cli.Witness(context.Background(), witnessReqAt(1, 1, 1, payload, sha, created))
	if err != nil || !r2.OK {
		t.Fatalf("retry witness: %v %+v", err, r2)
	}
	if r2.AckSeq != r1.AckSeq || r2.Signature != r1.Signature {
		t.Fatalf("retry produced a second ack: %+v then %+v", r1, r2)
	}
	// One ack on the chain, not two.
	entries, _ := os.ReadDir(filepath.Join(dir, "custody", "segments"))
	if len(entries) != 1 {
		t.Fatalf("expected 1 held segment, got %d", len(entries))
	}
}

// The chain survives a restart: a new daemon on the same custody dir
// continues the sequence rather than starting a new history.
func TestCustodySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	srv := startCustody(t, dir)
	p1, s1 := testPayload(t, 1)
	if _, err := (&Client{Socket: srv.SocketPath()}).Witness(
		context.Background(), witnessReq(1, 1, 1, p1, s1)); err != nil {
		t.Fatal(err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}
	srv2 := startCustody(t, dir)
	defer srv2.Stop()
	p2, s2 := testPayload(t, 2)
	r2, err := (&Client{Socket: srv2.SocketPath()}).Witness(
		context.Background(), witnessReq(2, 2, 2, p2, s2))
	if err != nil || !r2.OK {
		t.Fatalf("post-restart witness: %v %+v", err, r2)
	}
	if r2.AckSeq != 2 {
		t.Fatalf("chain did not continue across restart: ack_seq %d", r2.AckSeq)
	}
	if findings := VerifyCustodyDir(filepath.Join(dir, "custody")); len(findings) != 0 {
		t.Fatalf("custody verify: %v", findings)
	}
}

// A rewritten held payload or an edited chain is a finding — the
// independent verifier does not trust the witness's own claims.
func TestCustodyVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	srv := startCustody(t, dir)
	payload, sha := testPayload(t, 1)
	if _, err := (&Client{Socket: srv.SocketPath()}).Witness(
		context.Background(), witnessReq(1, 1, 1, payload, sha)); err != nil {
		t.Fatal(err)
	}
	// Rewrite the held bytes under the same name — an attacker with
	// filesystem access can chmod the read-only copy.
	seg := filepath.Join(dir, "custody", "segments", sha)
	if err := os.Chmod(seg, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := VerifyCustodyDir(filepath.Join(dir, "custody"))
	if len(findings) == 0 {
		t.Fatal("rewritten custody bytes went unnoticed")
	}
}

// A wrong token is refused before any custody logic runs.
func TestCustodyTokenRefused(t *testing.T) {
	dir := t.TempDir()
	sockDir, err := os.MkdirTemp("", "cx-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	srv, err := NewServer(Config{
		SocketDir:  sockDir,
		CustodyDir: filepath.Join(dir, "custody"),
		KeyPath:    filepath.Join(dir, "custody", "witness.key"),
		Token:      "secret-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	payload, sha := testPayload(t, 1)
	resp, err := (&Client{Socket: srv.SocketPath()}).Witness(
		context.Background(), witnessReq(1, 1, 1, payload, sha))
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatal("unauthenticated witness was accepted")
	}
}

func strings64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
