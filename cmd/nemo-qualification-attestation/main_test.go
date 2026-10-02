package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDistRoot assembles the minimum distribution root the tool reads:
// the manifests directory carrying the component manifest, its digest
// sidecar, and the transfer manifest.
func writeDistRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	manifests := filepath.Join(root, "manifests")
	if err := os.MkdirAll(manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name":"nemo-control","crabbox_version":"0.0.0-test","platform":"linux_amd64"}`
	manifestPath := filepath.Join(manifests, "component-manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(manifest))
	if err := os.WriteFile(filepath.Join(manifests, "component-manifest.sha256"), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifests, "nemo-transfer-manifest.json"), []byte(`{"runtime_version":"0.9.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestEmitThenVerifyRoundTrip(t *testing.T) {
	root := writeDistRoot(t)
	archive := filepath.Join(t.TempDir(), "dist.tar.gz")
	if err := os.WriteFile(archive, []byte("fake archive bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "qualification.json")

	err := emitAttestation(root, archive, "abc123", "gate-a,gate-b", out)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := verifyAttestation(root, out); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The record really does bind the bytes: the archive digest must be
	// the digest of the archive, and the subject the manifest's own.
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var record attestation
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("fake archive bytes"))
	if record.Subject.ArchiveSHA256 != hex.EncodeToString(want[:]) {
		t.Fatal("the archive digest in the record is not the archive's digest")
	}
	if record.Subject.Platform != "linux_amd64" || record.Subject.Name != "nemo-control" {
		t.Fatalf("subject does not carry the manifest's identity: %+v", record.Subject)
	}
	if len(record.Gates) != 2 || record.Gates[0].ID != "gate-a" {
		t.Fatalf("gates not recorded in order: %+v", record.Gates)
	}
	if record.Source.Commit != "abc123" {
		t.Fatalf("the commit is not bound: %+v", record.Source)
	}
}

func TestVerifyRefusesADistributionTheRecordDoesNotBind(t *testing.T) {
	root := writeDistRoot(t)
	out := filepath.Join(t.TempDir(), "qualification.json")
	if err := emitAttestation(root, "", "abc123", "gate-a", out); err != nil {
		t.Fatalf("emit: %v", err)
	}
	// Tamper: a different distribution's transfer manifest under the
	// same layout — the attestation must not bind it.
	other := writeDistRoot(t)
	if err := os.WriteFile(filepath.Join(other, "manifests", "nemo-transfer-manifest.json"), []byte(`{"runtime_version":"9.9.9-different"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := verifyAttestation(other, out)
	if err == nil || !strings.Contains(err.Error(), "transfer_manifest_sha256") {
		t.Fatalf("a record must not verify against bytes it does not bind: %v", err)
	}
}

func TestEmitRefusesAStakelessManifest(t *testing.T) {
	root := writeDistRoot(t)
	// A sidecar that disagrees with the manifest cannot be attested —
	// the release-root identity must be self-consistent first.
	if err := os.WriteFile(filepath.Join(root, "manifests", "component-manifest.sha256"), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := emitAttestation(root, "", "abc123", "gate-a", filepath.Join(t.TempDir(), "a.json")); err == nil {
		t.Fatal("emitting over a disagreeing sidecar must fail")
	}
}

func TestEmitRequiresCommitAndGates(t *testing.T) {
	root := writeDistRoot(t)
	out := filepath.Join(t.TempDir(), "a.json")
	if err := emitAttestation(root, "", "", "gate-a", out); err == nil || !strings.Contains(err.Error(), "commit") {
		t.Fatalf("a record must bind a source commit: %v", err)
	}
	if err := emitAttestation(root, "", "abc123", "", out); err == nil || !strings.Contains(err.Error(), "gates") {
		t.Fatalf("a record with no gates attests nothing: %v", err)
	}
}

func TestVerifyRefusesMalformedRecords(t *testing.T) {
	root := writeDistRoot(t)
	out := filepath.Join(t.TempDir(), "qualification.json")
	if err := emitAttestation(root, "", "abc123", "gate-a", out); err != nil {
		t.Fatalf("emit: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	// A recorded failure is not a qualification — non-pass results are
	// refused outright rather than reported.
	record["gates"] = []any{map[string]any{"id": "gate-a", "result": "fail"}}
	broken, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	brokenPath := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(brokenPath, broken, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAttestation(root, brokenPath); err == nil || !strings.Contains(err.Error(), "only carries passes") {
		t.Fatalf("a recorded failure must not verify: %v", err)
	}
}
