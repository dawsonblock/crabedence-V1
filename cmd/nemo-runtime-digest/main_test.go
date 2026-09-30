package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func baseTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"Cargo.toml":          "[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs": "pub fn a() {}\n",
		"crates/b/src/lib.rs": "pub fn b() {}\n",
	})
}

func TestDigestIsStableAndContentSensitive(t *testing.T) {
	root := baseTree(t)
	first, err := digestRuntime(root)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first.NemoRuntimeSHA256 == "" {
		t.Fatal("the digest must not be empty")
	}
	if first.RuntimeVersion != "1.2.3" {
		t.Fatalf("version: got %q", first.RuntimeVersion)
	}
	if first.FileCount != 3 {
		t.Fatalf("file count: got %d", first.FileCount)
	}

	// The same tree digests the same way.
	second, err := digestRuntime(root)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first.NemoRuntimeSHA256 != second.NemoRuntimeSHA256 {
		t.Fatal("the digest must be stable across runs")
	}

	// Changing a byte changes the digest.
	if err := os.WriteFile(filepath.Join(root, "crates/a/src/lib.rs"), []byte("pub fn a() { let _ = 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := digestRuntime(root)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if changed.NemoRuntimeSHA256 == first.NemoRuntimeSHA256 {
		t.Fatal("a content change must change the digest")
	}

	// So does a rename, because the path is part of the record.
	if err := os.Rename(
		filepath.Join(root, "crates/b/src/lib.rs"),
		filepath.Join(root, "crates/b/src/other.rs"),
	); err != nil {
		t.Fatal(err)
	}
	renamed, err := digestRuntime(root)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if renamed.NemoRuntimeSHA256 == changed.NemoRuntimeSHA256 {
		t.Fatal("a rename must change the digest")
	}
}

func TestBuildOutputIsNotDigested(t *testing.T) {
	root := baseTree(t)
	clean, err := digestRuntime(root)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// A build artifact must not move the runtime identity: a digest that
	// changed when someone ran `cargo build` would bind nothing.
	if err := os.MkdirAll(filepath.Join(root, "target", "debug"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target", "debug", "artifact"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	withArtifacts, err := digestRuntime(root)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if withArtifacts.NemoRuntimeSHA256 != clean.NemoRuntimeSHA256 {
		t.Fatal("build output must not change the runtime identity")
	}
	if withArtifacts.FileCount != clean.FileCount {
		t.Fatal("build output must not be counted")
	}
}

func TestMissingTreeFailsClosed(t *testing.T) {
	if _, err := digestRuntime(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing runtime tree must fail closed")
	}
}

func TestEmptyTreeFailsClosed(t *testing.T) {
	root := writeTree(t, map[string]string{"target/only-artifacts": "x"})
	if _, err := digestRuntime(root); err == nil {
		t.Fatal("a tree with no source files must fail closed")
	}
}

func TestVersionMustBeDeclared(t *testing.T) {
	root := writeTree(t, map[string]string{"crates/a/src/lib.rs": "pub fn a() {}\n"})
	if _, err := digestRuntime(root); err == nil {
		t.Fatal("a tree without a workspace version must fail closed")
	}
}

func writeManifestFile(t *testing.T, path string, manifest transferManifest) {
	t.Helper()
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func declarationFor(t *testing.T, root string) transferManifest {
	t.Helper()
	identity, err := digestRuntime(root)
	if err != nil {
		t.Fatal(err)
	}
	return transferManifest{
		Tree:              root,
		RuntimeVersion:    identity.RuntimeVersion,
		ShippedTreeSHA256: identity.NemoRuntimeSHA256,
		FileCount:         identity.FileCount,
		Excluded:          identity.Excluded,
	}
}

func TestManifestVerificationAcceptsAMatchingDeclaration(t *testing.T) {
	root := baseTree(t)
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declarationFor(t, root))
	if err := verifyManifest(path); err != nil {
		t.Fatalf("a matching declaration must verify: %v", err)
	}
}

func TestManifestVerificationRejectsDriftAndNamesTheField(t *testing.T) {
	root := baseTree(t)
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declarationFor(t, root))

	if err := os.WriteFile(filepath.Join(root, "crates/a/src/lib.rs"), []byte("pub fn a() { let _ = 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := verifyManifest(path)
	if err == nil {
		t.Fatal("tree drift must fail verification")
	}
	if !strings.Contains(err.Error(), "shipped_tree_sha256") {
		t.Fatalf("the failure must name the drifting field: %v", err)
	}
	if !strings.Contains(err.Error(), "-update") {
		t.Fatalf("the failure must say how to regenerate: %v", err)
	}
}

func TestManifestVerificationFailsClosedOnAMissingFile(t *testing.T) {
	if err := verifyManifest(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("a missing manifest must fail verification")
	}
}

func TestManifestUpdateRefreshesComputedFieldsAndKeepsTheInventory(t *testing.T) {
	root := baseTree(t)
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, transferManifest{
		Tree:                  root,
		RuntimeVersion:        "stale",
		ShippedTreeSHA256:     "stale",
		FileCount:             99,
		WorkspaceMembersAdded: []string{"bridges/nemo-crabedence"},
		LocalModifications:    []string{"Cargo.toml"},
		AddedPaths:            []string{"bridges/"},
	})

	if err := updateManifest(path); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := digestRuntime(root)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ShippedTreeSHA256 != identity.NemoRuntimeSHA256 ||
		updated.FileCount != identity.FileCount ||
		updated.RuntimeVersion != identity.RuntimeVersion {
		t.Fatalf("update must refresh the computed fields: %+v", updated)
	}
	if len(updated.Excluded) != len(identity.Excluded) {
		t.Fatalf("update must record the exclusion set: %+v", updated.Excluded)
	}
	if len(updated.WorkspaceMembersAdded) != 1 || updated.WorkspaceMembersAdded[0] != "bridges/nemo-crabedence" {
		t.Fatal("update must preserve the inventory fields")
	}
	if len(updated.LocalModifications) != 1 || updated.LocalModifications[0] != "Cargo.toml" {
		t.Fatal("update must preserve the local modifications")
	}
	if len(updated.AddedPaths) != 1 || updated.AddedPaths[0] != "bridges/" {
		t.Fatal("update must preserve the added paths")
	}
}

func TestManifestSourceIsCheckedWhenPresent(t *testing.T) {
	source := baseTree(t)
	sourceIdentity, err := digestRuntime(source)
	if err != nil {
		t.Fatal(err)
	}
	root := writeTree(t, map[string]string{
		"Cargo.toml":          "[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs": "pub fn a() { let _ = 1; }\n",
	})
	declaration := declarationFor(t, root)
	declaration.Source = &manifestSource{
		Path:      source,
		FileCount: sourceIdentity.FileCount,
		SHA256:    sourceIdentity.NemoRuntimeSHA256,
	}
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("a matching source declaration must verify: %v", err)
	}

	declaration.Source.SHA256 = strings.Repeat("0", 64)
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err == nil {
		t.Fatal("a wrong source identity must fail verification")
	}
}

func TestManifestInventoryMustMatchTheTree(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Cargo.toml":             "[workspace]\nmembers = [\n    \"crates/a\",\n    \"bridges/one\",\n]\n\n[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs":    "pub fn a() {}\n",
		"bridges/one/Cargo.toml": "x\n",
	})
	declaration := declarationFor(t, root)
	declaration.WorkspaceMembersAdded = []string{"bridges/one"}
	declaration.LocalModifications = []string{"crates/a/src/lib.rs"}
	declaration.AddedPaths = []string{"bridges/"}
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("a matching inventory must verify: %v", err)
	}

	// A member the workspace does not list is a failure.
	declaration.WorkspaceMembersAdded = []string{"bridges/two"}
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err == nil {
		t.Fatal("an unlisted workspace member must fail verification")
	}

	// So is a declared path that does not exist.
	declaration.WorkspaceMembersAdded = []string{"bridges/one"}
	declaration.AddedPaths = []string{"bridges/missing"}
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err == nil {
		t.Fatal("a declared path that does not exist must fail verification")
	}
}

func TestManifestSourceAbsenceIsReportedNotFailed(t *testing.T) {
	root := baseTree(t)
	declaration := declarationFor(t, root)
	declaration.Source = &manifestSource{
		Path:      filepath.Join(t.TempDir(), "absent-source"),
		FileCount: 1,
		SHA256:    strings.Repeat("0", 64),
	}
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("an absent source tree must not fail verification: %v", err)
	}
}
