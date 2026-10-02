package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// writeProvenanceDoc writes the in-tree provenance record carrying the
// generated blocks for the declared values — the source-identity block when
// a source is declared, then the delta block — the same artifact production
// writes before digesting, so the digest binds the doc that ships.
func writeProvenanceDoc(t *testing.T, root string, declared transferManifest) {
	t.Helper()
	doc := "provenance\n\n"
	if declared.Source != nil {
		doc += renderSourceBlock(*declared.Source) + "\n\n"
	}
	doc += renderDeltaBlock(declared) + "\n"
	path := filepath.Join(root, provenanceDocName)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// declaredManifest writes the provenance doc for the declared sets, digests
// the tree as it will stand (doc included), and fills the computed fields —
// the same ordering updateManifest uses.
func declaredManifest(t *testing.T, root string, declared transferManifest) transferManifest {
	t.Helper()
	writeProvenanceDoc(t, root, declared)
	identity, err := digestRuntime(root)
	if err != nil {
		t.Fatal(err)
	}
	declared.Tree = root
	declared.RuntimeVersion = identity.RuntimeVersion
	declared.ShippedTreeSHA256 = identity.NemoRuntimeSHA256
	declared.FileCount = identity.FileCount
	declared.Excluded = identity.Excluded
	return declared
}

func declarationFor(t *testing.T, root string) transferManifest {
	t.Helper()
	return declaredManifest(t, root, transferManifest{})
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
	skeleton := transferManifest{
		Tree:                  root,
		RuntimeVersion:        "stale",
		ShippedTreeSHA256:     "stale",
		FileCount:             99,
		WorkspaceMembersAdded: []string{"bridges/nemo-crabedence"},
		LocalModifications:    []string{"Cargo.toml"},
		AddedPaths:            []string{"bridges/"},
	}
	writeManifestFile(t, path, skeleton)
	// The tree carries the provenance record; update regenerates its block in
	// place rather than creating the file.
	writeProvenanceDoc(t, root, skeleton)

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
	// The vendored tree modifies crates/a and drops crates/b; the complete
	// delta must be declared.
	declaration := declaredManifest(t, root, transferManifest{
		Source: &manifestSource{
			Path:      source,
			FileCount: sourceIdentity.FileCount,
			SHA256:    sourceIdentity.NemoRuntimeSHA256,
		},
		LocalModifications: []string{"crates/a/src/lib.rs"},
		AddedPaths:         []string{"TRANSFER-PROVENANCE.md"},
		RemovedPaths:       []string{"crates/b/src/lib.rs"},
	})
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
	declaration := declaredManifest(t, root, transferManifest{
		WorkspaceMembersAdded: []string{"bridges/one"},
		LocalModifications:    []string{"crates/a/src/lib.rs"},
		AddedPaths:            []string{"bridges/", "TRANSFER-PROVENANCE.md"},
	})
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

// binaryTree is a synthetic workspace with an explicitly declared binary, an
// auto-discovered one, and a package feature.
func binaryTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"Cargo.toml":                          "[workspace]\nmembers = [\n    \"crates/one\",\n    \"crates/two\",\n]\n\n[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/one/Cargo.toml":               "[package]\nname = \"nemo-one\"\nversion = \"1.2.3\"\n\n[[bin]]\nname = \"nemo-one-host\"\npath = \"src/main.rs\"\n\n[features]\nunstable-thing = []\n",
		"crates/one/src/main.rs":              "fn main() {}\n",
		"crates/one/src/lib.rs":               "pub fn one() {}\n",
		"crates/two/Cargo.toml":               "[package]\nname = \"nemo-two\"\nversion = \"1.2.3\"\n",
		"crates/two/src/bin/nemo-two-tool.rs": "fn main() {}\n",
	})
}

func TestManifestBinariesMustHaveSourcesAndDeclarations(t *testing.T) {
	root := binaryTree(t)
	declaration := declarationFor(t, root)
	declaration.Binaries = []manifestBinary{
		{Role: "runtime", Package: "nemo-one", Binary: "nemo-one-host", Source: "crates/one/src/main.rs"},
		{Role: "plugin-host", Package: "nemo-two", Binary: "nemo-two-tool", Source: "crates/two/src/bin/nemo-two-tool.rs"},
		{Role: "qualification", Package: "nemo-one", Binary: "nemo-one-host", Source: "crates/one/src/main.rs", Features: []string{"unstable-thing"}},
	}
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("declared binaries with sources and declarations must verify: %v", err)
	}

	cases := []struct {
		name    string
		binary  manifestBinary
		wantErr string
	}{
		{
			name:    "source absent",
			binary:  manifestBinary{Role: "runtime", Package: "nemo-one", Binary: "nemo-one-host", Source: "crates/one/src/bin/missing.rs"},
			wantErr: "does not exist",
		},
		{
			name:    "source exists but nothing declares the binary",
			binary:  manifestBinary{Role: "runtime", Package: "nemo-one", Binary: "nemo-undeclared", Source: "crates/one/src/lib.rs"},
			wantErr: "neither declares a [[bin]] entry",
		},
		{
			name:    "declared path disagrees with the manifest",
			binary:  manifestBinary{Role: "runtime", Package: "nemo-one", Binary: "nemo-one-host", Source: "crates/one/src/lib.rs"},
			wantErr: "declares its path as",
		},
		{
			name:    "package does not match the source's package",
			binary:  manifestBinary{Role: "runtime", Package: "nemo-two", Binary: "nemo-one-host", Source: "crates/one/src/main.rs"},
			wantErr: "declares package",
		},
		{
			name:    "feature the package does not declare",
			binary:  manifestBinary{Role: "qualification", Package: "nemo-one", Binary: "nemo-one-host", Source: "crates/one/src/main.rs", Features: []string{"unstable-absent"}},
			wantErr: "declares no such feature",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			declaration.Binaries = []manifestBinary{tc.binary}
			writeManifestFile(t, path, declaration)
			err := verifyManifest(path)
			if err == nil {
				t.Fatal("the declaration must fail verification")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestManifestSourceAbsenceIsReportedNotFailed(t *testing.T) {
	root := baseTree(t)
	// The doc renders the declared identity even though the tree it describes
	// is absent — the block binds the declaration, not the on-disk copy.
	declaration := declaredManifest(t, root, transferManifest{
		Source: &manifestSource{
			Path:      filepath.Join(t.TempDir(), "absent-source"),
			FileCount: 1,
			SHA256:    strings.Repeat("0", 64),
		},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("an absent source tree must not fail verification: %v", err)
	}
}

// transferredPair builds the shape the real transfer has: a vendored tree
// that modifies one source file, adds a subtree, and removes one source
// file.
func transferredPair(t *testing.T) (source, vendored string) {
	source = writeTree(t, map[string]string{
		"Cargo.toml":          "[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs": "pub fn a() {}\n",
		"crates/b/src/lib.rs": "pub fn b() {}\n",
		"docs/old.md":         "retired\n",
	})
	vendored = writeTree(t, map[string]string{
		"Cargo.toml":             "[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs":    "pub fn a() { let _ = 1; }\n",
		"crates/b/src/lib.rs":    "pub fn b() {}\n",
		"bridges/x/src/lib.rs":   "pub fn x() {}\n",
		"TRANSFER-PROVENANCE.md": "provenance\n",
	})
	return source, vendored
}

func declarationForPair(t *testing.T, source, vendored string, declared transferManifest) transferManifest {
	t.Helper()
	sourceIdentity, err := digestRuntime(source)
	if err != nil {
		t.Fatal(err)
	}
	// The source identity lands on the declaration before the doc is written:
	// the record's generated source block renders it, so the tree digest the
	// declaration fills in covers the rendered value.
	declared.Source = &manifestSource{
		Path:      source,
		FileCount: sourceIdentity.FileCount,
		SHA256:    sourceIdentity.NemoRuntimeSHA256,
	}
	return declaredManifest(t, vendored, declared)
}

func TestDeltaVerificationAcceptsTheCompleteDeclaration(t *testing.T) {
	source, vendored := transferredPair(t)
	declaration := declarationForPair(t, source, vendored, transferManifest{
		LocalModifications: []string{"crates/a/src/lib.rs"},
		AddedPaths:         []string{"bridges/", "TRANSFER-PROVENANCE.md"},
		RemovedPaths:       []string{"docs/old.md"},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("the complete declaration must verify: %v", err)
	}
}

func TestDeltaVerificationRejectsAnIncompleteDeclaration(t *testing.T) {
	source, vendored := transferredPair(t)
	cases := []struct {
		name    string
		declare func(*transferManifest)
		wantErr string
	}{
		{
			name: "undeclared modification",
			declare: func(m *transferManifest) {
				m.LocalModifications = nil
				m.AddedPaths = []string{"bridges/", "TRANSFER-PROVENANCE.md"}
				m.RemovedPaths = []string{"docs/old.md"}
			},
			wantErr: "undeclared modification: crates/a/src/lib.rs",
		},
		{
			name: "stale modification declaration",
			declare: func(m *transferManifest) {
				m.LocalModifications = []string{"crates/a/src/lib.rs", "crates/b/src/lib.rs"}
				m.AddedPaths = []string{"bridges/", "TRANSFER-PROVENANCE.md"}
				m.RemovedPaths = []string{"docs/old.md"}
			},
			wantErr: "declared modification crates/b/src/lib.rs is identical to the source",
		},
		{
			name: "undeclared addition",
			declare: func(m *transferManifest) {
				m.LocalModifications = []string{"crates/a/src/lib.rs"}
				m.AddedPaths = []string{"TRANSFER-PROVENANCE.md"}
				m.RemovedPaths = []string{"docs/old.md"}
			},
			wantErr: "undeclared addition: bridges/x/src/lib.rs",
		},
		{
			// A declared directory prefix that exists in both trees covers
			// nothing that was actually added.
			name: "stale added-path declaration",
			declare: func(m *transferManifest) {
				m.LocalModifications = []string{"crates/a/src/lib.rs"}
				m.AddedPaths = []string{"bridges/", "TRANSFER-PROVENANCE.md", "crates/"}
				m.RemovedPaths = []string{"docs/old.md"}
			},
			wantErr: "declared added path crates/ covers no actual addition",
		},
		{
			name: "undeclared removal",
			declare: func(m *transferManifest) {
				m.LocalModifications = []string{"crates/a/src/lib.rs"}
				m.AddedPaths = []string{"bridges/", "TRANSFER-PROVENANCE.md"}
				m.RemovedPaths = nil
			},
			wantErr: "undeclared removal: docs/old.md",
		},
		{
			name: "stale removal declaration",
			declare: func(m *transferManifest) {
				m.LocalModifications = []string{"crates/a/src/lib.rs"}
				m.AddedPaths = []string{"bridges/", "TRANSFER-PROVENANCE.md"}
				m.RemovedPaths = []string{"docs/old.md", "crates/b/src/lib.rs"}
			},
			wantErr: "declared removed path crates/b/src/lib.rs still exists in the source",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var declared transferManifest
			tc.declare(&declared)
			declaration := declarationForPair(t, source, vendored, declared)
			path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
			writeManifestFile(t, path, declaration)
			err := verifyManifest(path)
			if err == nil {
				t.Fatal("an incomplete declaration must fail verification")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestDeltaSeesSymlinkDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	source, vendored := transferredPair(t)
	link := filepath.Join(vendored, "crates", "a", "src", "LINK")
	if err := os.Symlink("original-target", link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("original-target", filepath.Join(source, "crates", "a", "src", "LINK")); err != nil {
		t.Fatal(err)
	}

	declaration := declarationForPair(t, source, vendored, transferManifest{
		LocalModifications: []string{"crates/a/src/lib.rs"},
		AddedPaths:         []string{"bridges/", "TRANSFER-PROVENANCE.md"},
		RemovedPaths:       []string{"docs/old.md"},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("identical symlinks must verify: %v", err)
	}

	// The file digest never sees a link's target; the delta must.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("retargeted", link); err != nil {
		t.Fatal(err)
	}
	err := verifyManifest(path)
	if err == nil {
		t.Fatal("a retargeted symlink is a modification and must fail undeclared")
	}
	if !strings.Contains(err.Error(), "undeclared modification: crates/a/src/LINK") {
		t.Fatalf("error = %q, want the retargeted link named", err)
	}
}

func TestManifestUpdateRegeneratesTheDeltaInventory(t *testing.T) {
	source, vendored := transferredPair(t)
	// Stale inventory: names the wrong modification, misses the additions and
	// the removal entirely.
	declaration := declarationForPair(t, source, vendored, transferManifest{
		LocalModifications: []string{"Cargo.toml"},
		AddedPaths:         []string{"not-present/"},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)

	if err := updateManifest(path); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(updated.LocalModifications, []string{"crates/a/src/lib.rs"}) {
		t.Fatalf("update must regenerate the modification set: %v", updated.LocalModifications)
	}
	for _, want := range []string{"TRANSFER-PROVENANCE.md", "bridges/x/src/lib.rs"} {
		if !slices.Contains(updated.AddedPaths, want) {
			t.Fatalf("update must declare the addition %s: %v", want, updated.AddedPaths)
		}
	}
	if slices.Contains(updated.AddedPaths, "not-present/") {
		t.Fatal("update must drop a declared path that covers no actual addition")
	}
	if !slices.Equal(updated.RemovedPaths, []string{"docs/old.md"}) {
		t.Fatalf("update must regenerate the removal set: %v", updated.RemovedPaths)
	}
	if err := verifyManifest(path); err != nil {
		t.Fatalf("a regenerated manifest must verify: %v", err)
	}
}

func TestProvenanceDocDriftFailsVerification(t *testing.T) {
	source, vendored := transferredPair(t)
	declaration := declarationForPair(t, source, vendored, transferManifest{
		LocalModifications: []string{"crates/a/src/lib.rs"},
		AddedPaths:         []string{"bridges/", "TRANSFER-PROVENANCE.md"},
		RemovedPaths:       []string{"docs/old.md"},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("the doc generated for this declaration must verify: %v", err)
	}

	// A declared set that drifted from the doc's generated block is a stale
	// record even though the tree digest still matches — the doc and manifest
	// disagree about what shipped.
	declaration.LocalModifications = []string{"crates/a/src/lib.rs", "crates/b/src/lib.rs"}
	writeManifestFile(t, path, declaration)
	err := verifyManifest(path)
	if err == nil {
		t.Fatal("a doc block that disagrees with the manifest must fail verification")
	}
	if !strings.Contains(err.Error(), "TRANSFER-PROVENANCE.md is stale") {
		t.Fatalf("error = %q, want the stale-record failure named", err)
	}

	// Hand-editing the generated block is the same class of drift: the block
	// no longer renders the declared sets.
	writeManifestFile(t, path, declarationForPair(t, source, vendored, transferManifest{
		LocalModifications: []string{"crates/a/src/lib.rs"},
		AddedPaths:         []string{"bridges/", "TRANSFER-PROVENANCE.md"},
		RemovedPaths:       []string{"docs/old.md"},
	}))
	docPath := filepath.Join(vendored, provenanceDocName)
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(docPath, append(doc, []byte("hand-edited\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(path); err == nil {
		t.Fatal("a hand-edited tree must fail verification")
	}
}

// The source identity used to live in hand-maintained prose; it drifted from
// the manifest's declared source digest while the gate still passed. The
// block must render the declaration, and the digest over the tree then binds
// the rendered value.
func TestProvenanceDocSourceIdentityIsGenerated(t *testing.T) {
	source, vendored := transferredPair(t)
	declaration := declarationForPair(t, source, vendored, transferManifest{
		LocalModifications: []string{"crates/a/src/lib.rs"},
		AddedPaths:         []string{"bridges/", "TRANSFER-PROVENANCE.md"},
		RemovedPaths:       []string{"docs/old.md"},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path); err != nil {
		t.Fatalf("the doc generated for this declaration must verify: %v", err)
	}

	docPath := filepath.Join(vendored, provenanceDocName)
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), declaration.Source.SHA256) {
		t.Fatal("the generated source-identity block must carry the declared digest")
	}

	// A record whose rendered source identity disagrees with the declaration
	// is stale even though the delta block still matches. The doc is part of
	// the digested tree, so the edit must be declared over — a regenerated
	// manifest carrying a stale block is exactly how the drift shipped.
	staleDoc := strings.Replace(string(doc), declaration.Source.SHA256, strings.Repeat("0", 64), 1)
	if staleDoc == string(doc) {
		t.Fatal("the digest replacement must actually edit the doc")
	}
	if err := os.WriteFile(docPath, []byte(staleDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	identity, err := digestRuntime(vendored)
	if err != nil {
		t.Fatal(err)
	}
	declaration.ShippedTreeSHA256 = identity.NemoRuntimeSHA256
	declaration.FileCount = identity.FileCount
	writeManifestFile(t, path, declaration)
	err = verifyManifest(path)
	if err == nil {
		t.Fatal("a stale source-identity block must fail verification")
	}
	if !strings.Contains(err.Error(), "source-identity") {
		t.Fatalf("error = %q, want the source-identity block named", err)
	}

	// -update rewrites the block back to the declared identity.
	if err := syncProvenanceDoc(vendored, declaration, true); err != nil {
		t.Fatalf("regenerating the doc: %v", err)
	}
	repaired, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(repaired), declaration.Source.SHA256) {
		t.Fatal("the regenerated block must carry the declared digest again")
	}
}

// A duplicated marker pair would leave a second block past the splice that
// verification never reads — a stale copy hiding in the record. Both blocks
// share that failure mode, so the check is on the markers, not the payload.
func TestProvenanceDocRejectsDuplicateGeneratedBlocks(t *testing.T) {
	root := baseTree(t)
	declaration := declarationFor(t, root)
	docPath := filepath.Join(root, provenanceDocName)
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicated := string(doc) + "\n" + renderDeltaBlock(declaration) + "\n"
	if err := os.WriteFile(docPath, []byte(duplicated), 0o644); err != nil {
		t.Fatal(err)
	}
	identity, err := digestRuntime(root)
	if err != nil {
		t.Fatal(err)
	}
	declaration.ShippedTreeSHA256 = identity.NemoRuntimeSHA256
	declaration.FileCount = identity.FileCount
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	err = verifyManifest(path)
	if err == nil {
		t.Fatal("a duplicated generated block must fail verification")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %q, want the duplicate named", err)
	}
}

// A manifest that declares no source must not meet a record that claims one:
// the doc asserting provenance the manifest does not declare is the same
// class of disagreement as a stale value.
func TestProvenanceDocSourceBlockWithoutDeclaredSourceFails(t *testing.T) {
	root := baseTree(t)
	declaration := declarationFor(t, root)
	docPath := filepath.Join(root, provenanceDocName)
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.Replace(string(doc), deltaBlockBegin,
		renderSourceBlock(manifestSource{Path: "../elsewhere", FileCount: 1, SHA256: strings.Repeat("1", 64)})+"\n\n"+deltaBlockBegin, 1)
	if err := os.WriteFile(docPath, []byte(extra), 0o644); err != nil {
		t.Fatal(err)
	}
	// Re-declare the computed fields over the edited doc so the digest
	// matches and only the generated-block check can object.
	identity, err := digestRuntime(root)
	if err != nil {
		t.Fatal(err)
	}
	declaration.ShippedTreeSHA256 = identity.NemoRuntimeSHA256
	declaration.FileCount = identity.FileCount
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declaration)
	err = verifyManifest(path)
	if err == nil {
		t.Fatal("a source-identity block with no declared source must fail verification")
	}
	if !strings.Contains(err.Error(), "declares no source") {
		t.Fatalf("error = %q, want the undeclared source named", err)
	}
}
