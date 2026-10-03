package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
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

// writeTestPolicyWith writes a minimal format-2 policy for fixture trees and
// returns its path. The enumeration mirrors the real policy's exclusions;
// generated paths are caller-supplied so the generated-file tests can pin
// their own patterns.
func writeTestPolicyWith(t *testing.T, generated []string) string {
	t.Helper()
	if generated == nil {
		generated = []string{}
	}
	policy := map[string]interface{}{
		"policy":                    "test-canonical-tree",
		"policy_version":            1,
		"provenance_format_version": 2,
		"enumeration": map[string]interface{}{
			"excluded_dir_names":     []string{"target", ".git", "node_modules", ".venv", "__pycache__"},
			"excluded_dir_suffixes":  []string{".egg-info"},
			"excluded_file_names":    []string{".DS_Store"},
			"excluded_file_suffixes": []string{".pyc"},
			"generated_paths":        generated,
		},
	}
	encoded, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provenance-policy.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestPolicy(t *testing.T) string {
	t.Helper()
	return writeTestPolicyWith(t, nil)
}

// policyBinding reads a policy file back and returns the manifest-side
// reference (path + content hash) updateManifest would record.
func policyBinding(t *testing.T, policyPath string) *policyRef {
	t.Helper()
	sum, err := policyDigest(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	return &policyRef{Path: policyPath, SHA256: sum}
}

// writeProvenanceDocV2 is the format-2 counterpart of writeProvenanceDoc: the
// typed delta block and the file+symlink source block.
func writeProvenanceDocV2(t *testing.T, root string, declared transferManifest) {
	t.Helper()
	doc := "provenance\n\n"
	if declared.Source != nil {
		doc += renderSourceBlockV2(*declared.Source) + "\n\n"
	}
	doc += renderDeltaBlockV2(declared) + "\n"
	path := filepath.Join(root, provenanceDocName)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// declaredManifestV2 fills a format-2 manifest's computed fields for root —
// the same ordering updateManifest uses: provenance doc first, digest after.
func declaredManifestV2(t *testing.T, root, policyPath string, declared transferManifest) transferManifest {
	t.Helper()
	declared.FormatVersion = formatVersion
	declared.Policy = policyBinding(t, policyPath)
	writeProvenanceDocV2(t, root, declared)
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatal(err)
	}
	declared.Tree = root
	declared.RuntimeVersion = identity.RuntimeVersion
	declared.ShippedTreeSHA256 = identity.NemoRuntimeSHA256
	declared.FileCount = identity.FileCount
	declared.SymlinkCount = identity.SymlinkCount
	return declared
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
	if err := verifyManifest(path, false); err != nil {
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
	err := verifyManifest(path, false)
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
	if err := verifyManifest(filepath.Join(t.TempDir(), "absent.json"), false); err == nil {
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
	policyPath := writeTestPolicy(t)

	if err := updateManifest(path, policyPath); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ShippedTreeSHA256 != identity.NemoRuntimeSHA256 ||
		updated.FileCount != identity.FileCount ||
		updated.RuntimeVersion != identity.RuntimeVersion {
		t.Fatalf("update must refresh the computed fields: %+v", updated)
	}
	if updated.FormatVersion != formatVersion || updated.Policy == nil {
		t.Fatalf("update must emit the current provenance format and bind the policy: %+v", updated)
	}
	if len(updated.WorkspaceMembersAdded) != 1 || updated.WorkspaceMembersAdded[0] != "bridges/nemo-crabedence" {
		t.Fatal("update must preserve the inventory fields")
	}
	if updated.Delta == nil || !slices.Equal(updated.Delta.ModifiedFiles, []string{"Cargo.toml"}) {
		t.Fatalf("update must carry the local modifications in the typed delta: %+v", updated.Delta)
	}
	if !slices.Equal(updated.Delta.AddedFiles, []string{"bridges/"}) {
		t.Fatalf("update must carry the added paths in the typed delta: %+v", updated.Delta.AddedFiles)
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
	if err := verifyManifest(path, false); err != nil {
		t.Fatalf("a matching source declaration must verify: %v", err)
	}

	declaration.Source.SHA256 = strings.Repeat("0", 64)
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path, false); err == nil {
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
	if err := verifyManifest(path, false); err != nil {
		t.Fatalf("a matching inventory must verify: %v", err)
	}

	// A member the workspace does not list is a failure.
	declaration.WorkspaceMembersAdded = []string{"bridges/two"}
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path, false); err == nil {
		t.Fatal("an unlisted workspace member must fail verification")
	}

	// So is a declared path that does not exist.
	declaration.WorkspaceMembersAdded = []string{"bridges/one"}
	declaration.AddedPaths = []string{"bridges/missing"}
	writeManifestFile(t, path, declaration)
	if err := verifyManifest(path, false); err == nil {
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
	if err := verifyManifest(path, false); err != nil {
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
			err := verifyManifest(path, false)
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
	if err := verifyManifest(path, false); err != nil {
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
	if err := verifyManifest(path, false); err != nil {
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
			err := verifyManifest(path, false)
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
	if err := verifyManifest(path, false); err != nil {
		t.Fatalf("identical symlinks must verify: %v", err)
	}

	// The file digest never sees a link's target; the delta must.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("retargeted", link); err != nil {
		t.Fatal(err)
	}
	err := verifyManifest(path, false)
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

	policyPath := writeTestPolicy(t)
	if err := updateManifest(path, policyPath); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Delta == nil {
		t.Fatalf("a regenerated manifest must carry the typed delta: %+v", updated)
	}
	if !slices.Equal(updated.Delta.ModifiedFiles, []string{"crates/a/src/lib.rs"}) {
		t.Fatalf("update must regenerate the modification set: %v", updated.Delta.ModifiedFiles)
	}
	for _, want := range []string{"TRANSFER-PROVENANCE.md", "bridges/x/src/lib.rs"} {
		if !slices.Contains(updated.Delta.AddedFiles, want) {
			t.Fatalf("update must declare the addition %s: %v", want, updated.Delta.AddedFiles)
		}
	}
	if slices.Contains(updated.Delta.AddedFiles, "not-present/") {
		t.Fatal("update must drop a declared path that covers no actual addition")
	}
	if !slices.Equal(updated.Delta.RemovedFiles, []string{"docs/old.md"}) {
		t.Fatalf("update must regenerate the removal set: %v", updated.Delta.RemovedFiles)
	}
	if err := verifyManifest(path, false); err != nil {
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
	if err := verifyManifest(path, false); err != nil {
		t.Fatalf("the doc generated for this declaration must verify: %v", err)
	}

	// A declared set that drifted from the doc's generated block is a stale
	// record even though the tree digest still matches — the doc and manifest
	// disagree about what shipped.
	declaration.LocalModifications = []string{"crates/a/src/lib.rs", "crates/b/src/lib.rs"}
	writeManifestFile(t, path, declaration)
	err := verifyManifest(path, false)
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
	if err := verifyManifest(path, false); err == nil {
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
	if err := verifyManifest(path, false); err != nil {
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
	err = verifyManifest(path, false)
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
	err = verifyManifest(path, false)
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
	err = verifyManifest(path, false)
	if err == nil {
		t.Fatal("a source-identity block with no declared source must fail verification")
	}
	if !strings.Contains(err.Error(), "declares no source") {
		t.Fatalf("error = %q, want the undeclared source named", err)
	}
}

// declarationForPairV2 fills a format-2 manifest for a source/vendored pair:
// the bound policy, the typed delta, and both canonical-stream identities —
// the same artifacts updateManifest produces.
func declarationForPairV2(t *testing.T, source, vendored, policyPath string, delta typedDelta) transferManifest {
	t.Helper()
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	sourceIdentity, err := digestRuntimeV2(source, &policy)
	if err != nil {
		t.Fatal(err)
	}
	declared := transferManifest{
		Source: &manifestSource{
			Path:         source,
			FileCount:    sourceIdentity.FileCount,
			SymlinkCount: sourceIdentity.SymlinkCount,
			SHA256:       sourceIdentity.NemoRuntimeSHA256,
		},
		Delta: &delta,
	}
	return declaredManifestV2(t, vendored, policyPath, declared)
}

func TestDigestV2BindsSymlinksAndTheExecutableBit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	policyPath := writeTestPolicy(t)
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	root := baseTree(t)
	first, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first.SymlinkCount != 0 {
		t.Fatalf("a link-free tree must report zero symlinks: %d", first.SymlinkCount)
	}

	// A symlink is an identity-bearing object: adding one must change the
	// digest even though no regular file moved.
	link := filepath.Join(root, "crates", "a", "src", "LINK")
	if err := os.Symlink("lib.rs", link); err != nil {
		t.Fatal(err)
	}
	linked, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest with link: %v", err)
	}
	if linked.SymlinkCount != 1 {
		t.Fatalf("symlink count: got %d", linked.SymlinkCount)
	}
	if linked.NemoRuntimeSHA256 == first.NemoRuntimeSHA256 {
		t.Fatal("adding a symlink must change the tree identity")
	}

	// Retargeting changes identity — the target is the record.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../b/src/lib.rs", link); err != nil {
		t.Fatal(err)
	}
	retargeted, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest retargeted: %v", err)
	}
	if retargeted.NemoRuntimeSHA256 == linked.NemoRuntimeSHA256 {
		t.Fatal("retargeting a symlink must change the tree identity")
	}

	// Removal must restore the original identity exactly.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	removed, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest after removal: %v", err)
	}
	if removed.NemoRuntimeSHA256 != first.NemoRuntimeSHA256 {
		t.Fatal("removing the symlink must restore the prior identity")
	}

	// The executable bit is provenance-relevant for shipped scripts.
	script := filepath.Join(root, "crates", "a", "src", "lib.rs")
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	exec, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest exec: %v", err)
	}
	if exec.NemoRuntimeSHA256 == removed.NemoRuntimeSHA256 {
		t.Fatal("flipping the executable bit must change the tree identity")
	}
}

func TestDigestV2ExcludesTransientsAndGenerated(t *testing.T) {
	policyPath := writeTestPolicyWith(t, []string{"generated/out.py", "generated/"})
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	root := baseTree(t)
	first, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	for rel, contents := range map[string]string{
		"target/debug/app":     "build output\n",
		"node_modules/x/i.js":  "dep\n",
		"__pycache__/m.pyc":    "cache\n",
		"pkg.egg-info/PKG":     "metadata\n",
		".DS_Store":            "junk\n",
		"notes.pyc":            "bytecode\n",
		"generated/out.py":     "# generated\n",
		"generated/other/x.py": "# generated subtree\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	withArtifacts, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest with artifacts: %v", err)
	}
	if withArtifacts.NemoRuntimeSHA256 != first.NemoRuntimeSHA256 || withArtifacts.FileCount != first.FileCount {
		t.Fatal("transient build state and generated paths must not change the tree identity")
	}
}

func TestDigestV2RejectsNonCanonicalObjects(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fifo creation is POSIX-only")
	}
	policyPath := writeTestPolicy(t)
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	root := baseTree(t)
	fifo := filepath.Join(root, "crates", "a", "src", "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if _, err := digestRuntimeV2(root, &policy); err == nil {
		t.Fatal("a fifo inside the canonical tree must fail enumeration, not silently skip")
	}
}

func TestDiffTreesV2ClassifiesEveryObjectKind(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	policyPath := writeTestPolicy(t)
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	source := writeTree(t, map[string]string{
		"Cargo.toml":          "[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs": "pub fn a() {}\n",
		"gone.rs":             "gone\n",
	})
	vendored := writeTree(t, map[string]string{
		"Cargo.toml":          "[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs": "pub fn a() { let _ = 1; }\n",
	})
	if err := os.Symlink("target-a", filepath.Join(source, "retargeted")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target-b", filepath.Join(vendored, "retargeted")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dangling", filepath.Join(source, "removed-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("fresh", filepath.Join(vendored, "added-link")); err != nil {
		t.Fatal(err)
	}
	// A file in the source that is a symlink in the runtime is a retype.
	if err := os.WriteFile(filepath.Join(source, "retyped"), []byte("file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("now-a-link", filepath.Join(vendored, "retyped")); err != nil {
		t.Fatal(err)
	}
	// Same content, different mode: a mode change, not a modification.
	if err := os.WriteFile(filepath.Join(source, "tool.sh"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendored, "tool.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	delta, err := diffTreesV2(source, vendored, &policy)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !slices.Equal(delta.ModifiedFiles, []string{"crates/a/src/lib.rs"}) {
		t.Fatalf("modified: %v", delta.ModifiedFiles)
	}
	if !slices.Equal(delta.AddedFiles, []string{"TRANSFER-PROVENANCE.md"}) && len(delta.AddedFiles) != 0 {
		// No provenance doc in this fixture: every added file must surface.
		for _, p := range delta.AddedFiles {
			if strings.Contains(p, "retargeted") {
				t.Fatalf("a symlink must not appear in added_files: %v", delta.AddedFiles)
			}
		}
	}
	if !slices.Equal(delta.RemovedFiles, []string{"gone.rs"}) {
		t.Fatalf("removed files: %v", delta.RemovedFiles)
	}
	if !slices.Equal(delta.AddedSymlinks, []string{"added-link"}) {
		t.Fatalf("added symlinks: %v", delta.AddedSymlinks)
	}
	if !slices.Equal(delta.RemovedSymlinks, []string{"removed-link"}) {
		t.Fatalf("removed symlinks: %v", delta.RemovedSymlinks)
	}
	if !slices.Equal(delta.RetargetedSymlinks, []string{"retargeted"}) {
		t.Fatalf("retargeted symlinks: %v", delta.RetargetedSymlinks)
	}
	if !slices.Equal(delta.RetypedPaths, []string{"retyped"}) {
		t.Fatalf("retyped paths: %v", delta.RetypedPaths)
	}
	if len(delta.ModeChanges) != 1 || delta.ModeChanges[0].Path != "tool.sh" ||
		delta.ModeChanges[0].From != "-" || delta.ModeChanges[0].To != "x" {
		t.Fatalf("mode changes: %+v", delta.ModeChanges)
	}
}

func TestManifestV2RejectsUnsupportedAndAmbiguousForms(t *testing.T) {
	root := baseTree(t)
	policyPath := writeTestPolicy(t)
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")

	// A future format is never reinterpreted.
	future := declarationFor(t, root)
	future.FormatVersion = 3
	writeManifestFile(t, path, future)
	if err := verifyManifest(path, false); err == nil || !strings.Contains(err.Error(), "provenance_format_version 3") {
		t.Fatalf("a future version must be rejected: %v", err)
	}

	// Format 2 without its policy binding is incomplete.
	loose := declaredManifestV2(t, root, policyPath, transferManifest{Delta: &typedDelta{}})
	loose.Policy = nil
	writeManifestFile(t, path, loose)
	if err := verifyManifest(path, false); err == nil || !strings.Contains(err.Error(), "no policy") {
		t.Fatalf("a v2 manifest must bind the policy: %v", err)
	}

	// Format 2 carrying the flat v1 delta fields is ambiguous.
	flat := declaredManifestV2(t, root, policyPath, transferManifest{Delta: &typedDelta{}})
	flat.LocalModifications = []string{"Cargo.toml"}
	writeManifestFile(t, path, flat)
	if err := verifyManifest(path, false); err == nil || !strings.Contains(err.Error(), "flat v1 delta") {
		t.Fatalf("flat fields in a v2 manifest must be rejected: %v", err)
	}

	// A swapped policy breaks the hash binding.
	bound := declaredManifestV2(t, root, policyPath, transferManifest{Delta: &typedDelta{}})
	bound.Policy = &policyRef{Path: bound.Policy.Path, SHA256: strings.Repeat("0", 64)}
	writeManifestFile(t, path, bound)
	if err := verifyManifest(path, false); err == nil || !strings.Contains(err.Error(), "enumeration rules") {
		t.Fatalf("a policy hash mismatch must fail closed: %v", err)
	}
}

func TestManifestV2RejectsGeneratedDeclarations(t *testing.T) {
	policyPath := writeTestPolicyWith(t, []string{"gen/out.py"})
	// The generated file exists on disk: enumeration must exclude it AND the
	// declaration must refuse to claim it — the exact way generated protobuf
	// bindings once rode into the source delta.
	root := writeTree(t, map[string]string{
		"Cargo.toml":          "[workspace.package]\nversion = \"1.2.3\"\n",
		"crates/a/src/lib.rs": "pub fn a() {}\n",
		"gen/out.py":          "# generated\n",
	})
	declared := declaredManifestV2(t, root, policyPath, transferManifest{
		Delta: &typedDelta{AddedFiles: []string{"gen/out.py"}},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declared)
	err := verifyManifest(path, false)
	if err == nil {
		t.Fatal("declaring a generated path as source must fail")
	}
	if !strings.Contains(err.Error(), "generated artifact") {
		t.Fatalf("error = %q, want the generated-path rejection named", err)
	}
}

func TestManifestV2RequireSourceFailsClosed(t *testing.T) {
	root := baseTree(t)
	policyPath := writeTestPolicy(t)
	missing := filepath.Join(t.TempDir(), "absent-source")
	declared := declaredManifestV2(t, root, policyPath, transferManifest{
		Source: &manifestSource{Path: missing, FileCount: 3, SHA256: strings.Repeat("0", 64)},
		Delta:  &typedDelta{},
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")

	// Standalone shipping-tree verification may report and continue.
	writeManifestFile(t, path, declared)
	if err := verifyManifest(path, false); err != nil {
		t.Fatalf("informational verification may proceed without the source: %v", err)
	}

	// The flag is official transfer-provenance qualification: fail closed.
	if err := verifyManifest(path, true); err == nil || !strings.Contains(err.Error(), "requires it") {
		t.Fatalf("-require-source must fail when the source is absent: %v", err)
	}

	// The manifest can demand the same strictness on its own.
	declared.Source.Required = true
	writeManifestFile(t, path, declared)
	if err := verifyManifest(path, false); err == nil || !strings.Contains(err.Error(), "requires it") {
		t.Fatalf("source.required must fail when the source is absent: %v", err)
	}
}

func TestManifestV2VerifyTransferIsExhaustiveForSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	policyPath := writeTestPolicy(t)
	source, vendored := transferredPair(t)
	if err := os.MkdirAll(filepath.Join(vendored, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target-a", filepath.Join(source, "docs", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target-b", filepath.Join(vendored, "docs", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("fresh", filepath.Join(vendored, "docs", "new-link")); err != nil {
		t.Fatal(err)
	}
	declared := declarationForPairV2(t, source, vendored, policyPath, typedDelta{
		ModifiedFiles: []string{"crates/a/src/lib.rs"},
		AddedFiles:    []string{"TRANSFER-PROVENANCE.md", "bridges/x/src/lib.rs"},
		RemovedFiles:  []string{"docs/old.md"},
		// The symlink classes deliberately left undeclared.
	})
	path := filepath.Join(t.TempDir(), "nemo-transfer-manifest.json")
	writeManifestFile(t, path, declared)
	err := verifyManifest(path, false)
	if err == nil {
		t.Fatal("undeclared symlink changes must fail verification")
	}
	if !strings.Contains(err.Error(), "undeclared added symlink: docs/new-link") {
		t.Fatalf("error = %q, want the added link named", err)
	}
	if !strings.Contains(err.Error(), "undeclared retargeted symlink: docs/link") {
		t.Fatalf("error = %q, want the retargeted link named", err)
	}

	// Declare the full symlink delta: verification passes.
	declared.Delta.AddedSymlinks = []string{"docs/new-link"}
	declared.Delta.RetargetedSymlinks = []string{"docs/link"}
	writeManifestFile(t, path, declaredManifestV2(t, vendored, policyPath, declared))
	if err := verifyManifest(path, false); err != nil {
		t.Fatalf("the complete symlink declaration must verify: %v", err)
	}
}

func TestGeneratedPathMatching(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"gen/", "gen/out.py", true},
		{"gen/", "gen/sub/deep.py", true},
		{"gen/", "generation/out.py", false},
		{"crates/node/*.node", "crates/node/x.node", true},
		{"crates/node/*.node", "crates/node/sub/x.node", false},
		{"examples/**/relay-plugin.local.toml", "examples/a/b/relay-plugin.local.toml", true},
		{"examples/**/relay-plugin.local.toml", "examples/relay-plugin.local.toml", true},
		{"out.py", "out.py", true},
		{"out.py", "sub/out.py", false},
		{"**/pb2.py", "a/b/pb2.py", true},
	}
	for _, c := range cases {
		if got := generatedMatch(c.pattern, c.path); got != c.want {
			t.Errorf("generatedMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// The format-2 golden vector: a fixed fixture tree must digest to exactly
// this value — the same bytes the Python reference implementation produces
// record-for-record. A format regression changes the value; an intentional
// format change regenerates the fixture deliberately.
func TestDigestV2GoldenFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	policyPath := writeTestPolicy(t)
	policy, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	root := writeTree(t, map[string]string{
		"Cargo.toml":          "[workspace.package]\nversion = \"9.9.9\"\n",
		"crates/a/src/lib.rs": "pub fn a() {}\n",
		"tool.sh":             "#!/bin/sh\ntrue\n",
	})
	if err := os.Chmod(filepath.Join(root, "tool.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("crates/a/src/lib.rs", filepath.Join(root, "LINK")); err != nil {
		t.Fatal(err)
	}
	identity, err := digestRuntimeV2(root, &policy)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	// FILE records for Cargo.toml / lib.rs / tool.sh (x) plus SYMLINK LINK,
	// byte-sorted: the stream any conforming implementation must emit.
	const want = "9cc44e1e276860ac273a2a0516223d7ad4ce90eacbe8e28cc2d2dd5a6b1b98b2"
	if identity.NemoRuntimeSHA256 != want {
		t.Fatalf("golden digest drifted: got %s, want %s", identity.NemoRuntimeSHA256, want)
	}
	if identity.FileCount != 3 || identity.SymlinkCount != 1 {
		t.Fatalf("counts: got %d files %d links", identity.FileCount, identity.SymlinkCount)
	}
}
