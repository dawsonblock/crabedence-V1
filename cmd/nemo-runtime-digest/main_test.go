package main

import (
	"os"
	"path/filepath"
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
