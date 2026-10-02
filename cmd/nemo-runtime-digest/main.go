// Command nemo-runtime-digest prints the identity of the NeMo Relay runtime a
// release carries.
//
// The release evidence chain already binds the Crabedence source revision and
// the capability policy:
//
//	source commit → release → registry digest → runtime → effect receipt
//
// This tool adds the other half of the distribution. A release ships two
// runtimes, and the source commit identifies only one of them:
//
//	source commit → release → {registry digest, NeMo Relay runtime digest}
//
// The digest is computed over the vendored tree's source files, sorted by
// path, so it changes when the runtime changes and does not change when a
// build artifact or a working-copy detail does. It is a regular-file
// identity: only `find -type f` entries are hashed, so symlinks and other
// non-regular entries — the tree carries a few, like the per-crate LICENSE
// links — are not part of the digest. Their presence in a shipped root is
// covered separately: the component manifest's exhaustive check refuses a
// distribution carrying anything undeclared. `-envelope` prints the digest
// with the exact inputs it covers, in the same idiom as the registry
// envelope: a consumer verifies what it was given rather than reproducing
// the computation.
//
// Recompute by hand (the same definition, shell-only):
//
//	cd runtimes/nemo-relay
//	find . -type f -not -path './target/*' -print0 \
//	  | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// defaultRoot is the vendored NeMo Relay runtime, relative to the repository.
const defaultRoot = "runtimes/nemo-relay"

// excluded are directories that are build output or working-copy state rather
// than source: a digest that moved when someone ran `cargo build` would bind
// nothing.
var excluded = map[string]bool{
	"target":       true,
	".git":         true,
	"node_modules": true,
	".venv":        true,
	".uv-cache":    true,
	"__pycache__":  true,
}

// envelope is the verifiable runtime identity export.
type envelope struct {
	// NemoRuntimeSHA256 is the SHA-256 of the sorted file records.
	NemoRuntimeSHA256 string `json:"nemo_runtime_sha256"`
	// RuntimeVersion is the workspace version the tree declares.
	RuntimeVersion string `json:"runtime_version"`
	// Tree is the path the digest covers, relative to the repository.
	Tree string `json:"tree"`
	// FileCount is how many source files the digest covers.
	FileCount int `json:"file_count"`
	// Excluded names the directories the digest deliberately does not cover.
	Excluded []string `json:"excluded"`
}

func main() {
	envelopeOnly := flag.Bool("envelope", false, "print the verifiable runtime identity envelope instead of the bare digest")
	root := flag.String("root", defaultRoot, "the vendored runtime tree to digest")
	manifestPath := flag.String("manifest", "", "verify the transfer manifest at this path; with -update, rewrite its computed fields (the manifest declares the tree to digest, relative to the repository root)")
	update := flag.Bool("update", false, "rewrite the manifest's computed fields instead of verifying them")
	flag.Parse()

	if *manifestPath != "" {
		var err error
		if *update {
			err = updateManifest(*manifestPath)
		} else {
			err = verifyManifest(*manifestPath)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "nemo-runtime-digest: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *update {
		fmt.Fprintln(os.Stderr, "nemo-runtime-digest: -update requires -manifest")
		os.Exit(2)
	}

	identity, err := digestRuntime(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nemo-runtime-digest: %v\n", err)
		os.Exit(1)
	}

	if *envelopeOnly {
		encoded, err := json.MarshalIndent(identity, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "nemo-runtime-digest: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(encoded))
		return
	}
	fmt.Println(identity.NemoRuntimeSHA256)
}

func digestRuntime(root string) (envelope, error) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return envelope{}, fmt.Errorf("the NeMo Relay runtime tree is missing at %s", root)
	}

	paths, err := sourceFiles(root)
	if err != nil {
		return envelope{}, err
	}
	if len(paths) == 0 {
		return envelope{}, fmt.Errorf("the NeMo Relay runtime tree at %s contains no source files", root)
	}

	// The records are hashed in path order, and the path is part of the record,
	// so a renamed file changes the digest even when its contents do not.
	sort.Strings(paths)
	outer := sha256.New()
	for _, path := range paths {
		sum, err := fileDigest(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, "./"))))
		if err != nil {
			return envelope{}, err
		}
		fmt.Fprintf(outer, "%s  %s\n", sum, path)
	}

	version, err := workspaceVersion(root)
	if err != nil {
		return envelope{}, err
	}

	excludedNames := make([]string, 0, len(excluded))
	for name := range excluded {
		excludedNames = append(excludedNames, name)
	}
	sort.Strings(excludedNames)

	return envelope{
		NemoRuntimeSHA256: hex.EncodeToString(outer.Sum(nil)),
		RuntimeVersion:    version,
		Tree:              root,
		FileCount:         len(paths),
		Excluded:          excludedNames,
	}, nil
}

// sourceFiles returns the tree's files as `./`-prefixed slash paths, matching
// the `find .` spelling the documented shell equivalent produces.
func sourceFiles(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && excluded[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, "./"+filepath.ToSlash(relative))
		return nil
	})
	return paths, err
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// transferManifest is the declared identity of the vendored runtime transfer.
//
// It lives outside the tree it covers (runtimes/nemo-transfer-manifest.json):
// a declaration inside the tree would be part of the digest it declares, and a
// digest of content that contains the digest can never be self-consistent. The
// computed fields are checked against the tree; the inventory fields are
// checked structurally — every declared path exists and every declared
// workspace member is a member — and, when the source copy is present,
// exhaustively: the declared delta must equal the actual one.
type transferManifest struct {
	// Tree is the vendored runtime tree, relative to the repository root.
	Tree string `json:"tree"`
	// RuntimeVersion is the workspace version the tree declares.
	RuntimeVersion string `json:"runtime_version"`
	// ShippedTreeSHA256 is the identity of the shipped tree.
	ShippedTreeSHA256 string `json:"shipped_tree_sha256"`
	// FileCount is how many source files the digest covers.
	FileCount int `json:"file_count"`
	// Excluded names the directories the digest deliberately does not cover.
	Excluded []string `json:"excluded"`
	// Source is the development fork the tree was copied from, when declared.
	Source *manifestSource `json:"source,omitempty"`
	// WorkspaceMembersAdded lists the workspace members the transfer adds.
	WorkspaceMembersAdded []string `json:"workspace_members_added,omitempty"`
	// LocalModifications lists the upstream files the transfer modifies.
	LocalModifications []string `json:"local_modifications,omitempty"`
	// AddedPaths lists the paths that exist only in the vendored tree. An
	// entry may name a file or a directory prefix (trailing slash) that
	// covers an entire added subtree.
	AddedPaths []string `json:"added_paths,omitempty"`
	// RemovedPaths lists the upstream paths the vendored tree deletes. Absent
	// means none — an undeclared deletion fails verification.
	RemovedPaths []string `json:"removed_paths,omitempty"`
	// Binaries lists the executables the vendored tree must produce, with the
	// source each is built from. A declared binary whose source is absent is
	// exactly the defect this inventory exists to catch.
	Binaries []manifestBinary `json:"binaries,omitempty"`
}

// manifestBinary is one executable the transfer declares.
type manifestBinary struct {
	// Role is what the binary is for: runtime, plugin-host, or qualification.
	Role string `json:"role"`
	// Package is the Cargo package that declares the binary.
	Package string `json:"package"`
	// Binary is the binary's name.
	Binary string `json:"binary"`
	// Source is the entry-point source file, relative to the tree.
	Source string `json:"source"`
	// Features are the package features the binary requires, if any.
	Features []string `json:"features,omitempty"`
}

// manifestSource is the declared identity of the source copy.
type manifestSource struct {
	// Path is the source tree, relative to the repository root.
	Path string `json:"path"`
	// FileCount is how many files the source tree had when it was copied.
	FileCount int `json:"file_count"`
	// SHA256 is the source tree's identity, under the same definition.
	SHA256 string `json:"sha256"`
}

func readManifest(path string) (transferManifest, error) {
	var manifest transferManifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return manifest, fmt.Errorf("%s is not a valid transfer manifest: %w", path, err)
	}
	return manifest, nil
}

// verifyManifest checks the declared identity against the tree it describes.
// The source tree is only recomputed when it is present: a standalone checkout
// of this repository does not carry it, and that absence is reported rather
// than silently skipped.
func verifyManifest(path string) error {
	manifest, err := readManifest(path)
	if err != nil {
		return err
	}
	if manifest.Tree == "" {
		return fmt.Errorf("%s declares no tree", path)
	}
	identity, err := digestRuntime(manifest.Tree)
	if err != nil {
		return err
	}

	var mismatches []string
	if manifest.RuntimeVersion != identity.RuntimeVersion {
		mismatches = append(mismatches, fmt.Sprintf("runtime_version: declared %q, computed %q", manifest.RuntimeVersion, identity.RuntimeVersion))
	}
	if manifest.ShippedTreeSHA256 != identity.NemoRuntimeSHA256 {
		mismatches = append(mismatches, fmt.Sprintf("shipped_tree_sha256: declared %s, computed %s", manifest.ShippedTreeSHA256, identity.NemoRuntimeSHA256))
	}
	if manifest.FileCount != identity.FileCount {
		mismatches = append(mismatches, fmt.Sprintf("file_count: declared %d, computed %d", manifest.FileCount, identity.FileCount))
	}
	if !slices.Equal(manifest.Excluded, identity.Excluded) {
		mismatches = append(mismatches, fmt.Sprintf("excluded: declared %v, computed %v", manifest.Excluded, identity.Excluded))
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%s does not match %s:\n  %s\nregenerate with: go run ./cmd/nemo-runtime-digest -manifest %s -update",
			manifest.Tree, path, strings.Join(mismatches, "\n  "), path)
	}
	fmt.Printf("ok: %s %s (%d files, %s)\n", identity.Tree, identity.NemoRuntimeSHA256, identity.FileCount, identity.RuntimeVersion)

	if err := verifyInventory(path, manifest); err != nil {
		return err
	}
	fmt.Printf("ok: inventory %d workspace members, %d modifications, %d added paths\n",
		len(manifest.WorkspaceMembersAdded), len(manifest.LocalModifications), len(manifest.AddedPaths))

	if err := verifyBinaries(path, manifest); err != nil {
		return err
	}
	if len(manifest.Binaries) > 0 {
		fmt.Printf("ok: %d declared binaries have sources and declarations\n", len(manifest.Binaries))
	}

	// The provenance record's generated blocks are the manifest rendered
	// for a human reader: they must say exactly what the manifest declares,
	// computed or not. A stale block is drift, and drift fails here so CI
	// catches a declaration that was edited without regenerating the doc.
	if err := syncProvenanceDoc(manifest.Tree, manifest, false); err != nil {
		return err
	}
	fmt.Printf("ok: %s's generated blocks match the manifest\n", provenanceDocName)

	if manifest.Source == nil {
		return nil
	}
	if _, err := os.Stat(manifest.Source.Path); err != nil {
		fmt.Fprintf(os.Stderr, "note: source tree %s is not present; the declared source identity was not recomputed\n", manifest.Source.Path)
		return nil
	}
	source, err := digestRuntime(manifest.Source.Path)
	if err != nil {
		return fmt.Errorf("source tree %s: %w", manifest.Source.Path, err)
	}
	if source.NemoRuntimeSHA256 != manifest.Source.SHA256 || source.FileCount != manifest.Source.FileCount {
		return fmt.Errorf("source tree %s does not match its declared identity: declared %s (%d files), computed %s (%d files)\nregenerate with: go run ./cmd/nemo-runtime-digest -manifest %s -update",
			manifest.Source.Path, manifest.Source.SHA256, manifest.Source.FileCount,
			source.NemoRuntimeSHA256, source.FileCount, path)
	}
	fmt.Printf("ok: source %s %s (%d files)\n", source.Tree, source.NemoRuntimeSHA256, source.FileCount)

	// The inventory claims are not advisory: the difference between the two
	// trees must equal the declared patch set exactly. An undeclared
	// modification, addition, or removal means the human-auditable delta this
	// transfer exists to record is incomplete.
	delta, err := verifyDelta(manifest)
	if err != nil {
		return err
	}
	fmt.Printf("ok: delta %d modifications, %d added, %d removed — all declared\n",
		len(delta.modified), len(delta.added), len(delta.removed))
	return nil
}

// verifyInventory checks the manifest's structural claims against the tree:
// every declared workspace member is in the vendored Cargo.toml's members
// list, and every declared modified or added path exists. The digest covers
// the bytes; this covers the claims the digest cannot express.
func verifyInventory(manifestPath string, manifest transferManifest) error {
	if len(manifest.WorkspaceMembersAdded) > 0 {
		members, err := declaredWorkspaceMembers(manifest.Tree)
		if err != nil {
			return err
		}
		for _, added := range manifest.WorkspaceMembersAdded {
			if !slices.Contains(members, added) {
				return fmt.Errorf("%s declares workspace member %q, but %s/Cargo.toml does not list it",
					manifestPath, added, manifest.Tree)
			}
		}
	}
	for _, path := range slices.Concat(manifest.LocalModifications, manifest.AddedPaths) {
		if _, err := os.Stat(filepath.Join(manifest.Tree, path)); err != nil {
			return fmt.Errorf("%s declares %q, but %s/%s does not exist",
				manifestPath, path, manifest.Tree, strings.TrimSuffix(path, "/"))
		}
	}
	return nil
}

// verifyBinaries checks every declared binary against the tree: the source
// exists, the package it belongs to declares it (an explicit `[[bin]]` entry
// or an auto-discovered `src/bin/<name>.rs`), a declared `[[bin]]` path is the
// source the manifest names, and every declared feature exists. A manifest
// that declares a binary the tree cannot build is a release defect, not a
// documentation nit.
func verifyBinaries(manifestPath string, manifest transferManifest) error {
	root := filepath.Clean(manifest.Tree)
	for _, binary := range manifest.Binaries {
		source := filepath.Join(manifest.Tree, binary.Source)
		if !strings.HasPrefix(filepath.Clean(source), root+string(filepath.Separator)) {
			return fmt.Errorf("%s declares %s with a source outside the tree: %s", manifestPath, binary.Binary, binary.Source)
		}
		if info, err := os.Stat(source); err != nil || info.IsDir() {
			return fmt.Errorf("%s declares the %s binary at %s, but the source does not exist — a declared binary with no source is a release defect",
				manifestPath, binary.Binary, binary.Source)
		}

		packageManifest, packageDir, err := packageManifestFor(root, source)
		if err != nil {
			return fmt.Errorf("%s declares the %s binary in package %s, but no package manifest declares it: %w",
				manifestPath, binary.Binary, binary.Package, err)
		}
		raw, err := os.ReadFile(packageManifest)
		if err != nil {
			return err
		}
		text := string(raw)
		if name := packageName(text); name != binary.Package {
			return fmt.Errorf("%s declares the %s binary in package %q, but %s declares package %q",
				manifestPath, binary.Binary, binary.Package, packageManifest, name)
		}

		declaredPath, declared := declaredBinaryPath(text, binary.Binary)
		if !declared {
			// Cargo also auto-discovers src/bin/<name>.rs.
			auto := filepath.Join(packageDir, "src", "bin", binary.Binary+".rs")
			if info, err := os.Stat(auto); err != nil || info.IsDir() {
				return fmt.Errorf("%s declares the %s binary, but %s neither declares a [[bin]] entry for it nor provides %s",
					manifestPath, binary.Binary, packageManifest, auto)
			}
			continue
		}
		if declaredPath != "" {
			packageRelative, err := filepath.Rel(packageDir, source)
			if err != nil {
				return err
			}
			if filepath.ToSlash(packageRelative) != declaredPath {
				return fmt.Errorf("%s declares the %s binary at %s, but %s declares its path as %q",
					manifestPath, binary.Binary, binary.Source, packageManifest, declaredPath)
			}
		}
		for _, feature := range binary.Features {
			if !packageDeclaresFeature(text, feature) {
				return fmt.Errorf("%s declares the %s binary with feature %q, but %s declares no such feature",
					manifestPath, binary.Binary, feature, packageManifest)
			}
		}
	}
	return nil
}

// packageManifestFor walks up from a source file to the Cargo.toml of the
// package that contains it.
func packageManifestFor(root, source string) (string, string, error) {
	dir := filepath.Dir(filepath.Clean(source))
	for {
		candidate := filepath.Join(dir, "Cargo.toml")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, dir, nil
		}
		if dir == root {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(dir, root+string(filepath.Separator)) {
			break
		}
		dir = parent
	}
	return "", "", fmt.Errorf("no Cargo.toml found above %s", source)
}

// packageName extracts the `name` of a Cargo.toml's [package] section.
func packageName(manifest string) string {
	inPackage := false
	for _, line := range strings.Split(manifest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inPackage = trimmed == "[package]"
			continue
		}
		if !inPackage {
			continue
		}
		if value, ok := strings.CutPrefix(trimmed, "name"); ok {
			value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "="))
			return strings.Trim(value, `"`)
		}
	}
	return ""
}

// declaredBinaryPath returns the package-relative path a Cargo.toml declares
// for a [[bin]] with the given name, and whether it declares one at all.
func declaredBinaryPath(manifest, binary string) (string, bool) {
	section := ""
	var block []string
	declaredPath, declared := "", false
	flush := func() {
		if section != "[[bin]]" {
			return
		}
		name, path := "", ""
		for _, line := range block {
			trimmed := strings.TrimSpace(line)
			if value, ok := strings.CutPrefix(trimmed, "name"); ok {
				name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "=")), `"`)
			}
			if value, ok := strings.CutPrefix(trimmed, "path"); ok {
				path = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "=")), `"`)
			}
		}
		if name == binary {
			declared = true
			declaredPath = path
		}
	}
	for _, line := range strings.Split(manifest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			flush()
			section = trimmed
			block = nil
			continue
		}
		block = append(block, line)
	}
	flush()
	return declaredPath, declared
}

// packageDeclaresFeature reports whether a Cargo.toml's [features] section
// declares the feature.
func packageDeclaresFeature(manifest, feature string) bool {
	inFeatures := false
	for _, line := range strings.Split(manifest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inFeatures = trimmed == "[features]"
			continue
		}
		if !inFeatures || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if name, _, found := strings.Cut(trimmed, "="); found && strings.TrimSpace(name) == feature {
			return true
		}
	}
	return false
}

// membersArray matches the workspace manifest's `members = [...]` array,
// anchored to the start of a line so `default-members` cannot be mistaken
// for it.
var membersArray = regexp.MustCompile(`(?m)^members\s*=\s*\[([^\]]*)\]`)

// quotedEntry matches one quoted string inside the members array.
var quotedEntry = regexp.MustCompile(`"([^"]+)"`)

// declaredWorkspaceMembers extracts the quoted entries of the workspace
// `members` array from the vendored Cargo.toml.
func declaredWorkspaceMembers(tree string) ([]string, error) {
	manifest, err := os.ReadFile(filepath.Join(tree, "Cargo.toml"))
	if err != nil {
		return nil, err
	}
	block := membersArray.FindSubmatch(manifest)
	if block == nil {
		return nil, fmt.Errorf("%s/Cargo.toml declares no members array", tree)
	}
	var members []string
	for _, match := range quotedEntry.FindAllSubmatch(block[1], -1) {
		members = append(members, string(match[1]))
	}
	return members, nil
}

// treeDelta is the complete difference between the source copy and the
// vendored tree: which paths carry different content, which exist only in
// the vendored tree, and which only the source still has.
type treeDelta struct {
	modified []string
	added    []string
	removed  []string
}

// treeEntries maps every non-directory entry under root to a content
// identity: the file digest for regular files, the link target for symlinks,
// and the node type for anything else. The tree carries symlinks the file
// digest never sees — a retargeted link must still surface in the delta, so
// this walk is broader than sourceFiles on purpose.
func treeEntries(root string) (map[string]string, error) {
	entries := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && excluded[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		switch typ := entry.Type(); {
		case typ.IsRegular():
			sum, err := fileDigest(path)
			if err != nil {
				return err
			}
			entries[key] = "file:" + sum
		case typ&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			entries[key] = "symlink:" + target
		default:
			entries[key] = "other:" + typ.String()
		}
		return nil
	})
	return entries, err
}

// diffTrees computes the treeDelta between the source copy and the vendored
// tree, applying the same exclusion set to both.
func diffTrees(source, vendored string) (treeDelta, error) {
	src, err := treeEntries(source)
	if err != nil {
		return treeDelta{}, fmt.Errorf("reading the source tree: %w", err)
	}
	vend, err := treeEntries(vendored)
	if err != nil {
		return treeDelta{}, fmt.Errorf("reading the vendored tree: %w", err)
	}
	var delta treeDelta
	for path, sourceID := range src {
		vendoredID, ok := vend[path]
		if !ok {
			delta.removed = append(delta.removed, path)
			continue
		}
		if vendoredID != sourceID {
			delta.modified = append(delta.modified, path)
		}
	}
	for path := range vend {
		if _, ok := src[path]; !ok {
			delta.added = append(delta.added, path)
		}
	}
	sort.Strings(delta.modified)
	sort.Strings(delta.added)
	sort.Strings(delta.removed)
	return delta, nil
}

// addedPathCovers reports whether a declared added_paths entry covers an
// actual added path: an exact match, or a directory prefix covering a whole
// added subtree.
func addedPathCovers(declared, actual string) bool {
	if strings.HasSuffix(declared, "/") {
		return strings.HasPrefix(actual, declared)
	}
	return actual == declared
}

// verifyDelta checks that the declared inventory is the complete difference
// between the source copy and the vendored tree — not merely that the
// declared paths exist. The digest proves what the tree is; this proves the
// human-auditable delta is all of it.
func verifyDelta(manifest transferManifest) (treeDelta, error) {
	delta, err := diffTrees(manifest.Source.Path, manifest.Tree)
	if err != nil {
		return treeDelta{}, err
	}

	var problems []string
	declaredModifications := slices.Clone(manifest.LocalModifications)
	sort.Strings(declaredModifications)
	for _, path := range delta.modified {
		if !slices.Contains(declaredModifications, path) {
			problems = append(problems, fmt.Sprintf("undeclared modification: %s", path))
		}
	}
	for _, path := range declaredModifications {
		if !slices.Contains(delta.modified, path) {
			problems = append(problems, fmt.Sprintf("declared modification %s is identical to the source (stale declaration)", path))
		}
	}
	for _, path := range delta.added {
		covered := false
		for _, declared := range manifest.AddedPaths {
			if addedPathCovers(declared, path) {
				covered = true
				break
			}
		}
		if !covered {
			problems = append(problems, fmt.Sprintf("undeclared addition: %s", path))
		}
	}
	for _, declared := range manifest.AddedPaths {
		covers := false
		for _, path := range delta.added {
			if addedPathCovers(declared, path) {
				covers = true
				break
			}
		}
		if !covers {
			problems = append(problems, fmt.Sprintf("declared added path %s covers no actual addition (stale declaration)", declared))
		}
	}
	declaredRemoved := slices.Clone(manifest.RemovedPaths)
	sort.Strings(declaredRemoved)
	for _, path := range delta.removed {
		if !slices.Contains(declaredRemoved, path) {
			problems = append(problems, fmt.Sprintf("undeclared removal: %s", path))
		}
	}
	for _, path := range declaredRemoved {
		if !slices.Contains(delta.removed, path) {
			problems = append(problems, fmt.Sprintf("declared removed path %s still exists in the source (stale declaration)", path))
		}
	}
	if len(problems) > 0 {
		return delta, fmt.Errorf("the declared transfer delta is not the actual delta between %s and %s:\n  %s\nregenerate with: go run ./cmd/nemo-runtime-digest -manifest <manifest> -update",
			manifest.Source.Path, manifest.Tree, strings.Join(problems, "\n  "))
	}
	return delta, nil
}

// provenanceDocName is the in-tree transfer record carrying the generated
// delta block.
const provenanceDocName = "TRANSFER-PROVENANCE.md"

// The generated blocks' markers. Everything between a marker pair is
// produced by -update from the manifest's declarations and checked by
// verify — a doc and a manifest that disagree about the delta or the
// declared source identity is the drift these blocks exist to catch.
const (
	deltaBlockBegin = "<!-- BEGIN GENERATED TRANSFER DELTA — regenerated by `nemo-runtime-digest -update`; do not edit by hand -->"
	deltaBlockEnd   = "<!-- END GENERATED TRANSFER DELTA -->"

	sourceBlockBegin = "<!-- BEGIN GENERATED SOURCE IDENTITY — regenerated by `nemo-runtime-digest -update`; do not edit by hand -->"
	sourceBlockEnd   = "<!-- END GENERATED SOURCE IDENTITY -->"
)

// renderDeltaBlock renders the manifest's declared delta as the canonical
// generated block: every modified, added, and removed path, in order.
func renderDeltaBlock(manifest transferManifest) string {
	var block strings.Builder
	block.WriteString(deltaBlockBegin + "\n\n")
	block.WriteString("| Kind | Path |\n| --- | --- |\n")
	write := func(kind string, paths []string) {
		if len(paths) == 0 {
			block.WriteString("| " + kind + " | — |\n")
			return
		}
		for _, path := range paths {
			block.WriteString("| " + kind + " | `" + path + "` |\n")
		}
	}
	write("modified", manifest.LocalModifications)
	write("added", manifest.AddedPaths)
	write("removed", manifest.RemovedPaths)
	block.WriteString("\n" + deltaBlockEnd)
	return block.String()
}

// renderSourceBlock renders the manifest's declared source identity — the
// file count and digest of the tree the vendored copy was taken from. Like
// the delta block it renders the declaration: whether the declared identity
// still matches the source tree on disk is the source recompute's job.
func renderSourceBlock(source manifestSource) string {
	var block strings.Builder
	block.WriteString(sourceBlockBegin + "\n\n")
	fmt.Fprintf(&block, "%d files. Digest over the sorted `sha256(path, content)` records of the\nsource tree as it was copied, before any local modification:\n\n", source.FileCount)
	block.WriteString("```text\n" + source.SHA256 + "\n```\n\n")
	block.WriteString(sourceBlockEnd)
	return block.String()
}

// spliceGenerated replaces doc's marker-delimited block — markers included —
// with rendered. The block must exist exactly once: a record missing the
// markers cannot be checked at all, and a record carrying a duplicate pair
// hides a block the splice never reaches — both are drift in themselves.
func spliceGenerated(doc, begin, end, rendered, name, docPath string) (string, error) {
	if strings.Count(doc, begin) > 1 || strings.Count(doc, end) > 1 {
		return "", fmt.Errorf("%s carries duplicate %s markers — run `nemo-runtime-digest -update` after removing the copy", docPath, name)
	}
	beginIdx := strings.Index(doc, begin)
	endIdx := strings.Index(doc, end)
	if beginIdx < 0 || endIdx < 0 || beginIdx > endIdx {
		return "", fmt.Errorf("%s carries no generated %s — run `nemo-runtime-digest -update` to regenerate it", docPath, name)
	}
	return doc[:beginIdx] + rendered + doc[endIdx+len(end):], nil
}

// syncProvenanceDoc reconciles the generated blocks inside
// TRANSFER-PROVENANCE.md with the manifest: the transfer delta, and the
// source identity when the manifest declares one. With write=false it
// reports drift as an error; with write=true it rewrites the file. A doc
// without the markers is drift in itself — the blocks must exist.
func syncProvenanceDoc(tree string, manifest transferManifest, write bool) error {
	docPath := filepath.Join(tree, provenanceDocName)
	raw, err := os.ReadFile(docPath)
	if err != nil {
		return fmt.Errorf("the provenance record %s: %w", docPath, err)
	}
	doc := string(raw)

	var stale []string
	reconciled, err := spliceGenerated(doc, deltaBlockBegin, deltaBlockEnd, renderDeltaBlock(manifest), "delta block", docPath)
	if err != nil {
		return err
	}
	if reconciled != doc {
		stale = append(stale, "delta")
	}
	if manifest.Source != nil {
		spliced, err := spliceGenerated(reconciled, sourceBlockBegin, sourceBlockEnd, renderSourceBlock(*manifest.Source), "source-identity block", docPath)
		if err != nil {
			return err
		}
		if spliced != reconciled {
			stale = append(stale, "source-identity")
		}
		reconciled = spliced
	} else if strings.Contains(reconciled, sourceBlockBegin) {
		return fmt.Errorf("%s carries a generated source-identity block, but the manifest declares no source — the record and the declaration disagree", docPath)
	}
	if len(stale) == 0 {
		return nil
	}
	if !write {
		which := strings.Join(stale, " and ") + " block"
		if len(stale) > 1 {
			which += "s do"
		} else {
			which += " does"
		}
		return fmt.Errorf("%s is stale: its generated %s not match the manifest — regenerate with `nemo-runtime-digest -manifest %s -update`", docPath, which, "runtimes/nemo-transfer-manifest.json")
	}
	if err := os.WriteFile(docPath, []byte(reconciled), 0o644); err != nil {
		return err
	}
	return nil
}

// updateDeltaInventory rewrites the declared delta to the computed one.
// Declared added-path entries that still cover real additions survive — a
// directory prefix covering a whole added subtree expresses intent a flat
// file list cannot — and actual additions no declaration covers are added
// verbatim.
func updateDeltaInventory(manifest *transferManifest, delta treeDelta) {
	manifest.LocalModifications = delta.modified
	manifest.RemovedPaths = delta.removed
	kept := manifest.AddedPaths[:0]
	for _, declared := range manifest.AddedPaths {
		for _, path := range delta.added {
			if addedPathCovers(declared, path) {
				kept = append(kept, declared)
				break
			}
		}
	}
	for _, path := range delta.added {
		covered := false
		for _, declared := range kept {
			if addedPathCovers(declared, path) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, path)
		}
	}
	sort.Strings(kept)
	manifest.AddedPaths = kept
}

// updateManifest rewrites the manifest's computed fields from the tree,
// preserving the inventory fields a human maintains. A missing manifest is
// created with the computed fields alone.
func updateManifest(path string) error {
	manifest, err := readManifest(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		manifest = transferManifest{}
	}
	if manifest.Tree == "" {
		manifest.Tree = defaultRoot
	}
	if manifest.Source != nil {
		if _, err := os.Stat(manifest.Source.Path); err == nil {
			source, err := digestRuntime(manifest.Source.Path)
			if err != nil {
				return fmt.Errorf("source tree %s: %w", manifest.Source.Path, err)
			}
			manifest.Source.SHA256 = source.NemoRuntimeSHA256
			manifest.Source.FileCount = source.FileCount
			delta, err := diffTrees(manifest.Source.Path, manifest.Tree)
			if err != nil {
				return fmt.Errorf("computing the source delta: %w", err)
			}
			updateDeltaInventory(&manifest, delta)
		} else {
			fmt.Fprintf(os.Stderr, "note: source tree %s is not present; the declared delta inventory is preserved, not regenerated\n", manifest.Source.Path)
		}
	}
	// The provenance record is a file inside the tree it documents: sync its
	// generated delta block first, so the digest below covers the record as
	// it will ship — a digest taken before the doc would bind a stale one.
	if err := syncProvenanceDoc(manifest.Tree, manifest, true); err != nil {
		return fmt.Errorf("regenerating the provenance record: %w", err)
	}
	identity, err := digestRuntime(manifest.Tree)
	if err != nil {
		return err
	}
	manifest.RuntimeVersion = identity.RuntimeVersion
	manifest.ShippedTreeSHA256 = identity.NemoRuntimeSHA256
	manifest.FileCount = identity.FileCount
	manifest.Excluded = identity.Excluded
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("updated: %s — %s %s (%d files, %s)\n", path, identity.Tree, identity.NemoRuntimeSHA256, identity.FileCount, identity.RuntimeVersion)
	return nil
}

// workspaceVersion reads the version the vendored workspace declares, so the
// evidence names the runtime release as well as its digest.
func workspaceVersion(root string) (string, error) {
	manifest, err := os.ReadFile(filepath.Join(root, "Cargo.toml"))
	if err != nil {
		return "", err
	}
	inWorkspacePackage := false
	for _, line := range strings.Split(string(manifest), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inWorkspacePackage = trimmed == "[workspace.package]"
			continue
		}
		if !inWorkspacePackage {
			continue
		}
		if value, ok := strings.CutPrefix(trimmed, "version"); ok {
			value = strings.TrimSpace(value)
			value = strings.TrimSpace(strings.TrimPrefix(value, "="))
			return strings.Trim(value, `"`), nil
		}
	}
	return "", fmt.Errorf("the NeMo Relay workspace manifest at %s declares no version", root)
}
