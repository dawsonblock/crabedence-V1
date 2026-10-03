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
	// SymlinkCount is how many symlinks the digest covers (format 2+).
	SymlinkCount int `json:"symlink_count,omitempty"`
	// FormatVersion is the provenance format the digest was computed under.
	FormatVersion int `json:"format_version,omitempty"`
	// Excluded names the directories the digest deliberately does not cover.
	Excluded []string `json:"excluded"`
}

// provenancePolicy is the machine-readable canonical-tree model from
// runtimes/nemo-provenance-policy.json: which objects are source, which are
// generated, and the exact enumeration rules. The manifest binds the file by
// SHA-256 so the rules a digest was computed under cannot drift silently.
type provenancePolicy struct {
	Policy                  string `json:"policy"`
	PolicyVersion           int    `json:"policy_version"`
	ProvenanceFormatVersion int    `json:"provenance_format_version"`
	Enumeration             struct {
		ExcludedDirNames     []string `json:"excluded_dir_names"`
		ExcludedDirSuffixes  []string `json:"excluded_dir_suffixes"`
		ExcludedFileNames    []string `json:"excluded_file_names"`
		ExcludedFileSuffixes []string `json:"excluded_file_suffixes"`
		GeneratedPaths       []string `json:"generated_paths"`
	} `json:"enumeration"`
}

// excludedDirs is the directory-name pruning set under a policy.
func (p *provenancePolicy) excludedDirs() map[string]bool {
	set := map[string]bool{}
	for _, name := range p.Enumeration.ExcludedDirNames {
		set[name] = true
	}
	return set
}

// readPolicy loads the canonical-tree policy; a missing file fails closed —
// format 2 cannot be computed without its declared enumeration rules.
func readPolicy(path string) (provenancePolicy, error) {
	var policy provenancePolicy
	raw, err := os.ReadFile(path)
	if err != nil {
		return policy, fmt.Errorf("the provenance policy %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return policy, fmt.Errorf("%s is not a valid provenance policy: %w", path, err)
	}
	if policy.ProvenanceFormatVersion != formatVersion {
		return policy, fmt.Errorf("%s declares provenance_format_version %d; this tool implements %d", path, policy.ProvenanceFormatVersion, formatVersion)
	}
	return policy, nil
}

// policyDigest binds a policy file by content hash into the manifest.
func policyDigest(path string) (string, error) {
	sum, err := fileDigest(path)
	if err != nil {
		return "", fmt.Errorf("the provenance policy %s: %w", path, err)
	}
	return sum, nil
}

// matchGlob matches a slash-separated path against a provenance glob: '*'
// and '?' stay within one path element, '**' crosses elements. The pattern
// is anchored at the tree root unless it begins with '**/'.
func matchGlob(pattern, path string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchSegments(pattern, path []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			for i := 0; i <= len(path); i++ {
				if matchSegments(pattern[1:], path[i:]) {
					return true
				}
			}
			return false
		}
		if len(path) == 0 || !matchElement(pattern[0], path[0]) {
			return false
		}
		pattern, path = pattern[1:], path[1:]
	}
	return len(path) == 0
}

// matchElement is the classic single-segment wildcard match.
func matchElement(pattern, s string) bool {
	pb, sb, star, retry := 0, 0, -1, -1
	for sb < len(s) {
		if pb < len(pattern) && (pattern[pb] == '?' || pattern[pb] == s[sb]) {
			pb++
			sb++
			continue
		}
		if pb < len(pattern) && pattern[pb] == '*' {
			star, retry, pb = pb, sb, pb+1
			continue
		}
		if star >= 0 {
			pb, retry, sb = star+1, retry+1, retry
			continue
		}
		return false
	}
	for pb < len(pattern) && pattern[pb] == '*' {
		pb++
	}
	return pb == len(pattern)
}

// generatedMatch reports whether the tree-relative path hits a generated
// pattern: a trailing-slash pattern names a directory subtree; anything
// else must match the whole path. Directory subtrees prune the walk itself.
func generatedMatch(pattern, path string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	return matchGlob(pattern, path) || matchGlob(pattern+"/**", path)
}

func (p *provenancePolicy) isGenerated(path string) bool {
	for _, pattern := range p.Enumeration.GeneratedPaths {
		if generatedMatch(pattern, path) {
			return true
		}
	}
	return false
}

// pruneDir reports whether a directory drops out of canonical enumeration:
// a name in the exclusion set, an excluded suffix, or a generated subtree.
func (p *provenancePolicy) pruneDir(name, rel string) bool {
	if p.excludedDirs()[name] {
		return true
	}
	for _, suffix := range p.Enumeration.ExcludedDirSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	for _, pattern := range p.Enumeration.GeneratedPaths {
		if strings.HasSuffix(pattern, "/") && generatedMatch(pattern, rel) {
			return true
		}
	}
	return false
}

// skipFile reports whether a non-directory entry leaves canonical
// enumeration: an excluded name, an excluded suffix, or a generated path.
func (p *provenancePolicy) skipFile(name, rel string) bool {
	for _, excluded := range p.Enumeration.ExcludedFileNames {
		if name == excluded {
			return true
		}
	}
	for _, suffix := range p.Enumeration.ExcludedFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return p.isGenerated(rel)
}

// formatVersion is the provenance format this tool emits. Version 2 binds
// symlinks and executable bits into the canonical stream, enumerates by
// policy, and carries a typed transfer delta.
const formatVersion = 2

// canonicalEntry is one provenance-relevant filesystem object: a regular
// file or a symlink. Anything else is a malformed tree, not a silent skip.
type canonicalEntry struct {
	path   string // normalized "./"-prefixed slash path
	kind   string // "file" or "symlink"
	sha256 string // files only
	exec   bool   // files only
	target string // symlinks only
}

// record renders the entry's canonical-stream line — the exact bytes the
// tree digest is computed over. The format is fixed by the policy spec:
//
//	FILE<TAB>./path<TAB>sha256<TAB>x|-
//	SYMLINK<TAB>./path<TAB>target
func (e canonicalEntry) record() string {
	switch e.kind {
	case "file":
		exec := "-"
		if e.exec {
			exec = "x"
		}
		return "FILE\t" + e.path + "\t" + e.sha256 + "\t" + exec + "\n"
	case "symlink":
		return "SYMLINK\t" + e.path + "\t" + e.target + "\n"
	}
	return ""
}

// identity is the entry's identity for delta comparison: the content digest
// and mode for files, the target for symlinks. A changed identity is a
// declared difference, whichever class it lands in.
func (e canonicalEntry) identity() string {
	switch e.kind {
	case "file":
		exec := "-"
		if e.exec {
			exec = "x"
		}
		return "file:" + e.sha256 + ":" + exec
	case "symlink":
		return "symlink:" + e.target
	}
	return "other"
}

// canonicalEntries enumerates the tree under policy: regular files and
// symlinks, exclusions and generated paths pruned, in byte-wise path order.
// Any other object type fails the walk — a fifo or socket inside a source
// tree is a defect, not something the digest may skip.
func canonicalEntries(root string, policy *provenancePolicy) ([]canonicalEntry, error) {
	var entries []canonicalEntry
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if path != root && policy.pruneDir(entry.Name(), rel) {
				return fs.SkipDir
			}
			return nil
		}
		if policy.skipFile(entry.Name(), rel) {
			return nil
		}
		normalized := "./" + rel
		if seen[normalized] {
			return fmt.Errorf("duplicate canonical path %s", normalized)
		}
		seen[normalized] = true
		switch typ := entry.Type(); {
		case typ.IsRegular():
			sum, err := fileDigest(path)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			entries = append(entries, canonicalEntry{
				path:   normalized,
				kind:   "file",
				sha256: sum,
				exec:   info.Mode().Perm()&0o111 != 0,
			})
		case typ&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			entries = append(entries, canonicalEntry{path: normalized, kind: "symlink", target: target})
		default:
			return fmt.Errorf("%s is neither a regular file nor a symlink (mode %s): the canonical tree does not carry this object type", normalized, typ.String())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Byte-wise lexicographic path order — the canonical stream's only
	// ordering. WalkDir order is lexical already; sort defensively so the
	// invariant does not depend on traversal internals.
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return entries, nil
}

// digestRuntimeV2 computes the format-2 identity: the canonical record
// stream over files, symlinks, and executable bits.
func digestRuntimeV2(root string, policy *provenancePolicy) (envelope, error) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return envelope{}, fmt.Errorf("the NeMo Relay runtime tree is missing at %s", root)
	}
	entries, err := canonicalEntries(root, policy)
	if err != nil {
		return envelope{}, err
	}
	if len(entries) == 0 {
		return envelope{}, fmt.Errorf("the NeMo Relay runtime tree at %s contains no source files", root)
	}

	outer := sha256.New()
	files, links := 0, 0
	for _, entry := range entries {
		io.WriteString(outer, entry.record())
		if entry.kind == "symlink" {
			links++
		} else {
			files++
		}
	}
	if files == 0 {
		return envelope{}, fmt.Errorf("the NeMo Relay runtime tree at %s contains no source files", root)
	}

	version, err := workspaceVersion(root)
	if err != nil {
		return envelope{}, err
	}
	return envelope{
		NemoRuntimeSHA256: hex.EncodeToString(outer.Sum(nil)),
		RuntimeVersion:    version,
		Tree:              root,
		FileCount:         files,
		SymlinkCount:      links,
		FormatVersion:     formatVersion,
		Excluded:          append([]string(nil), policy.Enumeration.ExcludedDirNames...),
	}, nil
}

// defaultPolicy is the canonical-tree policy, relative to the repository.
const defaultPolicy = "runtimes/nemo-provenance-policy.json"

func main() {
	envelopeOnly := flag.Bool("envelope", false, "print the verifiable runtime identity envelope instead of the bare digest")
	root := flag.String("root", defaultRoot, "the vendored runtime tree to digest")
	policyPath := flag.String("policy", defaultPolicy, "the canonical-tree provenance policy (format 2)")
	manifestPath := flag.String("manifest", "", "verify the transfer manifest at this path; with -update, rewrite its computed fields (the manifest declares the tree to digest, relative to the repository root)")
	update := flag.Bool("update", false, "rewrite the manifest's computed fields instead of verifying them")
	requireSource := flag.Bool("require-source", false, "transfer-provenance qualification: the declared source tree must be present and verify — absence fails closed instead of reporting a note")
	list := flag.Bool("list", false, "print the policy-enumerated tree paths (one per line, relative to -root) instead of digesting; requires the format-2 policy")
	listZ := flag.Bool("z", false, "with -list, terminate each path with NUL instead of LF so names containing newlines survive verbatim")
	flag.Parse()

	if *list {
		policy, err := readPolicy(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nemo-runtime-digest: %v\n", err)
			os.Exit(1)
		}
		entries, err := canonicalEntries(*root, &policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nemo-runtime-digest: %v\n", err)
			os.Exit(1)
		}
		for _, entry := range entries {
			if *listZ {
				fmt.Printf("%s\x00", strings.TrimPrefix(entry.path, "./"))
			} else {
				fmt.Println(strings.TrimPrefix(entry.path, "./"))
			}
		}
		return
	}

	if *manifestPath != "" {
		var err error
		if *update {
			err = updateManifest(*manifestPath, *policyPath)
		} else {
			err = verifyManifest(*manifestPath, *requireSource)
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

	// The bare digest tracks the same definition the manifest verifies:
	// format 2 when the policy is present, the legacy regular-file digest
	// otherwise, so a tree without the policy still yields an identity.
	var identity envelope
	var err error
	if _, statErr := os.Stat(*policyPath); statErr == nil {
		policy, polErr := readPolicy(*policyPath)
		if polErr != nil {
			fmt.Fprintf(os.Stderr, "nemo-runtime-digest: %v\n", polErr)
			os.Exit(1)
		}
		identity, err = digestRuntimeV2(*root, &policy)
	} else {
		identity, err = digestRuntime(*root)
	}
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
	// FormatVersion selects the provenance format: absent or 1 is the
	// original regular-file manifest; 2 is the policy-driven canonical
	// stream with a typed delta. Any other value is rejected outright —
	// an older or newer manifest is never silently reinterpreted.
	FormatVersion int `json:"provenance_format_version,omitempty"`
	// Tree is the vendored runtime tree, relative to the repository root.
	Tree string `json:"tree"`
	// RuntimeVersion is the workspace version the tree declares.
	RuntimeVersion string `json:"runtime_version"`
	// ShippedTreeSHA256 is the identity of the shipped tree.
	ShippedTreeSHA256 string `json:"shipped_tree_sha256"`
	// FileCount is how many source files the digest covers.
	FileCount int `json:"file_count"`
	// SymlinkCount is how many symlinks the digest covers (format 2).
	SymlinkCount int `json:"symlink_count,omitempty"`
	// Excluded names the directories the digest deliberately does not cover.
	Excluded []string `json:"excluded,omitempty"`
	// Policy binds the canonical-tree policy the digest was computed under
	// (format 2): the file's path and its content hash.
	Policy *policyRef `json:"policy,omitempty"`
	// Source is the development fork the tree was copied from, when declared.
	Source *manifestSource `json:"source,omitempty"`
	// WorkspaceMembersAdded lists the workspace members the transfer adds.
	WorkspaceMembersAdded []string `json:"workspace_members_added,omitempty"`
	// LocalModifications lists the upstream files the transfer modifies
	// (format 1).
	LocalModifications []string `json:"local_modifications,omitempty"`
	// AddedPaths lists the paths that exist only in the vendored tree. An
	// entry may name a file or a directory prefix (trailing slash) that
	// covers an entire added subtree (format 1).
	AddedPaths []string `json:"added_paths,omitempty"`
	// RemovedPaths lists the upstream paths the vendored tree deletes. Absent
	// means none — an undeclared deletion fails verification (format 1).
	RemovedPaths []string `json:"removed_paths,omitempty"`
	// Delta is the typed, exhaustive transfer difference (format 2).
	Delta *typedDelta `json:"delta,omitempty"`
	// Binaries lists the executables the vendored tree must produce, with the
	// source each is built from. A declared binary whose source is absent is
	// exactly the defect this inventory exists to catch.
	Binaries []manifestBinary `json:"binaries,omitempty"`
}

// policyRef binds the provenance policy by path and content hash.
type policyRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// typedDelta is the exhaustive format-2 transfer delta: every object class
// tracked separately so no filesystem change can hide inside a file count.
type typedDelta struct {
	ModifiedFiles      []string     `json:"modified_files,omitempty"`
	AddedFiles         []string     `json:"added_files,omitempty"`
	RemovedFiles       []string     `json:"removed_files,omitempty"`
	AddedSymlinks      []string     `json:"added_symlinks,omitempty"`
	RemovedSymlinks    []string     `json:"removed_symlinks,omitempty"`
	RetargetedSymlinks []string     `json:"retargeted_symlinks,omitempty"`
	RetypedPaths       []string     `json:"retyped_paths,omitempty"`
	ModeChanges        []modeChange `json:"mode_changes,omitempty"`
}

// modeChange records an executable-bit transition with no content change.
type modeChange struct {
	Path string `json:"path"`
	From string `json:"from"` // "x" or "-"
	To   string `json:"to"`
}

// resolvedDelta renders the effective declaration in typed form for either
// format version: v2 reads delta, v1 reads the flat fields.
func (m transferManifest) resolvedDelta() typedDelta {
	if m.Delta != nil {
		return *m.Delta
	}
	return typedDelta{
		ModifiedFiles: m.LocalModifications,
		AddedFiles:    m.AddedPaths,
		RemovedFiles:  m.RemovedPaths,
	}
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
	// SymlinkCount is how many symlinks the source tree carried (format 2).
	SymlinkCount int `json:"symlink_count,omitempty"`
	// SHA256 is the source tree's identity, under the same definition.
	SHA256 string `json:"sha256"`
	// Required marks transfer-provenance qualification: the source tree must
	// be present and must recompute to this identity — absence is a hard
	// failure, not a skipped check (format 2).
	Required bool `json:"required,omitempty"`
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
// than silently skipped — unless requireSource (or, under format 2, the
// manifest's source.required) makes provenance qualification strict, in
// which case absence fails closed.
func verifyManifest(path string, requireSource bool) error {
	manifest, err := readManifest(path)
	if err != nil {
		return err
	}
	switch {
	case manifest.FormatVersion < 0 || manifest.FormatVersion > formatVersion:
		return fmt.Errorf("%s declares provenance_format_version %d; this tool implements at most %d — refusing to reinterpret it",
			path, manifest.FormatVersion, formatVersion)
	case manifest.FormatVersion == formatVersion:
		return verifyManifestV2(path, manifest, requireSource)
	}
	if len(manifest.LocalModifications) == 0 && len(manifest.AddedPaths) == 0 && len(manifest.RemovedPaths) == 0 && manifest.Delta != nil {
		return fmt.Errorf("%s declares a typed delta without provenance_format_version %d — set the version or use the flat fields", path, formatVersion)
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
		if requireSource {
			return fmt.Errorf("the declared source tree %s is not present — transfer-provenance qualification requires it", manifest.Source.Path)
		}
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

// verifyManifestV2 is the format-2 path: the policy is bound by hash, the
// canonical stream covers files and symlinks, generated paths cannot be
// declared, and the typed delta must equal the computed one exhaustively.
func verifyManifestV2(path string, manifest transferManifest, requireSource bool) error {
	if manifest.Tree == "" {
		return fmt.Errorf("%s declares no tree", path)
	}
	if manifest.Policy == nil {
		return fmt.Errorf("%s declares provenance_format_version 2 but no policy — the enumeration rules must be bound", path)
	}
	if len(manifest.LocalModifications) > 0 || len(manifest.AddedPaths) > 0 || len(manifest.RemovedPaths) > 0 {
		return fmt.Errorf("%s declares format 2 but uses the flat v1 delta fields — the typed delta object is required", path)
	}
	if manifest.Delta == nil {
		return fmt.Errorf("%s declares format 2 but no delta object", path)
	}
	policy, err := readPolicy(manifest.Policy.Path)
	if err != nil {
		return err
	}
	if sum, err := policyDigest(manifest.Policy.Path); err != nil {
		return err
	} else if sum != manifest.Policy.SHA256 {
		return fmt.Errorf("%s binds policy %s as %s, but the file hashes %s — the enumeration rules do not match the declaration",
			path, manifest.Policy.Path, manifest.Policy.SHA256, sum)
	}
	fmt.Printf("ok: policy %s %s\n", manifest.Policy.Path, manifest.Policy.SHA256)

	identity, err := digestRuntimeV2(manifest.Tree, &policy)
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
	if manifest.SymlinkCount != identity.SymlinkCount {
		mismatches = append(mismatches, fmt.Sprintf("symlink_count: declared %d, computed %d", manifest.SymlinkCount, identity.SymlinkCount))
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%s does not match %s:\n  %s\nregenerate with: go run ./cmd/nemo-runtime-digest -manifest %s -update",
			manifest.Tree, path, strings.Join(mismatches, "\n  "), path)
	}
	fmt.Printf("ok: %s %s (%d files, %d symlinks, %s, format %d)\n",
		identity.Tree, identity.NemoRuntimeSHA256, identity.FileCount, identity.SymlinkCount, identity.RuntimeVersion, formatVersion)

	if err := verifyInventoryV2(path, manifest, &policy); err != nil {
		return err
	}
	if err := verifyBinaries(path, manifest); err != nil {
		return err
	}
	if len(manifest.Binaries) > 0 {
		fmt.Printf("ok: %d declared binaries have sources and declarations\n", len(manifest.Binaries))
	}

	if err := syncProvenanceDocV2(manifest.Tree, manifest, false); err != nil {
		return err
	}
	fmt.Printf("ok: %s's generated blocks match the manifest\n", provenanceDocName)

	if manifest.Source == nil {
		return nil
	}
	if _, err := os.Stat(manifest.Source.Path); err != nil {
		if requireSource || manifest.Source.Required {
			return fmt.Errorf("the declared source tree %s is not present — transfer-provenance qualification requires it", manifest.Source.Path)
		}
		fmt.Fprintf(os.Stderr, "note: source tree %s is not present; the declared source identity was not recomputed\n", manifest.Source.Path)
		return nil
	}
	source, err := digestRuntimeV2(manifest.Source.Path, &policy)
	if err != nil {
		return fmt.Errorf("source tree %s: %w", manifest.Source.Path, err)
	}
	var sourceMismatch []string
	if source.NemoRuntimeSHA256 != manifest.Source.SHA256 {
		sourceMismatch = append(sourceMismatch, fmt.Sprintf("sha256: declared %s, computed %s", manifest.Source.SHA256, source.NemoRuntimeSHA256))
	}
	if source.FileCount != manifest.Source.FileCount {
		sourceMismatch = append(sourceMismatch, fmt.Sprintf("file_count: declared %d, computed %d", manifest.Source.FileCount, source.FileCount))
	}
	if source.SymlinkCount != manifest.Source.SymlinkCount {
		sourceMismatch = append(sourceMismatch, fmt.Sprintf("symlink_count: declared %d, computed %d", manifest.Source.SymlinkCount, source.SymlinkCount))
	}
	if len(sourceMismatch) > 0 {
		return fmt.Errorf("source tree %s does not match its declared identity:\n  %s\nregenerate with: go run ./cmd/nemo-runtime-digest -manifest %s -update",
			manifest.Source.Path, strings.Join(sourceMismatch, "\n  "), path)
	}
	fmt.Printf("ok: source %s %s (%d files, %d symlinks)\n",
		source.Tree, source.NemoRuntimeSHA256, source.FileCount, source.SymlinkCount)

	delta, err := verifyDeltaV2(manifest, &policy)
	if err != nil {
		return err
	}
	fmt.Printf("ok: delta %d modified, %d added files, %d removed files, %d added links, %d removed links, %d retargeted, %d retyped, %d mode changes — all declared\n",
		len(delta.ModifiedFiles), len(delta.AddedFiles), len(delta.RemovedFiles),
		len(delta.AddedSymlinks), len(delta.RemovedSymlinks), len(delta.RetargetedSymlinks),
		len(delta.RetypedPaths), len(delta.ModeChanges))
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

// verifyInventoryV2 checks the format-2 structural claims: every declared
// workspace member is a member, every declared forward-side path exists, and
// — the contamination guard — no declared path may be an excluded or
// generated object, which is exactly how generated build outputs once rode
// into the source declaration.
func verifyInventoryV2(manifestPath string, manifest transferManifest, policy *provenancePolicy) error {
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
	var declared []string
	delta := manifest.resolvedDelta()
	declared = append(declared, delta.ModifiedFiles...)
	declared = append(declared, delta.AddedFiles...)
	declared = append(declared, delta.AddedSymlinks...)
	declared = append(declared, delta.RetargetedSymlinks...)
	declared = append(declared, delta.RetypedPaths...)
	for _, change := range delta.ModeChanges {
		declared = append(declared, change.Path)
	}
	for _, path := range declared {
		trimmed := strings.TrimSuffix(path, "/")
		if trimmed == "" {
			return fmt.Errorf("%s declares an empty path", manifestPath)
		}
		if policy.isGenerated(trimmed) {
			return fmt.Errorf("%s declares %q, but that path is a generated artifact under the provenance policy — generated output cannot be declared as source", manifestPath, path)
		}
		if _, err := os.Lstat(filepath.Join(manifest.Tree, filepath.FromSlash(trimmed))); err != nil {
			return fmt.Errorf("%s declares %q, but %s/%s does not exist", manifestPath, path, manifest.Tree, trimmed)
		}
	}
	return nil
}

// treeEntriesV2 maps every canonical object under root to its delta
// identity — content hash plus mode for files, target for symlinks — using
// the format-2 enumeration so generated objects never enter the comparison.
func treeEntriesV2(root string, policy *provenancePolicy) (map[string]canonicalEntry, error) {
	entries, err := canonicalEntries(root, policy)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]canonicalEntry, len(entries))
	for _, entry := range entries {
		byPath[strings.TrimPrefix(entry.path, "./")] = entry
	}
	return byPath, nil
}

// diffTreesV2 computes the typed delta between the source copy and the
// vendored tree, classifying every difference by object kind.
func diffTreesV2(source, vendored string, policy *provenancePolicy) (typedDelta, error) {
	src, err := treeEntriesV2(source, policy)
	if err != nil {
		return typedDelta{}, fmt.Errorf("reading the source tree: %w", err)
	}
	vend, err := treeEntriesV2(vendored, policy)
	if err != nil {
		return typedDelta{}, fmt.Errorf("reading the vendored tree: %w", err)
	}
	var delta typedDelta
	for path, srcEntry := range src {
		vendEntry, ok := vend[path]
		if !ok {
			if srcEntry.kind == "symlink" {
				delta.RemovedSymlinks = append(delta.RemovedSymlinks, path)
			} else {
				delta.RemovedFiles = append(delta.RemovedFiles, path)
			}
			continue
		}
		if vendEntry.kind != srcEntry.kind {
			delta.RetypedPaths = append(delta.RetypedPaths, path)
			continue
		}
		switch srcEntry.kind {
		case "symlink":
			if vendEntry.target != srcEntry.target {
				delta.RetargetedSymlinks = append(delta.RetargetedSymlinks, path)
			}
		default:
			if vendEntry.sha256 != srcEntry.sha256 {
				delta.ModifiedFiles = append(delta.ModifiedFiles, path)
			} else if vendEntry.exec != srcEntry.exec {
				delta.ModeChanges = append(delta.ModeChanges, modeChange{
					Path: path,
					From: execFlag(srcEntry.exec),
					To:   execFlag(vendEntry.exec),
				})
			}
		}
	}
	for path, vendEntry := range vend {
		if _, ok := src[path]; !ok {
			if vendEntry.kind == "symlink" {
				delta.AddedSymlinks = append(delta.AddedSymlinks, path)
			} else {
				delta.AddedFiles = append(delta.AddedFiles, path)
			}
		}
	}
	sort.Strings(delta.ModifiedFiles)
	sort.Strings(delta.AddedFiles)
	sort.Strings(delta.RemovedFiles)
	sort.Strings(delta.AddedSymlinks)
	sort.Strings(delta.RemovedSymlinks)
	sort.Strings(delta.RetargetedSymlinks)
	sort.Strings(delta.RetypedPaths)
	sort.Slice(delta.ModeChanges, func(i, j int) bool { return delta.ModeChanges[i].Path < delta.ModeChanges[j].Path })
	return delta, nil
}

func execFlag(exec bool) string {
	if exec {
		return "x"
	}
	return "-"
}

// verifyDeltaV2 requires the declared typed delta to be the complete
// computed difference — every class, in both directions.
func verifyDeltaV2(manifest transferManifest, policy *provenancePolicy) (typedDelta, error) {
	delta, err := diffTreesV2(manifest.Source.Path, manifest.Tree, policy)
	if err != nil {
		return typedDelta{}, err
	}
	declared := manifest.resolvedDelta()
	var problems []string
	check := func(name string, actual, declaredPaths []string, allowPrefixes bool) {
		sortedDeclared := slices.Clone(declaredPaths)
		sort.Strings(sortedDeclared)
		for _, path := range actual {
			covered := false
			for _, d := range sortedDeclared {
				if allowPrefixes && strings.HasSuffix(d, "/") {
					if strings.HasPrefix(path, d) {
						covered = true
						break
					}
					continue
				}
				if path == d {
					covered = true
					break
				}
			}
			if !covered {
				problems = append(problems, fmt.Sprintf("undeclared %s: %s", name, path))
			}
		}
		for _, d := range sortedDeclared {
			covers := false
			for _, path := range actual {
				if allowPrefixes && strings.HasSuffix(d, "/") {
					if strings.HasPrefix(path, d) {
						covers = true
						break
					}
					continue
				}
				if path == d {
					covers = true
					break
				}
			}
			if !covers {
				problems = append(problems, fmt.Sprintf("declared %s entry %s matches no actual difference (stale declaration)", name, d))
			}
		}
	}
	check("modified file", delta.ModifiedFiles, declared.ModifiedFiles, false)
	check("added file", delta.AddedFiles, declared.AddedFiles, true)
	check("removed file", delta.RemovedFiles, declared.RemovedFiles, false)
	check("added symlink", delta.AddedSymlinks, declared.AddedSymlinks, true)
	check("removed symlink", delta.RemovedSymlinks, declared.RemovedSymlinks, false)
	check("retargeted symlink", delta.RetargetedSymlinks, declared.RetargetedSymlinks, false)
	check("retyped path", delta.RetypedPaths, declared.RetypedPaths, false)

	declaredModes := map[string]modeChange{}
	for _, change := range declared.ModeChanges {
		declaredModes[change.Path] = change
	}
	actualModes := map[string]modeChange{}
	for _, change := range delta.ModeChanges {
		actualModes[change.Path] = change
	}
	for path, actual := range actualModes {
		d, ok := declaredModes[path]
		if !ok {
			problems = append(problems, fmt.Sprintf("undeclared mode change: %s (%s→%s)", path, actual.From, actual.To))
			continue
		}
		if d.From != actual.From || d.To != actual.To {
			problems = append(problems, fmt.Sprintf("mode change %s declared as %s→%s but computed %s→%s", path, d.From, d.To, actual.From, actual.To))
		}
	}
	for path := range declaredModes {
		if _, ok := actualModes[path]; !ok {
			problems = append(problems, fmt.Sprintf("declared mode change %s matches no actual difference (stale declaration)", path))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return delta, fmt.Errorf("the declared transfer delta is not the actual delta between %s and %s:\n  %s\nregenerate with: go run ./cmd/nemo-runtime-digest -manifest <manifest> -update",
			manifest.Source.Path, manifest.Tree, strings.Join(problems, "\n  "))
	}
	return delta, nil
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

// renderDeltaBlockV2 renders the typed format-2 delta: every object class
// under its own kind so a symlink or mode change is never laundered into a
// file list.
func renderDeltaBlockV2(manifest transferManifest) string {
	delta := manifest.resolvedDelta()
	var block strings.Builder
	block.WriteString(deltaBlockBegin + "\n\n")
	block.WriteString("| Kind | Path | Detail |\n| --- | --- | --- |\n")
	write := func(kind string, paths []string) {
		for _, path := range paths {
			block.WriteString("| " + kind + " | `" + path + "` | |\n")
		}
	}
	write("modified file", delta.ModifiedFiles)
	write("added file", delta.AddedFiles)
	write("removed file", delta.RemovedFiles)
	write("added symlink", delta.AddedSymlinks)
	write("removed symlink", delta.RemovedSymlinks)
	write("retargeted symlink", delta.RetargetedSymlinks)
	write("retyped", delta.RetypedPaths)
	for _, change := range delta.ModeChanges {
		block.WriteString("| mode change | `" + change.Path + "` | " + change.From + " → " + change.To + " |\n")
	}
	if len(delta.ModifiedFiles)+len(delta.AddedFiles)+len(delta.RemovedFiles)+
		len(delta.AddedSymlinks)+len(delta.RemovedSymlinks)+len(delta.RetargetedSymlinks)+
		len(delta.RetypedPaths)+len(delta.ModeChanges) == 0 {
		block.WriteString("| — | — | |\n")
	}
	block.WriteString("\n" + deltaBlockEnd)
	return block.String()
}

// renderSourceBlockV2 renders the format-2 source identity: files, symlinks,
// and the canonical-stream digest.
func renderSourceBlockV2(source manifestSource) string {
	var block strings.Builder
	block.WriteString(sourceBlockBegin + "\n\n")
	fmt.Fprintf(&block, "%d files, %d symlinks. Format-2 canonical digest (`FILE`/`SYMLINK` records,\nSHA-256, sorted byte-wise) over the source tree as it was copied, before any\nlocal modification:\n\n", source.FileCount, source.SymlinkCount)
	block.WriteString("```text\n" + source.SHA256 + "\n```\n\n")
	block.WriteString(sourceBlockEnd)
	return block.String()
}

// syncProvenanceDocV2 reconciles the generated blocks with the format-2
// declaration — the same drift contract as the v1 blocks.
func syncProvenanceDocV2(tree string, manifest transferManifest, write bool) error {
	docPath := filepath.Join(tree, provenanceDocName)
	raw, err := os.ReadFile(docPath)
	if err != nil {
		return fmt.Errorf("the provenance record %s: %w", docPath, err)
	}
	doc := string(raw)

	var stale []string
	reconciled, err := spliceGenerated(doc, deltaBlockBegin, deltaBlockEnd, renderDeltaBlockV2(manifest), "delta block", docPath)
	if err != nil {
		return err
	}
	if reconciled != doc {
		stale = append(stale, "delta")
	}
	if manifest.Source != nil {
		spliced, err := spliceGenerated(reconciled, sourceBlockBegin, sourceBlockEnd, renderSourceBlockV2(*manifest.Source), "source-identity block", docPath)
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

// updateDeltaInventoryV2 regenerates the typed delta declarations. Directory
// prefixes that still cover real additions survive in each added class.
func updateDeltaInventoryV2(manifest *transferManifest, delta typedDelta) {
	keptAdds := func(declared, actual []string) []string {
		var kept []string
		for _, d := range declared {
			for _, path := range actual {
				if addedPathCovers(d, path) {
					kept = append(kept, d)
					break
				}
			}
		}
		for _, path := range actual {
			covered := false
			for _, d := range kept {
				if addedPathCovers(d, path) {
					covered = true
					break
				}
			}
			if !covered {
				kept = append(kept, path)
			}
		}
		sort.Strings(kept)
		return kept
	}
	declared := manifest.resolvedDelta()
	manifest.Delta = &typedDelta{
		ModifiedFiles:      delta.ModifiedFiles,
		AddedFiles:         keptAdds(declared.AddedFiles, delta.AddedFiles),
		RemovedFiles:       delta.RemovedFiles,
		AddedSymlinks:      keptAdds(declared.AddedSymlinks, delta.AddedSymlinks),
		RemovedSymlinks:    delta.RemovedSymlinks,
		RetargetedSymlinks: delta.RetargetedSymlinks,
		RetypedPaths:       delta.RetypedPaths,
		ModeChanges:        delta.ModeChanges,
	}
	// A regenerated declaration is always format-2: the flat v1 fields are
	// cleared so the manifest carries exactly one delta representation.
	manifest.LocalModifications = nil
	manifest.AddedPaths = nil
	manifest.RemovedPaths = nil
}

// updateManifest rewrites the manifest's computed fields from the tree,
// preserving the inventory fields a human maintains, and upgrades the
// declaration to the current provenance format. A missing manifest is
// created with the computed fields alone.
func updateManifest(path, policyPath string) error {
	manifest, err := readManifest(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		manifest = transferManifest{}
	}
	if manifest.FormatVersion > formatVersion {
		return fmt.Errorf("%s declares provenance_format_version %d; this tool implements at most %d — refusing to reinterpret it", path, manifest.FormatVersion, formatVersion)
	}
	if manifest.Tree == "" {
		manifest.Tree = defaultRoot
	}
	policy, err := readPolicy(policyPath)
	if err != nil {
		return err
	}
	policySum, err := policyDigest(policyPath)
	if err != nil {
		return err
	}
	manifest.FormatVersion = formatVersion
	manifest.Policy = &policyRef{Path: policyPath, SHA256: policySum}
	if manifest.Source != nil {
		if _, err := os.Stat(manifest.Source.Path); err == nil {
			source, err := digestRuntimeV2(manifest.Source.Path, &policy)
			if err != nil {
				return fmt.Errorf("source tree %s: %w", manifest.Source.Path, err)
			}
			manifest.Source.SHA256 = source.NemoRuntimeSHA256
			manifest.Source.FileCount = source.FileCount
			manifest.Source.SymlinkCount = source.SymlinkCount
			delta, err := diffTreesV2(manifest.Source.Path, manifest.Tree, &policy)
			if err != nil {
				return fmt.Errorf("computing the source delta: %w", err)
			}
			updateDeltaInventoryV2(&manifest, delta)
		} else {
			fmt.Fprintf(os.Stderr, "note: source tree %s is not present; the declared delta inventory is preserved, not regenerated\n", manifest.Source.Path)
			if manifest.Delta == nil && (len(manifest.LocalModifications) > 0 || len(manifest.AddedPaths) > 0 || len(manifest.RemovedPaths) > 0) {
				resolved := manifest.resolvedDelta()
				manifest.Delta = &resolved
				manifest.LocalModifications, manifest.AddedPaths, manifest.RemovedPaths = nil, nil, nil
			}
		}
	} else if manifest.Delta == nil {
		resolved := manifest.resolvedDelta()
		manifest.Delta = &resolved
		manifest.LocalModifications, manifest.AddedPaths, manifest.RemovedPaths = nil, nil, nil
	}
	// The provenance record is a file inside the tree it documents: sync its
	// generated delta block first, so the digest below covers the record as
	// it will ship — a digest taken before the doc would bind a stale one.
	if err := syncProvenanceDocV2(manifest.Tree, manifest, true); err != nil {
		return fmt.Errorf("regenerating the provenance record: %w", err)
	}
	identity, err := digestRuntimeV2(manifest.Tree, &policy)
	if err != nil {
		return err
	}
	manifest.RuntimeVersion = identity.RuntimeVersion
	manifest.ShippedTreeSHA256 = identity.NemoRuntimeSHA256
	manifest.FileCount = identity.FileCount
	manifest.SymlinkCount = identity.SymlinkCount
	manifest.Excluded = nil
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("updated: %s — %s %s (%d files, %d symlinks, %s, format %d)\n",
		path, identity.Tree, identity.NemoRuntimeSHA256, identity.FileCount, identity.SymlinkCount, identity.RuntimeVersion, formatVersion)
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
