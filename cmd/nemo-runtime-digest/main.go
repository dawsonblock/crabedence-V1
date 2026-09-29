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
// build artifact or a working-copy detail does. `-envelope` prints the digest
// with the exact inputs it covers, in the same idiom as the registry envelope:
// a consumer verifies what it was given rather than reproducing the
// computation.
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
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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
	flag.Parse()

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
