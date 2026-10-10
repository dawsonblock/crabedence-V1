// Command nemo-component-manifest binds the NEMO-CONTROL distribution.
//
// A distribution that ships two runtimes has to bind both identities: the
// transfer manifest says which NEMO source the vendored tree came from, and
// this manifest says which bytes the distribution actually carries — every
// shipped binary, the capability schema, the registry envelope, and the
// transfer manifest itself, each by SHA-256, plus the registry digest the
// runtime will serve. The component manifest is the artifact a release signs;
// its own digest is what a consumer checks first.
//
// The shipping set is not restated here: the binaries come from the transfer
// manifest's declared entries (the runtime and the plugin host), so a
// component cannot be shipped without having been declared, built, and
// verified first.
//
// Usage:
//
//	go run ./cmd/nemo-component-manifest -root dist/nemo-control -crabbox-version "$(cat VERSION)"
//	go run ./cmd/nemo-component-manifest -root dist/nemo-control -verify
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// defaultRoot is where the distribution is assembled, relative to the
// repository.
const defaultRoot = "dist/nemo-control"

// shippingRoles are the binary roles the distribution carries. Qualification
// binaries are tooling, not distribution content.
var shippingRoles = map[string]bool{
	"runtime":     true,
	"plugin-host": true,
}

// requiredFiles are the non-binary components every distribution carries.
var requiredFiles = []struct {
	name string
	kind string
	path string
}{
	{"capability-invocation-v1", "schema", "share/capability-invocation-v1.json"},
	{"capability-registry-envelope", "registry-envelope", "share/capability-registry-envelope.json"},
	{"nemo-transfer-manifest", "manifest", "manifests/nemo-transfer-manifest.json"},
}

// component is one bound artifact.
type component struct {
	// Name is the component's name.
	Name string `json:"name"`
	// Kind is binary, schema, registry-envelope, or manifest.
	Kind string `json:"kind"`
	// Path is the component's path inside the distribution.
	Path string `json:"path"`
	// SHA256 is the component's digest.
	SHA256 string `json:"sha256"`
}

// componentManifest is the distribution's bound identity — the release-root
// manifest: one canonical record of what the release is (versions, platform,
// toolchain, qualification identity) and what it carries (every component by
// SHA-256). Its own digest, in the .sha256 sidecar, is the release-root
// identity a signature would bind and a receipt can cite.
type componentManifest struct {
	// Name is the distribution's name.
	Name string `json:"name"`
	// CrabboxVersion is the Crabbox release the CLI binary came from.
	CrabboxVersion string `json:"crabbox_version"`
	// NemoRuntimeVersion is the vendored NeMo Relay workspace version.
	NemoRuntimeVersion string `json:"nemo_runtime_version"`
	// NemoRuntimeSHA256 is the vendored tree identity the transfer declares.
	NemoRuntimeSHA256 string `json:"nemo_runtime_sha256"`
	// CapabilityRegistrySHA256 is the capability policy the runtime serves.
	CapabilityRegistrySHA256 string `json:"capability_registry_sha256"`
	// Platform is the distribution's target ("linux_amd64", "darwin_arm64").
	Platform string `json:"platform"`
	// Build records the toolchain that produced it — evidence, not a secret.
	Build buildInfo `json:"build"`
	// Qualification names the gates this artifact is qualified by: the suite
	// identities whose pass is part of what this release claims to be.
	Qualification []string `json:"qualification"`
	// Components are the bound artifacts, in the distribution's layout.
	Components []component `json:"components"`
}

// buildInfo is the toolchain evidence the release records.
type buildInfo struct {
	// GoVersion is the Go toolchain's reported version.
	GoVersion string `json:"go_version,omitempty"`
	// RustVersion is the Rust toolchain's reported version.
	RustVersion string `json:"rust_version,omitempty"`
	// Profile is the cargo build profile the Rust components were built with.
	Profile string `json:"profile,omitempty"`
}

// transferDeclaration is the subset of the transfer manifest this tool reads.
// It is a consumer's view, not a second copy of the format: the digest tool
// owns verification of the declaration itself.
type transferDeclaration struct {
	RuntimeVersion    string `json:"runtime_version"`
	ShippedTreeSHA256 string `json:"shipped_tree_sha256"`
	Binaries          []struct {
		Role   string `json:"role"`
		Binary string `json:"binary"`
	} `json:"binaries"`
}

// registryEnvelope is the subset of the registry envelope this tool reads.
type registryEnvelope struct {
	RegistrySHA256 string `json:"registry_sha256"`
}

func main() {
	root := flag.String("root", defaultRoot, "the assembled distribution root")
	transferPath := flag.String("transfer-manifest", "", "the transfer manifest the distribution carries (default <root>/manifests/nemo-transfer-manifest.json)")
	crabboxVersion := flag.String("crabbox-version", "", "the Crabbox version the CLI binary came from (required unless -verify)")
	platform := flag.String("platform", runtime.GOOS+"_"+runtime.GOARCH, "the distribution's target platform (goos_goarch)")
	rustVersion := flag.String("rust-version", "", "the Rust toolchain version that built the components (evidence)")
	profile := flag.String("profile", "", "the cargo profile the Rust components were built with (evidence)")
	qualification := flag.String("qualification", "", "comma-separated gate identities this distribution is qualified by")
	verify := flag.Bool("verify", false, "verify the existing component manifest instead of writing it")
	allowedSigners := flag.String("allowed-signers", "", "ssh allowed_signers file — with -verify, require manifests/component-manifest.sha256.sig to authenticate the sidecar")
	signerIdentity := flag.String("signer-identity", "", "the principal the signature must verify under (required with -allowed-signers)")
	flag.Parse()

	if *transferPath == "" {
		*transferPath = filepath.Join(*root, "manifests", "nemo-transfer-manifest.json")
	}

	if *verify {
		if err := verifyManifest(*root, *transferPath, *allowedSigners, *signerIdentity); err != nil {
			fmt.Fprintf(os.Stderr, "nemo-component-manifest: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if strings.TrimSpace(*crabboxVersion) == "" {
		fmt.Fprintln(os.Stderr, "nemo-component-manifest: -crabbox-version is required (read it from VERSION)")
		os.Exit(2)
	}
	meta := metadata{
		Platform: *platform,
		Build: buildInfo{
			GoVersion:   runtime.Version(),
			RustVersion: *rustVersion,
			Profile:     *profile,
		},
		Qualification: splitList(*qualification),
	}
	if err := writeManifest(*root, *transferPath, *crabboxVersion, meta); err != nil {
		fmt.Fprintf(os.Stderr, "nemo-component-manifest: %v\n", err)
		os.Exit(1)
	}
}

// metadata is the release-root identity that cannot be recomputed from the
// distribution's bytes: which platform it targets, which toolchain produced
// it, and which gates qualify it.
type metadata struct {
	Platform      string
	Build         buildInfo
	Qualification []string
}

// splitList parses a comma-separated list into trimmed, non-empty items.
func splitList(raw string) []string {
	var items []string
	for _, item := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

// writeManifest binds the distribution and writes the manifest and its digest
// sidecar.
func writeManifest(root, transferPath, crabboxVersion string, meta metadata) error {
	manifest, err := buildManifest(root, transferPath, crabboxVersion, meta)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(root, "manifests", "component-manifest.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	digest, err := digestFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "manifests", "component-manifest.sha256"), []byte(digest+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s — %d components, sha256 %s\n", path, len(manifest.Components), digest)
	return nil
}

// verifyManifest recomputes the distribution's identity and compares it with
// the manifest it carries. The source-level fields — Crabbox version,
// platform, toolchain, qualification — cannot be recomputed from the
// distribution's bytes, so they are carried over; every file's content is
// checked, and the set must be exact: a file the manifest does not declare is
// a failure, not an oversight the manifest never claimed.
// signatureNamespace binds the SSH signature to this purpose — a signature
// made for any other document or protocol cannot be replayed here.
const signatureNamespace = "nemo-control-release"

func verifyManifest(root, transferPath, allowedSigners, signerIdentity string) error {
	path := filepath.Join(root, "manifests", "component-manifest.json")
	raw, err := readRegularFile(path)
	if err != nil {
		return err
	}
	var declared componentManifest
	if err := json.Unmarshal(raw, &declared); err != nil {
		return fmt.Errorf("%s is not a valid component manifest: %w", path, err)
	}
	computed, err := buildManifest(root, transferPath, declared.CrabboxVersion, metadata{
		Platform:      declared.Platform,
		Build:         declared.Build,
		Qualification: declared.Qualification,
	})
	if err != nil {
		return err
	}

	var mismatches []string
	// The digest sidecar is the release-root identity: it must say what the
	// manifest actually hashes to, not just exist. When an allowed-signers
	// file is configured the sidecar must also carry an authentic release
	// signature — that is the binding to release origin, not just to bytes.
	sidecarPath := filepath.Join(root, "manifests", "component-manifest.sha256")
	sidecarRaw, err := readRegularFile(sidecarPath)
	if err != nil {
		mismatches = append(mismatches, fmt.Sprintf("component-manifest.sha256: %v", err))
	} else {
		manifestDigest, err := digestFile(path)
		if err != nil {
			return err
		}
		if declared := strings.TrimSpace(string(sidecarRaw)); declared != manifestDigest {
			mismatches = append(mismatches, fmt.Sprintf("component-manifest.sha256: declares %s, manifest digests to %s", declared, manifestDigest))
		}
	}
	// Exhaustiveness: every regular file in the distribution is either a
	// declared component or one of the manifest artifacts themselves.
	if err := checkExhaustive(root, declared.Components); err != nil {
		mismatches = append(mismatches, err.Error())
	}
	if allowedSigners != "" {
		if strings.TrimSpace(signerIdentity) == "" {
			mismatches = append(mismatches, "-allowed-signers requires -signer-identity — an authenticated signature needs a named principal")
		} else if err := verifySidecarSignature(sidecarPath, allowedSigners, signerIdentity); err != nil {
			mismatches = append(mismatches, err.Error())
		}
	}
	if declared.Name != computed.Name {
		mismatches = append(mismatches, fmt.Sprintf("name: declared %q, computed %q", declared.Name, computed.Name))
	}
	if declared.NemoRuntimeVersion != computed.NemoRuntimeVersion {
		mismatches = append(mismatches, fmt.Sprintf("nemo_runtime_version: declared %q, computed %q", declared.NemoRuntimeVersion, computed.NemoRuntimeVersion))
	}
	if declared.NemoRuntimeSHA256 != computed.NemoRuntimeSHA256 {
		mismatches = append(mismatches, fmt.Sprintf("nemo_runtime_sha256: declared %s, computed %s", declared.NemoRuntimeSHA256, computed.NemoRuntimeSHA256))
	}
	if declared.CapabilityRegistrySHA256 != computed.CapabilityRegistrySHA256 {
		mismatches = append(mismatches, fmt.Sprintf("capability_registry_sha256: declared %s, computed %s", declared.CapabilityRegistrySHA256, computed.CapabilityRegistrySHA256))
	}
	if len(declared.Components) != len(computed.Components) {
		mismatches = append(mismatches, fmt.Sprintf("components: declared %d, computed %d", len(declared.Components), len(computed.Components)))
	} else {
		for i := range declared.Components {
			if declared.Components[i] != computed.Components[i] {
				mismatches = append(mismatches, fmt.Sprintf("component %s: declared %s, computed %s", computed.Components[i].Path, declared.Components[i].SHA256, computed.Components[i].SHA256))
			}
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%s does not match the distribution it describes:\n  %s\nregenerate with: go run ./cmd/nemo-component-manifest -root %s -crabbox-version %s",
			path, strings.Join(mismatches, "\n  "), root, declared.CrabboxVersion)
	}
	fmt.Printf("ok: %s — %d components match the distribution\n", path, len(computed.Components))
	return nil
}

// checkExhaustive fails when the distribution carries a file the manifest
// does not declare — the manifest artifacts themselves (the JSON, its
// .sha256 sidecar, and the sidecar's signature) are the only exempt files,
// since a declaration inside the tree they describe could never name them
// without self-reference.
func checkExhaustive(root string, components []component) error {
	declared := make(map[string]bool, len(components))
	for _, c := range components {
		declared[c.Path] = true
	}
	// The manifest's own artifacts: written after the component list is
	// computed, so no manifest could ever name them. The .sig signs the
	// sidecar, which binds the manifest — declaring it inside the manifest
	// would require the signature to exist before it is made.
	exempt := map[string]bool{
		"manifests/component-manifest.json":       true,
		"manifests/component-manifest.sha256":     true,
		"manifests/component-manifest.sha256.sig": true,
	}
	var undeclared []string
	var nonRegular []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// Walk's info is Lstat-based — a symlink, fifo, or device cannot
		// pass as the file it names. The distribution ships only regular
		// files and directories; any other node fails even at a declared or
		// exempt path, because a name check cannot see what it isn't.
		if !info.Mode().IsRegular() {
			nonRegular = append(nonRegular, rel+" ("+info.Mode().Type().String()+")")
			return nil
		}
		if !declared[rel] && !exempt[rel] {
			undeclared = append(undeclared, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(nonRegular) > 0 {
		return fmt.Errorf("the distribution carries nodes that are not regular files or directories: %s", strings.Join(nonRegular, ", "))
	}
	if len(undeclared) > 0 {
		return fmt.Errorf("the distribution carries files the manifest does not declare: %s", strings.Join(undeclared, ", "))
	}
	return nil
}

// verifySidecarSignature authenticates the release-root sidecar with
// ssh-keygen's signature format: the signature file must exist and verify
// under signerIdentity in the nemo-control-release namespace against the
// allowed_signers file. A missing sig or a signature under a different
// principal fails — the sidecar's digest is only release-origin evidence
// once a named signer is bound to it.
func verifySidecarSignature(sidecarPath, allowedSigners, signerIdentity string) error {
	sigPath := sidecarPath + ".sig"
	if info, err := os.Lstat(sigPath); err != nil {
		return fmt.Errorf("component-manifest.sha256.sig: %v — this verification requires a signed release root", err)
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("component-manifest.sha256.sig is %s, not a regular file", info.Mode().Type())
	}
	sidecar, err := readRegularFile(sidecarPath)
	if err != nil {
		return err
	}
	cmd := exec.Command("ssh-keygen",
		"-Y", "verify",
		"-f", allowedSigners,
		"-I", signerIdentity,
		"-n", signatureNamespace,
		"-s", sigPath)
	cmd.Stdin = strings.NewReader(string(sidecar))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("component-manifest.sha256.sig does not authenticate the sidecar under %q: %v: %s",
			signerIdentity, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildManifest computes the distribution's identity from what it carries.
func buildManifest(root, transferPath, crabboxVersion string, meta metadata) (componentManifest, error) {
	raw, err := readRegularFile(transferPath)
	if err != nil {
		return componentManifest{}, err
	}
	var transfer transferDeclaration
	if err := json.Unmarshal(raw, &transfer); err != nil {
		return componentManifest{}, fmt.Errorf("%s is not a valid transfer manifest: %w", transferPath, err)
	}

	manifest := componentManifest{
		Name:               "nemo-control",
		CrabboxVersion:     crabboxVersion,
		NemoRuntimeVersion: transfer.RuntimeVersion,
		NemoRuntimeSHA256:  transfer.ShippedTreeSHA256,
		Platform:           meta.Platform,
		Build:              meta.Build,
		Qualification:      meta.Qualification,
	}

	// The CLI is the one binary the transfer manifest does not declare: it is
	// this repository's own, not the vendored tree's.
	if err := bind(&manifest, root, "crabbox", "binary", "bin/crabbox"); err != nil {
		return componentManifest{}, err
	}
	for _, binary := range transfer.Binaries {
		if !shippingRoles[binary.Role] {
			continue
		}
		if err := bind(&manifest, root, binary.Binary, "binary", filepath.Join("bin", binary.Binary)); err != nil {
			return componentManifest{}, err
		}
	}
	if len(manifest.Components) < 3 {
		return componentManifest{}, fmt.Errorf("the transfer manifest declares no shipping binaries (runtime, plugin-host); the distribution would carry only the CLI")
	}
	for _, required := range requiredFiles {
		if err := bind(&manifest, root, required.name, required.kind, required.path); err != nil {
			return componentManifest{}, err
		}
	}

	envelopeRaw, err := readRegularFile(filepath.Join(root, "share", "capability-registry-envelope.json"))
	if err != nil {
		return componentManifest{}, err
	}
	var envelope registryEnvelope
	if err := json.Unmarshal(envelopeRaw, &envelope); err != nil {
		return componentManifest{}, fmt.Errorf("the capability registry envelope is not valid JSON: %w", err)
	}
	if envelope.RegistrySHA256 == "" {
		return componentManifest{}, fmt.Errorf("the capability registry envelope carries no registry_sha256")
	}
	manifest.CapabilityRegistrySHA256 = envelope.RegistrySHA256
	return manifest, nil
}

// bind hashes one component and appends it to the manifest. The component
// must be a regular file — digestFile refuses anything else before opening.
func bind(manifest *componentManifest, root, name, kind, path string) error {
	digest, err := digestFile(filepath.Join(root, path))
	if err != nil {
		return fmt.Errorf("the %s component (%s) is not a regular file in the distribution: %w", name, path, err)
	}
	manifest.Components = append(manifest.Components, component{
		Name:   name,
		Kind:   kind,
		Path:   filepath.ToSlash(path),
		SHA256: digest,
	})
	return nil
}

// readRegularFile reads a file that must be a regular file: Lstat never
// follows a symlink, so a link or a fifo at a trusted path cannot read or
// block on whatever it stands for.
func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is %s, not a regular file", path, info.Mode().Type())
	}
	return os.ReadFile(path)
}

// digestFile returns the SHA-256 of a regular file — refusing links, fifos,
// and other node types before opening them.
func digestFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is %s, not a regular file", path, info.Mode().Type())
	}
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
