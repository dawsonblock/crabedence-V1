package sandboxexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RuntimeManifest pins the exact bytes of the execution runtime: the
// msb executable, the libkrunfw firmware it boots guests with, and the
// version they belong to. A binary that reports the right version but
// hashes differently is a substituted runtime and refuses — the
// version string is a claim, the digest is the identity.
//
// The manifest is the operator's qualified-release record; it is
// required for a configured backend, so "the runtime that happens to
// be installed" can never become the execution environment by
// omission.
type RuntimeManifest struct {
	Version string `json:"version"`
	// MSBSHA256 is the lowercase hex SHA-256 of the msb executable.
	MSBSHA256 string `json:"msb_sha256"`
	// LibkrunfwSHA256 is the lowercase hex SHA-256 of the firmware
	// shared library the runtime boots guests with.
	LibkrunfwSHA256 string `json:"libkrunfw_sha256"`
}

// LoadRuntimeManifest reads and validates a runtime manifest file.
// Parsing is strict and bounded: unknown fields, malformed digests or
// an absent version refuse rather than defaulting.
func LoadRuntimeManifest(path string) (*RuntimeManifest, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("runtime manifest path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime manifest %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("runtime manifest %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("runtime manifest %s is not a regular file", path)
	}
	if info.Size() > 64*1024 {
		return nil, fmt.Errorf("runtime manifest %s exceeds 64KiB", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runtime manifest %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m RuntimeManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse runtime manifest %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("runtime manifest %s carries trailing data", path)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("runtime manifest %s: %w", path, err)
	}
	return &m, nil
}

// Validate refuses a manifest that cannot pin anything.
func (m *RuntimeManifest) Validate() error {
	if m == nil {
		return fmt.Errorf("missing runtime manifest")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("version is required")
	}
	if !isSHA256Digest("sha256:" + m.MSBSHA256) {
		return fmt.Errorf("msb_sha256 must be a lowercase 64-hex digest")
	}
	if !isSHA256Digest("sha256:" + m.LibkrunfwSHA256) {
		return fmt.Errorf("libkrunfw_sha256 must be a lowercase 64-hex digest")
	}
	return nil
}

// firmwarePath resolves the installed firmware library from the
// runtime's own prerequisite report (msb doctor) — the runtime names
// the exact library it will boot guests with, so the manifest check
// hashes that file, not a guessed path.
func (b *MSBBackend) firmwarePath(ctx context.Context) (string, error) {
	out, err := b.runOnce(ctx, "doctor")
	if err != nil {
		return "", fmt.Errorf("resolve firmware path (msb doctor): %v: %s", err, strings.TrimSpace(string(out)))
	}
	// The doctor line names the library as its final field:
	//   ✓ libkrunfw           /path/to/lib/libkrunfw.5.dylib
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "libkrunfw") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		candidate := fields[len(fields)-1]
		if !strings.HasSuffix(candidate, ".dylib") && !strings.Contains(candidate, ".so") {
			continue
		}
		if !filepath.IsAbs(candidate) {
			return "", fmt.Errorf("msb doctor named a relative firmware path %q", candidate)
		}
		if st, err := os.Stat(candidate); err != nil || st.IsDir() {
			return "", fmt.Errorf("firmware library %s is not a readable file", candidate)
		}
		return candidate, nil
	}
	return "", fmt.Errorf("msb doctor did not name the firmware library")
}

// runtimeManifest is the effective manifest (nil when unset — the
// caller's verification refuses that before any dispatch).
func (b *MSBBackend) runtimeManifest() RuntimeManifest {
	if b.RuntimeManifest == nil {
		return RuntimeManifest{}
	}
	return *b.RuntimeManifest
}

// verifyRuntimeIdentity proves the installed runtime is the qualified
// bytes: the executable and the firmware it boots guests with must
// hash to the manifest's digests. It returns the firmware path for the
// startup report.
func (b *MSBBackend) verifyRuntimeIdentity(ctx context.Context, version string) (string, error) {
	if b.RuntimeManifest == nil {
		return "", fmt.Errorf("a runtime manifest is required for the microsandbox backend — the qualified release manifest pins the msb executable and firmware bytes (pass -runtime-manifest)")
	}
	if err := b.RuntimeManifest.Validate(); err != nil {
		return "", err
	}
	if m := b.RuntimeManifest.Version; m != version {
		return "", fmt.Errorf("runtime manifest pins version %s but the installed runtime is %s", m, version)
	}
	msbSum, err := hashFileSHA256(b.Bin)
	if err != nil {
		return "", fmt.Errorf("hash the msb executable %s: %w", b.Bin, err)
	}
	if msbSum != b.RuntimeManifest.MSBSHA256 {
		return "", fmt.Errorf("msb executable digest %s does not match the qualified manifest %s — refusing a substituted executable",
			msbSum, b.RuntimeManifest.MSBSHA256)
	}
	fwPath, err := b.firmwarePath(ctx)
	if err != nil {
		return "", err
	}
	fwSum, err := hashFileSHA256(fwPath)
	if err != nil {
		return "", fmt.Errorf("hash the firmware library %s: %w", fwPath, err)
	}
	if fwSum != b.RuntimeManifest.LibkrunfwSHA256 {
		return "", fmt.Errorf("firmware library digest %s does not match the qualified manifest %s — refusing a substituted virtualization component",
			fwSum, b.RuntimeManifest.LibkrunfwSHA256)
	}
	return fwPath, nil
}

// sandboxBootID reads the runtime's boot-generation identity for a
// sandbox from its own state directory (the storage path the inspect
// document reports). The boot id is the runtime's identity for this
// boot: a substituted VM under the same name carries a different one,
// which is exactly what the execution-identity binding must catch.
//
// The runtime is pinned by hash, so this state-file format is a pinned
// interface, not an incidental path; a missing or malformed file is a
// refusal, never a silent absence of binding.
func (b *MSBBackend) sandboxBootID(doc map[string]any) (string, error) {
	storage, _ := doc["storage"].(map[string]any)
	path := jsonString(storage, "path")
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("inspect document does not name the sandbox storage path — cannot bind the VM boot generation")
	}
	raw, err := os.ReadFile(filepath.Join(path, "runtime", "runtime-boot-id"))
	if err != nil {
		return "", fmt.Errorf("read the sandbox boot identity under %s: %w", path, err)
	}
	bootID := strings.TrimSpace(string(raw))
	if !bootIDPattern.MatchString(bootID) {
		return "", fmt.Errorf("sandbox boot identity %q is not a runtime boot id", bootID)
	}
	return bootID, nil
}
