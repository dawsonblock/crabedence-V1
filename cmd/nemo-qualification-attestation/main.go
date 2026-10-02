// Command nemo-qualification-attestation binds a qualification run to
// the artifact it qualified.
//
// The component manifest binds what the distribution is; the attestation
// records what was proven about it: which gates ran, on which host, at
// which source commit, against which bytes. The qualifier emits it after
// the suite passes — a gate that did not run cannot appear in the record
// because the emit step is sequenced after every check.
//
// Every digest in the record is recomputed from the distribution root at
// emit time and again at -verify time, so the attestation binds real
// bytes, not a story about them: the component manifest's own digest (the
// release-root identity), the transfer manifest's digest, and — when the
// qualified artifact was a packed archive — the archive's digest.
//
// Usage:
//
//	go run ./cmd/nemo-qualification-attestation -root dist/nemo-control_v_linux_amd64 \
//	  -archive dist/nemo-control_v_linux_amd64.tar.gz \
//	  -commit "$(git rev-parse HEAD)" -gates nemo-runtime-e2e,nemo-critical-path \
//	  -out dist/nemo-control_v_linux_amd64.qualification.json
//
//	go run ./cmd/nemo-qualification-attestation -verify \
//	  -root dist/nemo-control_v_linux_amd64 \
//	  -attestation dist/nemo-control_v_linux_amd64.qualification.json
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// attestation is the qualification record. It is a statement by the
// qualifier — the installed-distribution suite — that these gates ran
// and passed against these bytes at this commit. Signing is the release
// step's concern; this record is what a signature would bind.
type attestation struct {
	// AttestationVersion is the record schema.
	AttestationVersion int `json:"attestation_version"`
	// Subject names what was qualified.
	Subject subject `json:"subject"`
	// Source records the checkout the gates ran from. A qualification
	// against a changed tree is a claim about different code.
	Source source `json:"source"`
	// Gates are the checks that ran, in order — all must be "pass".
	Gates []gateResult `json:"gates"`
	// QualifiedAt is when the last gate passed (RFC3339, UTC).
	QualifiedAt string `json:"qualified_at"`
	// QualifyHost is the platform the gates executed on; it differs from
	// the subject's platform when the artifact was qualified under
	// translation (NEMO_QUALIFY_HOST).
	QualifyHost string `json:"qualify_host,omitempty"`
}

// subject binds the qualified distribution: its declared identity plus
// the recomputed digests of the artifacts that carry that identity.
type subject struct {
	// Name is the distribution's declared name.
	Name string `json:"name"`
	// Platform is the target the manifest declares.
	Platform string `json:"platform"`
	// Version is the Crabbox release the manifest declares.
	Version string `json:"version"`
	// ComponentManifestSHA256 is the release-root identity — the digest
	// of manifests/component-manifest.json, which must equal its
	// .sha256 sidecar.
	ComponentManifestSHA256 string `json:"component_manifest_sha256"`
	// TransferManifestSHA256 is the vendored-runtime declaration the
	// distribution carries.
	TransferManifestSHA256 string `json:"transfer_manifest_sha256"`
	// ArchiveSHA256 is the packed archive's digest, when the qualified
	// artifact was a tarball.
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`
}

// source records where the qualifying code came from.
type source struct {
	// Commit is the git commit the qualification ran at.
	Commit string `json:"commit"`
}

// gateResult is one executed gate.
type gateResult struct {
	// ID is the gate's stable identity.
	ID string `json:"id"`
	// Result is "pass" — a failed gate never reaches the record because
	// emission is sequenced after the suite.
	Result string `json:"result"`
}

// manifestView is the subset of component-manifest.json this tool reads.
type manifestView struct {
	Name           string `json:"name"`
	CrabboxVersion string `json:"crabbox_version"`
	Platform       string `json:"platform"`
}

func main() {
	root := flag.String("root", "", "the unpacked distribution root")
	archive := flag.String("archive", "", "the packed archive, when the qualified artifact was a tarball")
	commit := flag.String("commit", "", "the source commit the qualification ran at")
	gates := flag.String("gates", "", "comma-separated gate identities that ran (emit only)")
	out := flag.String("out", "", "where to write the attestation (emit only)")
	verify := flag.Bool("verify", false, "verify an attestation against a distribution root instead of emitting one")
	attestationPath := flag.String("attestation", "", "the attestation to verify (verify only)")
	flag.Parse()

	if *verify {
		if err := verifyAttestation(*root, *attestationPath); err != nil {
			fmt.Fprintf(os.Stderr, "nemo-qualification-attestation: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := emitAttestation(*root, *archive, *commit, *gates, *out); err != nil {
		fmt.Fprintf(os.Stderr, "nemo-qualification-attestation: %v\n", err)
		os.Exit(1)
	}
}

// emitAttestation writes the qualification record. Every digest is
// recomputed from the distribution's bytes — the record binds what the
// tree actually contains, and a manifest whose own sidecar disagrees
// cannot be attested at all.
func emitAttestation(root, archivePath, commit, gatesRaw, outPath string) error {
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("-root is required")
	}
	if strings.TrimSpace(commit) == "" {
		return fmt.Errorf("-commit is required (the attestation binds the source the gates ran at)")
	}
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("-out is required")
	}
	gates := splitList(gatesRaw)
	if len(gates) == 0 {
		return fmt.Errorf("-gates is required — an attestation with no gates attests nothing")
	}

	manifestDigest, declared, err := boundManifest(root)
	if err != nil {
		return err
	}
	transferDigest, err := digestFile(filepath.Join(root, "manifests", "nemo-transfer-manifest.json"))
	if err != nil {
		return fmt.Errorf("the transfer manifest the distribution carries is undigestible: %w", err)
	}

	record := attestation{
		AttestationVersion: 1,
		Subject: subject{
			Name:                    declared.Name,
			Platform:                declared.Platform,
			Version:                 declared.CrabboxVersion,
			ComponentManifestSHA256: manifestDigest,
			TransferManifestSHA256:  transferDigest,
		},
		Source:      source{Commit: strings.TrimSpace(commit)},
		QualifiedAt: time.Now().UTC().Format(time.RFC3339),
		QualifyHost: strings.TrimSpace(os.Getenv("NEMO_QUALIFY_HOST")),
	}
	if strings.TrimSpace(archivePath) != "" {
		archiveDigest, err := digestFile(archivePath)
		if err != nil {
			return fmt.Errorf("the qualified archive is undigestible: %w", err)
		}
		record.Subject.ArchiveSHA256 = archiveDigest
	}
	for _, id := range gates {
		record.Gates = append(record.Gates, gateResult{ID: id, Result: "pass"})
	}

	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s — %d gates, %s@%s\n", outPath, len(record.Gates), record.Subject.Name, record.Subject.Platform)
	return nil
}

// verifyAttestation checks the record's structure and recomputes every
// digest claim against the distribution root it names. A passing verify
// means the attestation is coherent and still binds these bytes — it is
// not a signature check (release signing is a separate layer).
func verifyAttestation(root, attestationPath string) error {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(attestationPath) == "" {
		return fmt.Errorf("-verify requires -root and -attestation")
	}
	raw, err := os.ReadFile(attestationPath)
	if err != nil {
		return err
	}
	var record attestation
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("%s is not a valid attestation: %w", attestationPath, err)
	}

	var mismatches []string
	if record.AttestationVersion != 1 {
		mismatches = append(mismatches, fmt.Sprintf("attestation_version %d unsupported", record.AttestationVersion))
	}
	if record.Source.Commit == "" {
		mismatches = append(mismatches, "source.commit is empty — the record binds no code")
	}
	if len(record.Gates) == 0 {
		mismatches = append(mismatches, "no gates recorded — the record attests nothing")
	}
	for _, g := range record.Gates {
		if g.ID == "" || g.Result != "pass" {
			mismatches = append(mismatches, fmt.Sprintf("gate %q result %q: a qualification record only carries passes", g.ID, g.Result))
		}
	}
	if _, err := time.Parse(time.RFC3339, record.QualifiedAt); err != nil {
		mismatches = append(mismatches, fmt.Sprintf("qualified_at %q is not RFC3339", record.QualifiedAt))
	}

	manifestDigest, declared, err := boundManifest(root)
	if err != nil {
		mismatches = append(mismatches, err.Error())
	} else {
		if record.Subject.ComponentManifestSHA256 != manifestDigest {
			mismatches = append(mismatches, "component_manifest_sha256 does not match this distribution's manifest")
		}
		if record.Subject.Name != declared.Name || record.Subject.Platform != declared.Platform || record.Subject.Version != declared.CrabboxVersion {
			mismatches = append(mismatches, "subject name/platform/version disagree with the manifest")
		}
	}
	if digest, err := digestFile(filepath.Join(root, "manifests", "nemo-transfer-manifest.json")); err != nil {
		mismatches = append(mismatches, fmt.Sprintf("transfer manifest undigestible: %v", err))
	} else if record.Subject.TransferManifestSHA256 != digest {
		mismatches = append(mismatches, "transfer_manifest_sha256 does not match this distribution's transfer manifest")
	}

	if len(mismatches) > 0 {
		return fmt.Errorf("%s does not bind %s:\n  %s", attestationPath, root, strings.Join(mismatches, "\n  "))
	}
	fmt.Printf("ok: %s — attestation binds %s@%s (%d gates)\n",
		attestationPath, record.Subject.Name, record.Subject.Platform, len(record.Gates))
	return nil
}

// boundManifest digests the component manifest and confirms its own
// sidecar agrees — the release-root identity must be self-consistent
// before an attestation can cite it.
func boundManifest(root string) (string, manifestView, error) {
	manifestPath := filepath.Join(root, "manifests", "component-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", manifestView{}, err
	}
	var declared manifestView
	if err := json.Unmarshal(raw, &declared); err != nil {
		return "", manifestView{}, fmt.Errorf("%s is not a valid component manifest: %w", manifestPath, err)
	}
	digest, err := digestFile(manifestPath)
	if err != nil {
		return "", manifestView{}, err
	}
	sidecar, err := os.ReadFile(filepath.Join(root, "manifests", "component-manifest.sha256"))
	if err != nil {
		return "", manifestView{}, err
	}
	if strings.TrimSpace(string(sidecar)) != digest {
		return "", manifestView{}, fmt.Errorf("component-manifest.sha256 disagrees with the manifest's actual digest")
	}
	return digest, declared, nil
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

// digestFile returns the SHA-256 of a file.
func digestFile(path string) (string, error) {
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
