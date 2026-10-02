package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

// distributionTree assembles a synthetic distribution with the components the
// manifest requires.
func distributionTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "bin", "crabbox"), "crabbox-binary\n")
	writeFile(t, filepath.Join(root, "bin", "nemo-crabedence-runtime"), "runtime-binary\n")
	writeFile(t, filepath.Join(root, "bin", "nemo-plugin-host"), "plugin-host-binary\n")
	writeFile(t, filepath.Join(root, "share", "capability-invocation-v1.json"), "{}\n")
	writeFile(t, filepath.Join(root, "share", "capability-registry-envelope.json"), `{"registry_sha256":"abc123","canonical_payload":"e30="}`+"\n")
	writeFile(t, filepath.Join(root, "manifests", "nemo-transfer-manifest.json"), `{
  "runtime_version": "1.2.3",
  "shipped_tree_sha256": "tree-digest",
  "binaries": [
    {"role": "runtime", "package": "nemo-crabedence-runtime", "binary": "nemo-crabedence-runtime", "source": "bridges/x/src/main.rs"},
    {"role": "plugin-host", "package": "nemo-relay-native-loader", "binary": "nemo-plugin-host", "source": "crates/native-loader/src/bin/nemo-plugin-host.rs"},
    {"role": "qualification", "package": "nemo-relay-ledger", "binary": "nemo-effect-schema", "source": "crates/ledger/src/bin/nemo_effect_schema.rs"}
  ]
}`+"\n")
	return root
}

func TestComponentManifestBindsTheShippingSet(t *testing.T) {
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")

	manifest, err := buildManifest(root, transfer, "9.9.9", metadata{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if manifest.Name != "nemo-control" || manifest.CrabboxVersion != "9.9.9" {
		t.Fatalf("manifest header: %+v", manifest)
	}
	if manifest.NemoRuntimeVersion != "1.2.3" || manifest.NemoRuntimeSHA256 != "tree-digest" {
		t.Fatalf("runtime identity: %+v", manifest)
	}
	if manifest.CapabilityRegistrySHA256 != "abc123" {
		t.Fatalf("registry digest = %q, want abc123", manifest.CapabilityRegistrySHA256)
	}
	for _, c := range manifest.Components {
		if c.Name == "nemo-effect-schema" {
			t.Fatal("a qualification binary must not be bound as distribution content")
		}
	}
	if len(manifest.Components) != 6 {
		t.Fatalf("components = %d, want 6: %+v", len(manifest.Components), manifest.Components)
	}
	for _, c := range manifest.Components {
		got, err := digestFile(filepath.Join(root, filepath.FromSlash(c.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.SHA256 {
			t.Fatalf("%s: digest %s, want %s", c.Path, got, c.SHA256)
		}
	}
}

func TestComponentManifestFailsClosedOnMissingComponents(t *testing.T) {
	cases := []struct{ name, remove, wantErr string }{
		{"missing runtime binary", "bin/nemo-crabedence-runtime", "nemo-crabedence-runtime"},
		{"missing plugin host", "bin/nemo-plugin-host", "nemo-plugin-host"},
		{"missing schema", "share/capability-invocation-v1.json", "capability-invocation-v1"},
		{"missing envelope", "share/capability-registry-envelope.json", "capability-registry-envelope"},
		{"missing transfer manifest", "manifests/nemo-transfer-manifest.json", "nemo-transfer-manifest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := distributionTree(t)
			transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
			if err := os.Remove(filepath.Join(root, tc.remove)); err != nil {
				t.Fatal(err)
			}
			if _, err := buildManifest(root, transfer, "9.9.9", metadata{}); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestComponentManifestVerify(t *testing.T) {
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
	if err := writeManifest(root, transfer, "9.9.9", metadata{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := verifyManifest(root, transfer, "", ""); err != nil {
		t.Fatalf("a matching manifest must verify: %v", err)
	}

	// A tampered binary is a failure that names the component.
	if err := os.WriteFile(filepath.Join(root, "bin", "nemo-plugin-host"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := verifyManifest(root, transfer, "", "")
	if err == nil {
		t.Fatal("tampering must fail verification")
	}
	if !strings.Contains(err.Error(), "nemo-plugin-host") {
		t.Fatalf("the failure must name the component: %v", err)
	}
}

func TestComponentManifestRejectsUndeclaredFiles(t *testing.T) {
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
	if err := writeManifest(root, transfer, "9.9.9", metadata{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := verifyManifest(root, transfer, "", ""); err != nil {
		t.Fatalf("a clean distribution must verify: %v", err)
	}

	// An undeclared file is a failure that names it — the manifest must be
	// exhaustive, not merely accurate for what it lists.
	writeFile(t, filepath.Join(root, "bin", "stowaway"), "not-declared\n")
	err := verifyManifest(root, transfer, "", "")
	if err == nil {
		t.Fatal("an undeclared file must fail verification")
	}
	if !strings.Contains(err.Error(), "bin/stowaway") {
		t.Fatalf("the failure must name the undeclared file: %v", err)
	}
}

func TestComponentManifestRefusesNonRegularNodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
	if err := writeManifest(root, transfer, "9.9.9", metadata{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := verifyManifest(root, transfer, "", ""); err != nil {
		t.Fatalf("a clean distribution must verify: %v", err)
	}

	// A link or other node type at a path the manifest declares cannot stand
	// in for the file: the name matches, but the node is not what was bound.
	// Rebuild the tree for each case so failure modes stay independent.
	cases := []struct {
		name    string
		inject  func(t *testing.T, root string)
		wantErr string
	}{
		{
			"symlink at a declared path",
			func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "bin", "nemo-plugin-host")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", filepath.Join(root, "bin", "nemo-plugin-host")); err != nil {
					t.Fatal(err)
				}
			},
			"not a regular file",
		},
		{
			"symlink at an exempt path",
			func(t *testing.T, root string) {
				t.Helper()
				if err := os.Symlink("/etc/passwd", filepath.Join(root, "manifests", "component-manifest.sha256.sig")); err != nil {
					t.Fatal(err)
				}
			},
			"not regular files or directories",
		},
		{
			"symlink at a fresh path",
			func(t *testing.T, root string) {
				t.Helper()
				if err := os.Symlink("/etc/passwd", filepath.Join(root, "bin", "stowaway")); err != nil {
					t.Fatal(err)
				}
			},
			"not regular files or directories",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caseRoot := distributionTree(t)
			caseTransfer := filepath.Join(caseRoot, "manifests", "nemo-transfer-manifest.json")
			if err := writeManifest(caseRoot, caseTransfer, "9.9.9", metadata{}); err != nil {
				t.Fatalf("write: %v", err)
			}
			tc.inject(t, caseRoot)
			err := verifyManifest(caseRoot, caseTransfer, "", "")
			if err == nil {
				t.Fatal("a non-regular node must fail verification")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestComponentManifestVerifiesTheDigestSidecar(t *testing.T) {
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
	if err := writeManifest(root, transfer, "9.9.9", metadata{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := verifyManifest(root, transfer, "", ""); err != nil {
		t.Fatalf("a clean distribution must verify: %v", err)
	}

	// The release-root identity is the sidecar's claim about the manifest's
	// digest; a sidecar that says anything else is not the identity.
	writeFile(t, filepath.Join(root, "manifests", "component-manifest.sha256"), strings.Repeat("0", 64)+"\n")
	err := verifyManifest(root, transfer, "", "")
	if err == nil {
		t.Fatal("a wrong sidecar digest must fail verification")
	}
	if !strings.Contains(err.Error(), "component-manifest.sha256") {
		t.Fatalf("the failure must name the sidecar: %v", err)
	}

	// A missing sidecar is the same class of failure.
	if err := os.Remove(filepath.Join(root, "manifests", "component-manifest.sha256")); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(root, transfer, "", ""); err == nil {
		t.Fatal("a missing sidecar must fail verification")
	}
}

func TestComponentManifestCarriesTheReleaseIdentity(t *testing.T) {
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
	meta := metadata{
		Platform:      "linux_arm64",
		Build:         buildInfo{GoVersion: "go-test", RustVersion: "rustc-test", Profile: "release"},
		Qualification: []string{"runtime-e2e", "critical-path"},
	}
	manifest, err := buildManifest(root, transfer, "9.9.9", meta)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if manifest.Platform != "linux_arm64" {
		t.Fatalf("platform = %q", manifest.Platform)
	}
	if manifest.Build.RustVersion != "rustc-test" || manifest.Build.Profile != "release" {
		t.Fatalf("build metadata: %+v", manifest.Build)
	}
	if len(manifest.Qualification) != 2 {
		t.Fatalf("qualification: %+v", manifest.Qualification)
	}

	// And the identity round-trips through write+verify.
	if err := writeManifest(root, transfer, "9.9.9", meta); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := verifyManifest(root, transfer, "", ""); err != nil {
		t.Fatalf("the release identity must survive verification: %v", err)
	}
}

func TestComponentManifestRefusesAnEmptyShippingSet(t *testing.T) {
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
	writeFile(t, transfer, `{"runtime_version":"1.2.3","shipped_tree_sha256":"d","binaries":[{"role":"qualification","package":"p","binary":"q","source":"s"}]}`+"\n")
	if _, err := buildManifest(root, transfer, "9.9.9", metadata{}); err == nil || !strings.Contains(err.Error(), "no shipping binaries") {
		t.Fatalf("error = %v, want a refusal for an empty shipping set", err)
	}
}

// signWithTestKey generates an ed25519 keypair and allowed_signers file in a
// temp dir, signs the given file under the nemo-control-release namespace,
// and returns the signers path. Skips when ssh-keygen is unavailable.
func signWithTestKey(t *testing.T, file, principal string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "release-key")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", principal, "-f", key, "-q").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v: %s", err, out)
	}
	signers := filepath.Join(dir, "allowed-signers")
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pub))
	writeFile(t, signers, principal+" "+fields[0]+" "+fields[1]+"\n")
	if out, err := exec.Command("ssh-keygen", "-Y", "sign", "-n", "nemo-control-release", "-f", key, file).CombinedOutput(); err != nil {
		t.Fatalf("sign: %v: %s", err, out)
	}
	return signers
}

func TestComponentManifestAuthenticatesTheReleaseSignature(t *testing.T) {
	root := distributionTree(t)
	transfer := filepath.Join(root, "manifests", "nemo-transfer-manifest.json")
	if err := writeManifest(root, transfer, "9.9.9", metadata{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	sidecar := filepath.Join(root, "manifests", "component-manifest.sha256")
	signers := signWithTestKey(t, sidecar, "release@test")

	// Signed and named: the signature authenticates the sidecar.
	if err := verifyManifest(root, transfer, signers, "release@test"); err != nil {
		t.Fatalf("a signed release root must verify: %v", err)
	}
	// The .sig file itself is exempt — it cannot be declared inside the
	// manifest it authenticates — but everything else still is.
	writeFile(t, filepath.Join(root, "bin", "stowaway"), "not-declared\n")
	if err := verifyManifest(root, transfer, signers, "release@test"); err == nil || !strings.Contains(err.Error(), "bin/stowaway") {
		t.Fatalf("undeclared files still fail under a signed root: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "bin", "stowaway")); err != nil {
		t.Fatal(err)
	}

	// A different principal is not this distribution's release.
	if err := verifyManifest(root, transfer, signers, "mallory@evil"); err == nil {
		t.Fatal("a signature under a foreign principal must fail")
	}
	// Signers configured, signature absent: fail, not warn.
	if err := os.Remove(sidecar + ".sig"); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(root, transfer, signers, "release@test"); err == nil || !strings.Contains(err.Error(), "component-manifest.sha256.sig") {
		t.Fatalf("a missing signature must fail closed: %v", err)
	}
	// Signers configured, identity omitted: fail — an authenticated
	// signature needs a named principal.
	if err := verifyManifest(root, transfer, signers, ""); err == nil || !strings.Contains(err.Error(), "signer-identity") {
		t.Fatalf("a missing signer identity must fail: %v", err)
	}
	// And without signers configured an unsigned root still verifies —
	// local development builds are not released artifacts.
	if err := verifyManifest(root, transfer, "", ""); err != nil {
		t.Fatalf("an unsigned root without configured signers must verify: %v", err)
	}
}
