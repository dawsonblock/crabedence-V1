package execution

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
)

// TestServeWritesRegistrySnapshotOnAFreshDirectory proves serve exports
// the registry snapshot into the socket directory on a fresh machine:
// the directory does not exist until Service.Start creates and secures
// it, so a snapshot written before startup would fail with ENOENT and
// take the whole service down.
func TestServeWritesRegistrySnapshotOnAFreshDirectory(t *testing.T) {
	t.Setenv("CRABEDENCE_STORE_BACKEND", "none")

	parent := shortSocketDir(t)
	// The socket directory deliberately does not exist yet.
	dir := filepath.Join(parent, "crabedence")
	socketPath := filepath.Join(dir, "execution.sock")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ServeOptions{SocketPath: socketPath}) }()

	snapshotPath := filepath.Join(dir, "capabilities.json")
	deadline := time.Now().Add(10 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		if payload, err := os.ReadFile(snapshotPath); err == nil {
			data = payload
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned an error: %v", err)
	}
	if data == nil {
		t.Fatal("serve must export the registry snapshot next to its socket")
	}

	var envelope capability.SnapshotEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if len(envelope.RegistrySHA256) != 64 {
		t.Fatalf("registry digest = %q, want a 64-character hex digest", envelope.RegistrySHA256)
	}
	if envelope.CanonicalPayload == "" {
		t.Fatal("envelope must carry the canonical payload bytes")
	}
	// The digest must cover exactly the bytes the envelope carries.
	payload, err := base64.StdEncoding.DecodeString(envelope.CanonicalPayload)
	if err != nil {
		t.Fatalf("canonical payload is not valid base64: %v", err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != envelope.RegistrySHA256 {
		t.Fatal("registry digest does not cover the canonical payload it ships with")
	}
	var descriptors []map[string]any
	if err := json.Unmarshal(payload, &descriptors); err != nil {
		t.Fatalf("canonical payload is not a descriptor array: %v", err)
	}
	if len(descriptors) == 0 {
		t.Fatal("snapshot must contain the built-in descriptors")
	}
	// The registry is static for a release: the complete built-in
	// capability surface is present even when a deployment has no
	// GitHub credentials (adapter availability is runtime state, not
	// registry membership).
	ids := make(map[string]bool, len(descriptors))
	for _, descriptor := range descriptors {
		if id, ok := descriptor["id"].(string); ok {
			ids[id] = true
		}
	}
	for _, want := range []string{"system.echo", "system.info", "test.counter.increment", "github.issue.create", "github.issue.get"} {
		if !ids[want] {
			t.Fatalf("registry snapshot is missing %s (registry membership must not depend on deployment configuration)", want)
		}
	}

	info, err := os.Stat(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("snapshot mode = %04o, want 0600", perm)
	}
}

// TestServeWritesVerifiableRuntimeIdentity proves the deployment
// identity export: a runtime configuration digest that is separate from
// the registry digest, covers the exact canonical bytes it ships with,
// and records only normalized, non-secret configuration.
func TestServeWritesVerifiableRuntimeIdentity(t *testing.T) {
	t.Setenv("CRABEDENCE_STORE_BACKEND", "none")
	t.Setenv("CRABBOX_GITHUB_ENABLED", "false")
	t.Setenv("CRABBOX_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")

	parent := shortSocketDir(t)
	dir := filepath.Join(parent, "crabedence")
	socketPath := filepath.Join(dir, "execution.sock")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ServeOptions{SocketPath: socketPath, Release: "0.52.0-rc.1"})
	}()

	identityPath := filepath.Join(dir, "runtime-identity.json")
	deadline := time.Now().Add(10 * time.Second)
	var identityData []byte
	for time.Now().Before(deadline) {
		if payload, err := os.ReadFile(identityPath); err == nil {
			identityData = payload
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned an error: %v", err)
	}
	if identityData == nil {
		t.Fatal("serve must export the runtime identity next to its socket")
	}

	var envelope RuntimeIdentityEnvelope
	if err := json.Unmarshal(identityData, &envelope); err != nil {
		t.Fatalf("runtime identity is not valid JSON: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.CanonicalPayload)
	if err != nil {
		t.Fatalf("runtime identity payload is not valid base64: %v", err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != envelope.RuntimeConfigurationSHA256 {
		t.Fatal("runtime configuration digest does not cover the canonical payload it ships with")
	}

	var config RuntimeConfiguration
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatalf("runtime identity payload is not a configuration: %v", err)
	}
	if config.Release != "0.52.0-rc.1" {
		t.Fatalf("release identity = %q, want 0.52.0-rc.1", config.Release)
	}
	if config.EffectStore != "none" {
		t.Fatalf("effect store = %q, want none", config.EffectStore)
	}
	// GitHub is disabled in this deployment: it must not appear as an
	// enabled adapter, and the registry digest must still be the static
	// release registry (registry membership is independent of adapter
	// configuration).
	for _, adapter := range config.EnabledAdapters {
		if adapter == "github" {
			t.Fatal("a disabled adapter must not appear in the runtime configuration")
		}
	}
	if len(config.RegistrySHA256) != 64 {
		t.Fatalf("registry digest = %q, want a 64-character hex digest", config.RegistrySHA256)
	}

	var snapshot capability.SnapshotEnvelope
	snapshotData, err := os.ReadFile(filepath.Join(dir, "capabilities.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(snapshotData, &snapshot); err != nil {
		t.Fatal(err)
	}
	if config.RegistrySHA256 != snapshot.RegistrySHA256 {
		t.Fatalf("runtime identity registry digest %s does not match the served registry %s",
			config.RegistrySHA256, snapshot.RegistrySHA256)
	}
	if envelope.RuntimeConfigurationSHA256 == snapshot.RegistrySHA256 {
		t.Fatal("runtime configuration identity must be distinct from the registry identity")
	}
}
