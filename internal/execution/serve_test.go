package execution

import (
	"context"
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

	var snapshot capability.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if len(snapshot.RegistrySHA256) != 64 {
		t.Fatalf("registry digest = %q, want a 64-character hex digest", snapshot.RegistrySHA256)
	}
	if len(snapshot.Descriptors) == 0 {
		t.Fatal("snapshot must contain the built-in descriptors")
	}

	info, err := os.Stat(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("snapshot mode = %04o, want 0600", perm)
	}
}
