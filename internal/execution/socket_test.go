package execution

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
)

// Socket-path hardening tests: startup must fail closed on any
// filesystem object it cannot prove is safe, and must never remove
// something that is not a stale socket owned by the current user.

func newSocketTestService(path string) *Service {
	return NewService(capability.NewRegistry(), succeedHandler{}, path)
}

// shortSocketDir returns a private owner-only directory with a short
// path — macOS caps Unix socket paths at 104 bytes, and t.TempDir()
// embeds the test name.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cbx-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestStartClearsStaleSocketAndSecuresIt(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "sock")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(dir, "execution.sock")

	// Create a real stale socket the way a crashed service would:
	// Go's listener unlinks on close by default, so disable that.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	if _, err := os.Lstat(sockPath); err != nil {
		t.Fatalf("stale socket file should remain after close: %v", err)
	}

	svc := newSocketTestService(sockPath)
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start should clear a stale socket it owns: %v", err)
	}
	defer svc.Stop()

	info, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected a socket at %s, got mode %s", sockPath, info.Mode())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %04o, want 0600", perm)
	}
}

func TestStartRefusesRegularFileAtSocketPath(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "execution.sock")
	if err := os.WriteFile(sockPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := newSocketTestService(sockPath)
	if err := svc.Start(context.Background()); err == nil {
		svc.Stop()
		t.Fatal("Start must refuse a regular file occupying the socket path")
	}

	data, readErr := os.ReadFile(sockPath)
	if readErr != nil {
		t.Fatalf("regular file was removed by Start: %v", readErr)
	}
	if string(data) != "not a socket" {
		t.Fatalf("regular file content changed: %q", data)
	}
}

func TestStartRefusesDirectoryAtSocketPath(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "execution.sock")
	if err := os.MkdirAll(sockPath, 0o700); err != nil {
		t.Fatal(err)
	}

	svc := newSocketTestService(sockPath)
	if err := svc.Start(context.Background()); err == nil {
		svc.Stop()
		t.Fatal("Start must refuse a directory occupying the socket path")
	}
	if _, err := os.Lstat(sockPath); err != nil {
		t.Fatalf("directory was removed by Start: %v", err)
	}
}

func TestStartRefusesSymlinkAtSocketPath(t *testing.T) {
	dir := shortSocketDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "execution.sock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	svc := newSocketTestService(link)
	if err := svc.Start(context.Background()); err == nil {
		svc.Stop()
		t.Fatal("Start must refuse a symlink occupying the socket path")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink was removed by Start: %v", err)
	}
}

func TestStartRefusesSymlinkedSocketDirectory(t *testing.T) {
	realDir := shortSocketDir(t)
	linkParent := shortSocketDir(t)
	link := filepath.Join(linkParent, "sock")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	svc := newSocketTestService(filepath.Join(link, "execution.sock"))
	if err := svc.Start(context.Background()); err == nil {
		svc.Stop()
		t.Fatal("Start must refuse a symlinked socket directory")
	}
}

func TestStartSecuresSocketDirectory(t *testing.T) {
	dir := filepath.Join(shortSocketDir(t), "sock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	svc := newSocketTestService(filepath.Join(dir, "execution.sock"))
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("socket directory mode = %04o, want 0700", perm)
	}
}

func TestStartFailsWhenDirectoryCannotBeCreated(t *testing.T) {
	dir := shortSocketDir(t)
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := newSocketTestService(filepath.Join(blocker, "sub", "execution.sock"))
	if err := svc.Start(context.Background()); err == nil {
		svc.Stop()
		t.Fatal("Start must fail when the socket directory cannot be created")
	}
}
