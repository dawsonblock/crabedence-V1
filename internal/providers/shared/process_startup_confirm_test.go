package shared

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTimeoutWindowConfirmSurvivesWindow(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 50 * time.Millisecond}
	exited := make(chan error, 1)
	// Don't send on exited — simulate a surviving process.
	result, err := confirm.Wait(context.Background(), nil, exited)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !result.Ready {
		t.Fatalf("expected Ready=true, got false")
	}
	if result.Stage != "timeout-window" {
		t.Fatalf("expected Stage=timeout-window, got %s", result.Stage)
	}
}

func TestTimeoutWindowConfirmDetectsExit(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 5 * time.Second}
	exited := make(chan error, 1)
	exited <- nil // Process exited immediately.
	result, err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected exit error, got nil")
	}
	if !result.ProcessExited {
		t.Fatalf("expected ProcessExited=true, got false")
	}
}

func TestTimeoutWindowConfirmDetectsContextCancellation(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 5 * time.Second}
	exited := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := confirm.Wait(ctx, nil, exited)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
}

func TestFileHandoffConfirmWaitsForFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ack")
	expected := "ready"

	// Write the file after a short delay.
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(path, []byte(expected), 0o600)
	}()

	confirm := FileHandoffConfirm{
		Path:            path,
		ExpectedContent: expected,
		Timeout:         2 * time.Second,
		PollInterval:    10 * time.Millisecond,
	}
	exited := make(chan error, 1)
	result, err := confirm.Wait(context.Background(), nil, exited)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !result.Ready {
		t.Fatalf("expected Ready=true")
	}
	if result.Stage != "file-handoff" {
		t.Fatalf("expected Stage=file-handoff, got %s", result.Stage)
	}
}

func TestFileHandoffConfirmTimesOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "never-appears")
	confirm := FileHandoffConfirm{
		Path:            path,
		ExpectedContent: "ready",
		Timeout:         50 * time.Millisecond,
		PollInterval:    10 * time.Millisecond,
	}
	exited := make(chan error, 1)
	result, err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !result.Retryable {
		t.Fatalf("expected Retryable=true for timeout")
	}
}

func TestFileHandoffConfirmDetectsExit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ack")
	confirm := FileHandoffConfirm{
		Path:            path,
		ExpectedContent: "ready",
		Timeout:         5 * time.Second,
		PollInterval:    10 * time.Millisecond,
	}
	exited := make(chan error, 1)
	exited <- nil
	result, err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected exit error, got nil")
	}
	if !result.ProcessExited {
		t.Fatalf("expected ProcessExited=true")
	}
}

func TestProcessExitConfirmReturnsExitError(t *testing.T) {
	confirm := ProcessExitConfirm{Timeout: 5 * time.Second}
	exited := make(chan error, 1)
	exited <- nil
	result, err := confirm.Wait(context.Background(), nil, exited)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !result.Ready {
		t.Fatalf("expected Ready=true for exit code 0")
	}
	if !result.ProcessExited {
		t.Fatalf("expected ProcessExited=true")
	}
}

func TestProcessExitConfirmTimesOut(t *testing.T) {
	confirm := ProcessExitConfirm{Timeout: 50 * time.Millisecond}
	exited := make(chan error, 1)
	_, err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestFileHandoffConfirmContextCancelBeatsReadyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ack")
	// File already exists with correct content.
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	confirm := FileHandoffConfirm{
		Path:            path,
		ExpectedContent: "ready",
		Timeout:         5 * time.Second,
		PollInterval:    10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Already cancelled.
	exited := make(chan error, 1)
	_, err := confirm.Wait(ctx, nil, exited)
	if err == nil {
		t.Fatal("expected context error when context is already cancelled, got nil")
	}
}

func TestFileHandoffConfirmExitBeatsReadyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ack")
	// File already exists with correct content.
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	confirm := FileHandoffConfirm{
		Path:            path,
		ExpectedContent: "ready",
		Timeout:         5 * time.Second,
		PollInterval:    10 * time.Millisecond,
	}
	exited := make(chan error, 1)
	exited <- nil // Process already exited.
	_, err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected exit error when process already exited, got nil")
	}
}

func TestFileHandoffConfirmDetectsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ack")
	confirm := FileHandoffConfirm{
		Path:            path,
		ExpectedContent: "ready",
		Timeout:         5 * time.Second,
		PollInterval:    10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	exited := make(chan error, 1)
	_, err := confirm.Wait(ctx, nil, exited)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
}

// pathError builds an *os.PathError with the given syscall errno, matching
// the shape os.ReadFile returns on Unix.
func pathError(op, path string, errno syscall.Errno) *os.PathError {
	return &os.PathError{Op: op, Path: path, Err: errno}
}

// TestIsTransientFileErrorClassification pins the retry-vs-fail decision for
// every errno the startup handoff can encounter. Persistent configuration
// errors (EACCES, ENOTDIR, ELOOP, EISDIR) must fail immediately so the
// caller sees the real cause instead of a misleading "timed out". Genuine
// transient conditions (EAGAIN, EINTR, ESTALE, EBUSY, ETXTBSY) retry.
func TestIsTransientFileErrorClassification(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		transient bool
	}{
		{"EAGAIN is transient", pathError("open", "/x", syscall.EAGAIN), true},
		{"EINTR is transient", pathError("open", "/x", syscall.EINTR), true},
		{"ESTALE is transient", pathError("open", "/x", syscall.ESTALE), true},
		{"EBUSY is transient", pathError("open", "/x", syscall.EBUSY), true},
		{"ETXTBSY is transient", pathError("open", "/x", syscall.ETXTBSY), true},
		{"EACCES is persistent", pathError("open", "/x", syscall.EACCES), false},
		{"EPERM is persistent", pathError("open", "/x", syscall.EPERM), false},
		{"ENOTDIR is persistent", pathError("open", "/x", syscall.ENOTDIR), false},
		{"ELOOP is persistent", pathError("open", "/x", syscall.ELOOP), false},
		{"EISDIR is persistent", pathError("open", "/x", syscall.EISDIR), false},
		{"ENAMETOOLONG is persistent", pathError("open", "/x", syscall.ENAMETOOLONG), false},
		{"EROFS is persistent", pathError("open", "/x", syscall.EROFS), false},
		{"ENOENT is persistent here (caller handles via os.ErrNotExist)", pathError("open", "/x", syscall.ENOENT), false},
		{"non-PathError is persistent", fs.ErrInvalid, false},
		{"nil is persistent", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTransientFileError(tc.err)
			if got != tc.transient {
				t.Fatalf("isTransientFileError(%v) = %v, want %v", tc.err, got, tc.transient)
			}
		})
	}
}

// TestFileHandoffConfirmFailsImmediatelyOnPermissionDenied verifies that a
// persistent filesystem error (EACCES) surfaces immediately with the real
// cause, not after polling until timeout. This is the regression guard for
// the plan's "persistent FS errors never degrade into timeouts" gate.
func TestFileHandoffConfirmFailsImmediatelyOnPermissionDenied(t *testing.T) {
	// Create a directory with no read permission for the ack file path.
	// On Unix, ReadFile inside it returns EACCES, which isTransientFileError
	// classifies as persistent, so Wait must return the EACCES error
	// immediately rather than timing out.
	dir := t.TempDir()
	parent := filepath.Join(dir, "noperm")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	ackPath := filepath.Join(parent, "ack")
	// Write the file, then strip parent read/search permission so ReadFile
	// fails with EACCES. Restore in a defer so cleanup can remove it.
	if err := os.WriteFile(ackPath, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0o755) //nolint:errcheck

	confirm := FileHandoffConfirm{
		Path:            ackPath,
		ExpectedContent: "ready",
		Timeout:         2 * time.Second,
		PollInterval:    10 * time.Millisecond,
	}
	exited := make(chan error, 1)
	start := time.Now()
	_, err := confirm.Wait(context.Background(), nil, exited)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected EACCES error, got nil")
	}
	// Must fail well before the 2s timeout — immediate means immediate.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("EACCES took %s to surface; persistent error should fail immediately, not poll", elapsed)
	}
}
