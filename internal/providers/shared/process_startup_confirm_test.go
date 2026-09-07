package shared

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTimeoutWindowConfirmSurvivesWindow(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 50 * time.Millisecond}
	exited := make(chan error, 1)
	// Don't send on exited — simulate a surviving process.
	err := confirm.Wait(context.Background(), nil, exited)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
}

func TestTimeoutWindowConfirmDetectsExit(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 5 * time.Second}
	exited := make(chan error, 1)
	exited <- nil // Process exited immediately.
	err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected exit error, got nil")
	}
}

func TestTimeoutWindowConfirmDetectsContextCancellation(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 5 * time.Second}
	exited := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := confirm.Wait(ctx, nil, exited)
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
	err := confirm.Wait(context.Background(), nil, exited)
	if err != nil {
		t.Fatalf("wait: %v", err)
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
	err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
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
	err := confirm.Wait(context.Background(), nil, exited)
	if err == nil {
		t.Fatal("expected exit error, got nil")
	}
}

func TestProcessExitConfirmReturnsExitError(t *testing.T) {
	confirm := ProcessExitConfirm{Timeout: 5 * time.Second}
	exited := make(chan error, 1)
	exited <- nil
	err := confirm.Wait(context.Background(), nil, exited)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
}

func TestProcessExitConfirmTimesOut(t *testing.T) {
	confirm := ProcessExitConfirm{Timeout: 50 * time.Millisecond}
	exited := make(chan error, 1)
	err := confirm.Wait(context.Background(), nil, exited)
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
	err := confirm.Wait(ctx, nil, exited)
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
	err := confirm.Wait(context.Background(), nil, exited)
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
	err := confirm.Wait(ctx, nil, exited)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
}
