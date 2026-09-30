package shared

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"
)

// TestStartupConfirmResultPopulatedOnSuccess verifies that the
// StartupConfirmResult is populated with the correct stage, duration, and
// ready=true when the process survives the observe window.
func TestStartupConfirmResultPopulatedOnSuccess(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 50 * time.Millisecond}
	exited := make(chan error, 1)
	result, err := confirm.Wait(context.Background(), exited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stage != "timeout-window" {
		t.Fatalf("stage = %q, want timeout-window", result.Stage)
	}
	if !result.Ready {
		t.Fatal("ready = false, want true")
	}
	if result.ProcessExited {
		t.Fatal("processExited = true, want false")
	}
	if result.Duration <= 0 {
		t.Fatal("duration should be positive")
	}
}

// TestStartupConfirmResultPopulatedOnProcessExit verifies that the
// StartupConfirmResult is populated with processExited=true when the
// process exits during the observe window.
func TestStartupConfirmResultPopulatedOnProcessExit(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 50 * time.Millisecond}
	exited := make(chan error, 1)
	exited <- errors.New("exit code 1")
	result, err := confirm.Wait(context.Background(), exited)
	if err == nil {
		t.Fatal("expected error on process exit")
	}
	if result.Stage != "timeout-window" {
		t.Fatalf("stage = %q, want timeout-window", result.Stage)
	}
	if result.Ready {
		t.Fatal("ready = true, want false")
	}
	if !result.ProcessExited {
		t.Fatal("processExited = false, want true")
	}
	if result.Retryable {
		t.Fatal("retryable = true, want false for process exit")
	}
}

// TestStartupConfirmResultPopulatedOnCancellation verifies that the
// StartupConfirmResult is populated with retryable=true when the context
// is cancelled during the observe window.
func TestStartupConfirmResultPopulatedOnCancellation(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 50 * time.Millisecond}
	exited := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	result, err := confirm.Wait(ctx, exited)
	if err == nil {
		t.Fatal("expected error on cancellation")
	}
	if result.Stage != "timeout-window" {
		t.Fatalf("stage = %q, want timeout-window", result.Stage)
	}
	if result.Ready {
		t.Fatal("ready = true, want false")
	}
	if result.ProcessExited {
		t.Fatal("processExited = true, want false")
	}
	if !result.Retryable {
		t.Fatal("retryable = false, want true for cancellation")
	}
}

// TestFileHandoffConfirmResultPopulatedOnSuccess verifies that
// FileHandoffConfirm populates the result correctly when the file appears.
func TestFileHandoffConfirmResultPopulatedOnSuccess(t *testing.T) {
	confirm := FileHandoffConfirm{
		Path:            "/nonexistent/path",
		ExpectedContent: "ready",
		Timeout:         50 * time.Millisecond,
		PollInterval:    5 * time.Millisecond,
		FileReader: func(path string) ([]byte, error) {
			return []byte("ready"), nil
		},
	}
	exited := make(chan error, 1)
	result, err := confirm.Wait(context.Background(), exited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stage != "file-handoff" {
		t.Fatalf("stage = %q, want file-handoff", result.Stage)
	}
	if !result.Ready {
		t.Fatal("ready = false, want true")
	}
	if result.ProcessExited {
		t.Fatal("processExited = true, want false")
	}
}

// TestFileHandoffConfirmResultPopulatedOnProcessExit verifies that
// FileHandoffConfirm populates processExited=true when the process exits
// before the file appears.
func TestFileHandoffConfirmResultPopulatedOnProcessExit(t *testing.T) {
	confirm := FileHandoffConfirm{
		Path:            "/nonexistent/path",
		ExpectedContent: "ready",
		Timeout:         50 * time.Millisecond,
		PollInterval:    5 * time.Millisecond,
		FileReader: func(path string) ([]byte, error) {
			return nil, fs.ErrNotExist
		},
	}
	exited := make(chan error, 1)
	exited <- errors.New("process died")
	result, err := confirm.Wait(context.Background(), exited)
	if err == nil {
		t.Fatal("expected error on process exit")
	}
	if result.Stage != "file-handoff" {
		t.Fatalf("stage = %q, want file-handoff", result.Stage)
	}
	if result.Ready {
		t.Fatal("ready = true, want false")
	}
	if !result.ProcessExited {
		t.Fatal("processExited = false, want true")
	}
}

// TestFileHandoffConfirmResultPopulatedOnTimeout verifies that
// FileHandoffConfirm populates retryable=true when the file does not
// appear within the timeout.
func TestFileHandoffConfirmResultPopulatedOnTimeout(t *testing.T) {
	confirm := FileHandoffConfirm{
		Path:            "/nonexistent/path",
		ExpectedContent: "ready",
		Timeout:         30 * time.Millisecond,
		PollInterval:    5 * time.Millisecond,
		FileReader: func(path string) ([]byte, error) {
			return nil, fs.ErrNotExist
		},
	}
	exited := make(chan error, 1)
	result, err := confirm.Wait(context.Background(), exited)
	if err == nil {
		t.Fatal("expected error on timeout")
	}
	if result.Stage != "file-handoff" {
		t.Fatalf("stage = %q, want file-handoff", result.Stage)
	}
	if result.Ready {
		t.Fatal("ready = true, want false")
	}
	if !result.Retryable {
		t.Fatal("retryable = false, want true for timeout")
	}
}

// TestStartupConfirmRaceProcessExitVsTimeout verifies that the startup
// confirmation correctly handles the race between process exit and timeout.
// This is a regression test for the case where the process exits just as
// the timeout fires — the exit should win.
func TestStartupConfirmRaceProcessExitVsTimeout(t *testing.T) {
	confirm := TimeoutWindowConfirm{Timeout: 20 * time.Millisecond}
	exited := make(chan error, 1)
	// Send the exit error immediately so it races with the timeout.
	exited <- errors.New("exit code 1")
	result, err := confirm.Wait(context.Background(), exited)
	if err == nil {
		t.Fatal("expected error on process exit")
	}
	if !result.ProcessExited {
		t.Fatal("processExited = false, want true (exit should win over timeout)")
	}
}
