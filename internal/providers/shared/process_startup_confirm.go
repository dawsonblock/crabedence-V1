package shared

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"
)

// TimeoutWindowConfirm is the simplest startup confirmation strategy: the
// process is considered ready if it survives the observe timeout without
// exiting. This is Tart's default behavior — a VM that doesn't crash within
// the startup window is presumed booted.
type TimeoutWindowConfirm struct {
	// Timeout is the survival window. If zero, defaults to 2s.
	Timeout time.Duration
}

func (c TimeoutWindowConfirm) Wait(ctx context.Context, _ ProcessHandle, exited <-chan error) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case err := <-exited:
		if err != nil {
			return fmt.Errorf("process exited during startup: %w", err)
		}
		return fmt.Errorf("process exited unexpectedly during startup")
	case <-timer.C:
		return nil
	}
}

// FileHandoffConfirm waits for a file to appear with expected content, which
// is Lume's launch-gate protocol: the wrapper script writes its PID, waits
// for a gate file, then writes an ack file. If the process exits before the
// file appears, the wait fails.
//
// Event precedence is: context cancellation > process exit > readiness.
// This means even if the expected file exists, the wait fails if the context
// is already cancelled or the process has already exited. This prevents
// false-positive readiness when the process died after writing the file but
// before the caller observed it.
type FileHandoffConfirm struct {
	// Path is the file to poll.
	Path string
	// ExpectedContent is the trimmed content that indicates readiness.
	ExpectedContent string
	// Timeout is the maximum wait. If zero, defaults to 2s.
	Timeout time.Duration
	// PollInterval is the file-check interval. If zero, defaults to 10ms.
	PollInterval time.Duration
}

func (c FileHandoffConfirm) Wait(ctx context.Context, _ ProcessHandle, exited <-chan error) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	interval := c.PollInterval
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}
	deadline := time.NewTimer(timeout)
	ticker := time.NewTicker(interval)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		// Check cancellation and exit BEFORE readiness, so that a file
		// left behind by a dead process does not produce false success.
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case err := <-exited:
			if err != nil {
				return fmt.Errorf("process exited before handoff: %w", err)
			}
			return fmt.Errorf("process exited before handoff")
		default:
		}
		// Check readiness. Distinguish "file not ready yet" (continue)
		// from actual I/O errors (fail immediately).
		if ready, err := c.checkReady(); err != nil {
			return fmt.Errorf("read handoff file %s: %w", c.Path, err)
		} else if ready {
			// Re-check exit one more time before committing readiness,
			// to close the race between file-write and process-death.
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case err := <-exited:
				if err != nil {
					return fmt.Errorf("process exited before handoff: %w", err)
				}
				return fmt.Errorf("process exited before handoff")
			default:
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case err := <-exited:
			if err != nil {
				return fmt.Errorf("process exited before handoff: %w", err)
			}
			return fmt.Errorf("process exited before handoff")
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for %s", c.Path)
		case <-ticker.C:
		}
	}
}

// checkReady returns (true, nil) if the file exists with expected content,
// (false, nil) if the file is not yet ready (missing or wrong content), or
// (false, err) for unexpected I/O errors (permission denied, etc.).
func (c FileHandoffConfirm) checkReady() (bool, error) {
	data, err := os.ReadFile(c.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		// Treat "file exists but not ready" as not-ready rather than
		// an error — the file may be mid-write.
		if isTransientFileError(err) {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(string(data)) == c.ExpectedContent, nil
}

// isTransientFileError returns true for errors that are likely to resolve
// on retry (file being written, temporary lock, etc.). It uses an explicit
// errno allowlist rather than treating every *os.PathError as transient,
// since many PathErrors (EACCES due to permissions, ENOTDIR, ELOOP, etc.)
// represent persistent configuration or filesystem problems that should
// fail immediately rather than poll until timeout.
func isTransientFileError(err error) bool {
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		return false
	}
	errno, ok := pathErr.Err.(syscall.Errno)
	if !ok {
		return false
	}
	switch errno {
	case syscall.ENOENT, fs.ErrNotExist:
		// File doesn't exist yet — may appear during startup.
		return true
	case syscall.EAGAIN, syscall.EINTR:
		// Resource temporarily unavailable / interrupted — retryable.
		return true
	default:
		return false
	}
}

// ProcessExitConfirm waits for the process to exit (used when the process
// should complete during startup, e.g. a one-shot command). It returns nil
// if the process exits with code 0, or an error with the exit details.
// This is not used by Tart/Lume but is provided for providers that need
// exit-based readiness (e.g. smoke tests).
type ProcessExitConfirm struct {
	// Timeout bounds the wait. If zero, waits indefinitely.
	Timeout time.Duration
}

func (c ProcessExitConfirm) Wait(ctx context.Context, _ ProcessHandle, exited <-chan error) error {
	var timeoutCh <-chan time.Time
	if c.Timeout > 0 {
		timer := time.NewTimer(c.Timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timeoutCh:
		return fmt.Errorf("process did not exit within %s", c.Timeout)
	case err := <-exited:
		return err
	}
}

// Compile-time checks.
var _ ProcessStartupConfirm = TimeoutWindowConfirm{}
var _ ProcessStartupConfirm = FileHandoffConfirm{}
var _ ProcessStartupConfirm = ProcessExitConfirm{}
