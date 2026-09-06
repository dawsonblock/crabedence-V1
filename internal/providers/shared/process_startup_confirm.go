package shared

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// TimeoutWindowConfirm is the simplest startup confirmation strategy: the
// process is considered ready if it survives the observe timeout without
// exiting. This is Tart's default behavior — a VM that doesn't crash within
// the startup window is presumed booted.
type TimeoutWindowConfirm struct {
	// Timeout is the survival window. If zero, the caller's ObserveTimeout
	// from ProcessStartRequest is used.
	Timeout time.Duration
}

func (c TimeoutWindowConfirm) Wait(ctx context.Context, _ ProcessHandle, exited <-chan error) error {
	timeout := c.Timeout
	if timeout <= 0 {
		// Fall back to a reasonable default if the caller didn't set one.
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
		if data, err := os.ReadFile(c.Path); err == nil && strings.TrimSpace(string(data)) == c.ExpectedContent {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-exited:
			return fmt.Errorf("process exited before handoff: %v", err)
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for %s", c.Path)
		case <-ticker.C:
		}
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
