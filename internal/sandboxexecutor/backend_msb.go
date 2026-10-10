package sandboxexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MSBBackend executes signed job contracts in Microsandbox microVMs
// (libkrun on Apple Silicon / Linux KVM). The executor hands it a
// verified contract; the backend maps the contract's declared limits
// onto msb flags exactly — a limit the contract did not authorize is
// never invented, and a contract's declared limit is never widened.
//
// Execution model: the job's msb run process stays a managed child
// for the contract's whole life — foreground msb run propagates the
// guest command's exit code, which is the only trustworthy exit
// signal the CLI offers (inspect reports no exit code). Shutdown
// never kills a job's child: the VM's own --timeout bounds it, the
// ledger marks the watch interrupted, and the deterministic sandbox
// name lets a restarted executor reconcile what survived.
type MSBBackend struct {
	// Bin is the msb binary path (e.g. ~/.microsandbox/bin/msb).
	Bin string
	// StateDir holds captured-output artifacts (owner-only). One
	// file per job, mode 0600; the ledger row binds the file's
	// SHA-256, so the artifact is evidence, not just logs.
	StateDir string
	// ExtraArgs are additional operator-pinned msb run flags,
	// appended verbatim before the image (e.g. ["--root-disk","tmpfs:2G"]).
	ExtraArgs []string
	// NamePrefix namespaces every sandbox this backend creates —
	// Inspect refuses handles that lack it, so the backend can never
	// be pointed at sandboxes it did not launch.
	NamePrefix string
	// LaunchGrace is how long Dispatch waits for the run process to
	// die on its own before reporting the job launched. An early
	// exit is arbitrated by sandbox existence (Inspect) rather than
	// guessed. Zero uses a default.
	LaunchGrace time.Duration
	// KeepSandboxes leaves stopped VMs in place after result
	// collection — a forensics posture; default removes them since
	// the artifact store is the durable evidence.
	KeepSandboxes bool

	mu    sync.Mutex
	procs map[string]*msbProc
}

// msbProc is one running job's managed child plus its bounded
// artifact capture. finished closes exactly once when the child is
// reaped; outcome is written before the close so every reader —
// Dispatch's launch arbitration and Wait alike — sees the same
// result. A single-consumer channel here would let Dispatch steal a
// fast job's outcome and starve the monitor forever.
type msbProc struct {
	cmd      *exec.Cmd
	file     *os.File
	finished chan struct{}
	outcome  msbOutcome
}

type msbOutcome struct {
	code      int
	err       error
	sha256    string
	nbytes    int64
	truncated bool
}

// cappedWriter drops bytes past a bound while still feeding the
// hash — the artifact never exceeds the contract's output budget,
// and the hash covers what was actually stored.
type cappedWriter struct {
	w         io.Writer
	remaining int64
	written   int64
	truncated bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.truncated = true
		return len(p), nil
	}
	n := int64(len(p))
	chunk := p
	if n > c.remaining {
		chunk = p[:c.remaining]
		c.truncated = true
	}
	m, err := c.w.Write(chunk)
	c.remaining -= int64(m)
	c.written += int64(m)
	if err != nil {
		return m, err
	}
	return len(p), nil
}

// msbJobName derives the deterministic sandbox handle for a job.
// Deterministic naming is the ambiguity control: if Dispatch's
// outcome is uncertain, the name is still known and Inspect can
// reconcile whether a VM actually exists.
func (b *MSBBackend) msbJobName(jobID string) string {
	prefix := b.NamePrefix
	if prefix == "" {
		prefix = "sx-"
	}
	name := prefix + jobID
	// msb bounds names at 128 UTF-8 bytes; the tail matters more
	// than the head for uniqueness, so truncate the middle.
	if len(name) > 120 {
		sum := sha256.Sum256([]byte(name))
		name = name[:100] + "-" + hex.EncodeToString(sum[:])[:16]
	}
	return name
}

// runOnce executes a short msb utility call (inspect, rm) under ctx.
func (b *MSBBackend) runOnce(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, b.Bin, args...)
	cmd.Stdin = nil
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return []byte(out.String()), err
}

// runArgs maps a verified contract onto msb run flags, 1:1.
func (b *MSBBackend) runArgs(job *JobContractV1, name string) ([]string, error) {
	args := []string{"run", "--no-stdin", "--no-tty", "-n", name}
	if job.Resources.CPUs > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%g", job.Resources.CPUs))
	}
	if job.Resources.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dM", job.Resources.MemoryMB))
	}
	args = append(args, "--timeout", fmt.Sprintf("%ds", job.Resources.TimeoutSeconds))
	if job.Resources.Pids > 0 {
		args = append(args, "--rlimit", fmt.Sprintf("nproc=%d", job.Resources.Pids))
	}
	switch job.Network.Mode {
	case NetworkNone:
		args = append(args, "--net", "none")
	case NetworkAllowlist:
		args = append(args, "--net-default", "deny")
		for _, allow := range job.Network.Allow {
			args = append(args, "--net-rule", "allow@"+allow)
		}
	case NetworkPublic:
		args = append(args, "--net", "public")
	default:
		return nil, fmt.Errorf("contract network mode %q has no backend mapping", job.Network.Mode)
	}
	for _, kv := range job.Env {
		args = append(args, "-e", kv)
	}
	for _, m := range job.Filesystem.Mounts {
		spec := m.Source + ":" + m.Dest
		if m.Options != "" {
			spec += ":" + m.Options
		}
		args = append(args, "-v", spec)
	}
	args = append(args, b.ExtraArgs...)
	args = append(args, job.Image, "--")
	args = append(args, job.Argv...)
	return args, nil
}

// Dispatch starts the job's microVM: spawn `msb run` as a managed
// child streaming output into the bounded artifact file, wait a
// launch-grace window, then classify:
//
//   - still running past grace  → launched (RUNNING)
//   - early exit + sandbox exists → the VM ran; launched, the
//     monitor will collect the real exit code
//   - early exit + no sandbox    → definitive refusal
//   - dispatch ctx expires       → ambiguous; the deterministic
//     handle is returned so the ledger records where to look
func (b *MSBBackend) Dispatch(ctx context.Context, job *JobContractV1) (string, error) {
	if job == nil {
		return "", fmt.Errorf("dispatch requires a signed job contract")
	}
	name := b.msbJobName(job.JobID)
	args, err := b.runArgs(job, name)
	if err != nil {
		return "", err
	}
	bound := int64(job.Resources.MaxOutputBytes)
	if bound <= 0 {
		bound = 8 << 20
	}
	if err := os.MkdirAll(b.StateDir, 0o700); err != nil {
		return "", fmt.Errorf("create artifact dir %s: %w", b.StateDir, err)
	}
	artifactPath := filepath.Join(b.StateDir, name+".out")
	file, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create artifact %s: %w", artifactPath, err)
	}

	cmd := exec.Command(b.Bin, args...)
	cmd.Stdin = nil
	capw := &cappedWriter{w: file, remaining: bound}
	hasher := sha256.New()
	cmd.Stdout = io.MultiWriter(capw, hasher)
	cmd.Stderr = io.MultiWriter(capw, hasher)

	if err := cmd.Start(); err != nil {
		file.Close()
		os.Remove(artifactPath)
		return "", fmt.Errorf("spawn msb run: %w", err)
	}
	proc := &msbProc{cmd: cmd, file: file, finished: make(chan struct{})}
	go func() {
		werr := cmd.Wait()
		code := 0
		if werr != nil {
			var ee *exec.ExitError
			if errors.As(werr, &ee) {
				code = ee.ExitCode()
			} else {
				code = -1
			}
		}
		file.Sync()
		file.Close()
		proc.outcome = msbOutcome{
			code: code, err: werr,
			sha256: hex.EncodeToString(hasher.Sum(nil)),
			nbytes: capw.written, truncated: capw.truncated,
		}
		close(proc.finished)
	}()

	b.mu.Lock()
	if b.procs == nil {
		b.procs = map[string]*msbProc{}
	}
	b.procs[name] = proc
	b.mu.Unlock()

	grace := b.LaunchGrace
	if grace <= 0 {
		grace = 1500 * time.Millisecond
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-proc.finished:
		out := proc.outcome
		// The run process already exited. Did a VM exist? If yes,
		// the job reached execution — that is a dispatch, not a
		// refusal; the monitor reports the real exit code.
		ictx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		live, ierr := b.Inspect(ictx, name)
		cancel()
		if ierr != nil {
			// Process died AND we cannot prove a VM existed —
			// ambiguous by construction.
			return name, fmt.Errorf("%w: run exited early (code %d) and sandbox existence is unverifiable: %v",
				ErrAmbiguousDispatch, out.code, ierr)
		}
		if live || out.code == 0 {
			return name, nil
		}
		// A nonzero early exit with a stopped sandbox still means
		// the VM existed — Inspect's "stopped" reports not-live, so
		// probe existence directly.
		exists, eerr := b.sandboxExists(name)
		if eerr != nil {
			return name, fmt.Errorf("%w: run exited early (code %d): %v", ErrAmbiguousDispatch, out.code, eerr)
		}
		if exists {
			return name, nil
		}
		b.dropProc(name)
		return "", fmt.Errorf("msb run failed before launch (exit %d): %s", out.code, artifactHead(artifactPath))
	case <-timer.C:
		return name, nil
	case <-ctx.Done():
		return name, fmt.Errorf("%w: dispatch deadline expired before launch settled: %v", ErrAmbiguousDispatch, ctx.Err())
	}
}

func (b *MSBBackend) dropProc(name string) {
	b.mu.Lock()
	delete(b.procs, name)
	b.mu.Unlock()
}

// sandboxExists reports whether the handle names a sandbox at all —
// live or stopped — via `msb inspect` succeeding.
func (b *MSBBackend) sandboxExists(name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := b.inspectRaw(ctx, name)
	if err == nil {
		return true, nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "not found") ||
		strings.Contains(strings.ToLower(err.Error()), "no sandbox") ||
		strings.Contains(strings.ToLower(err.Error()), "does not exist") {
		return false, nil
	}
	return false, err
}

// inspectRaw returns the parsed `msb inspect --format json` document.
func (b *MSBBackend) inspectRaw(ctx context.Context, name string) (map[string]any, error) {
	out, err := b.runOnce(ctx, "inspect", "--format", "json", name)
	if err != nil {
		return nil, fmt.Errorf("msb inspect %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("msb inspect %s: malformed json: %w", name, err)
	}
	return doc, nil
}

// Inspect reports whether the handle names a live sandbox — the
// reconcile aid after a daemon restart, never a re-dispatch trigger.
// It refuses handles outside this backend's namespace: the executor
// must never query a sandbox it did not create.
func (b *MSBBackend) Inspect(ctx context.Context, handle string) (bool, error) {
	prefix := b.NamePrefix
	if prefix == "" {
		prefix = "sx-"
	}
	if !strings.HasPrefix(handle, prefix) {
		return false, fmt.Errorf("handle %q is outside this backend's namespace %q", handle, prefix)
	}
	doc, err := b.inspectRaw(ctx, handle)
	if err != nil {
		return false, err
	}
	status, _ := doc["status"].(string)
	switch strings.ToLower(status) {
	case "running", "starting", "paused", "stopping":
		return true, nil
	default:
		return false, nil
	}
}

// Wait blocks on the job's managed run process, then reports the
// bound result: guest exit code plus the artifact path, size, and
// SHA-256. Context cancellation abandons the watch only — the child
// (and its VM) is deliberately left alive under its contract timeout.
func (b *MSBBackend) Wait(ctx context.Context, handle string) (*ExecResult, error) {
	b.mu.Lock()
	proc := b.procs[handle]
	b.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("no managed run for handle %q (dispatch belonged to another lifetime?)", handle)
	}
	select {
	case <-proc.finished:
		out := proc.outcome
		b.dropProc(handle)
		res := &ExecResult{
			ExitCode:     out.code,
			OutputSHA256: out.sha256,
			OutputPath:   filepath.Join(b.StateDir, handle+".out"),
			OutputBytes:  out.nbytes,
			Truncated:    out.truncated,
			FinishedAt:   time.Now().UTC(),
		}
		if !b.KeepSandboxes {
			rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _ = b.runOnce(rmCtx, "rm", "-f", handle)
			cancel()
		}
		return res, nil
	case <-ctx.Done():
		// The daemon is stopping: the job's ledger row stays RUNNING
		// and reconcile marks it ambiguous next open. The child keeps
		// running under its own contract timeout.
		return nil, ctx.Err()
	}
}

// Close abandons watches without touching the managed children —
// their contract timeouts bound them, and the next ledger lifetime
// reconciles their sandbox handles.
func (b *MSBBackend) Close() error { return nil }

// Name is the provider identity receipts and ledger rows attest.
func (b *MSBBackend) Name() string { return "microsandbox" }

// artifactHead reads a small prefix of a failed launch's captured
// output for the refusal message — bounded, never the whole file.
func artifactHead(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

var _ Backend = (*MSBBackend)(nil)
