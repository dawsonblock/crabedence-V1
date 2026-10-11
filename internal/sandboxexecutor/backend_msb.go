package sandboxexecutor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// defaultMaxOutputBytes bounds captured output when a contract
// declares no max_output_bytes.
const defaultMaxOutputBytes = 8 << 20

// MSBBackend executes signed job contracts in Microsandbox microVMs
// (libkrun on Apple Silicon / Linux KVM). The executor hands it a
// verified contract; the backend maps the contract's declared limits
// onto msb flags exactly — a limit the contract did not authorize is
// never invented, and a contract's declared limit is never widened.
//
// Execution model — every job gets a fresh, exclusively created VM:
//
//  1. `msb create` boots an idle microVM under the job's deterministic
//     handle. `create` refuses an existing handle outright; `msb run`
//     would instead silently reuse a named sandbox and ignore every
//     creation flag, so a pre-created sandbox could become the
//     execution environment. The backend never calls `msb run`.
//  2. `msb inspect` proves the booted VM carries exactly the policy
//     the contract authorized — image digest, network policy,
//     resources, workdir, security profile, and the dispatch labels
//     that bind this VM to this contract. A mismatch destroys the VM
//     before any guest command runs.
//  3. `msb exec` runs the contract's argv as a managed child,
//     streaming output into the bounded artifact file. The child's
//     exit code, the artifact digest and truncation are collected
//     from that one child.
//
// The sandbox's --max-duration is pinned to the contract timeout, so
// even an abandoned VM (daemon crash, lost monitor) cannot outlive
// its authorization. Shutdown never kills a job's child: the VM's own
// --max-duration bounds it, the ledger marks the watch interrupted,
// and the deterministic sandbox name lets a restarted executor
// reconcile what survived.
type MSBBackend struct {
	// Bin is the msb binary path (e.g. ~/.microsandbox/bin/msb).
	Bin string
	// StateDir holds captured-output artifacts (owner-only). One
	// file per job, mode 0600; the ledger row binds the file's
	// SHA-256, so the artifact is evidence, not just logs.
	StateDir string
	// ExtraArgs are additional operator-pinned msb create flags,
	// appended verbatim before the image (e.g. ["--root-disk","tmpfs:2G"]).
	ExtraArgs []string
	// NamePrefix namespaces every sandbox this backend creates —
	// Inspect refuses handles that lack it, so the backend can never
	// be pointed at sandboxes it did not launch.
	NamePrefix string
	// KeepSandboxes leaves stopped VMs in place after result
	// collection — a forensics posture; default removes them since
	// the artifact store is the durable evidence.
	KeepSandboxes bool

	mu    sync.Mutex
	procs map[string]*msbProc
}

// msbProc is one running job's managed exec child plus its bounded
// artifact capture. finished closes exactly once when the child is
// reaped; outcome is written before the close so every reader —
// Dispatch's launch arbitration and Wait alike — sees the same
// result. A single-consumer channel here would let Dispatch steal a
// fast job's outcome and starve the monitor forever.
type msbProc struct {
	cmd       *exec.Cmd
	collector *outputCollector
	finished  chan struct{}
	outcome   msbOutcome
}

type msbOutcome struct {
	code      int
	err       error
	sha256    string
	nbytes    int64
	truncated bool
}

// outputCollector is the backend's single bounded artifact sink.
// stdout and stderr both arrive on separate copier goroutines, so the
// collector is internally synchronized and every byte is stored and
// hashed under the same lock — the digest covers exactly the bytes
// the artifact file holds, and a bound the contract set is never
// exceeded on disk. Bytes past the bound are drained and discarded,
// never hashed: a digest over unstored bytes would attest output the
// evidence cannot reproduce.
type outputCollector struct {
	mu        sync.Mutex
	f         *os.File
	hasher    hash.Hash
	remaining int64
	written   int64
	truncated bool
}

func newOutputCollector(f *os.File, bound int64) *outputCollector {
	if bound <= 0 {
		bound = defaultMaxOutputBytes
	}
	return &outputCollector{f: f, hasher: sha256.New(), remaining: bound}
}

func (c *outputCollector) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		if len(p) > 0 {
			c.truncated = true
		}
		return len(p), nil
	}
	chunk := p
	if int64(len(chunk)) > c.remaining {
		chunk = chunk[:c.remaining]
		c.truncated = true
	}
	n, err := c.f.Write(chunk)
	if n > 0 {
		_, _ = c.hasher.Write(chunk[:n])
		c.written += int64(n)
		c.remaining -= int64(n)
	}
	if err != nil {
		return n, err
	}
	if n < len(chunk) {
		return n, io.ErrShortWrite
	}
	return len(p), nil
}

// digest is the SHA-256 of the bytes stored in the artifact file —
// the same value a verifier recomputes from the file itself.
func (c *outputCollector) digest() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return hex.EncodeToString(c.hasher.Sum(nil))
}

func (c *outputCollector) stats() (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written, c.truncated
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

// dispatchNonce is the per-dispatch identity label — a value only
// this dispatch attempt knows, so verification proves the sandbox it
// inspects is the sandbox this Dispatch created.
func dispatchNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate dispatch identity: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// runOnce executes a short msb utility call (create, inspect, rm)
// under ctx.
func (b *MSBBackend) runOnce(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, b.Bin, args...)
	cmd.Stdin = nil
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return []byte(out.String()), err
}

// pinnedImage renders the contract's image as the immutable
// reference msb must boot: the authority-pinned digest, never a
// mutable tag the registry could have moved.
func pinnedImage(job *JobContractV2) string {
	if strings.Contains(job.Image, "@") {
		return job.Image
	}
	return job.Image + "@" + job.ImageDigest
}

// createArgs maps a verified contract onto `msb create` flags, 1:1,
// plus the dispatch labels that bind the VM to this contract.
func (b *MSBBackend) createArgs(job *JobContractV2, name, nonce string) ([]string, error) {
	args := []string{"create", "-q", "-n", name}
	if job.Resources.CPUs > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%g", job.Resources.CPUs))
	}
	if job.Resources.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dM", job.Resources.MemoryMB))
	}
	if job.Resources.DiskMB > 0 {
		args = append(args, "--root-disk", fmt.Sprintf("%dM", job.Resources.DiskMB))
	}
	// --max-duration is the VM's own hard bound: even if this
	// process dies, the sandbox cannot outlive the contract.
	args = append(args, "--max-duration", fmt.Sprintf("%ds", job.Resources.TimeoutSeconds))
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
	if job.Filesystem.Workdir != "" {
		args = append(args, "-w", job.Filesystem.Workdir)
	}
	if job.Security != "" {
		args = append(args, "--security", job.Security)
	}
	args = append(args,
		"--label", "crabedence.job="+job.JobID,
		"--label", "crabedence.dispatch="+nonce,
	)
	args = append(args, b.ExtraArgs...)
	args = append(args, pinnedImage(job))
	return args, nil
}

// execArgs maps the contract's argv onto `msb exec` inside the
// already-verified sandbox. The command timeout is pinned to the
// contract's timeout — the same bound the VM itself carries.
func (b *MSBBackend) execArgs(job *JobContractV2, name string) []string {
	args := []string{"exec", "--no-tty", "--no-stdin",
		"--timeout", fmt.Sprintf("%ds", job.Resources.TimeoutSeconds)}
	if job.Resources.Pids > 0 {
		args = append(args, "--rlimit", fmt.Sprintf("nproc=%d", job.Resources.Pids))
	}
	args = append(args, name, "--")
	args = append(args, job.Argv...)
	return args
}

// Dispatch boots the job's microVM and starts its authorized command:
//
//  1. `msb create` — exclusive creation. An existing sandbox under
//     the job's handle is a definitive refusal: the job never runs in
//     a VM this dispatch did not create.
//  2. `msb inspect` — the booted VM must carry exactly the policy the
//     contract authorized; a mismatch destroys it before any guest
//     command runs.
//  3. `msb exec` — the contract's argv as a managed child whose
//     stdout/stderr stream into the bounded artifact file.
//
// A dispatch deadline that expires mid-create is ambiguous by
// construction — the VM may exist — so the handle is returned for
// reconcile, never a blind retry.
func (b *MSBBackend) Dispatch(ctx context.Context, job *JobContractV2) (string, error) {
	if job == nil {
		return "", fmt.Errorf("dispatch requires a signed job contract")
	}
	name := b.msbJobName(job.JobID)
	nonce, err := dispatchNonce()
	if err != nil {
		return "", err
	}
	createArgs, err := b.createArgs(job, name, nonce)
	if err != nil {
		return "", err
	}

	bound := int64(job.Resources.MaxOutputBytes)
	if bound <= 0 {
		bound = defaultMaxOutputBytes
	}
	if err := os.MkdirAll(b.StateDir, 0o700); err != nil {
		return "", fmt.Errorf("create artifact dir %s: %w", b.StateDir, err)
	}
	artifactPath := filepath.Join(b.StateDir, name+".out")
	file, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create artifact %s: %w", artifactPath, err)
	}
	// refuse discards the artifact file a never-launched job would
	// otherwise leave behind.
	refuse := func(err error) (string, error) {
		file.Close()
		os.Remove(artifactPath)
		return "", err
	}

	out, cerr := b.runOnce(ctx, createArgs...)
	if cerr != nil {
		if ctx.Err() != nil {
			// The VM may exist, but this dispatch never reached exec —
			// so the artifact can never receive output. Close and
			// discard it: a stalled dispatch must leak neither a
			// descriptor nor a stale file.
			file.Close()
			os.Remove(artifactPath)
			return name, fmt.Errorf("%w: create deadline expired before the VM was proven: %v", ErrAmbiguousDispatch, ctx.Err())
		}
		if strings.Contains(strings.ToLower(string(out)), "already exists") {
			return refuse(fmt.Errorf("sandbox %q already exists — refusing to reuse a VM this dispatch did not create: %s",
				name, artifactHead(artifactPath)))
		}
		// A create can fail after the VM was already booted (a guest
		// validation error, for instance). Destroy the leftover only
		// when it carries this dispatch's identity label — proof it
		// came from this create, not from someone else.
		b.destroyIfOurs(name, nonce)
		return refuse(fmt.Errorf("msb create failed: %v: %s", cerr, strings.TrimSpace(string(out))))
	}

	// Pre-execution policy verification: the VM that boots must be
	// the VM the contract authorized, or it never runs the job.
	doc, ierr := b.inspectRaw(ctx, name)
	if ierr != nil {
		b.destroy(name)
		return refuse(fmt.Errorf("verify sandbox %s before execution: %w", name, ierr))
	}
	if verr := verifySandboxPolicy(job, name, nonce, doc); verr != nil {
		b.destroy(name)
		return refuse(fmt.Errorf("sandbox %s failed policy verification — destroyed before execution: %w", name, verr))
	}

	cmd := exec.Command(b.Bin, b.execArgs(job, name)...)
	cmd.Stdin = nil
	collector := newOutputCollector(file, bound)
	cmd.Stdout = collector
	cmd.Stderr = collector
	if err := cmd.Start(); err != nil {
		b.destroy(name)
		return refuse(fmt.Errorf("spawn msb exec: %w", err))
	}
	proc := &msbProc{cmd: cmd, collector: collector, finished: make(chan struct{})}
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
		nbytes, truncated := collector.stats()
		proc.outcome = msbOutcome{
			code: code, err: werr,
			sha256: collector.digest(),
			nbytes: nbytes, truncated: truncated,
		}
		close(proc.finished)
	}()

	b.mu.Lock()
	if b.procs == nil {
		b.procs = map[string]*msbProc{}
	}
	b.procs[name] = proc
	b.mu.Unlock()
	return name, nil
}

// destroy removes a sandbox this backend created. Failures are
// ignored by design: the VM's own --max-duration is the backstop, and
// a destroy that cannot run must not mask the verification failure
// that triggered it.
func (b *MSBBackend) destroy(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = b.runOnce(ctx, "rm", "-f", name)
}

// destroyIfOurs removes a sandbox left behind by a failed create, but
// only when its labels carry this dispatch's identity — a sandbox
// without that proof is not ours to remove (it may be a pre-existing
// trap the job is supposed to refuse, not adopt).
func (b *MSBBackend) destroyIfOurs(name, nonce string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	doc, err := b.inspectRaw(ctx, name)
	if err != nil {
		return
	}
	cfg, _ := doc["config"].(map[string]any)
	labels, _ := cfg["labels"].(map[string]any)
	if jsonString(labels, "crabedence.dispatch") == nonce {
		b.destroy(name)
	}
}

func (b *MSBBackend) dropProc(name string) {
	b.mu.Lock()
	delete(b.procs, name)
	b.mu.Unlock()
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

// Wait blocks on the job's managed exec child, then reports the bound
// result: guest exit code plus the artifact path, size, and SHA-256.
// Context cancellation abandons the watch only — the child (and its
// VM) is deliberately left alive under its contract timeout.
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
			b.destroy(handle)
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

// ─── Runtime policy verification ─────────────────────────────────────
//
// A signed contract is a claim about the VM that should run; the
// inspect document is what actually booted. verifySandboxPolicy
// compares the two and refuses on any difference — an unapproved
// setting is a refusal, never a warning. This runs before the guest
// command starts, so a VM that fails verification never executes the
// job at all.

func jsonString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func jsonNumber(m map[string]any, key string) (float64, bool) {
	n, ok := m[key].(float64)
	return n, ok
}

// allowTarget renders one contract allow entry as the msb rule
// destination it must map onto: "*.example.com" → domain_suffix,
// "example.com" → domain. V2 validation has already refused anything
// else.
func allowTarget(entry string) (kind, value string) {
	if rest, ok := strings.CutPrefix(entry, "*."); ok {
		return "domain_suffix", rest
	}
	return "domain", entry
}

// ruleTarget renders an inspect rule destination as the same
// (kind, value) pair allowTarget produces.
func ruleTarget(dest map[string]any) (kind, value string) {
	for _, k := range []string{"domain", "domain_suffix", "group"} {
		if v := jsonString(dest, k); v != "" {
			return k, v
		}
	}
	return "", ""
}

// verifySandboxPolicy proves the booted sandbox carries exactly the
// policy the signed contract authorized. The persisted `config` is
// the desired policy; `active_config` is what actually booted — both
// must match, or a setting that was accepted but never applied (or is
// pending a restart) would appear authorized while the guest runs
// without it.
func verifySandboxPolicy(job *JobContractV2, name, nonce string, doc map[string]any) error {
	cfg, ok := doc["config"].(map[string]any)
	if !ok {
		return fmt.Errorf("inspect document carries no config object")
	}
	if err := verifySandboxConfig(job, name, nonce, cfg); err != nil {
		return err
	}
	active, ok := doc["active_config"].(map[string]any)
	if !ok {
		return fmt.Errorf("sandbox has no resolved active configuration — refusing to execute in a VM that is not running its authorized policy")
	}
	if err := verifySandboxConfig(job, name, nonce, active); err != nil {
		return fmt.Errorf("booted configuration diverges from the authorized policy: %w", err)
	}
	return nil
}

func verifySandboxConfig(job *JobContractV2, name, nonce string, cfg map[string]any) error {
	if got := jsonString(cfg, "name"); got != name {
		return fmt.Errorf("sandbox name %q does not match the authorized handle %q", got, name)
	}
	labels, _ := cfg["labels"].(map[string]any)
	if got := jsonString(labels, "crabedence.job"); got != job.JobID {
		return fmt.Errorf("sandbox label crabedence.job=%q does not match job %q", got, job.JobID)
	}
	if got := jsonString(labels, "crabedence.dispatch"); got != nonce {
		return fmt.Errorf("sandbox dispatch label does not match this dispatch — the VM is not the one this contract created")
	}
	if got := jsonString(cfg, "manifest_digest"); got != job.ImageDigest {
		return fmt.Errorf("sandbox image digest %q does not match the authorized %q", got, job.ImageDigest)
	}
	res, _ := cfg["resources"].(map[string]any)
	if job.Resources.CPUs > 0 {
		if got, ok := jsonNumber(res, "cpus"); !ok || got != job.Resources.CPUs {
			return fmt.Errorf("sandbox cpus = %v, contract authorized %g", got, job.Resources.CPUs)
		}
	}
	if job.Resources.MemoryMB > 0 {
		if got, ok := jsonNumber(res, "memory_mib"); !ok || uint64(got) != job.Resources.MemoryMB {
			return fmt.Errorf("sandbox memory_mib = %v, contract authorized %d", got, job.Resources.MemoryMB)
		}
	}
	if job.Resources.DiskMB > 0 {
		img, _ := cfg["image"].(map[string]any)
		oci, _ := img["Oci"].(map[string]any)
		rd, _ := oci["root_disk"].(map[string]any)
		if got, ok := jsonNumber(rd, "size_mib"); !ok || uint64(got) != job.Resources.DiskMB {
			return fmt.Errorf("sandbox root disk size_mib = %v, contract authorized %d", got, job.Resources.DiskMB)
		}
	}
	lc, _ := cfg["lifecycle"].(map[string]any)
	if got, ok := jsonNumber(lc, "max_duration_secs"); !ok || uint32(got) != job.Resources.TimeoutSeconds {
		return fmt.Errorf("sandbox max_duration_secs = %v, contract authorized %d — the VM could outlive its authorization",
			got, job.Resources.TimeoutSeconds)
	}
	if job.Filesystem.Workdir != "" {
		rt, _ := cfg["runtime"].(map[string]any)
		if got := jsonString(rt, "workdir"); got != job.Filesystem.Workdir {
			return fmt.Errorf("sandbox workdir %q does not match the authorized %q", got, job.Filesystem.Workdir)
		}
	}
	if got := jsonString(cfg, "security_profile"); got != job.Security {
		return fmt.Errorf("sandbox security profile %q does not match the authorized %q", got, job.Security)
	}
	if err := verifyNetworkPolicy(job, cfg); err != nil {
		return err
	}
	if err := verifyEnvironment(job, cfg); err != nil {
		return err
	}
	return verifyMounts(job, cfg)
}

func verifyNetworkPolicy(job *JobContractV2, cfg map[string]any) error {
	netw, _ := cfg["network"].(map[string]any)
	policy, _ := netw["policy"].(map[string]any)
	egress := jsonString(policy, "default_egress")
	ingress := jsonString(policy, "default_ingress")
	rules, _ := policy["rules"].([]any)
	switch job.Network.Mode {
	case NetworkNone:
		if egress != "deny" || ingress != "deny" {
			return fmt.Errorf("network mode none but the sandbox default policy is egress=%q ingress=%q", egress, ingress)
		}
		if len(rules) != 0 {
			return fmt.Errorf("network mode none but the sandbox carries %d network rule(s)", len(rules))
		}
	case NetworkAllowlist:
		if egress != "deny" || ingress != "deny" {
			return fmt.Errorf("network allowlist but the sandbox default policy is egress=%q ingress=%q", egress, ingress)
		}
		if len(rules) != len(job.Network.Allow) {
			return fmt.Errorf("network allowlist has %d entries but the sandbox carries %d rule(s)", len(job.Network.Allow), len(rules))
		}
		want := map[string]bool{}
		for _, allow := range job.Network.Allow {
			kind, value := allowTarget(allow)
			want[kind+":"+value] = true
		}
		for i, raw := range rules {
			rule, _ := raw.(map[string]any)
			if jsonString(rule, "action") != "allow" || jsonString(rule, "direction") != "egress" {
				return fmt.Errorf("sandbox rule %d is not an egress allow", i)
			}
			dest, _ := rule["destination"].(map[string]any)
			kind, value := ruleTarget(dest)
			if !want[kind+":"+value] {
				return fmt.Errorf("sandbox rule %d permits %s:%s, which the contract did not authorize", i, kind, value)
			}
			delete(want, kind+":"+value)
		}
		if len(want) != 0 {
			return fmt.Errorf("the sandbox is missing %d authorized allow rule(s)", len(want))
		}
	case NetworkPublic:
		if egress != "deny" {
			return fmt.Errorf("network mode public but the sandbox default egress is %q", egress)
		}
		// `--net public` composes exactly two rules: the gateway DNS
		// rule (group host) and the public egress allow. Any other
		// rule is reachability the contract never authorized.
		public := false
		for i, raw := range rules {
			rule, _ := raw.(map[string]any)
			if jsonString(rule, "action") != "allow" || jsonString(rule, "direction") != "egress" {
				return fmt.Errorf("sandbox rule %d is not an egress allow", i)
			}
			dest, _ := rule["destination"].(map[string]any)
			kind, value := ruleTarget(dest)
			switch {
			case kind == "group" && value == "public":
				public = true
			case kind == "group" && value == "host":
				// the sandbox's own DNS gateway
			default:
				return fmt.Errorf("sandbox rule %d permits %s:%s, which the contract did not authorize", i, kind, value)
			}
		}
		if !public {
			return fmt.Errorf("network mode public but the sandbox carries no public egress rule")
		}
	}
	return nil
}

func verifyEnvironment(job *JobContractV2, cfg map[string]any) error {
	env, _ := cfg["env"].([]any)
	have := map[string]string{}
	for _, raw := range env {
		e, _ := raw.(map[string]any)
		have[jsonString(e, "key")] = jsonString(e, "value")
	}
	for _, kv := range job.Env {
		key, value, _ := strings.Cut(kv, "=")
		if got, ok := have[key]; !ok || got != value {
			return fmt.Errorf("sandbox environment is missing the authorized %s=… entry", key)
		}
	}
	return nil
}

// mountReadOnly extracts the read-only intent from a contract mount's
// option string — msb's `ro`/`rw` flags. Unrecognized tokens are not
// interpreted here: the CLI refuses what it cannot honor, and the job
// refuses with it.
func mountReadOnly(options string) (value, declared bool) {
	for _, tok := range strings.Split(options, ",") {
		switch strings.TrimSpace(tok) {
		case "ro":
			return true, true
		case "rw":
			return false, true
		}
	}
	return false, false
}

func verifyMounts(job *JobContractV2, cfg map[string]any) error {
	mounts, _ := cfg["mounts"].([]any)
	if len(mounts) != len(job.Filesystem.Mounts) {
		return fmt.Errorf("sandbox carries %d mount(s) but the contract authorized %d", len(mounts), len(job.Filesystem.Mounts))
	}
	authorized := map[string]*Mount{}
	for i := range job.Filesystem.Mounts {
		m := &job.Filesystem.Mounts[i]
		authorized[filepath.Clean(m.Source)+"\x00"+m.Dest] = m
	}
	for i, raw := range mounts {
		m, _ := raw.(map[string]any)
		key := filepath.Clean(jsonString(m, "host")) + "\x00" + jsonString(m, "guest")
		declared, ok := authorized[key]
		if !ok {
			return fmt.Errorf("sandbox mount %d (%s → %s) was not authorized",
				i, jsonString(m, "host"), jsonString(m, "guest"))
		}
		// A host path the authority mounted read-only must not boot
		// writable: the flag is part of the signed policy.
		if want, ok := mountReadOnly(declared.Options); ok {
			opts, _ := m["options"].(map[string]any)
			got, _ := opts["readonly"].(bool)
			if got != want {
				return fmt.Errorf("sandbox mount %s is readonly=%t but the contract declared %q",
					jsonString(m, "guest"), got, declared.Options)
			}
		}
		delete(authorized, key)
	}
	return nil
}

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
