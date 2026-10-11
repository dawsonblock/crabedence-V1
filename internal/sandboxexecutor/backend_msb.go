package sandboxexecutor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// defaultMaxOutputBytes bounds captured output when a contract
// declares no max_output_bytes.
const defaultMaxOutputBytes = 8 << 20

// PinnedMSBVersion is the Microsandbox runtime this backend is
// qualified against. The runtime-owned job protocol it carries is
// what makes a guest exit event observable independently of any CLI
// process exit code; an adapter that cannot say which runtime
// behavior it was tested against cannot claim that property, so a
// different version is refused, never assumed compatible.
const PinnedMSBVersion = "0.7.8"

// maxDurationGrace extends the sandbox's own --max-duration beyond
// the contract timeout. Without it, the VM's death races the
// runtime's terminal job-record write and a contract timeout
// degrades to lost/UNKNOWN; with it, the runtime kills the command at
// the contract deadline while the VM still lives to record the
// outcome. The grace is fixed and bounded — an abandoned VM outlives
// its authorization by at most this, and never by an unbounded
// amount.
const maxDurationGrace = 30 * time.Second

// maxCLIOutputBytes bounds the captured output of one adapter CLI
// call. The adapter's own calls (version, doctor, create, inspect,
// jobs, rm, exec -d) return small documents; a runtime that floods
// them is broken or hostile, and the executor must not accumulate
// without bound on its behalf. The artifact capture is bounded
// separately by the contract's declared output budget.
const maxCLIOutputBytes = 4 << 20

// boundedBuffer collects at most limit bytes; further bytes are
// dropped and flagged, never accumulated.
type boundedBuffer struct {
	buf        strings.Builder
	limit      int
	overflowed bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.limit {
		if len(p) > 0 {
			w.overflowed = true
		}
		return len(p), nil
	}
	room := w.limit - w.buf.Len()
	if len(p) > room {
		w.buf.Write(p[:room])
		w.overflowed = true
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

func (w *boundedBuffer) String() string { return w.buf.String() }

// jobPollInterval paces Wait's observation of the runtime's job
// record. The record is the only evidence Wait trusts, so polling is
// deliberately boring: one bounded `inspect --job` call per tick.
const jobPollInterval = 500 * time.Millisecond

// captureMargin bounds the artifact capture after a terminal
// observation: reading the runtime's retained output and publishing
// it durably. A capture that cannot finish inside the margin leaves
// the job unresolved rather than terminal-without-evidence.
const captureMargin = 60 * time.Second

// Image fetch policies a backend may pin. The default is never: the
// executor refuses a job whose authorized image is not present
// locally, instead of fetching it mid-dispatch where a slow registry
// turns a definitive launch into an ambiguous one.
const (
	PullNever     = "never"
	PullIfMissing = "if-missing"
)

// Deployment profiles a backend may pin — the host-runtime isolation
// profile the sandbox boots under. The executor's model is one fresh,
// exclusively owned VM per job, so the default is the strongest local
// profile; anything else must be an explicit operator decision and is
// verified against the booted configuration like every other policy
// dimension. The flag spells it with a hyphen, the inspect document
// with an underscore.
const (
	DeploymentSingleTenant = "single-tenant"
	DeploymentMultiTenant  = "multi-tenant"
)

// jobIDPattern is the runtime's job identity shape, enforced by the
// CLI's own validator: "job_" plus 32 lowercase hex digits.
var jobIDPattern = regexp.MustCompile(`^job_[0-9a-f]{32}$`)

// MSBBackend executes signed job contracts in Microsandbox microVMs
// (libkrun on Apple Silicon / Linux KVM). The executor hands it a
// verified contract; the backend maps the contract's declared limits
// onto msb flags exactly — a limit the contract did not authorize is
// never invented, and a contract's declared limit is never widened.
//
// Execution model — every job gets a fresh, exclusively created VM
// whose workload is a runtime-owned job:
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
//  3. `msb exec -d` starts the contract's argv as a runtime-owned
//     job. The runtime — not this adapter, and not a CLI process
//     exit code — records the job's terminal state: exited with the
//     guest's code, timed_out, failed (the guest rejected the
//     command before it started), or lost. Wait observes that record
//     until it is terminal; an outcome that cannot be observed is
//     never invented.
//  4. The job's retained output is captured into a bounded artifact:
//     written to a private temp file, fsynced, atomically published,
//     and re-read to prove the digest the ledger will bind.
//
// The sandbox's --max-duration is pinned to the contract timeout plus
// a fixed observation grace, so even an abandoned VM cannot outlive
// its authorization by more than that bound. Shutdown never kills a
// job's VM: the ledger marks the watch interrupted and the
// deterministic sandbox name lets a restarted executor reconcile
// what survived.
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
	// PullPolicy pins the image-fetch policy on every create: "never"
	// (default) requires the authorized image to be present locally
	// and refuses fast otherwise; "if-missing" lets the CLI fetch the
	// pinned digest, at the cost of a dispatch whose latency — and
	// possible ambiguity — depends on the network.
	PullPolicy string
	// KeepSandboxes leaves stopped VMs in place after result
	// collection — a forensics posture; default removes them since
	// the artifact store is the durable evidence.
	KeepSandboxes bool
	// DeploymentProfile pins the host-runtime isolation profile every
	// sandbox boots under ("single-tenant", the default, or
	// "multi-tenant"). It is part of the verified policy: the booted
	// configuration must carry exactly this profile, so a runtime
	// that quietly downgraded confinement refuses before any guest
	// command runs.
	DeploymentProfile string
	// RequiredVersion pins the runtime the adapter is qualified
	// against; empty means PinnedMSBVersion. VerifyRuntime refuses
	// any other version.
	RequiredVersion string
	// PollInterval paces Wait's observation polls; zero uses
	// jobPollInterval.
	PollInterval time.Duration
	// ObservationSlack extends the contract timeout for the
	// observation window; zero uses maxDurationGrace + captureMargin.
	// It exists so tests can exercise unobserved-outcome paths in
	// bounded time — operators leave it at the default.
	ObservationSlack time.Duration
}

// requiredVersion is the effective runtime pin.
func (b *MSBBackend) requiredVersion() string {
	if b.RequiredVersion != "" {
		return b.RequiredVersion
	}
	return PinnedMSBVersion
}

// deploymentProfile is the effective host-runtime isolation profile.
func (b *MSBBackend) deploymentProfile() string {
	if b.DeploymentProfile != "" {
		return b.DeploymentProfile
	}
	return DeploymentSingleTenant
}

// deploymentProfileJSON renders the profile as the inspect document
// spells it. Unknown values refuse: "the profile the operator forgot"
// is never silently the runtime's default.
func deploymentProfileJSON(profile string) (string, error) {
	switch profile {
	case DeploymentSingleTenant:
		return "single_tenant", nil
	case DeploymentMultiTenant:
		return "multi_tenant", nil
	default:
		return "", fmt.Errorf("unknown deployment profile %q (want %q or %q)", profile, DeploymentSingleTenant, DeploymentMultiTenant)
	}
}

// VerifyHost proves the host can run the confined microVMs this
// adapter promises: the runtime's own prerequisite check (virtual
// extension, libkrunfw, root-clone support) must pass. An executor
// that cannot say its host is supported refuses to run rather than
// downgrading the isolation it was configured for.
func (b *MSBBackend) VerifyHost(ctx context.Context) (string, error) {
	out, err := b.runOnce(ctx, "doctor")
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("host confinement check failed (msb doctor): %v: %s", err, text)
	}
	return text, nil
}

// VerifyRuntime proves the configured msb binary is the pinned
// version — the adapter's observation semantics are qualified against
// one runtime's job protocol, and a silent version drift would
// invalidate exactly the properties this backend exists to provide.
// It returns the observed version for the startup report.
func (b *MSBBackend) VerifyRuntime(ctx context.Context) (string, error) {
	out, err := b.runOnce(ctx, "--version")
	if err != nil {
		return "", fmt.Errorf("probe msb version (%s): %v: %s", b.Bin, err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 || fields[0] != "msb" {
		return "", fmt.Errorf("unrecognized msb version output %q", strings.TrimSpace(string(out)))
	}
	got := fields[1]
	if got != b.requiredVersion() {
		return got, fmt.Errorf("msb %s is not the pinned runtime %s — the adapter's job-protocol semantics are qualified against the pinned version; upgrade the runtime or pin the qualified version explicitly", got, b.requiredVersion())
	}
	return got, nil
}

// msbJobRecord is the runtime's durable job metadata as
// `msb inspect --job <id> --format json` reports it. Only the fields
// the classification depends on are decoded; unknown fields are
// ignored so a compatible runtime can add metadata without breaking
// observation.
type msbJobRecord struct {
	ID          string         `json:"id"`
	RuntimeBoot string         `json:"runtime_boot_id"`
	Command     []string       `json:"command"`
	State       string         `json:"state"`
	PID         *uint32        `json:"pid"`
	CreatedAt   int64          `json:"created_at"`
	StartedAt   *int64         `json:"started_at"`
	FinishedAt  *int64         `json:"finished_at"`
	ExitCode    *int           `json:"exit_code"`
	Failure     *msbJobFailure `json:"failure"`
	Error       *string        `json:"error"`
	TimedOut    bool           `json:"timed_out"`
}

type msbJobFailure struct {
	Kind      string `json:"kind"`
	Errno     *int   `json:"errno"`
	ErrnoName string `json:"errno_name"`
	Message   string `json:"message"`
	Stage     string `json:"stage"`
}

// finishedAt converts the runtime's finish timestamp, falling back to
// observation time when the record carries none.
func (r *msbJobRecord) finishedAt() time.Time {
	if r.FinishedAt != nil {
		return time.UnixMilli(*r.FinishedAt).UTC()
	}
	return time.Now().UTC()
}

// errorText renders the runtime's own explanation of a lost job.
func (r *msbJobRecord) errorText() string {
	if r.Error != nil && *r.Error != "" {
		return *r.Error
	}
	return "the runtime did not confirm an exit result"
}

// failureText renders a typed spawn failure for the audit log.
func (f *msbJobFailure) text() string {
	if f == nil {
		return "the guest rejected the command before it started"
	}
	parts := []string{}
	if f.Kind != "" {
		parts = append(parts, f.Kind)
	}
	if f.Message != "" {
		parts = append(parts, f.Message)
	}
	if f.ErrnoName != "" {
		parts = append(parts, "("+f.ErrnoName+")")
	}
	if len(parts) == 0 {
		return "the guest rejected the command before it started"
	}
	return strings.Join(parts, ": ")
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

// runOnce executes a short msb utility call (create, inspect, jobs,
// rm, exec -d) under ctx, with its output bounded: a runtime that
// floods a utility call is refused, never accumulated.
func (b *MSBBackend) runOnce(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, b.Bin, args...)
	cmd.Stdin = nil
	out := newBoundedBuffer(maxCLIOutputBytes)
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if out.overflowed {
		return []byte(out.String()), fmt.Errorf("msb %s produced more than %d bytes of output",
			strings.Join(args, " "), maxCLIOutputBytes)
	}
	return []byte(out.String()), err
}

// pinnedImage renders the contract's image as the immutable
// reference msb must boot: the authority-pinned digest, never a
// mutable tag the registry could have moved. V2 validation refuses a
// digest inside the image string, so the reference and the digest
// compose unambiguously.
func pinnedImage(job *JobContractV2) string {
	return job.Image + "@" + job.ImageDigest
}

// vmMaxDuration is the sandbox's own hard bound: the contract timeout
// plus the fixed observation grace, so the runtime can record a
// timed-out job's terminal state while the VM still lives.
func vmMaxDuration(job *JobContractV2) time.Duration {
	return time.Duration(job.Resources.TimeoutSeconds)*time.Second + maxDurationGrace
}

// createArgs maps a verified contract onto `msb create` flags, 1:1,
// plus the dispatch labels that bind the VM to this contract.
func (b *MSBBackend) createArgs(job *JobContractV2, name, nonce string) ([]string, error) {
	args := []string{"create", "-q", "-n", name}
	if _, err := deploymentProfileJSON(b.deploymentProfile()); err != nil {
		return nil, err
	}
	args = append(args, "--deployment-profile", b.deploymentProfile())
	if job.Resources.CPUs > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%g", job.Resources.CPUs))
	}
	if job.Resources.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dM", job.Resources.MemoryMB))
	}
	if job.Resources.DiskMB > 0 {
		args = append(args, "--root-disk", fmt.Sprintf("%dM", job.Resources.DiskMB))
	}
	args = append(args, "--max-duration", fmt.Sprintf("%ds", int(vmMaxDuration(job)/time.Second)))
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
	policy := b.PullPolicy
	if policy == "" {
		policy = PullNever
	}
	if policy != PullNever && policy != PullIfMissing {
		return nil, fmt.Errorf("unknown image pull policy %q (want %q or %q)", policy, PullNever, PullIfMissing)
	}
	args = append(args, "--pull", policy)
	args = append(args, b.ExtraArgs...)
	args = append(args, pinnedImage(job))
	return args, nil
}

// launchArgs maps the contract's argv onto a runtime-owned detached
// job. The command timeout is pinned to the contract's timeout — the
// same deadline the VM itself carries (plus the observation grace).
func (b *MSBBackend) launchArgs(job *JobContractV2, name string) []string {
	args := []string{"exec", "-d", "--no-tty", "--no-stdin",
		"--timeout", fmt.Sprintf("%ds", job.Resources.TimeoutSeconds)}
	if job.Resources.Pids > 0 {
		args = append(args, "--rlimit", fmt.Sprintf("nproc=%d", job.Resources.Pids))
	}
	args = append(args, name, "--")
	args = append(args, job.Argv...)
	return args
}

// parseRunID extracts the runtime-owned job identity from a detached
// launch's output. Exactly one well-formed identity must appear — a
// launch that prints none (or several) cannot be correlated to a job.
func parseRunID(out string) (string, bool) {
	found := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !jobIDPattern.MatchString(line) {
			continue
		}
		if found != "" && found != line {
			return "", false
		}
		found = line
	}
	return found, found != ""
}

// listJobs returns the runtime's job records for a sandbox. It is the
// recovery probe: when a detached launch fails without naming its job,
// the sandbox may still hold one — the launch may have been admitted
// and its identity lost in transport, and a blind re-launch would
// duplicate it.
func (b *MSBBackend) listJobs(ctx context.Context, name string) ([]msbJobRecord, error) {
	out, err := b.runOnce(ctx, "jobs", "--all", "--format", "json", name)
	if err != nil {
		return nil, fmt.Errorf("msb jobs %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	var page struct {
		Items []msbJobRecord `json:"items"`
	}
	if err := json.Unmarshal(out, &page); err != nil {
		return nil, fmt.Errorf("msb jobs %s: malformed json: %w", name, err)
	}
	return page.Items, nil
}

// matchContractJobs returns the sandbox's jobs whose recorded command
// is exactly the contract's argv. Our sandboxes are exclusive to one
// dispatch, so a match is proof the job belongs to this contract.
func matchContractJobs(jobs []msbJobRecord, job *JobContractV2) []msbJobRecord {
	var matched []msbJobRecord
	for _, rec := range jobs {
		if !sameArgv(rec.Command, job.Argv) {
			continue
		}
		matched = append(matched, rec)
	}
	return matched
}

// sameArgv compares a runtime job record's command against the
// contract's argv element-wise — the correlation that proves an
// observed job is the authorized command, not a lookalike.
func sameArgv(recorded, authorized []string) bool {
	if len(recorded) != len(authorized) {
		return false
	}
	for i := range recorded {
		if recorded[i] != authorized[i] {
			return false
		}
	}
	return true
}

// Dispatch boots the job's microVM and starts its authorized command
// as a runtime-owned job:
//
//  1. `msb create` — exclusive creation. An existing sandbox under
//     the job's handle is a definitive refusal: the job never runs in
//     a VM this dispatch did not create.
//  2. `msb inspect` — the booted VM must carry exactly the policy the
//     contract authorized; a mismatch destroys it before any guest
//     command runs.
//  3. `msb exec -d` — the contract's argv as a runtime-owned job
//     whose terminal state the runtime records durably. A launch that
//     fails without naming its job is probed against the sandbox's
//     job list before it is called a refusal: an admitted-but-unnamed
//     job is adopted, never duplicated.
//
// A dispatch deadline that expires mid-create is ambiguous by
// construction — the VM may exist — so the handle is returned for
// reconcile, never a blind retry.
func (b *MSBBackend) Dispatch(ctx context.Context, job *JobContractV2) (DispatchResult, error) {
	if job == nil {
		return DispatchResult{}, fmt.Errorf("dispatch requires a signed job contract")
	}
	name := b.msbJobName(job.JobID)
	nonce, err := dispatchNonce()
	if err != nil {
		return DispatchResult{}, err
	}
	createArgs, err := b.createArgs(job, name, nonce)
	if err != nil {
		return DispatchResult{}, err
	}

	out, cerr := b.runOnce(ctx, createArgs...)
	if cerr != nil {
		if ctx.Err() != nil {
			// The VM may exist; the dispatch never reached a
			// verified launch, so the handle is returned for
			// reconcile, never a blind retry.
			return DispatchResult{Handle: name}, fmt.Errorf("%w: create deadline expired before the VM was proven: %v", ErrAmbiguousDispatch, ctx.Err())
		}
		if strings.Contains(strings.ToLower(string(out)), "already exists") {
			return DispatchResult{}, fmt.Errorf("sandbox %q already exists — refusing to reuse a VM this dispatch did not create", name)
		}
		// A create can fail after the VM was already booted (a guest
		// validation error, for instance). Destroy the leftover only
		// when it carries this dispatch's identity label — proof it
		// came from this create, not from someone else.
		b.destroyIfOurs(name, nonce)
		return DispatchResult{}, fmt.Errorf("msb create failed: %v: %s", cerr, strings.TrimSpace(string(out)))
	}

	// Pre-execution policy verification: the VM that boots must be
	// the VM the contract authorized, or it never runs the job.
	doc, ierr := b.inspectRaw(ctx, name)
	if ierr != nil {
		b.destroy(name)
		return DispatchResult{}, fmt.Errorf("verify sandbox %s before execution: %w", name, ierr)
	}
	if verr := verifySandboxPolicy(job, name, nonce, b.deploymentProfile(), doc); verr != nil {
		b.destroy(name)
		return DispatchResult{}, fmt.Errorf("sandbox %s failed policy verification — destroyed before execution: %w", name, verr)
	}

	lout, lerr := b.runOnce(ctx, b.launchArgs(job, name)...)
	if lerr == nil {
		if runID, ok := parseRunID(string(lout)); ok {
			return DispatchResult{Handle: name, RunID: runID}, nil
		}
	}
	// The launch did not name a job. It may still have been admitted:
	// probe the sandbox before calling it a refusal, and adopt the
	// job the runtime recorded rather than duplicating it.
	probeCtx, cancel := context.WithTimeout(ctx, b.dispatchProbeTimeout())
	defer cancel()
	jobs, perr := b.listJobs(probeCtx, name)
	switch {
	case perr != nil:
		// The probe failed too — the outcome is genuinely unknown.
		return DispatchResult{Handle: name}, fmt.Errorf("%w: detached launch failed (%v: %s) and the job list could not be read: %v",
			ErrAmbiguousDispatch, lerr, strings.TrimSpace(string(lout)), perr)
	default:
		matched := matchContractJobs(jobs, job)
		switch len(matched) {
		case 1:
			// The launch was admitted; only its identity was lost.
			return DispatchResult{Handle: name, RunID: matched[0].ID}, nil
		case 0:
			b.destroy(name)
			if lerr != nil {
				return DispatchResult{}, fmt.Errorf("msb exec -d failed: %v: %s", lerr, strings.TrimSpace(string(lout)))
			}
			return DispatchResult{}, fmt.Errorf("msb exec -d named no job and the sandbox records none: %s", strings.TrimSpace(string(lout)))
		default:
			return DispatchResult{Handle: name}, fmt.Errorf("%w: sandbox %s records %d jobs matching the authorized command — an operator must reconcile them",
				ErrAmbiguousDispatch, name, len(matched))
		}
	}
}

// dispatchProbeTimeout bounds the post-failure job-list probe so a
// wedged runtime cannot pin the admission path.
func (b *MSBBackend) dispatchProbeTimeout() time.Duration { return 15 * time.Second }

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

// inspectJob returns the runtime's durable job record for one job.
func (b *MSBBackend) inspectJob(ctx context.Context, name, runID string) (*msbJobRecord, error) {
	out, err := b.runOnce(ctx, "inspect", "--job", runID, "--format", "json", name)
	if err != nil {
		return nil, fmt.Errorf("msb inspect --job %s %s: %v: %s", runID, name, err, strings.TrimSpace(string(out)))
	}
	var rec msbJobRecord
	if err := json.Unmarshal(out, &rec); err != nil {
		return nil, fmt.Errorf("msb inspect --job %s %s: malformed json: %w", runID, name, err)
	}
	if rec.ID != runID {
		return nil, fmt.Errorf("msb inspect --job %s %s: record names job %q", runID, name, rec.ID)
	}
	return &rec, nil
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

// Resume re-establishes observation of a run a previous lifetime left
// unresolved. When the run identity was lost with the crash — the
// window between the runtime admitting a job and the ledger naming it
// — the runtime's own job list is the proof of what was admitted: a
// single job matching the authorized argv is adopted; zero or several
// are unobserved, never guessed at. The run is then observed exactly
// as a live monitor would, so a recovered job reaches the same
// terminal result and artifact it would have reached live.
func (b *MSBBackend) Resume(ctx context.Context, job *JobContractV2, handle, runID string) (string, *ExecResult, error) {
	if job == nil {
		return runID, nil, fmt.Errorf("resume requires the job's signed contract")
	}
	if runID == "" {
		jobs, err := b.listJobs(ctx, handle)
		if err != nil {
			return "", nil, fmt.Errorf("%w: cannot read the sandbox's job list: %v", ErrExecutionUnobserved, err)
		}
		matched := matchContractJobs(jobs, job)
		switch len(matched) {
		case 0:
			return "", nil, fmt.Errorf("%w: sandbox %s records no job matching the authorized command", ErrExecutionUnobserved, handle)
		case 1:
			runID = matched[0].ID
		default:
			return "", nil, fmt.Errorf("%w: sandbox %s records %d jobs matching the authorized command — an operator must reconcile them",
				ErrExecutionUnobserved, handle, len(matched))
		}
	}
	res, err := b.Wait(ctx, job, handle, runID)
	return runID, res, err
}

// Wait observes the job's runtime-owned record until it is terminal,
// then captures the job's retained output into a durable artifact.
// The observation window is the contract timeout plus the fixed
// grace the VM itself carries, plus the capture margin — an outcome
// the runtime never records inside that window is unobserved, and
// unobserved outcomes are never recorded as results.
//
// The returned result distinguishes what was actually observed:
//   - ExitVerified: the runtime recorded the guest's termination.
//   - TimedOut: the runtime killed the command at the deadline.
//   - FailureKind: the guest rejected the command before it started.
//
// A terminal observation whose artifact cannot be finalized returns
// the observation together with an error — the plan's "not fully
// verified" — and anything unobservable returns
// ErrExecutionUnobserved. Neither is ever a terminal claim.
func (b *MSBBackend) Wait(ctx context.Context, job *JobContractV2, handle, runID string) (*ExecResult, error) {
	if job == nil {
		return nil, fmt.Errorf("wait requires the job's signed contract")
	}
	if !jobIDPattern.MatchString(runID) {
		return nil, fmt.Errorf("%w: run identity %q is not a runtime job id", ErrExecutionUnobserved, runID)
	}
	slack := b.ObservationSlack
	if slack <= 0 {
		slack = maxDurationGrace + captureMargin
	}
	window := time.Duration(job.Resources.TimeoutSeconds)*time.Second + slack
	obsCtx, cancelObs := context.WithTimeout(ctx, window)
	defer cancelObs()

	res, err := b.observe(obsCtx, ctx, job, handle, runID)
	if err != nil {
		return nil, err
	}

	// The exit is observed; the artifact must now be finalized or
	// the result is not fully verified. The capture gets its own
	// bounded window so an observation that finished near the
	// deadline does not doom the artifact.
	capCtx, cancelCap := context.WithTimeout(ctx, captureMargin)
	defer cancelCap()
	cap, cerr := b.capture(capCtx, job, handle, runID)
	if cerr != nil {
		return res, fmt.Errorf("artifact finalization failed for job %s: %w", job.JobID, cerr)
	}
	res.CaptureSource = "runtime-job-log"
	res.OutputPath = cap.path
	res.OutputSHA256 = cap.sha256
	res.OutputBytes = cap.nbytes
	res.Truncated = cap.truncated
	return res, nil
}

// observe polls the runtime's job record until it is terminal.
// parent distinguishes a shutdown (its cancellation is returned as
// such — the row stays RUNNING for reconcile) from the observation
// deadline (an unobserved outcome).
func (b *MSBBackend) observe(obsCtx, parent context.Context, job *JobContractV2, handle, runID string) (*ExecResult, error) {
	interval := b.PollInterval
	if interval <= 0 {
		interval = jobPollInterval
	}
	var lastErr error
	for {
		rec, err := b.inspectJob(obsCtx, handle, runID)
		if err == nil {
			if !sameArgv(rec.Command, job.Argv) {
				return nil, fmt.Errorf("%w: job %s records a different command than the contract authorized", ErrExecutionUnobserved, runID)
			}
			switch rec.State {
			case "exited":
				res := &ExecResult{RuntimeState: rec.State, RunID: runID, FinishedAt: rec.finishedAt()}
				switch {
				case rec.TimedOut:
					// The runtime killed the command at the deadline:
					// an observed outcome, but not a guest exit.
					res.TimedOut = true
				case rec.ExitCode != nil:
					res.ExitVerified = true
					res.ExitCode = *rec.ExitCode
				default:
					return nil, fmt.Errorf("%w: job %s is exited without an exit code and without a timeout", ErrExecutionUnobserved, runID)
				}
				return res, nil
			case "failed":
				kind := "unknown"
				if rec.Failure != nil && rec.Failure.Kind != "" {
					kind = rec.Failure.Kind
				}
				return &ExecResult{
					RuntimeState:   rec.State,
					RunID:          runID,
					FailureKind:    kind,
					FailureMessage: rec.Failure.text(),
					FinishedAt:     rec.finishedAt(),
				}, nil
			case "lost":
				return nil, fmt.Errorf("%w: the runtime lost job %s: %s", ErrExecutionUnobserved, runID, rec.errorText())
			}
		} else {
			lastErr = err
		}
		select {
		case <-obsCtx.Done():
			if parent.Err() != nil {
				return nil, parent.Err()
			}
			if lastErr != nil {
				return nil, fmt.Errorf("%w: no terminal record for job %s within its observation window (last error: %v)", ErrExecutionUnobserved, runID, lastErr)
			}
			return nil, fmt.Errorf("%w: job %s did not reach a terminal state within its observation window", ErrExecutionUnobserved, runID)
		case <-time.After(interval):
		}
	}
}

// captureResult is one finalized artifact.
type captureResult struct {
	path      string
	sha256    string
	nbytes    int64
	truncated bool
}

// capture reads the runtime's retained capture of the job's
// stdout+stderr — bounded by the contract's max_output_bytes — and
// publishes it durably: a private temp file, fsync, close, atomic
// rename, then a read-back hash that must equal the digest computed
// while streaming. The artifact is exactly the bytes on disk; the
// digest that lands in evidence is recomputed from the published
// file, never carried over from memory.
func (b *MSBBackend) capture(ctx context.Context, job *JobContractV2, name, runID string) (*captureResult, error) {
	bound := int64(job.Resources.MaxOutputBytes)
	if bound <= 0 {
		bound = defaultMaxOutputBytes
	}
	if err := os.MkdirAll(b.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create artifact dir %s: %w", b.StateDir, err)
	}
	finalPath := filepath.Join(b.StateDir, name+".out")
	tmp, err := os.CreateTemp(b.StateDir, "."+name+".out-*")
	if err != nil {
		return nil, fmt.Errorf("create artifact temp file: %w", err)
	}
	tmpPath := tmp.Name()
	published := false
	defer func() {
		if !published {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	cmd := exec.CommandContext(ctx, b.Bin, "logs", "--job", runID, name)
	cmd.Stdin = nil
	collector := &boundedArtifactWriter{f: tmp, hasher: sha256.New(), remaining: bound}
	cmd.Stdout = collector
	// The CLI's diagnostics are only used for a refusal message —
	// bounded so a broken runtime cannot flood the executor's memory
	// through the failure path either.
	stderr := newBoundedBuffer(64 * 1024)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn msb logs: %w", err)
	}
	werr := cmd.Wait()
	if werr != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("artifact capture interrupted: %w", ctx.Err())
		}
		return nil, fmt.Errorf("msb logs --job %s failed: %v: %s", runID, werr, strings.TrimSpace(stderr.String()))
	}
	nbytes, truncated := collector.stats()
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("sync artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close artifact: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return nil, fmt.Errorf("publish artifact %s: %w", finalPath, err)
	}
	published = true
	if dir, err := os.Open(b.StateDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	// Read-back: the digest bound to evidence must be the digest of
	// the published bytes, not of a stream that was written.
	readBack, rerr := hashFileSHA256(finalPath)
	if rerr != nil {
		return nil, fmt.Errorf("read back artifact %s: %w", finalPath, rerr)
	}
	if readBack != collector.digest() {
		return nil, fmt.Errorf("artifact %s changed between write and read-back (wrote %s, read %s)", finalPath, collector.digest(), readBack)
	}
	if info, serr := os.Stat(finalPath); serr != nil {
		return nil, fmt.Errorf("stat artifact %s: %w", finalPath, serr)
	} else if info.Size() != nbytes {
		return nil, fmt.Errorf("artifact %s holds %d bytes after publication, wrote %d", finalPath, info.Size(), nbytes)
	}
	return &captureResult{path: finalPath, sha256: readBack, nbytes: nbytes, truncated: truncated}, nil
}

// boundedArtifactWriter stores at most bound bytes of the runtime's
// retained output and hashes exactly the stored bytes. Bytes past the
// bound are drained and discarded — never hashed — so the digest
// always covers the artifact's content, and truncation is an explicit
// observation rather than a silent cut.
type boundedArtifactWriter struct {
	f         *os.File
	hasher    hash.Hash
	remaining int64
	written   int64
	truncated bool
}

func (w *boundedArtifactWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		if len(p) > 0 {
			w.truncated = true
		}
		return len(p), nil
	}
	chunk := p
	if int64(len(chunk)) > w.remaining {
		chunk = chunk[:w.remaining]
		w.truncated = true
	}
	n, err := w.f.Write(chunk)
	if n > 0 {
		_, _ = w.hasher.Write(chunk[:n])
		w.written += int64(n)
		w.remaining -= int64(n)
	}
	if err != nil {
		return n, err
	}
	if n < len(chunk) {
		return n, io.ErrShortWrite
	}
	return len(p), nil
}

func (w *boundedArtifactWriter) digest() string {
	return hex.EncodeToString(w.hasher.Sum(nil))
}

func (w *boundedArtifactWriter) stats() (int64, bool) {
	return w.written, w.truncated
}

// Cleanup removes the sandbox a finished job leaves behind. A sandbox
// that is already gone is a success — the goal is absence. The
// operator's forensics posture (KeepSandboxes) turns cleanup into a
// no-op.
func (b *MSBBackend) Cleanup(ctx context.Context, handle string) error {
	if b.KeepSandboxes {
		return nil
	}
	out, err := b.runOnce(ctx, "rm", "-f", handle)
	if err != nil {
		if strings.Contains(strings.ToLower(string(out)), "not found") {
			return nil
		}
		return fmt.Errorf("remove sandbox %s: %v: %s", handle, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Close releases backend resources. Nothing is long-lived: every
// observation is a bounded CLI call, and a running job belongs to the
// runtime, not this process.
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
func verifySandboxPolicy(job *JobContractV2, name, nonce, deploymentProfile string, doc map[string]any) error {
	cfg, ok := doc["config"].(map[string]any)
	if !ok {
		return fmt.Errorf("inspect document carries no config object")
	}
	if err := verifySandboxConfig(job, name, nonce, deploymentProfile, cfg); err != nil {
		return err
	}
	active, ok := doc["active_config"].(map[string]any)
	if !ok {
		return fmt.Errorf("sandbox has no resolved active configuration — refusing to execute in a VM that is not running its authorized policy")
	}
	if err := verifySandboxConfig(job, name, nonce, deploymentProfile, active); err != nil {
		return fmt.Errorf("booted configuration diverges from the authorized policy: %w", err)
	}
	return nil
}

func verifySandboxConfig(job *JobContractV2, name, nonce, deploymentProfile string, cfg map[string]any) error {
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
	if got, ok := jsonNumber(lc, "max_duration_secs"); !ok || uint32(got) != uint32(vmMaxDuration(job)/time.Second) {
		return fmt.Errorf("sandbox max_duration_secs = %v, contract authorized %d plus the %s observation grace",
			got, job.Resources.TimeoutSeconds, maxDurationGrace)
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
	wantProfile, perr := deploymentProfileJSON(deploymentProfile)
	if perr != nil {
		return perr
	}
	if got := jsonString(cfg, "deployment_profile"); got != wantProfile {
		return fmt.Errorf("sandbox deployment profile %q does not match the required %q — refusing to run under a downgraded host confinement", got, wantProfile)
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

var _ Backend = (*MSBBackend)(nil)
