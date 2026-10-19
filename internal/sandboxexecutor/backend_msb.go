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
	"sync"
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
	// RuntimeManifest pins the exact bytes of the runtime — the msb
	// executable and the libkrunfw firmware. It is required: a runtime
	// that reports the pinned version but hashes differently is a
	// substituted runtime and refuses. Nil refuses verification.
	RuntimeManifest *RuntimeManifest
	// PollInterval paces Wait's observation polls; zero uses
	// jobPollInterval.
	PollInterval time.Duration
	// ObservationSlack extends the contract timeout for the
	// observation window; zero uses maxDurationGrace + captureMargin.
	// It exists so tests can exercise unobserved-outcome paths in
	// bounded time — operators leave it at the default.
	ObservationSlack time.Duration

	// envMu guards the per-image baseline cache; the baseline is fixed
	// for a pinned digest, so it is resolved once.
	envMu       sync.Mutex
	envBaseline map[string]imageBaseline
}

// imageBaseline is the pinned image's own execution defaults — the
// environment the runtime injects, the command and entrypoint it boots
// with, the user it runs as and the directory it starts in. All of it
// is fixed for the pinned digest, and all of it is part of the
// authorized policy.
type imageBaseline struct {
	Env        []string
	Cmd        []string
	Entrypoint []string
	User       string
	WorkingDir string
}

// imageDefaults resolves the pinned image's own config environment
// — the part of the guest environment the runtime injects at boot, and
// therefore part of the authorized set. The result is cached per
// digest: it cannot change while the digest is pinned.
func (b *MSBBackend) imageDefaults(ctx context.Context, job *JobContractV2) (imageBaseline, error) {
	b.envMu.Lock()
	if base, ok := b.envBaseline[job.ImageDigest]; ok {
		b.envMu.Unlock()
		return base, nil
	}
	b.envMu.Unlock()
	// The lookup is a cached read of a pinned artifact: it gets its own
	// bounded context so a cold lookup can never consume the dispatch's
	// launch budget (or be cancelled mid-flight by it).
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	out, err := b.runOnce(lookupCtx, "image", "inspect", "--format", "json", job.Image+"@"+job.ImageDigest)
	if err != nil {
		return imageBaseline{}, fmt.Errorf("inspect the pinned image %s: %v: %s", job.ImageDigest, err, strings.TrimSpace(string(out)))
	}
	var doc struct {
		Digest string `json:"digest"`
		Config struct {
			Env        []string `json:"env"`
			Cmd        []string `json:"cmd"`
			Entrypoint []string `json:"entrypoint"`
			User       string   `json:"user"`
			WorkingDir string   `json:"working_dir"`
		} `json:"config"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return imageBaseline{}, fmt.Errorf("inspect the pinned image %s: malformed json: %w", job.ImageDigest, err)
	}
	if doc.Digest != job.ImageDigest {
		return imageBaseline{}, fmt.Errorf("image inspect reports digest %s, the contract authorized %s — refusing a substituted image", doc.Digest, job.ImageDigest)
	}
	base := imageBaseline{
		Env:        normalizeEnvSet(doc.Config.Env),
		Cmd:        doc.Config.Cmd,
		Entrypoint: doc.Config.Entrypoint,
		User:       doc.Config.User,
		WorkingDir: doc.Config.WorkingDir,
	}
	b.envMu.Lock()
	if b.envBaseline == nil {
		b.envBaseline = map[string]imageBaseline{}
	}
	b.envBaseline[job.ImageDigest] = base
	b.envMu.Unlock()
	return base, nil
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
// version AND the qualified bytes — the executable and the firmware it
// boots guests with must hash to the runtime manifest. A binary that
// reports the right version but differs in content is a substituted
// runtime, and the version string alone would never catch it. It
// returns the observed version for the startup report.
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
	if _, err := b.verifyRuntimeIdentity(ctx, got); err != nil {
		return got, err
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

// preExecutionStages are the failure stages the pinned runtime reports
// when it rejected a command before creating a process. The set is
// qualified against the pinned runtime — the stage is the runtime's own
// statement of where it failed — and an unrecognized stage fails
// closed: if the executor cannot read the stage as pre-execution, it
// cannot prove the workload never ran, and that is an unresolved
// outcome rather than a no-effect claim.
var preExecutionStages = map[string]bool{
	"Command::spawn": true,
}

// preExecutionFailure reports whether the runtime's record positively
// evidences that no process was ever created: a typed failure at a
// recognized pre-execution stage, with no pid and no start timestamp.
// Every signal must agree — one that shows a started process refuses
// the claim outright.
func preExecutionFailure(rec *msbJobRecord) bool {
	if rec.Failure == nil || rec.PID != nil || rec.StartedAt != nil {
		return false
	}
	return preExecutionStages[rec.Failure.Stage]
}

// failureShape renders what a failed record actually shows, so an
// operator reading the audit log can see which signal was missing
// rather than only that the claim was refused.
func (r *msbJobRecord) failureShape() string {
	kind, stage := "-", "-"
	if r.Failure != nil {
		if r.Failure.Kind != "" {
			kind = r.Failure.Kind
		}
		if r.Failure.Stage != "" {
			stage = r.Failure.Stage
		}
	}
	return fmt.Sprintf("failure=%t kind=%s stage=%s pid=%t started=%t",
		r.Failure != nil, kind, stage, r.PID != nil, r.StartedAt != nil)
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

// msbJobName derives the sandbox handle for one dispatch attempt:
// the job identity suffixed with the attempt's dispatch nonce. The
// nonce tail is what makes the handle unforgeable — no other
// dispatch, tenant, or re-attempt can mint the same name — so the
// handle is itself the deletion key: `msb rm <handle>` destroys by
// identity, and a substituted or foreign instance can never occupy
// the name it resolves.
//
// Determinism survives crash recovery through persistence, not
// re-derivation: the plan's handle and nonce are committed to the
// ledger before any VM exists, so a later lifetime reconciles the
// recorded handle and never needs to guess it.
//
// msb bounds names at 128 UTF-8 bytes; the nonce tail is the part
// that must never be truncated away, so a long job id is hashed out
// of the middle and the nonce is always preserved intact.
func (b *MSBBackend) msbJobName(jobID, nonce string) string {
	prefix := b.NamePrefix
	if prefix == "" {
		prefix = "sx-"
	}
	suffix := "-" + nonce
	name := prefix + jobID + suffix
	if len(name) > 120 {
		sum := sha256.Sum256([]byte(name))
		head := 120 - len(suffix) - 17
		if head < 0 {
			head = 0
		}
		name = name[:head] + "-" + hex.EncodeToString(sum[:])[:16] + suffix
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

// listJobs returns the runtime's complete job records for a sandbox.
// It is the recovery probe: when a detached launch fails without
// naming its job, the sandbox may still hold one — the launch may have
// been admitted and its identity lost in transport, and a blind
// re-launch would duplicate it.
//
// Discovery is exhaustive: the runtime pages its job list, so every
// page is followed until the runtime reports no continuation. A
// cursor that repeats, or a list that exceeds the page bound, is an
// error — incomplete discovery is never mistaken for absence of
// execution.
func (b *MSBBackend) listJobs(ctx context.Context, name string) ([]msbJobRecord, error) {
	const pageLimit = 200
	const maxPages = 25
	var all []msbJobRecord
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < maxPages; page++ {
		args := []string{"jobs", "--all", "--format", "json", "--limit", fmt.Sprint(pageLimit)}
		if cursor != "" {
			args = append(args, "--cursor", cursor)
		}
		args = append(args, name)
		out, err := b.runOnce(ctx, args...)
		if err != nil {
			return nil, fmt.Errorf("msb jobs %s: %v: %s", name, err, strings.TrimSpace(string(out)))
		}
		var doc struct {
			Items      []msbJobRecord `json:"items"`
			NextCursor *string        `json:"next_cursor"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			return nil, fmt.Errorf("msb jobs %s: malformed json: %w", name, err)
		}
		all = append(all, doc.Items...)
		if doc.NextCursor == nil || *doc.NextCursor == "" {
			return all, nil
		}
		if seen[*doc.NextCursor] {
			return nil, fmt.Errorf("msb jobs %s: the runtime repeated page cursor %q — refusing to treat incomplete discovery as absence", name, *doc.NextCursor)
		}
		seen[*doc.NextCursor] = true
		cursor = *doc.NextCursor
	}
	return nil, fmt.Errorf("msb jobs %s: job discovery exceeded %d pages — refusing to treat incomplete discovery as absence", name, maxPages)
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
	return sameStringSequence(recorded, authorized)
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
// policyFor compiles the canonical policy for one dispatch identity —
// the handle and nonce the VM will carry — and returns it with its
// digest. The pinned image's own config environment is part of the
// authorized set: the runtime injects it into every VM booted from
// that digest.
func (b *MSBBackend) policyFor(ctx context.Context, job *JobContractV2, handle, nonce string) (*EffectivePolicyV1, string, error) {
	imageEnv, err := b.imageDefaults(ctx, job)
	if err != nil {
		return nil, "", err
	}
	policy, err := b.buildEffectivePolicy(job, handle, nonce, b.requiredVersion(), imageEnv)
	if err != nil {
		return nil, "", err
	}
	digest, err := policy.Digest()
	if err != nil {
		return nil, "", err
	}
	return policy, digest, nil
}

// Prepare computes the dispatch identity without creating anything: the
// deterministic handle, a fresh nonce, the canonical policy and digest,
// the authorized image digest and the qualified runtime identity. The
// caller persists it before Dispatch, so the authorization on disk
// always precedes the VM it authorizes.
func (b *MSBBackend) Prepare(ctx context.Context, job *JobContractV2) (*DispatchPlan, error) {
	if job == nil {
		return nil, fmt.Errorf("prepare requires a signed job contract")
	}
	nonce, err := dispatchNonce()
	if err != nil {
		return nil, err
	}
	handle := b.msbJobName(job.JobID, nonce)
	policy, digest, err := b.policyFor(ctx, job, handle, nonce)
	if err != nil {
		return nil, err
	}
	m := b.runtimeManifest()
	return &DispatchPlan{
		Handle:                handle,
		Nonce:                 nonce,
		Policy:                policy,
		PolicyDigest:          digest,
		ImageDigest:           job.ImageDigest,
		RuntimeVersion:        m.Version,
		RuntimeMSBSHA256:      m.MSBSHA256,
		RuntimeFirmwareSHA256: m.LibkrunfwSHA256,
	}, nil
}

func (b *MSBBackend) Dispatch(ctx context.Context, job *JobContractV2, plan *DispatchPlan) (RunIdentity, error) {
	if job == nil {
		return RunIdentity{}, fmt.Errorf("dispatch requires a signed job contract")
	}
	if plan == nil {
		// The caller did not pre-persist a plan (a direct/test call):
		// prepare one now so the launch still runs under a canonical
		// identity. A prepare failure is a pre-launch refusal —
		// nothing has been created.
		prepared, perr := b.Prepare(ctx, job)
		if perr != nil {
			return RunIdentity{}, fmt.Errorf("%w: %v", ErrDispatchRefused, perr)
		}
		plan = prepared
	}
	if plan.Handle == "" || plan.Nonce == "" || plan.Policy == nil || plan.PolicyDigest == "" {
		return RunIdentity{}, fmt.Errorf("%w: the dispatch plan is incomplete (handle, nonce, policy and digest are required)", ErrDispatchRefused)
	}
	name, nonce, policy, policyDigest := plan.Handle, plan.Nonce, plan.Policy, plan.PolicyDigest
	createArgs, err := b.createArgs(job, name, nonce)
	if err != nil {
		return RunIdentity{}, fmt.Errorf("%w: %v", ErrDispatchRefused, err)
	}
	identity := RunIdentity{Handle: name, PolicyDigest: policyDigest, Nonce: nonce}

	out, cerr := b.runOnce(ctx, createArgs...)
	if cerr != nil {
		if ctx.Err() != nil {
			// The VM may exist; the dispatch never reached a
			// verified launch, so the handle is returned for
			// reconcile, never a blind retry.
			return identity, fmt.Errorf("%w: create deadline expired before the VM was proven: %v", ErrAmbiguousDispatch, ctx.Err())
		}
		if strings.Contains(strings.ToLower(string(out)), "already exists") {
			return RunIdentity{}, fmt.Errorf("%w: sandbox %q already exists — refusing to reuse a VM this dispatch did not create", ErrDispatchRefused, name)
		}
		// A create can fail after the VM was already booted (a guest
		// validation error, for instance). The leftover is removed
		// through the identity-bound cleanup path; when its absence
		// cannot be verified the resource is not a proven refusal —
		// the outcome is ambiguous and reconciliation owns the
		// residue the dispatch identity now records.
		if !b.refusedCleanup(ctx, job, name, nonce) {
			return identity, fmt.Errorf("%w: msb create failed (%v: %s) and the leftover instance could not be proven removed — resource cleanup remains owed under the dispatch identity", ErrAmbiguousDispatch, cerr, strings.TrimSpace(string(out)))
		}
		return RunIdentity{}, fmt.Errorf("%w: msb create failed: %v: %s", ErrDispatchRefused, cerr, strings.TrimSpace(string(out)))
	}

	// Pre-execution policy verification: the VM that boots must be
	// the VM the canonical policy describes, exactly, or it never
	// runs the job. The boot generation is then bound to the
	// dispatch, so a substituted VM under the same name cannot be
	// adopted later.
	doc, ierr := b.inspectRaw(ctx, name)
	if ierr != nil {
		// The VM we just created could not be inspected — a
		// transport failure says nothing about what now occupies
		// the name. Removal still goes through the verified,
		// identity-bound path; if absence cannot be proven, the
		// resource stays owed under the recorded dispatch identity
		// rather than forgotten under a refusal claim.
		if !b.refusedCleanup(ctx, job, name, nonce) {
			return identity, fmt.Errorf("%w: verify sandbox %s before execution failed (%v) and the leftover instance could not be proven removed — resource cleanup remains owed under the dispatch identity", ErrAmbiguousDispatch, name, ierr)
		}
		return RunIdentity{}, fmt.Errorf("%w: verify sandbox %s before execution: %v", ErrDispatchRefused, name, ierr)
	}
	if verr := verifyBootedPolicy(policy, doc); verr != nil {
		if !b.refusedCleanup(ctx, job, name, nonce) {
			return identity, fmt.Errorf("%w: sandbox %s failed policy verification and the leftover instance could not be proven removed — resource cleanup remains owed under the dispatch identity: %v", ErrAmbiguousDispatch, name, verr)
		}
		return RunIdentity{}, fmt.Errorf("%w: sandbox %s failed policy verification — destroyed before execution: %v", ErrDispatchRefused, name, verr)
	}
	bootID, berr := b.sandboxBootID(doc)
	if berr != nil {
		if !b.refusedCleanup(ctx, job, name, nonce) {
			return identity, fmt.Errorf("%w: could not bind the VM boot generation of %s and the leftover instance could not be proven removed — resource cleanup remains owed under the dispatch identity: %v", ErrAmbiguousDispatch, name, berr)
		}
		return RunIdentity{}, fmt.Errorf("%w: bind the VM boot generation of %s before execution: %v", ErrDispatchRefused, name, berr)
	}
	identity.BootID = bootID

	lout, lerr := b.runOnce(ctx, b.launchArgs(job, name)...)
	if lerr == nil {
		if runID, ok := parseRunID(string(lout)); ok {
			// The launch named a job: the workload started. It is
			// this dispatch's only if the runtime's record proves it
			// runs in the VM this dispatch verified; if that proof
			// cannot be made, the outcome is uncertain — the VM and
			// its workload are left for reconciliation, and no
			// no-effect claim is ever made about them.
			if aerr := b.verifyLaunchedRun(ctx, name, runID, bootID); aerr != nil {
				identity.RunID = runID
				return identity, fmt.Errorf("%w: %v", ErrAmbiguousDispatch, aerr)
			}
			identity.RunID = runID
			return identity, nil
		}
	}
	// The launch did not name a job. It may still have been admitted:
	// probe the sandbox before calling it a refusal, and adopt the
	// job the runtime recorded rather than duplicating it — provided
	// it runs in the boot generation this dispatch verified.
	probeCtx, cancel := context.WithTimeout(ctx, b.dispatchProbeTimeout())
	defer cancel()
	jobs, perr := b.listJobs(probeCtx, name)
	switch {
	case perr != nil:
		// The probe failed too — the outcome is genuinely unknown.
		return identity, fmt.Errorf("%w: detached launch failed (%v: %s) and the job list could not be read: %v",
			ErrAmbiguousDispatch, lerr, strings.TrimSpace(string(lout)), perr)
	default:
		matched := matchContractJobs(jobs, job)
		switch len(matched) {
		case 1:
			// The launch was admitted; only its identity was lost.
			// The record may be adopted only if it proves to run in
			// the boot generation this dispatch verified. A mismatch
			// means the job belongs to a different VM instance — a
			// substituted or re-created sandbox — and that workload
			// may still be running: it is preserved for operator
			// reconciliation, its identity returned as evidence, and
			// the outcome stays ambiguous. An unverified identity is
			// never proof the workload stopped, so nothing here is
			// destroyed and no refusal is claimed.
			if matched[0].RuntimeBoot != bootID {
				identity.RunID = matched[0].ID
				return identity, fmt.Errorf("%w: the sandbox records job %s under boot generation %s, not the verified %s — a substituted VM instance whose workload may be live is left for reconciliation, never destroyed on an identity mismatch",
					ErrAmbiguousDispatch, matched[0].ID, matched[0].RuntimeBoot, bootID)
			}
			identity.RunID = matched[0].ID
			return identity, nil
		case 0:
			// The launch may have been admitted. The runtime records
			// every job it admits — including one whose spawn it
			// rejected — so an empty list is not evidence that nothing
			// executed, and the CLI's own exit status is not either.
			// The VM is left for reconciliation rather than destroyed
			// under a workload that may be running, and no no-effect
			// claim is ever made about it.
			detail := fmt.Sprintf("msb exec -d failed: %v: %s", lerr, strings.TrimSpace(string(lout)))
			if lerr == nil {
				detail = fmt.Sprintf("msb exec -d named no job: %s", strings.TrimSpace(string(lout)))
			}
			return identity, fmt.Errorf("%w: %s, and the sandbox records no job for the authorized command — the runtime's record cannot prove that nothing executed",
				ErrAmbiguousDispatch, detail)
		default:
			return identity, fmt.Errorf("%w: sandbox %s records %d jobs matching the authorized command — an operator must reconcile them",
				ErrAmbiguousDispatch, name, len(matched))
		}
	}
}

// verifyLaunchedRun proves the runtime-owned job the launch named is
// running in the boot generation this dispatch verified — the
// execution-identity binding between the VM and the job.
func (b *MSBBackend) verifyLaunchedRun(ctx context.Context, name, runID, bootID string) error {
	rec, err := b.inspectJob(ctx, name, runID)
	if err != nil {
		return fmt.Errorf("verify the launched job %s: %w", runID, err)
	}
	if rec.RuntimeBoot != bootID {
		return fmt.Errorf("job %s reports boot generation %s but the verified VM is %s — refusing a substituted VM instance", runID, rec.RuntimeBoot, bootID)
	}
	return nil
}

// dispatchProbeTimeout bounds the post-failure job-list probe so a
// wedged runtime cannot pin the admission path.
func (b *MSBBackend) dispatchProbeTimeout() time.Duration { return 15 * time.Second }

// refusedCleanupTimeout bounds the identity-bound removal a refused
// dispatch still owes its leftover VM. It is detached from the
// dispatch context — which may be nearly spent — but never
// unbounded: inspect, conditional removal, and post-verification all
// run inside this window.
const refusedCleanupTimeout = 45 * time.Second

// refusedCleanup settles the resource accounting for a dispatch that
// is being refused after a VM may already exist. The leftover goes
// through the same identity-bound, verified removal a finished job's
// cleanup uses — never a best-effort destroy whose result is
// discarded. It reports whether the authorized instance is proven
// gone; when it is not, the caller returns the dispatch identity with
// ErrAmbiguousDispatch so the residue stays durable under
// reconciliation instead of evaporating behind a NO_EFFECT claim.
func (b *MSBBackend) refusedCleanup(ctx context.Context, job *JobContractV2, name, nonce string) bool {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refusedCleanupTimeout)
	defer cancel()
	res, err := b.Cleanup(cctx, CleanupRequest{
		JobID: job.JobID, BackendID: b.Name(), Handle: name, DispatchNonce: nonce,
	})
	return err == nil && res.Outcome.ProvesAbsent()
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
// unresolved. Recovery requires the persisted dispatch authorization:
// a row carrying no policy digest or nonce is never adopted — a
// matching command is not authority — and stays unresolved for an
// operator. When the run identity was lost with the crash — the
// window between the runtime admitting a job and the ledger naming it
// — the runtime's own job list is the proof of what was admitted: a
// single job matching the authorized argv is adopted; zero or several
// are unobserved, never guessed at. A recovered job must run in the
// boot generation the ledger recorded (when it recorded one): a
// substituted VM under the same name is never adopted. The run is then
// observed exactly as a live monitor would, so a recovered job reaches
// the same terminal result and artifact it would have reached live.
func (b *MSBBackend) Resume(ctx context.Context, job *JobContractV2, run RunIdentity) (RunIdentity, *ExecResult, error) {
	if job == nil {
		return run, nil, fmt.Errorf("resume requires the job's signed contract")
	}
	// The sandbox's *current* boot generation must be the one the
	// ledger recorded: a VM re-created under the same name is a
	// substituted instance, and nothing it records is this run.
	doc, derr := b.inspectRaw(ctx, run.Handle)
	if derr != nil {
		return run, nil, fmt.Errorf("%w: cannot inspect the sandbox to bind its boot generation: %v", ErrExecutionUnobserved, derr)
	}
	currentBoot, berr := b.sandboxBootID(doc)
	if berr != nil {
		return run, nil, fmt.Errorf("%w: %v", ErrExecutionUnobserved, berr)
	}
	if run.BootID != "" && currentBoot != run.BootID {
		return run, nil, fmt.Errorf("%w: sandbox %s is boot generation %s, not the dispatch's %s — refusing to adopt a substituted VM instance",
			ErrExecutionUnobserved, run.Handle, currentBoot, run.BootID)
	}
	// Authorization, not command matching: the VM must still match the
	// policy the dispatch was authorized under — the same handle, the
	// same dispatch nonce, the same operator configuration — and its
	// booted configuration must still equal that policy. A VM whose
	// policy cannot be proven is never adopted, whatever its name or
	// command says.
	//
	// The proof is mandatory. The dispatch authorization is persisted
	// before the backend may create anything, so a row carrying no
	// policy digest or no nonce cannot be authorized from the runtime's
	// record: matching command arguments, or finding a sandbox under
	// the expected name, is not authority. Such a row stays unresolved
	// for an operator instead of being adopted.
	if run.PolicyDigest == "" || run.Nonce == "" {
		return run, nil, fmt.Errorf("%w: the dispatch carries no persisted authorization (policy digest %q, nonce %q) — refusing to reconstruct authority from the runtime's record; the job stays unresolved",
			ErrExecutionUnobserved, run.PolicyDigest, run.Nonce)
	}
	policy, digest, perr := b.policyFor(ctx, job, run.Handle, run.Nonce)
	if perr != nil {
		return run, nil, fmt.Errorf("%w: cannot recompute the dispatch's policy to authorize recovery: %v", ErrExecutionUnobserved, perr)
	}
	if digest != run.PolicyDigest {
		return run, nil, fmt.Errorf("%w: sandbox %s would run under policy %s, not the dispatch's approved %s — refusing to adopt it (the operator configuration changed, or the authorization was rewritten)",
			ErrExecutionUnobserved, run.Handle, digest, run.PolicyDigest)
	}
	if verr := verifyBootedPolicy(policy, doc); verr != nil {
		return run, nil, fmt.Errorf("%w: sandbox %s no longer matches its approved policy: %v", ErrExecutionUnobserved, run.Handle, verr)
	}
	if run.RunID == "" {
		jobs, err := b.listJobs(ctx, run.Handle)
		if err != nil {
			return run, nil, fmt.Errorf("%w: cannot read the sandbox's job list: %v", ErrExecutionUnobserved, err)
		}
		matched := matchContractJobs(jobs, job)
		switch len(matched) {
		case 0:
			return run, nil, fmt.Errorf("%w: sandbox %s records no job matching the authorized command", ErrExecutionUnobserved, run.Handle)
		case 1:
			// The recovered job must be the boot generation the
			// ledger recorded; when the ledger recorded none (the
			// crash window), the job's own generation is adopted —
			// it is the runtime's record of what ran.
			if run.BootID != "" && matched[0].RuntimeBoot != run.BootID {
				return run, nil, fmt.Errorf("%w: sandbox %s records job %s under boot generation %s, not the dispatch's %s — refusing to adopt a substituted VM instance",
					ErrExecutionUnobserved, run.Handle, matched[0].ID, matched[0].RuntimeBoot, run.BootID)
			}
			if matched[0].RuntimeBoot != currentBoot {
				return run, nil, fmt.Errorf("%w: sandbox %s is boot generation %s but its job %s belongs to %s — refusing to adopt a substituted VM instance",
					ErrExecutionUnobserved, run.Handle, currentBoot, matched[0].ID, matched[0].RuntimeBoot)
			}
			run.RunID = matched[0].ID
			if run.BootID == "" {
				run.BootID = matched[0].RuntimeBoot
			}
		default:
			return run, nil, fmt.Errorf("%w: sandbox %s records %d jobs matching the authorized command — an operator must reconcile them",
				ErrExecutionUnobserved, run.Handle, len(matched))
		}
	}
	res, err := b.Wait(ctx, job, run)
	return run, res, err
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
func (b *MSBBackend) Wait(ctx context.Context, job *JobContractV2, run RunIdentity) (*ExecResult, error) {
	if job == nil {
		return nil, fmt.Errorf("wait requires the job's signed contract")
	}
	if !jobIDPattern.MatchString(run.RunID) {
		return nil, fmt.Errorf("%w: run identity %q is not a runtime job id", ErrExecutionUnobserved, run.RunID)
	}
	if !bootIDPattern.MatchString(run.BootID) {
		return nil, fmt.Errorf("%w: boot generation %q is not a runtime boot id — refusing to observe a run without its VM identity", ErrExecutionUnobserved, run.BootID)
	}
	slack := b.ObservationSlack
	if slack <= 0 {
		slack = maxDurationGrace + captureMargin
	}
	window := time.Duration(job.Resources.TimeoutSeconds)*time.Second + slack
	obsCtx, cancelObs := context.WithTimeout(ctx, window)
	defer cancelObs()

	res, err := b.observe(obsCtx, ctx, job, run)
	if err != nil {
		return nil, err
	}

	// The exit is observed; the artifact must now be finalized or
	// the result is not fully verified. The capture gets its own
	// bounded window so an observation that finished near the
	// deadline does not doom the artifact.
	capCtx, cancelCap := context.WithTimeout(ctx, captureMargin)
	defer cancelCap()
	cap, cerr := b.capture(capCtx, job, run.Handle, run.RunID)
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
func (b *MSBBackend) observe(obsCtx, parent context.Context, job *JobContractV2, run RunIdentity) (*ExecResult, error) {
	interval := b.PollInterval
	if interval <= 0 {
		interval = jobPollInterval
	}
	var lastErr error
	for {
		rec, err := b.inspectJob(obsCtx, run.Handle, run.RunID)
		if err == nil {
			if !sameArgv(rec.Command, job.Argv) {
				return nil, fmt.Errorf("%w: job %s records a different command than the contract authorized", ErrExecutionUnobserved, run.RunID)
			}
			if rec.RuntimeBoot != run.BootID {
				return nil, fmt.Errorf("%w: job %s reports boot generation %s, not the dispatch's %s — a substituted VM is never adopted",
					ErrExecutionUnobserved, run.RunID, rec.RuntimeBoot, run.BootID)
			}
			switch rec.State {
			case "exited":
				res := &ExecResult{RuntimeState: rec.State, RunID: run.RunID, BootID: run.BootID, PolicyDigest: run.PolicyDigest, FinishedAt: rec.finishedAt()}
				switch {
				case rec.TimedOut:
					// The runtime killed the command at the deadline:
					// an observed outcome, but not a guest exit.
					res.TimedOut = true
				case rec.ExitCode != nil:
					res.ExitVerified = true
					res.ExitCode = *rec.ExitCode
				default:
					return nil, fmt.Errorf("%w: job %s is exited without an exit code and without a timeout", ErrExecutionUnobserved, run.RunID)
				}
				return res, nil
			case "failed":
				// A no-effect claim needs positive evidence that no
				// process was ever created, and the runtime's own
				// record is where that lives: a typed failure, at a
				// pre-execution stage, with no pid and no start
				// timestamp. A bare `failed` state proves nothing about
				// whether the workload ran — defaulting the kind to
				// "unknown" made every failure a no-effect claim — so
				// an untyped failure, an unrecognized stage, or a
				// record showing a started process is unobserved
				// instead.
				if !preExecutionFailure(rec) {
					return nil, fmt.Errorf("%w: job %s is failed without proof that the command never started (%s)",
						ErrExecutionUnobserved, run.RunID, rec.failureShape())
				}
				return &ExecResult{
					RuntimeState:   rec.State,
					RunID:          run.RunID,
					BootID:         run.BootID,
					PolicyDigest:   run.PolicyDigest,
					FailureKind:    rec.Failure.Kind,
					FailureStage:   rec.Failure.Stage,
					FailureMessage: rec.Failure.text(),
					FinishedAt:     rec.finishedAt(),
				}, nil
			case "lost":
				return nil, fmt.Errorf("%w: the runtime lost job %s: %s", ErrExecutionUnobserved, run.RunID, rec.errorText())
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
				return nil, fmt.Errorf("%w: no terminal record for job %s within its observation window (last error: %v)", ErrExecutionUnobserved, run.RunID, lastErr)
			}
			return nil, fmt.Errorf("%w: job %s did not reach a terminal state within its observation window", ErrExecutionUnobserved, run.RunID)
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
	// The rename's durability is part of the artifact's integrity: an
	// unsynced directory can lose the published name in a crash while
	// evidence already claims the digest. A sync failure is an
	// unfinalized artifact — the result is not fully verified.
	if err := syncDir(b.StateDir); err != nil {
		return nil, fmt.Errorf("commit artifact directory %s: %w", b.StateDir, err)
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

// syncDir commits a directory entry (a rename's new name) to stable
// storage — the durability half of atomic publication.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	serr := dir.Sync()
	cerr := dir.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// boundedArtifactWriter stores at most bound bytes of the runtime's// retained output and hashes exactly the stored bytes. Bytes past the
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

// Cleanup removes the exact sandbox instance the request authorizes.
//
// The removal is identity-bound end to end: the destructive operation
// is never issued against a reusable name — the runtime is asked to
// delete every sandbox carrying the dispatch's ownership labels, so
// the only instance that can match is the one this dispatch created.
// A substituted or foreign VM under the same name cannot carry those
// labels and is never selected.
//
// Protocol:
//
//  1. Verify what currently occupies the handle. Its dispatch label
//     must equal the request's nonce and (when known) its job label
//     the request's job — anything else is a substitute or foreign
//     instance and is reported, never destroyed. A recorded boot
//     generation that no longer matches is reported too: the instance
//     still carries our authority, so it is removed, but the
//     divergence is evidence.
//  2. `msb rm -f <handle>` — deletion by the nonce-bound name. The
//     handle embeds this dispatch's 128-bit nonce (see msbJobName),
//     so the name the runtime resolves can only ever have been minted
//     by this dispatch: a substitute would have to occupy an
//     unforgeable name, which it cannot. That closes the resolve→
//     delete window by construction rather than by trusting the
//     runtime's internal timing — the identity condition is the name
//     itself, not a selector the CLI first maps onto a reusable one.
//     The label check in step 1 remains as the authorization gate:
//     a handle whose occupant presents foreign labels is refused
//     before the delete is ever issued.
//  3. Post-verify: the handle must now name nothing, or name an
//     instance that does not carry our labels (a substitute that
//     survived, correctly). The handle still naming our labels is a
//     contradiction the runtime claimed to have resolved — uncertain.
//
// An error never proves absence, and a timeout after the removal was
// issued is REMOVAL_UNCERTAIN unless the post-check resolves it. The
// one residual the CLI cannot close is a runtime-internal fault: msb
// resolves the name to its catalog record before deleting it, and if
// the runtime itself swapped the record under an occupied name the
// boundary cannot observe it — but occupying the name requires the
// nonce, and the nonce never leaves this executor's dispatch
// identity, so the residual requires a compromised runtime, at which
// point no CLI contract helps. A native conditional-delete binding
// (msb's own catalog-locked removal) remains the upgrade path and is
// tracked with the defect register.
func (b *MSBBackend) Cleanup(ctx context.Context, req CleanupRequest) (CleanupResult, error) {
	if b.KeepSandboxes {
		return refuse(CleanupRetainedByPolicy,
			"backend retention policy (keep_sandboxes): the sandbox is intentionally retained — the removal obligation is discharged by policy, not by verified absence")
	}
	if err := req.Validate(); err != nil {
		return refuse(CleanupIdentityUnverifiable, "%v", err)
	}
	prefix := b.NamePrefix
	if prefix == "" {
		prefix = "sx-"
	}
	if !strings.HasPrefix(req.Handle, prefix) {
		return refuse(CleanupIdentityUnverifiable,
			"handle %q is outside this backend's namespace %q — refusing to destroy outside the jobs this backend launched", req.Handle, prefix)
	}
	if !strings.HasSuffix(req.Handle, "-"+req.DispatchNonce) {
		// Every handle this backend mints ends with its dispatch
		// nonce — the nonce is the deletion key. A request whose
		// handle and claimed nonce disagree is malformed authority,
		// not an identity to verify: nothing is removed.
		return refuse(CleanupIdentityUnverifiable,
			"handle %q does not end with the claimed dispatch nonce — the deletion key and the asserted identity disagree", req.Handle)
	}

	// Step 1 — verify what the handle currently names.
	var notes string
	doc, ierr := b.inspectRaw(ctx, req.Handle)
	switch {
	case ierr == nil:
		cfg, _ := doc["config"].(map[string]any)
		labels, _ := cfg["labels"].(map[string]any)
		dispatch := jsonString(labels, "crabedence.dispatch")
		jobLabel := jsonString(labels, "crabedence.job")
		if dispatch != req.DispatchNonce || (req.JobID != "" && jobLabel != req.JobID) {
			return refuse(CleanupIdentityMismatch,
				"sandbox %s carries dispatch %q job %q, not the authorized %q/%q — a substituted or foreign instance is never destroyed; it belongs to an operator",
				req.Handle, dispatch, jobLabel, req.DispatchNonce, req.JobID)
		}
		if req.BootID != "" {
			if boot, berr := b.sandboxBootID(doc); berr == nil && boot != req.BootID {
				// Still our instance — labels cannot move — but the
				// boot generation diverged: someone rebooted it. The
				// removal remains authorized; the divergence is
				// evidence for the record.
				notes = fmt.Sprintf("note: sandbox %s boot generation %s diverged from the recorded %s (instance identity confirmed by labels); ", req.Handle, boot, req.BootID)
			}
		}
	case msbNotFound(ierr):
		// The handle names nothing. The authorized instance can only
		// exist at its handle — msb names are unique and an instance
		// cannot move — so absence at the name is verified absence.
		return refuse(CleanupAlreadyAbsentVerified,
			"sandbox %s is already absent — the authorized instance is gone", req.Handle)
	default:
		// The current occupant cannot be classified: we cannot prove
		// the label-conditioned removal would hit only the authorized
		// instance — but the removal itself is still conditioned, so
		// issue it and let the post-check resolve the outcome.
	}

	// Step 2 — identity-bound removal. The handle is the deletion
	// condition: it embeds this dispatch's nonce, so the name the
	// runtime resolves can only name this dispatch's instance — a
	// substitute or foreign sandbox cannot mint it, and a reused job
	// name under a newer nonce is a different name entirely. The
	// fence is carried on the request for the record — the runtime
	// cannot evaluate our leases, so the caller's commit-boundary
	// validation is what makes the fence durable.
	rmArgs := []string{"rm", "-f", req.Handle}
	out, rerr := b.runOnce(ctx, rmArgs...)
	switch {
	case rerr != nil && ctx.Err() == nil:
		if msbNotFound(fmt.Errorf("%v: %s", rerr, strings.ToLower(string(out)))) {
			// Nothing carried the authorized identity: either the
			// instance was already gone, or step 1 could not classify
			// the occupant and the labels agree there is nothing of
			// ours. The post-check resolves which.
		} else {
			// A real removal failure — possibly after partial effect.
			vctx, vcancel := postCleanupCtx(ctx)
			defer vcancel()
			return b.postCleanupVerify(vctx, req, notes+"the identity-conditioned removal failed: "+errText(rerr, out))
		}
	case ctx.Err() != nil:
		// The deadline expired with the removal in flight — the
		// command may or may not have taken effect.
		vctx, vcancel := postCleanupCtx(ctx)
		defer vcancel()
		return b.postCleanupVerify(vctx, req, notes+"the removal deadline expired after the command was issued — outcome uncertain")
	}

	// Step 3 — verify the resulting state independently.
	vctx, vcancel := postCleanupCtx(ctx)
	defer vcancel()
	return b.postCleanupVerify(vctx, req, notes)
}

// postCleanupVerifyTimeout bounds post-removal verification. The
// check runs detached from the caller's deadline — which may already
// be spent — but never unbounded: a hung inspect is REMOVAL_UNCERTAIN
// after this window, not an indefinite block on the external CLI.
const postCleanupVerifyTimeout = 15 * time.Second

// postCleanupCtx gives post-removal verification its own bounded
// lifetime: detached from the caller's (possibly already-expired)
// cancellation so the check can run to a conclusion, and re-deadlined
// so a hung runtime cannot park cleanup accounting forever.
func postCleanupCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), postCleanupVerifyTimeout)
}

// postCleanupVerify independently confirms what the handle now names
// after an identity-conditioned removal (or a failed one): absence or
// a foreign occupant proves the authorized instance is gone; our
// labels still present contradict the removal. pre may carry the
// failure context that forced verification.
func (b *MSBBackend) postCleanupVerify(ctx context.Context, req CleanupRequest, pre string) (CleanupResult, error) {
	doc, ierr := b.inspectRaw(ctx, req.Handle)
	switch {
	case ierr == nil:
		cfg, _ := doc["config"].(map[string]any)
		labels, _ := cfg["labels"].(map[string]any)
		if jsonString(labels, "crabedence.dispatch") == req.DispatchNonce &&
			(req.JobID == "" || jsonString(labels, "crabedence.job") == req.JobID) {
			return refuse(CleanupRemovalUncertain,
				"%ssandbox %s still carries the authorized identity after the removal — the runtime could not prove it was destroyed", prefixDetail(pre), req.Handle)
		}
		return refuse(CleanupRemovedVerified,
			"%ssandbox %s now names a different instance (dispatch %q) — the authorized instance is verified gone and the substitute survived",
			prefixDetail(pre), req.Handle, jsonString(labels, "crabedence.dispatch"))
	case msbNotFound(ierr):
		if pre != "" {
			return refuse(CleanupAlreadyAbsentVerified,
				"%s — sandbox %s is absent; nothing carrying the authorized identity remains", pre, req.Handle)
		}
		return refuse(CleanupRemovedVerified,
			"sandbox %s is absent — the authorized instance was removed and verified gone", req.Handle)
	default:
		return refuse(CleanupRemovalUncertain,
			"%spost-removal verification of %s failed (%v) — the authorized instance may be gone or may still exist", prefixDetail(pre), req.Handle, ierr)
	}
}

// prefixDetail joins the forced-verification context to a verdict.
func prefixDetail(pre string) string {
	if pre == "" {
		return ""
	}
	return pre + "; "
}

// errText renders a failed CLI call for evidence strings.
func errText(err error, out []byte) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return err.Error()
	}
	return fmt.Sprintf("%v: %s", err, msg)
}

// msbNotFound reports whether a CLI failure means the named sandbox
// (or the label selection) matched nothing.
func msbNotFound(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "not found") || strings.Contains(text, "does not exist") ||
		strings.Contains(text, "no sandbox")
}

// Close releases backend resources. Nothing is long-lived: every
// observation is a bounded CLI call, and a running job belongs to the
// runtime, not this process.
func (b *MSBBackend) Close() error { return nil }

// Name is the provider identity receipts and ledger rows attest.
func (b *MSBBackend) Name() string { return "microsandbox" }

// ─── Policy inspection helpers ───────────────────────────────────────
//
// A signed contract is a claim about the VM that should run; the
// inspect document is what actually booted. The canonical policy and
// its exact verification live in policy.go; these are the small
// readers they share.

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

// mountHostPermissionsConfined and mountStatVirtualizationStrict are
// the renderings that keep host identity out of the guest: the guest
// sees its own permission bits and its own file stats, never the
// host's. They are qualified against the pinned runtime, and a mount
// rendered any other way refuses rather than being assumed harmless.
const (
	mountHostPermissionsConfined  = "private"
	mountStatVirtualizationStrict = "strict"
)

// declaredMountHardening lists the hardening options a contract's mount
// declared, in msb's option spelling. Read-only intent is handled
// separately — it is compared exactly, in both directions — so it is
// not repeated here. Tokens the executor does not recognize are left
// alone: the CLI refuses what it cannot honor, and the job refuses with
// it.
func declaredMountHardening(options string) []string {
	out := []string{}
	for _, tok := range strings.Split(options, ",") {
		switch strings.TrimSpace(tok) {
		case "nodev", "nosuid", "noexec":
			out = append(out, strings.TrimSpace(tok))
		}
	}
	return out
}

var _ Backend = (*MSBBackend)(nil)
