package sandboxexecutor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// EffectivePolicyVersion is the canonical policy shape this executor
// compiles and verifies.
const EffectivePolicyVersion = 1

// bootIDPattern is the runtime's boot-generation identity shape, as
// the runtime's own state file and job records spell it.
var bootIDPattern = regexp.MustCompile(`^boot_[0-9a-f]{32}$`)

// EffectivePolicyV1 is the canonical, immutable policy one job runs
// under: the signed contract compiled together with every mandatory
// operator restriction. It is the single source of truth for
// verification — the booted VM must match it exactly, or no guest
// code starts — and its digest identifies the policy a result was
// produced under, so evidence names the authorization, not just the
// job.
//
// Every field is normalized (sorted, deduplicated, canonicalized) so
// two policies that mean the same thing hash the same, and a policy
// that means anything different hashes differently.
type EffectivePolicyV1 struct {
	Version     int      `json:"version"`
	JobID       string   `json:"job_id"`
	Principal   string   `json:"principal"`
	Image       string   `json:"image"`
	ImageDigest string   `json:"image_digest"`
	Argv        []string `json:"argv"`

	// Env is the complete authorized guest environment: the contract's
	// entries plus the pinned image's own config environment (fixed
	// for the pinned digest). The booted environment must equal this
	// set exactly — an entry nobody authorized refuses.
	Env []string `json:"env"`

	NetworkMode  string   `json:"network_mode"`
	NetworkAllow []string `json:"network_allow,omitempty"`

	// RuntimeShell is the pinned runtime's default command shell. An
	// execution hook the policy did not authorize — a different shell
	// the runtime would use for the guest command — is a refusal.
	RuntimeShell string `json:"runtime_shell"`
	// RuntimeCmd / RuntimeEntrypoint / RuntimeUser are the pinned
	// image's own execution defaults (fixed for its digest): the VM
	// must boot with exactly them, so nothing about how the guest
	// starts is left to an image or a runtime default nobody
	// authorized.
	RuntimeCmd        []string `json:"runtime_cmd,omitempty"`
	RuntimeEntrypoint []string `json:"runtime_entrypoint,omitempty"`
	RuntimeUser       string   `json:"runtime_user,omitempty"`

	SecurityProfile   string `json:"security_profile"`
	DeploymentProfile string `json:"deployment_profile"`
	// ExternalMountPolicy is the host-mount confinement the runtime
	// must boot under; the executor requires the strictest profile.
	ExternalMountPolicy string `json:"external_mount_policy"`

	Workdir string  `json:"workdir,omitempty"`
	Mounts  []Mount `json:"mounts,omitempty"`

	CPUs     float64 `json:"cpus,omitempty"`
	MemoryMB uint64  `json:"memory_mb,omitempty"`
	DiskMB   uint64  `json:"disk_mb,omitempty"`
	// MaxCPUs / MaxMemoryMB are the ceilings the runtime must boot
	// with: no headroom beyond the authorized budget, so a VM cannot
	// burst past what the contract and the pool accounted for.
	MaxCPUs         float64 `json:"max_cpus,omitempty"`
	MaxMemoryMB     uint64  `json:"max_memory_mb,omitempty"`
	Pids            uint32  `json:"pids,omitempty"`
	TimeoutSeconds  uint32  `json:"timeout_seconds"`
	MaxDurationSecs uint32  `json:"max_duration_secs"`
	MaxOutputBytes  uint64  `json:"max_output_bytes,omitempty"`

	SandboxName   string `json:"sandbox_name"`
	DispatchNonce string `json:"dispatch_nonce"`
	PullPolicy    string `json:"pull_policy"`

	RuntimeVersion        string `json:"runtime_version"`
	RuntimeMSBSHA256      string `json:"runtime_msb_sha256"`
	RuntimeFirmwareSHA256 string `json:"runtime_firmware_sha256"`
}

// ExternalMountPolicyStrict is the host-mount confinement the runtime
// must boot under: no implicit host paths.
const ExternalMountPolicyStrict = "strict"

// defaultRuntimeShell is the pinned runtime's default command shell —
// part of the effective policy, so a runtime that would run the guest
// command through anything else refuses.
const defaultRuntimeShell = "/bin/sh"

// buildEffectivePolicy compiles the contract and the backend's
// mandatory restrictions into the canonical policy for one dispatch.
// imageEnv is the pinned image's own config environment; it is part of
// the authorized set because the runtime injects it into every VM
// booted from that digest.
func (b *MSBBackend) buildEffectivePolicy(job *JobContractV2, name, nonce string, runtimeVersion string, image imageBaseline) (*EffectivePolicyV1, error) {
	if job == nil {
		return nil, fmt.Errorf("policy requires a signed job contract")
	}
	profile, err := deploymentProfileJSON(b.deploymentProfile())
	if err != nil {
		return nil, err
	}
	pull := b.PullPolicy
	if pull == "" {
		pull = PullNever
	}
	if pull != PullNever && pull != PullIfMissing {
		return nil, fmt.Errorf("unknown image pull policy %q (want %q or %q)", pull, PullNever, PullIfMissing)
	}
	env := normalizeEnvSet(append(append([]string{}, job.Env...), image.Env...))
	workdir := job.Filesystem.Workdir
	if workdir == "" {
		// The image's own working directory is the effective default
		// when the contract does not override it.
		workdir = image.WorkingDir
	}
	mounts := append([]Mount{}, job.Filesystem.Mounts...)
	sort.Slice(mounts, func(i, j int) bool {
		if mounts[i].Dest != mounts[j].Dest {
			return mounts[i].Dest < mounts[j].Dest
		}
		return mounts[i].Source < mounts[j].Source
	})
	allow := append([]string{}, job.Network.Allow...)
	sort.Strings(allow)
	manifest := b.runtimeManifest()
	return &EffectivePolicyV1{
		Version:               EffectivePolicyVersion,
		JobID:                 job.JobID,
		Principal:             job.Principal,
		Image:                 job.Image,
		ImageDigest:           job.ImageDigest,
		Argv:                  append([]string{}, job.Argv...),
		Env:                   env,
		NetworkMode:           job.Network.Mode,
		NetworkAllow:          allow,
		RuntimeShell:          defaultRuntimeShell,
		RuntimeCmd:            append([]string{}, image.Cmd...),
		RuntimeEntrypoint:     append([]string{}, image.Entrypoint...),
		RuntimeUser:           image.User,
		SecurityProfile:       job.Security,
		DeploymentProfile:     profile,
		ExternalMountPolicy:   ExternalMountPolicyStrict,
		Workdir:               workdir,
		Mounts:                mounts,
		CPUs:                  job.Resources.CPUs,
		MemoryMB:              job.Resources.MemoryMB,
		MaxCPUs:               job.Resources.CPUs,
		MaxMemoryMB:           job.Resources.MemoryMB,
		DiskMB:                job.Resources.DiskMB,
		Pids:                  job.Resources.Pids,
		TimeoutSeconds:        job.Resources.TimeoutSeconds,
		MaxDurationSecs:       uint32(vmMaxDuration(job) / time.Second),
		MaxOutputBytes:        job.Resources.MaxOutputBytes,
		SandboxName:           name,
		DispatchNonce:         nonce,
		PullPolicy:            pull,
		RuntimeVersion:        runtimeVersion,
		RuntimeMSBSHA256:      manifest.MSBSHA256,
		RuntimeFirmwareSHA256: manifest.LibkrunfwSHA256,
	}, nil
}

// CanonicalJSON renders the policy deterministically: Go marshals
// struct fields in declaration order and every slice is normalized, so
// the same policy always produces the same bytes.
func (p *EffectivePolicyV1) CanonicalJSON() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("missing policy")
	}
	return json.Marshal(p)
}

// Digest is the policy's stable identity — what evidence binds and
// what an operator compares across restarts.
func (p *EffectivePolicyV1) Digest() (string, error) {
	raw, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// jsonStrings reads a JSON array of strings.
func jsonStrings(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// sameStringSequence compares two string lists element-wise. For a
// command and an entrypoint the order *is* the meaning — ["/bin/sh",
// "-c"] and ["-c", "/bin/sh"] are different programs — so a reordered
// hook is a refusal, never an equivalent spelling of the authorized
// one.
func sameStringSequence(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizePolicyWord folds the spelling differences between a flag
// value and the runtime's resolved rendering of it.
func normalizePolicyWord(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "-", ""))
}

// normalizeEnvSet canonicalizes a KEY=VALUE set: entries sorted by key,
// duplicates refused (two values for one key is an ambiguous policy,
// never a silently-last-wins one). An empty value is legal; a missing
// '=' is not.
func normalizeEnvSet(entries []string) []string {
	seen := map[string]string{}
	for _, kv := range entries {
		key, value, found := strings.Cut(kv, "=")
		if !found {
			continue
		}
		if prior, ok := seen[key]; ok && prior != value {
			// A conflicting duplicate cannot be normalized
			// deterministically; keep both so verification refuses.
			seen[key] = prior + "\x00" + value
			continue
		}
		seen[key] = value
	}
	out := make([]string, 0, len(seen))
	for k, v := range seen {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// envSetIndex indexes a normalized env set by key for exact
// comparison.
func envSetIndex(entries []string) map[string]string {
	idx := map[string]string{}
	for _, kv := range entries {
		key, value, found := strings.Cut(kv, "=")
		if found {
			idx[key] = value
		}
	}
	return idx
}

// ─── Booted-configuration verification ──────────────────────────────
//
// verifyBootedPolicy proves the VM that booted carries exactly the
// canonical policy: both the persisted `config` (desired) and the
// resolved `active_config` (what actually booted) must match, and
// every security-sensitive setting is compared exactly — an
// unauthorized environment entry, host channel, initialization hook,
// mount, network rule or deployment setting is a refusal before any
// guest command runs.

func verifyBootedPolicy(p *EffectivePolicyV1, doc map[string]any) error {
	cfg, ok := doc["config"].(map[string]any)
	if !ok {
		return fmt.Errorf("inspect document carries no config object")
	}
	if err := verifyBootedConfig(p, cfg); err != nil {
		return err
	}
	active, ok := doc["active_config"].(map[string]any)
	if !ok {
		return fmt.Errorf("sandbox has no resolved active configuration — refusing to execute in a VM that is not running its authorized policy")
	}
	if err := verifyBootedConfig(p, active); err != nil {
		return fmt.Errorf("booted configuration diverges from the authorized policy: %w", err)
	}
	// Sandbox-level state that is not part of either configuration but
	// still decides what the guest sees: pending configuration changes
	// mean the VM is not (yet) the authorized one, and a paused or
	// recovery-required VM is not a fresh execution environment.
	if pending, ok := doc["pending_changes"].([]any); ok && len(pending) != 0 {
		return fmt.Errorf("sandbox carries %d pending configuration change(s) — refusing to execute before the authorized policy is actually applied", len(pending))
	}
	if pause, ok := doc["pause"].(map[string]any); ok {
		if paused, _ := pause["paused"].(bool); paused {
			return fmt.Errorf("sandbox is paused — refusing to execute in a suspended VM")
		}
		if recovery, _ := pause["recovery_required"].(bool); recovery {
			return fmt.Errorf("sandbox requires recovery — refusing to execute in a VM whose state is uncertain")
		}
	}
	return nil
}

// bootedConfigFields is the qualified shape of the pinned runtime's
// resolved configuration, as dotted paths — `[]` marks an array's
// elements. It is the schema the policy was qualified against, taken
// from the pinned runtime's own output.
//
// Verification is a closure at every level, not only at the top. A
// field the schema does not define refuses by name wherever it appears,
// so a capability the pinned runtime grows, or one a substituted
// runtime invents, can never ride along unverified inside a nested
// object. Closing only the top level left a whole surface invisible
// while the policy claimed to check the booted VM exactly — TLS
// interception, injected secrets, DNS overrides, host CA trust and the
// mount flags all lived below the keys that were checked.
//
// `vsock` is deliberately absent. A route is a guest-to-host channel
// and the policy never authorizes one, so it is refused in its own
// right (verifyNoHostChannels) before the closure is consulted.
var bootedConfigFields = map[string]bool{
	"deployment_profile":                        true,
	"env":                                       true,
	"env[]":                                     true,
	"env[].key":                                 true,
	"env[].value":                               true,
	"external_mount_policy":                     true,
	"image":                                     true,
	"image.Oci":                                 true,
	"image.Oci.reference":                       true,
	"image.Oci.root_disk":                       true,
	"image.Oci.root_disk.kind":                  true,
	"image.Oci.root_disk.size_mib":              true,
	"init":                                      true,
	"labels":                                    true,
	"lifecycle":                                 true,
	"lifecycle.ephemeral":                       true,
	"lifecycle.idle_timeout_secs":               true,
	"lifecycle.max_duration_secs":               true,
	"manifest_digest":                           true,
	"mounts":                                    true,
	"mounts[]":                                  true,
	"mounts[].follow_root_symlinks":             true,
	"mounts[].guest":                            true,
	"mounts[].host":                             true,
	"mounts[].host_permissions":                 true,
	"mounts[].options":                          true,
	"mounts[].options.nodev":                    true,
	"mounts[].options.noexec":                   true,
	"mounts[].options.nosuid":                   true,
	"mounts[].options.readonly":                 true,
	"mounts[].quota_mib":                        true,
	"mounts[].stat_virtualization":              true,
	"mounts[].type":                             true,
	"name":                                      true,
	"network":                                   true,
	"network.dns":                               true,
	"network.dns.nameservers":                   true,
	"network.dns.query_timeout_ms":              true,
	"network.dns.rebind_protection":             true,
	"network.enabled":                           true,
	"network.http":                              true,
	"network.http.deny_response":                true,
	"network.interface":                         true,
	"network.max_connections":                   true,
	"network.nat64_prefixes":                    true,
	"network.policy":                            true,
	"network.policy.default_egress":             true,
	"network.policy.default_ingress":            true,
	"network.policy.rules":                      true,
	"network.policy.rules[]":                    true,
	"network.policy.rules[].action":             true,
	"network.policy.rules[].destination":        true,
	"network.policy.rules[].destination.domain": true,
	"network.policy.rules[].destination.domain_suffix": true,
	"network.policy.rules[].destination.group":         true,
	"network.policy.rules[].direction":                 true,
	"network.policy.rules[].ports":                     true,
	"network.policy.rules[].protocols":                 true,
	"network.ports":                                    true,
	"network.secrets":                                  true,
	"network.secrets.secrets":                          true,
	"network.secrets.violation_action":                 true,
	"network.strict":                                   true,
	"network.tls":                                      true,
	"network.tls.block_quic_on_intercept":              true,
	"network.tls.bypass":                               true,
	"network.tls.cache":                                true,
	"network.tls.cache.capacity":                       true,
	"network.tls.cache.validity_hours":                 true,
	"network.tls.enabled":                              true,
	"network.tls.intercept_ca":                         true,
	"network.tls.intercept_ca.cert_path":               true,
	"network.tls.intercept_ca.key_path":                true,
	"network.tls.intercepted_ports":                    true,
	"network.tls.scoped_upstream_ca_cert":              true,
	"network.tls.scoped_verify_upstream":               true,
	"network.tls.upstream_ca_cert":                     true,
	"network.tls.verify_upstream":                      true,
	"network.trust_host_cas":                           true,
	"patches":                                          true,
	"pull_policy":                                      true,
	"resources":                                        true,
	"resources.cpus":                                   true,
	"resources.max_cpus":                               true,
	"resources.max_memory_mib":                         true,
	"resources.memory_mib":                             true,
	"rlimits":                                          true,
	"runtime":                                          true,
	"runtime.cmd":                                      true,
	"runtime.disable_metrics_sample":                   true,
	"runtime.entrypoint":                               true,
	"runtime.hostname":                                 true,
	"runtime.log_level":                                true,
	"runtime.metrics_sample_interval_ms":               true,
	"runtime.scripts":                                  true,
	"runtime.shell":                                    true,
	"runtime.user":                                     true,
	"runtime.workdir":                                  true,
	"security_profile":                                 true,
}

// openFields are containers whose contents the policy cannot enumerate,
// because the runtime owns them (labels) or because a dedicated check
// refuses them outright (init, patches, rlimits, script bindings,
// interface bindings, published ports). Their keys are not closed here;
// their values are still verified by that check.
var openFields = map[string]bool{
	"labels":            true,
	"init":              true,
	"patches":           true,
	"rlimits":           true,
	"runtime.scripts":   true,
	"network.interface": true,
	"network.ports":     true,
}

// verifyNoHostChannels refuses a VM carrying any guest-to-host vsock
// route. A host channel is reachability — and a host local-IPC
// endpoint — the policy never authorized, so its presence refuses
// even when every other configuration field matches exactly.
func verifyNoHostChannels(cfg map[string]any) error {
	vsock, ok := cfg["vsock"].(map[string]any)
	if !ok {
		return nil
	}
	routes, _ := vsock["routes"].([]any)
	if len(routes) == 0 {
		return nil
	}
	targets := make([]string, 0, len(routes))
	for _, raw := range routes {
		r, _ := raw.(map[string]any)
		targets = append(targets, fmt.Sprintf("%s:%v/%s",
			jsonString(r, "host_socket"), r["port"], jsonString(r, "socket_type")))
	}
	sort.Strings(targets)
	return fmt.Errorf("sandbox carries %d host channel(s) the policy did not authorize: %s",
		len(routes), strings.Join(targets, ", "))
}

// verifyClosedConfig refuses any field the qualified schema does not
// define, at every level of the configuration. The comparison is
// closed: an unknown key is an unauthorized setting whatever its name
// and wherever it sits, and the policy cannot verify what it does not
// understand.
func verifyClosedConfig(cfg map[string]any) error {
	return verifyClosedValue(cfg, "")
}

func verifyClosedValue(value any, path string) error {
	if openFields[path] {
		return nil
	}
	switch v := value.(type) {
	case map[string]any:
		unknown := make([]string, 0, len(v))
		for key := range v {
			if !bootedConfigFields[childPath(path, key)] {
				unknown = append(unknown, key)
			}
		}
		if len(unknown) != 0 {
			sort.Strings(unknown)
			return fmt.Errorf("sandbox configuration carries %d field(s) the policy does not define%s: %s",
				len(unknown), atPath(path), strings.Join(unknown, ", "))
		}
		for key, child := range v {
			if err := verifyClosedValue(child, childPath(path, key)); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := verifyClosedValue(item, path+"[]"); err != nil {
				return err
			}
		}
	}
	return nil
}

// childPath joins a schema path with one key.
func childPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// atPath names where in the configuration a refusal was found, so an
// operator does not have to search for it.
func atPath(path string) string {
	if path == "" {
		return ""
	}
	return " at " + path
}

func verifyBootedConfig(p *EffectivePolicyV1, cfg map[string]any) error {
	if err := verifyNoHostChannels(cfg); err != nil {
		return err
	}
	if err := verifyClosedConfig(cfg); err != nil {
		return err
	}
	if got := jsonString(cfg, "name"); got != p.SandboxName {
		return fmt.Errorf("sandbox name %q does not match the authorized handle %q", got, p.SandboxName)
	}
	labels, _ := cfg["labels"].(map[string]any)
	if got := jsonString(labels, "crabedence.job"); got != p.JobID {
		return fmt.Errorf("sandbox label crabedence.job=%q does not match job %q", got, p.JobID)
	}
	if got := jsonString(labels, "crabedence.dispatch"); got != p.DispatchNonce {
		return fmt.Errorf("sandbox dispatch label does not match this dispatch — the VM is not the one this policy created")
	}
	if got := jsonString(cfg, "manifest_digest"); got != p.ImageDigest {
		return fmt.Errorf("sandbox image digest %q does not match the authorized %q", got, p.ImageDigest)
	}
	if got := jsonString(cfg, "security_profile"); got != p.SecurityProfile {
		return fmt.Errorf("sandbox security profile %q does not match the authorized %q", got, p.SecurityProfile)
	}
	if got := jsonString(cfg, "deployment_profile"); got != p.DeploymentProfile {
		return fmt.Errorf("sandbox deployment profile %q does not match the required %q — refusing to run under a downgraded host confinement", got, p.DeploymentProfile)
	}
	if got := jsonString(cfg, "external_mount_policy"); got != p.ExternalMountPolicy {
		return fmt.Errorf("sandbox external mount policy %q does not match the required %q", got, p.ExternalMountPolicy)
	}
	// The runtime spells its resolved pull policy differently from the
	// flag that requested it ("never" → "Never", "if-missing" →
	// "IfMissing"): compare the normalized forms.
	if got := jsonString(cfg, "pull_policy"); got != "" && normalizePolicyWord(got) != normalizePolicyWord(p.PullPolicy) {
		return fmt.Errorf("sandbox pull policy %q does not match the required %q", got, p.PullPolicy)
	}
	// Initialization hooks and rootfs patches widen what runs before
	// (or as) the authorized command; none is authorized.
	if init := cfg["init"]; init != nil {
		return fmt.Errorf("sandbox carries an initialization hook (%v) the policy did not authorize", init)
	}
	if patches, ok := cfg["patches"].([]any); ok && len(patches) != 0 {
		return fmt.Errorf("sandbox carries %d rootfs patch(es) the policy did not authorize", len(patches))
	}
	rt, _ := cfg["runtime"].(map[string]any)
	if scripts, ok := rt["scripts"].(map[string]any); ok && len(scripts) != 0 {
		return fmt.Errorf("sandbox carries %d runtime script binding(s) the policy did not authorize", len(scripts))
	}
	// Execution hooks: the shell the guest command runs through, the
	// image's own command and entrypoint, the user it runs as and the
	// hostname it boots with must all be exactly what the policy
	// authorized — a runtime default nobody pinned is a refusal.
	if got := jsonString(rt, "shell"); got != p.RuntimeShell {
		return fmt.Errorf("sandbox runtime shell %q does not match the authorized %q", got, p.RuntimeShell)
	}
	if got := jsonStrings(rt, "cmd"); !sameStringSequence(got, p.RuntimeCmd) {
		return fmt.Errorf("sandbox runtime cmd %v does not match the image's authorized %v", got, p.RuntimeCmd)
	}
	if got := jsonStrings(rt, "entrypoint"); !sameStringSequence(got, p.RuntimeEntrypoint) {
		return fmt.Errorf("sandbox runtime entrypoint %v does not match the image's authorized %v", got, p.RuntimeEntrypoint)
	}
	if got := jsonString(rt, "user"); got != p.RuntimeUser {
		return fmt.Errorf("sandbox runtime user %q does not match the authorized %q", got, p.RuntimeUser)
	}
	if got := jsonString(rt, "hostname"); got != "" {
		return fmt.Errorf("sandbox boots with hostname %q, which the policy did not authorize", got)
	}
	if rlimits, ok := cfg["rlimits"].([]any); ok && len(rlimits) != 0 {
		return fmt.Errorf("sandbox carries %d sandbox-level rlimit(s) the policy did not authorize", len(rlimits))
	}
	res, _ := cfg["resources"].(map[string]any)
	if p.CPUs > 0 {
		if got, ok := jsonNumber(res, "cpus"); !ok || got != p.CPUs {
			return fmt.Errorf("sandbox cpus = %v, policy authorized %g", got, p.CPUs)
		}
		// The ceiling must equal the authorized budget: headroom above
		// it would let the guest consume more than the policy (and the
		// aggregate pool) accounted for.
		if got, ok := jsonNumber(res, "max_cpus"); !ok || got != p.MaxCPUs {
			return fmt.Errorf("sandbox max_cpus = %v, policy authorized %g", got, p.MaxCPUs)
		}
	}
	if p.MemoryMB > 0 {
		if got, ok := jsonNumber(res, "memory_mib"); !ok || uint64(got) != p.MemoryMB {
			return fmt.Errorf("sandbox memory_mib = %v, policy authorized %d", got, p.MemoryMB)
		}
		if got, ok := jsonNumber(res, "max_memory_mib"); !ok || uint64(got) != p.MaxMemoryMB {
			return fmt.Errorf("sandbox max_memory_mib = %v, policy authorized %d", got, p.MaxMemoryMB)
		}
	}
	if p.DiskMB > 0 {
		img, _ := cfg["image"].(map[string]any)
		oci, _ := img["Oci"].(map[string]any)
		rd, _ := oci["root_disk"].(map[string]any)
		if got, ok := jsonNumber(rd, "size_mib"); !ok || uint64(got) != p.DiskMB {
			return fmt.Errorf("sandbox root disk size_mib = %v, policy authorized %d", got, p.DiskMB)
		}
	}
	lc, _ := cfg["lifecycle"].(map[string]any)
	if got, ok := jsonNumber(lc, "max_duration_secs"); !ok || uint32(got) != p.MaxDurationSecs {
		return fmt.Errorf("sandbox max_duration_secs = %v, policy authorized %d", got, p.MaxDurationSecs)
	}
	// Lifecycle completeness: an ephemeral or idle-reaped sandbox is a
	// lifecycle the policy did not authorize (an idle reaper can
	// destroy the VM mid-job).
	if ephemeral, _ := lc["ephemeral"].(bool); ephemeral {
		return fmt.Errorf("sandbox lifecycle is ephemeral, which the policy did not authorize")
	}
	if idle, present := lc["idle_timeout_secs"]; present && idle != nil {
		return fmt.Errorf("sandbox carries an idle timeout (%v) the policy did not authorize", idle)
	}
	// The workdir is compared exactly, including the unset case: a VM
	// that boots into a directory nobody authorized is a refusal.
	if got := jsonString(rt, "workdir"); got != p.Workdir {
		return fmt.Errorf("sandbox workdir %q does not match the authorized %q", got, p.Workdir)
	}
	if err := verifyBootedNetwork(p, cfg); err != nil {
		return err
	}
	if err := verifyBootedEnvironment(p, cfg); err != nil {
		return err
	}
	return verifyBootedMounts(p, cfg)
}

// verifyBootedEnvironment is the exact environment comparison: the
// booted set must equal the authorized set — the contract's entries
// plus the pinned image's own config environment — with nothing extra
// and nothing missing. An extra variable is a setting nobody
// authorized, whatever its name.
func verifyBootedEnvironment(p *EffectivePolicyV1, cfg map[string]any) error {
	env, _ := cfg["env"].([]any)
	booted := make([]string, 0, len(env))
	for _, raw := range env {
		e, _ := raw.(map[string]any)
		booted = append(booted, jsonString(e, "key")+"="+jsonString(e, "value"))
	}
	// A booted environment with two entries for one key is not a set
	// the policy can authorize: the guest's view depends on resolution
	// order nobody approved.
	seen := map[string]bool{}
	for _, kv := range booted {
		key, _, _ := strings.Cut(kv, "=")
		if seen[key] {
			return fmt.Errorf("sandbox environment carries duplicate entries for %s", key)
		}
		seen[key] = true
	}
	want := envSetIndex(p.Env)
	have := envSetIndex(booted)
	for key, value := range want {
		got, ok := have[key]
		if !ok {
			return fmt.Errorf("sandbox environment is missing the authorized %s entry", key)
		}
		if got != value {
			return fmt.Errorf("sandbox environment %s=%q does not match the authorized value", key, got)
		}
	}
	extra := []string{}
	for key := range have {
		if _, ok := want[key]; !ok {
			extra = append(extra, key)
		}
	}
	if len(extra) != 0 {
		sort.Strings(extra)
		return fmt.Errorf("sandbox environment carries %d unauthorized variable(s): %s", len(extra), strings.Join(extra, ", "))
	}
	return nil
}

func verifyBootedNetwork(p *EffectivePolicyV1, cfg map[string]any) error {
	netw, _ := cfg["network"].(map[string]any)
	policy, _ := netw["policy"].(map[string]any)
	egress := jsonString(policy, "default_egress")
	ingress := jsonString(policy, "default_ingress")
	rules, _ := policy["rules"].([]any)
	// Host channels (network interfaces attached to the VM) are never
	// part of the authorized policy: a VM with an interface the policy
	// did not request is reachability nobody authorized.
	if iface, ok := netw["interface"].(map[string]any); ok && len(iface) != 0 {
		return fmt.Errorf("sandbox carries %d network interface binding(s) the policy did not authorize", len(iface))
	}
	if ports, ok := netw["ports"].([]any); ok && len(ports) != 0 {
		return fmt.Errorf("sandbox publishes %d port(s) the policy did not authorize", len(ports))
	}
	switch p.NetworkMode {
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
		if len(rules) != len(p.NetworkAllow) {
			return fmt.Errorf("network allowlist has %d entries but the sandbox carries %d rule(s)", len(p.NetworkAllow), len(rules))
		}
		want := map[string]bool{}
		for _, allow := range p.NetworkAllow {
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
				return fmt.Errorf("sandbox rule %d permits %s:%s, which the policy did not authorize", i, kind, value)
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
		// Public networking composes the runtime's own ingress default
		// with the public egress group; the policy pins that exact
		// shape rather than leaving it unverified.
		if ingress != "allow" {
			return fmt.Errorf("network mode public but the sandbox default ingress is %q, not the public mode's %q", ingress, "allow")
		}
		// `--net public` composes exactly two rules: the gateway DNS
		// rule (group host) and the public egress allow. Any other
		// rule is reachability the policy never authorized.
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
				return fmt.Errorf("sandbox rule %d permits %s:%s, which the policy did not authorize", i, kind, value)
			}
		}
		if !public {
			return fmt.Errorf("network mode public but the sandbox carries no public egress rule")
		}
	}
	// The runtime's network object carries an interception, secret and
	// resolution surface the policy never authorizes. Verification
	// reads it now: a guest whose TLS the host can intercept, whose
	// DNS is redirected, or whose environment can be seeded with host
	// secrets is not the VM the policy described, whatever the rest of
	// the configuration says.
	secrets, _ := netw["secrets"].(map[string]any)
	if injected, ok := secrets["secrets"].([]any); ok && len(injected) != 0 {
		return fmt.Errorf("sandbox carries %d injected secret(s) the policy did not authorize", len(injected))
	}
	tls, _ := netw["tls"].(map[string]any)
	if enabled, _ := tls["enabled"].(bool); enabled {
		return fmt.Errorf("sandbox enables TLS interception, which the policy did not authorize")
	}
	ca, _ := tls["intercept_ca"].(map[string]any)
	if jsonString(ca, "cert_path") != "" || jsonString(ca, "key_path") != "" {
		return fmt.Errorf("sandbox carries a TLS interception certificate authority the policy did not authorize")
	}
	for _, key := range []string{"bypass", "upstream_ca_cert", "scoped_upstream_ca_cert", "scoped_verify_upstream"} {
		if entries, ok := tls[key].([]any); ok && len(entries) != 0 {
			return fmt.Errorf("sandbox carries %d %s entr(ies) the policy did not authorize", len(entries), key)
		}
	}
	if trust, _ := netw["trust_host_cas"].(bool); trust {
		return fmt.Errorf("sandbox trusts the host's certificate authorities, which the policy did not authorize")
	}
	if strict, present := netw["strict"].(bool); present && !strict {
		return fmt.Errorf("sandbox network is not strict, which the policy requires")
	}
	dns, _ := netw["dns"].(map[string]any)
	if ns, ok := dns["nameservers"].([]any); ok && len(ns) != 0 {
		return fmt.Errorf("sandbox carries %d DNS nameserver override(s) the policy did not authorize", len(ns))
	}
	return nil
}

func verifyBootedMounts(p *EffectivePolicyV1, cfg map[string]any) error {
	mounts, _ := cfg["mounts"].([]any)
	if len(mounts) != len(p.Mounts) {
		return fmt.Errorf("sandbox carries %d mount(s) but the policy authorized %d", len(mounts), len(p.Mounts))
	}
	authorized := map[string]*Mount{}
	for i := range p.Mounts {
		m := &p.Mounts[i]
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
		// A host path the policy mounted read-only must not boot
		// writable: the flag is part of the signed policy.
		if want, ok := mountReadOnly(declared.Options); ok {
			opts, _ := m["options"].(map[string]any)
			got, _ := opts["readonly"].(bool)
			if got != want {
				return fmt.Errorf("sandbox mount %s is readonly=%t but the policy declared %q",
					jsonString(m, "guest"), got, declared.Options)
			}
		}
		// Following host root symlinks would let the mounted path
		// resolve somewhere the policy never authorized, so the flag is
		// part of what the mount must prove.
		if follow, _ := m["follow_root_symlinks"].(bool); follow {
			return fmt.Errorf("sandbox mount %s follows host root symlinks, which the policy did not authorize",
				jsonString(m, "guest"))
		}
		delete(authorized, key)
	}
	return nil
}
