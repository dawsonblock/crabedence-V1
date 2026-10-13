package sandboxexecutor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ─── Fake msb helper process ─────────────────────────────────────────
//
// The backend tests exercise the real adapter against a fake msb
// binary that reimplements the CLI surfaces the adapter depends on:
// exclusive `create`, `inspect --format json`, runtime-owned
// `exec -d` jobs, `inspect --job`, `jobs`, `logs --job` and `rm` —
// plus the real CLI's silent-reuse behavior on `run`, so the
// regression that motivated the hardened adapter stays reproducible.
//
// The helper is this test binary re-invoked with MSB_FAKE_HELPER=1;
// TestMain intercepts before flag parsing, so msb-style argv never
// reaches the testing package. State lives under MSB_FAKE_DIR as one
// JSON file per sandbox, mirroring `msb inspect --format json`, plus
// one job-record file per sandbox mirroring the runtime's durable
// job metadata.

func TestMain(m *testing.M) {
	if os.Getenv("MSB_FAKE_HELPER") == "1" {
		os.Exit(fakeMSBMain())
	}
	os.Exit(m.Run())
}

type fakeSandbox struct {
	Name           string             `json:"name"`
	Status         string             `json:"status"`
	BootID         string             `json:"boot_id"`
	Storage        fakeStorage        `json:"storage"`
	PendingChanges []any              `json:"pending_changes"`
	Pause          map[string]any     `json:"pause"`
	Config         fakeSandboxConfig  `json:"config"`
	ActiveConfig   *fakeSandboxConfig `json:"active_config"`
}

type fakeStorage struct {
	Path string `json:"path"`
}

type fakeSandboxConfig struct {
	Name                string            `json:"name"`
	Labels              map[string]string `json:"labels"`
	ManifestDigest      string            `json:"manifest_digest"`
	PullPolicy          string            `json:"pull_policy"`
	DeploymentProfile   string            `json:"deployment_profile"`
	ExternalMountPolicy string            `json:"external_mount_policy"`
	Init                any               `json:"init"`
	Patches             []any             `json:"patches"`
	Rlimits             []any             `json:"rlimits"`
	Env                 []fakeEnvVar      `json:"env"`
	Resources           fakeResources     `json:"resources"`
	Lifecycle           fakeLifecycle     `json:"lifecycle"`
	Runtime             fakeRuntime       `json:"runtime"`
	SecurityProfile     string            `json:"security_profile"`
	Network             fakeNetwork       `json:"network"`
	Mounts              []fakeMount       `json:"mounts"`
	Image               fakeImage         `json:"image"`
}

type fakeEnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type fakeResources struct {
	CPUs         float64 `json:"cpus"`
	MaxCPUs      float64 `json:"max_cpus"`
	MemoryMiB    uint64  `json:"memory_mib"`
	MaxMemoryMiB uint64  `json:"max_memory_mib"`
}

type fakeLifecycle struct {
	Ephemeral       bool    `json:"ephemeral"`
	IdleTimeoutSecs *uint32 `json:"idle_timeout_secs"`
	MaxDurationSecs *uint32 `json:"max_duration_secs"`
}

type fakeRuntime struct {
	Workdir *string        `json:"workdir"`
	Shell   string         `json:"shell"`
	Scripts map[string]any `json:"scripts"`
}

type fakeNetwork struct {
	Enabled   bool           `json:"enabled"`
	Interface map[string]any `json:"interface"`
	Ports     []any          `json:"ports"`
	Policy    fakePolicy     `json:"policy"`
}

type fakePolicy struct {
	DefaultEgress  string     `json:"default_egress"`
	DefaultIngress string     `json:"default_ingress"`
	Rules          []fakeRule `json:"rules"`
}

type fakeRule struct {
	Action      string     `json:"action"`
	Direction   string     `json:"direction"`
	Destination fakeTarget `json:"destination"`
}

type fakeTarget struct {
	Domain       string `json:"domain,omitempty"`
	DomainSuffix string `json:"domain_suffix,omitempty"`
	Group        string `json:"group,omitempty"`
}

type fakeMount struct {
	Host  string `json:"host,omitempty"`
	Guest string `json:"guest"`
	Type  string `json:"type"`
}

type fakeImage struct {
	Oci fakeOci `json:"Oci"`
}

type fakeOci struct {
	Reference string       `json:"reference"`
	RootDisk  fakeRootDisk `json:"root_disk"`
}

type fakeRootDisk struct {
	Kind    string `json:"kind"`
	SizeMiB uint64 `json:"size_mib"`
}

// fakeJobRecord mirrors the runtime's durable job metadata shape.
type fakeJobRecord struct {
	ID          string       `json:"id"`
	RuntimeBoot string       `json:"runtime_boot_id"`
	Command     []string     `json:"command"`
	State       string       `json:"state"`
	ExitCode    *int         `json:"exit_code"`
	Failure     *fakeFailure `json:"failure"`
	Error       *string      `json:"error"`
	TimedOut    bool         `json:"timed_out"`
	CreatedAt   int64        `json:"created_at"`
	StartedAt   *int64       `json:"started_at"`
	FinishedAt  *int64       `json:"finished_at"`
}

type fakeFailure struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// fakeDefaultImageEnv is the pinned image's own config environment the
// fake runtime injects into every VM (and reports from image inspect).
func fakeDefaultImageEnv() []string {
	if v := os.Getenv("MSB_FAKE_IMAGE_ENV"); v != "" {
		return strings.Split(v, ",")
	}
	return []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
}

func fakeDefaultConfig() fakeSandboxConfig {
	return fakeSandboxConfig{
		Labels:              map[string]string{},
		ManifestDigest:      testImageDigest,
		DeploymentProfile:   "single_tenant",
		ExternalMountPolicy: "strict",
		Resources:           fakeResources{CPUs: 1, MaxCPUs: 1, MemoryMiB: 512, MaxMemoryMiB: 512},
		Lifecycle:           fakeLifecycle{},
		Runtime:             fakeRuntime{Shell: "/bin/sh", Scripts: map[string]any{}},
		SecurityProfile:     SecurityDefault,
		Network: fakeNetwork{Enabled: true, Policy: fakePolicy{
			DefaultEgress: "deny", DefaultIngress: "deny",
		}},
		Image: fakeImage{Oci: fakeOci{RootDisk: fakeRootDisk{Kind: "managed", SizeMiB: 4096}}},
	}
}

func fakePublicPolicy() fakePolicy {
	return fakePolicy{
		DefaultEgress: "deny", DefaultIngress: "allow",
		Rules: []fakeRule{
			{Action: "allow", Direction: "egress", Destination: fakeTarget{Group: "host"}},
			{Action: "allow", Direction: "egress", Destination: fakeTarget{Group: "public"}},
		},
	}
}

func fakeRuleFor(entry string) fakeRule {
	target := fakeTarget{Domain: entry}
	if rest, ok := strings.CutPrefix(entry, "*."); ok {
		target = fakeTarget{DomainSuffix: rest}
	}
	return fakeRule{Action: "allow", Direction: "egress", Destination: target}
}

func fakeMSBMain() int {
	dir := os.Getenv("MSB_FAKE_DIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "fake msb: MSB_FAKE_DIR is required")
		return 2
	}
	if len(os.Args) < 2 {
		return 2
	}
	cmd, rest := os.Args[1], os.Args[2:]
	switch cmd {
	case "--version":
		version := os.Getenv("MSB_FAKE_VERSION")
		if version == "" {
			version = PinnedMSBVersion
		}
		fmt.Printf("msb %s\n", version)
		return 0
	case "doctor":
		if os.Getenv("MSB_FAKE_DOCTOR_FAIL") != "" {
			fmt.Fprintln(os.Stdout, "  ✗ Architecture        unsupported host (no virtual extension)")
			fmt.Fprintln(os.Stderr, "error: host setup is not ready")
			return 1
		}
		if fw := os.Getenv("MSB_FAKE_FIRMWARE"); fw != "" {
			fmt.Fprintf(os.Stdout, "  ✓ libkrunfw           %s\n", fw)
		}
		fmt.Fprintln(os.Stdout, "  ✓ Host setup is ready.")
		return 0
	case "flood":
		// A broken or hostile runtime that floods a utility call.
		chunk := strings.Repeat("A", 64*1024)
		for i := 0; i < 80; i++ { // 5 MiB, beyond the adapter's bound
			fmt.Fprint(os.Stdout, chunk)
		}
		return 0
	case "create":
		return fakeCreate(dir, rest)
	case "run":
		return fakeRun(dir, rest)
	case "inspect":
		if jobID := fakeFlagValue(rest, "--job"); jobID != "" {
			if os.Getenv("MSB_FAKE_JOB_INSPECT_FAIL") != "" {
				fmt.Fprintln(os.Stderr, "error: job inspection timed out")
				return 1
			}
			return fakeInspectJob(dir, rest, jobID)
		}
		return fakeInspect(dir, rest)
	case "image":
		return fakeImageCmd(rest)
	case "exec":
		return fakeExec(dir, rest)
	case "jobs":
		return fakeJobs(dir, rest)
	case "logs":
		return fakeLogs(dir, rest)
	case "rm":
		return fakeRemove(dir, rest)
	case "list":
		return 0
	default:
		fmt.Fprintf(os.Stderr, "fake msb: unsupported command %q\n", cmd)
		return 2
	}
}

// fakeFlagValue returns the value of one --flag in argv, or "".
func fakeFlagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// fakeName returns the last non-flag argument — the sandbox name in
// every command shape the adapter uses.
func fakeName(args []string) string {
	name := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--job", "--format", "--timeout", "--rlimit", "--env", "-e", "-w", "--workdir", "-u", "--user", "--tail", "--source":
			i++
		case "--all":
		default:
			if !strings.HasPrefix(a, "-") {
				name = a
			}
		}
	}
	return name
}

func fakeStatePath(dir, name string) string { return filepath.Join(dir, name+".json") }

// fakeBootID derives a fresh boot generation for a create: the fake's
// stand-in for the runtime's own boot identity. Re-creating a sandbox
// (a substitution) produces a different one.
func fakeBootID(name string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", name, time.Now().UnixNano())))
	return "boot_" + hex.EncodeToString(sum[:])[:32]
}

func fakeJobsPath(dir, name string) string { return filepath.Join(dir, name+".jobs.json") }

func fakeJobOutputPath(dir, name, id string) string {
	return filepath.Join(dir, name+"."+id+".out")
}

func fakeCreate(dir string, args []string) int {
	if secs := fakeEnvInt("MSB_FAKE_CREATE_SLEEP", 0); secs > 0 {
		time.Sleep(time.Duration(secs) * time.Second)
	}
	conf := fakeDefaultConfig()
	var name, image string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "-q", "--no-tty", "--no-stdin":
		case "-n", "--name":
			i++
			name = args[i]
		case "--cpus":
			i++
			conf.Resources.CPUs, _ = strconv.ParseFloat(args[i], 64)
			conf.Resources.MaxCPUs = conf.Resources.CPUs
		case "--memory":
			i++
			conf.Resources.MemoryMiB = fakeSizeMiB(args[i])
			conf.Resources.MaxMemoryMiB = conf.Resources.MemoryMiB
		case "--root-disk":
			i++
			conf.Image.Oci.RootDisk.SizeMiB = fakeSizeMiB(args[i])
		case "--max-duration":
			i++
			secs := uint32(fakeDurationSecs(args[i]))
			conf.Lifecycle.MaxDurationSecs = &secs
		case "--net":
			i++
			switch args[i] {
			case "none":
				conf.Network.Policy = fakePolicy{DefaultEgress: "deny", DefaultIngress: "deny"}
			case "public":
				conf.Network.Policy = fakePublicPolicy()
			}
		case "--net-default":
			i++
			conf.Network.Policy.DefaultEgress = args[i]
			conf.Network.Policy.DefaultIngress = args[i]
		case "--net-rule":
			i++
			rule := strings.TrimPrefix(args[i], "allow@")
			conf.Network.Policy.Rules = append(conf.Network.Policy.Rules, fakeRuleFor(rule))
		case "-e", "--env":
			i++
			key, value, _ := strings.Cut(args[i], "=")
			conf.Env = append(conf.Env, fakeEnvVar{Key: key, Value: value})
		case "-v", "--volume":
			i++
			parts := strings.SplitN(args[i], ":", 3)
			if len(parts) >= 2 {
				conf.Mounts = append(conf.Mounts, fakeMount{Host: parts[0], Guest: parts[1], Type: "Bind"})
			}
		case "-w", "--workdir":
			i++
			conf.Runtime.Workdir = &args[i]
		case "--security":
			i++
			conf.SecurityProfile = args[i]
		case "--label":
			i++
			key, value, _ := strings.Cut(args[i], "=")
			conf.Labels[key] = value
		case "--pull":
			i++
			conf.PullPolicy = args[i]
		case "--deployment-profile":
			i++
			conf.DeploymentProfile = strings.ReplaceAll(args[i], "-", "_")
		case "--max-cpus", "--max-memory", "--hostname":
			i++
		default:
			if !strings.HasPrefix(a, "-") {
				image = a
			}
		}
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "error: missing sandbox name")
		return 2
	}
	if strings.Contains(image, "@sha256:") {
		conf.ManifestDigest = image[strings.Index(image, "@")+1:]
	}
	conf.Name = name
	conf.Image.Oci.Reference = image
	// The runtime injects the pinned image's own config environment
	// into every VM: the booted set is the image baseline plus the
	// contract's entries.
	imageEnv := fakeDefaultImageEnv()
	merged := make([]fakeEnvVar, 0, len(imageEnv)+len(conf.Env))
	for _, kv := range imageEnv {
		key, value, _ := strings.Cut(kv, "=")
		merged = append(merged, fakeEnvVar{Key: key, Value: value})
	}
	conf.Env = append(merged, conf.Env...)

	if tamper := os.Getenv("MSB_FAKE_TAMPER"); tamper == "net_public" {
		conf.Network.Policy = fakePublicPolicy()
	} else if tamper == "ingress_allow" {
		conf.Network.Policy.DefaultIngress = "allow"
	} else if tamper == "public_plus_private" {
		conf.Network.Policy = fakePublicPolicy()
		conf.Network.Policy.Rules = append(conf.Network.Policy.Rules,
			fakeRule{Action: "allow", Direction: "egress", Destination: fakeTarget{Group: "private"}})
	} else if tamper == "deployment_multi" {
		conf.DeploymentProfile = "multi_tenant"
	} else if tamper == "extra_env" {
		conf.Env = append(conf.Env, fakeEnvVar{Key: "INJECTED", Value: "1"})
	} else if tamper == "init_hook" {
		conf.Init = map[string]any{"cmd": "/usr/bin/evil-init"}
	} else if tamper == "patches" {
		conf.Patches = []any{map[string]any{"path": "/etc/passwd"}}
	} else if tamper == "scripts" {
		conf.Runtime.Scripts = map[string]any{"evil": "/bin/evil"}
	} else if tamper == "rlimits" {
		conf.Rlimits = []any{map[string]any{"resource": "nofile", "value": 1 << 20}}
	} else if tamper == "mount_policy_loose" {
		conf.ExternalMountPolicy = "permissive"
	} else if tamper == "extra_interface" {
		conf.Network.Interface = map[string]any{"tap0": map[string]any{"ip": "10.0.0.2"}}
	} else if tamper == "port_publish" {
		conf.Network.Ports = []any{map[string]any{"host": 8080, "guest": 80}}
	} else if tamper == "max_cpus_headroom" {
		conf.Resources.MaxCPUs = conf.Resources.CPUs * 2
	} else if tamper == "max_memory_headroom" {
		conf.Resources.MaxMemoryMiB = conf.Resources.MemoryMiB * 2
	} else if tamper == "ephemeral" {
		conf.Lifecycle.Ephemeral = true
	} else if tamper == "idle_timeout" {
		idle := uint32(30)
		conf.Lifecycle.IdleTimeoutSecs = &idle
	} else if tamper == "workdir" {
		wd := "/tmp/unauthorized"
		conf.Runtime.Workdir = &wd
	}
	if os.Getenv("MSB_FAKE_CREATE_FAIL") != "" {
		fmt.Fprintln(os.Stderr, "error: invalid config: sandbox refused before boot")
		return 1
	}
	// Exclusive creation, exactly like the real CLI: an existing
	// sandbox is an error, never a silent reuse.
	path := fakeStatePath(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox already exists: sandbox '%s' already exists; remove it, start the stopped sandbox, or recreate with .replace()\n", name)
		return 1
	}
	defer f.Close()
	active := conf
	if os.Getenv("MSB_FAKE_TAMPER") == "active_diverges" {
		active.Network.Policy = fakePublicPolicy()
	}
	// The runtime's boot generation lives in the sandbox's own state
	// directory (the storage path the inspect document reports), and a
	// fresh create is a fresh boot.
	storagePath := filepath.Join(dir, name+".storage")
	if err := os.MkdirAll(filepath.Join(storagePath, "runtime"), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	bootID := fakeBootID(name)
	if os.Getenv("MSB_FAKE_BOOT_ID") != "" {
		bootID = os.Getenv("MSB_FAKE_BOOT_ID")
	}
	if err := os.WriteFile(filepath.Join(storagePath, "runtime", "runtime-boot-id"), []byte(bootID), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	sandbox := fakeSandbox{
		Name: name, Status: "Running", BootID: bootID,
		Storage: fakeStorage{Path: storagePath},
		Config:  conf, ActiveConfig: &active,
	}
	if os.Getenv("MSB_FAKE_TAMPER") == "pending_changes" {
		sandbox.PendingChanges = []any{map[string]any{"field": "network"}}
	}
	if os.Getenv("MSB_FAKE_TAMPER") == "paused" {
		sandbox.Pause = map[string]any{"paused": true, "recovery_required": false}
	}
	if os.Getenv("MSB_FAKE_TAMPER") == "recovery_required" {
		sandbox.Pause = map[string]any{"paused": false, "recovery_required": true}
	}
	raw, _ := json.Marshal(sandbox)
	_, _ = f.Write(raw)
	if os.Getenv("MSB_FAKE_CREATE_FAIL_AFTER") != "" {
		// Mirrors a create that booted the VM and then failed guest
		// validation: the sandbox record survives the failure.
		fmt.Fprintln(os.Stderr, "error: invalid config: could not validate workdir in guest")
		return 1
	}
	return 0
}

// fakeRun mirrors the real CLI's reuse behavior — the defect the
// hardened adapter exists to avoid: a named sandbox that already
// exists is reused and every creation flag is ignored.
func fakeRun(dir string, args []string) int {
	var name, image string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "-n", "--name":
			i++
			name = args[i]
		case "--":
			i = len(args)
		default:
			if !strings.HasPrefix(a, "-") {
				image = a
			}
		}
	}
	if name == "" {
		name = "fake-auto-name"
	}
	if _, err := os.Stat(fakeStatePath(dir, name)); err == nil {
		fmt.Fprintf(os.Stderr, "warn: sandbox '%s' already exists; creation flags ignored (use --replace to recreate)\n", name)
	} else {
		if code := fakeCreate(dir, []string{"-q", "-n", name, image}); code != 0 {
			return code
		}
	}
	_ = os.WriteFile(filepath.Join(dir, name+".exec"), []byte("executed"), 0o600)
	return 0
}

// fakeImageCmd models `msb image inspect --format json <ref>`: the
// pinned image's config environment, keyed by the digest the reference
// names.
func fakeImageCmd(args []string) int {
	ref := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && a != "inspect" && a != "json" {
			ref = a
		}
	}
	_, digest, found := strings.Cut(ref, "@")
	if !found || !strings.HasPrefix(digest, "sha256:") {
		fmt.Fprintf(os.Stderr, "error: image %q is not digest-pinned\n", ref)
		return 1
	}
	if os.Getenv("MSB_FAKE_IMAGE_DIGEST_MISMATCH") != "" {
		digest = "sha256:" + strings.Repeat("f", 64)
	}
	raw, _ := json.Marshal(map[string]any{
		"digest": digest,
		"config": map[string]any{"env": fakeDefaultImageEnv()},
	})
	os.Stdout.Write(raw)
	fmt.Fprintln(os.Stdout)
	return 0
}

func fakeInspect(dir string, args []string) int {
	name := fakeName(args)
	raw, err := os.ReadFile(fakeStatePath(dir, name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox not found: %s\n", name)
		return 1
	}
	os.Stdout.Write(raw)
	fmt.Fprintln(os.Stdout)
	return 0
}

// fakeExec models the runtime-owned detached launch: it records a job
// and prints its identity. Foreground exec is deliberately absent —
// the adapter must never use it, so the fake refuses it loudly.
func fakeExec(dir string, args []string) int {
	var name string
	detached := false
	command := []string{}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "-d", "--detach":
			detached = true
		case "--":
			command = args[i+1:]
			i = len(args)
		case "--timeout", "--rlimit", "--env", "-e", "-w", "--workdir", "-u", "--user":
			i++
		case "--no-tty", "--no-stdin":
		default:
			if !strings.HasPrefix(a, "-") {
				name = a
			}
		}
	}
	if !detached {
		fmt.Fprintln(os.Stderr, "error: unsupported: the adapter must launch runtime-owned jobs (-d)")
		return 2
	}
	if _, err := os.Stat(fakeStatePath(dir, name)); err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox not found: %s\n", name)
		return 1
	}
	if os.Getenv("MSB_FAKE_LAUNCH_FAIL") != "" {
		target := "command"
		if len(command) > 0 {
			target = command[0]
		}
		fmt.Fprintf(os.Stderr, "error: exec_failed: spawn %q: No such file or directory (os error 2)\n", target)
		return 1
	}
	if err := fakeWriteJob(dir, name, command); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if os.Getenv("MSB_FAKE_LAUNCH_FAIL_ADMITTED") != "" {
		// The launch was admitted and its identity lost in
		// transport: a job record exists, but the CLI never named it.
		fmt.Fprintln(os.Stderr, "error: transport closed before the job identity was confirmed")
		return 1
	}
	recs, _ := fakeReadJobs(dir, name)
	fmt.Fprintln(os.Stdout, recs[len(recs)-1].ID)
	return 0
}

// fakeWriteJob appends one job record and its captured output,
// modeling the runtime's durable job store.
func fakeWriteJob(dir, name string, command []string) error {
	recs, err := fakeReadJobs(dir, name)
	if err != nil {
		return err
	}
	seq := len(recs) + 1
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", name, seq, strings.Join(command, "\x00"))))
	sb, serr := fakeReadSandbox(dir, name)
	if serr != nil {
		return serr
	}
	rec := fakeJobRecord{
		ID:          "job_" + hex.EncodeToString(sum[:])[:32],
		RuntimeBoot: sb.BootID,
		Command:     command,
		State:       "exited",
		CreatedAt:   time.Now().UnixMilli(),
	}
	if os.Getenv("MSB_FAKE_JOB_BOOT_MISMATCH") != "" {
		rec.RuntimeBoot = "boot_" + strings.Repeat("9", 32)
	}
	switch {
	case os.Getenv("MSB_FAKE_JOB_LOST") != "":
		rec.State = "lost"
		msg := "owning runtime is no longer available; exit status is unknown"
		rec.Error = &msg
	case os.Getenv("MSB_FAKE_JOB_FAILURE") != "":
		rec.State = "failed"
		rec.Failure = &fakeFailure{Kind: os.Getenv("MSB_FAKE_JOB_FAILURE"), Message: "spawn failed"}
	case os.Getenv("MSB_FAKE_JOB_RUNNING") != "":
		// Stays running until enough polls have observed it.
		rec.State = "running"
		if err := os.WriteFile(fakePollsPath(dir, name), []byte(os.Getenv("MSB_FAKE_JOB_RUNNING")), 0o600); err != nil {
			return err
		}
	case os.Getenv("MSB_FAKE_JOB_TIMEDOUT") != "":
		rec.TimedOut = true
		code := -1
		rec.ExitCode = &code
	default:
		code := fakeEnvInt("MSB_FAKE_EXIT", 0)
		rec.ExitCode = &code
	}
	if os.Getenv("MSB_FAKE_JOB_COMMAND_TAMPER") != "" && len(rec.Command) > 0 {
		rec.Command = append([]string{"tampered"}, rec.Command[1:]...)
	}
	now := time.Now().UnixMilli()
	rec.StartedAt, rec.FinishedAt = &now, &now
	if err := os.WriteFile(fakeJobOutputPath(dir, name, rec.ID), fakeJobOutput(), 0o600); err != nil {
		return err
	}
	recs = append(recs, rec)
	raw, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	if err := os.WriteFile(fakeJobsPath(dir, name), raw, 0o600); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(dir, name+".exec"), []byte("executed"), 0o600)
	return nil
}

// fakeJobOutput renders the captured output for a job.
func fakeJobOutput() []byte {
	switch os.Getenv("MSB_FAKE_OUT") {
	case "quiet":
		return nil
	case "burst":
		n := fakeEnvInt("MSB_FAKE_BYTES", 200000)
		var buf bytes.Buffer
		chunk := bytes.Repeat([]byte{'A'}, 4096)
		for written := 0; written < n; written += len(chunk) {
			buf.Write(chunk)
		}
		return buf.Bytes()
	default:
		return []byte("hello\n")
	}
}

// fakeReadSandbox reads the fake sandbox state file.
func fakeReadSandbox(dir, name string) (fakeSandbox, error) {
	raw, err := os.ReadFile(fakeStatePath(dir, name))
	if err != nil {
		return fakeSandbox{}, err
	}
	var sb fakeSandbox
	if err := json.Unmarshal(raw, &sb); err != nil {
		return fakeSandbox{}, err
	}
	return sb, nil
}

func fakeReadJobs(dir, name string) ([]fakeJobRecord, error) {
	raw, err := os.ReadFile(fakeJobsPath(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var recs []fakeJobRecord
	if err := json.Unmarshal(raw, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func fakeWriteJobs(dir, name string, recs []fakeJobRecord) error {
	raw, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	return os.WriteFile(fakeJobsPath(dir, name), raw, 0o600)
}

func fakeInspectJob(dir string, args []string, jobID string) int {
	name := fakeName(args)
	if _, err := os.Stat(fakeStatePath(dir, name)); err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox not found: %s\n", name)
		return 1
	}
	recs, err := fakeReadJobs(dir, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	for i := range recs {
		if recs[i].ID != jobID {
			continue
		}
		// A job that models a slow start flips to exited after the
		// configured number of observations, counted durably so each
		// fake invocation sees the same progression.
		if recs[i].State == "running" {
			remaining := fakeEnvInt("MSB_FAKE_JOB_RUNNING", 1)
			if raw, err := os.ReadFile(fakePollsPath(dir, name)); err == nil {
				if n, cerr := strconv.Atoi(strings.TrimSpace(string(raw))); cerr == nil {
					remaining = n
				}
			}
			if remaining > 1 {
				_ = os.WriteFile(fakePollsPath(dir, name), []byte(strconv.Itoa(remaining-1)), 0o600)
			} else {
				recs[i].State = "exited"
				code := fakeEnvInt("MSB_FAKE_EXIT", 0)
				recs[i].ExitCode = &code
				now := time.Now().UnixMilli()
				recs[i].FinishedAt = &now
				_ = os.Remove(fakePollsPath(dir, name))
			}
			if err := fakeWriteJobs(dir, name, recs); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		}
		raw, _ := json.Marshal(recs[i])
		os.Stdout.Write(raw)
		fmt.Fprintln(os.Stdout)
		return 0
	}
	fmt.Fprintf(os.Stderr, "error: job not found: %s\n", jobID)
	return 1
}

func fakePollsPath(dir, name string) string { return filepath.Join(dir, name+".polls") }

func fakeJobs(dir string, args []string) int {
	name := fakeName(args)
	if _, err := os.Stat(fakeStatePath(dir, name)); err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox not found: %s\n", name)
		return 1
	}
	recs, err := fakeReadJobs(dir, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if recs == nil {
		recs = []fakeJobRecord{}
	}
	page := fakeEnvInt("MSB_FAKE_JOBS_PAGE", 0)
	if page <= 0 {
		raw, _ := json.Marshal(map[string]any{"items": recs, "next_cursor": nil})
		os.Stdout.Write(raw)
		fmt.Fprintln(os.Stdout)
		return 0
	}
	offset := 0
	if c := fakeFlagValue(args, "--cursor"); c != "" {
		if n, cerr := strconv.Atoi(c); cerr == nil {
			offset = n
		}
	}
	if offset > len(recs) {
		offset = len(recs)
	}
	end := offset + page
	if end > len(recs) {
		end = len(recs)
	}
	items := recs[offset:end]
	var next any
	if end < len(recs) {
		next = strconv.Itoa(end)
	}
	if os.Getenv("MSB_FAKE_JOBS_CURSOR_LOOP") != "" {
		next = "stuck"
	}
	raw, _ := json.Marshal(map[string]any{"items": items, "next_cursor": next})
	os.Stdout.Write(raw)
	fmt.Fprintln(os.Stdout)
	return 0
}

func fakeLogs(dir string, args []string) int {
	name := fakeName(args)
	jobID := fakeFlagValue(args, "--job")
	if _, err := os.Stat(fakeStatePath(dir, name)); err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox not found: %s\n", name)
		return 1
	}
	if os.Getenv("MSB_FAKE_LOGS_FAIL") != "" {
		fmt.Fprintln(os.Stderr, "error: job not found: output capture unavailable")
		return 1
	}
	raw, err := os.ReadFile(fakeJobOutputPath(dir, name, jobID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: job not found: %s\n", jobID)
		return 1
	}
	os.Stdout.Write(raw)
	return 0
}

func fakeRemove(dir string, args []string) int {
	removed := false
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if os.Getenv("MSB_FAKE_RM_FAIL") != "" {
			fmt.Fprintf(os.Stderr, "error: remove failed: sandbox %s is busy\n", a)
			return 1
		}
		if _, err := os.Stat(fakeStatePath(dir, a)); err != nil {
			continue
		}
		_ = os.Remove(fakeStatePath(dir, a))
		_ = os.Remove(filepath.Join(dir, a+".exec"))
		if recs, err := fakeReadJobs(dir, a); err == nil {
			for _, rec := range recs {
				_ = os.Remove(fakeJobOutputPath(dir, a, rec.ID))
			}
		}
		_ = os.Remove(fakeJobsPath(dir, a))
		fmt.Fprintf(os.Stdout, "  ✓ Removed %s\n", a)
		removed = true
	}
	if !removed {
		fmt.Fprintln(os.Stderr, "error: sandbox not found")
		return 1
	}
	return 0
}

func fakeSizeMiB(s string) uint64 {
	if rest, ok := strings.CutSuffix(s, "G"); ok {
		v, _ := strconv.ParseUint(rest, 10, 64)
		return v * 1024
	}
	rest := strings.TrimSuffix(s, "M")
	v, _ := strconv.ParseUint(rest, 10, 64)
	return v
}

func fakeDurationSecs(s string) int {
	if rest, ok := strings.CutSuffix(s, "s"); ok {
		v, _ := strconv.Atoi(rest)
		return v
	}
	v, _ := strconv.Atoi(s)
	return v
}

func fakeEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// ─── Test helpers ───────────────────────────────────────────────────

// fakeMSB returns the helper binary path with the fake CLI enabled,
// plus the directory its sandbox state lives in.
func fakeMSB(t *testing.T, env map[string]string) (bin, stateDir string) {
	t.Helper()
	stateDir = t.TempDir()
	t.Setenv("MSB_FAKE_HELPER", "1")
	t.Setenv("MSB_FAKE_DIR", stateDir)
	for k, v := range env {
		t.Setenv(k, v)
	}
	return os.Args[0], stateDir
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// testBackend builds an adapter with a fast observation window and the
// fake runtime's actual bytes pinned, so the runtime-identity check
// exercises real hashing against the fake executable and a firmware
// file the fake doctor names.
func testBackend(t *testing.T, bin, stateDir string) *MSBBackend {
	t.Helper()
	fw := filepath.Join(t.TempDir(), "libkrunfw.dylib")
	if err := os.WriteFile(fw, []byte("fake firmware bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MSB_FAKE_FIRMWARE", fw)
	return &MSBBackend{
		Bin:              bin,
		StateDir:         stateDir,
		PollInterval:     10 * time.Millisecond,
		ObservationSlack: 500 * time.Millisecond,
		RuntimeManifest: &RuntimeManifest{
			Version:         PinnedMSBVersion,
			MSBSHA256:       sha256File(t, bin),
			LibkrunfwSHA256: sha256File(t, fw),
		},
	}
}

func writeFakeSandbox(t *testing.T, dir, name string, conf fakeSandboxConfig) {
	t.Helper()
	conf.Name = name
	raw, err := json.Marshal(fakeSandbox{Name: name, Status: "Running", Config: conf, ActiveConfig: &conf})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeStatePath(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFakeSandbox(t *testing.T, dir, name string) fakeSandbox {
	t.Helper()
	raw, err := os.ReadFile(fakeStatePath(dir, name))
	if err != nil {
		t.Fatalf("read fake sandbox %s: %v", name, err)
	}
	var sb fakeSandbox
	if err := json.Unmarshal(raw, &sb); err != nil {
		t.Fatalf("parse fake sandbox %s: %v", name, err)
	}
	return sb
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ─── Bounded artifact writer ────────────────────────────────────────

// TestBoundedArtifactWriterDigestMatchesStoredBytes is the artifact
// invariant: the digest covers exactly the bytes on disk, bytes past
// the contract bound are drained and never hashed, and truncation is
// an explicit observation.
func TestBoundedArtifactWriterDigestMatchesStoredBytes(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "artifact")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := &boundedArtifactWriter{f: f, hasher: sha256.New(), remaining: 1000}

	for i := 0; i < 40; i++ {
		if _, err := w.Write(bytes.Repeat([]byte{'A'}, 64)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	written, truncated := w.stats()
	if written != 1000 {
		t.Fatalf("stored %d bytes, want the 1000-byte bound", written)
	}
	if !truncated {
		t.Fatal("truncation not reported")
	}
	if info, err := f.Stat(); err != nil || info.Size() != 1000 {
		t.Fatalf("artifact size = %v (err %v), want 1000", info, err)
	}
	if got := sha256File(t, f.Name()); got != w.digest() {
		t.Fatalf("digest %s does not match the stored bytes %s", w.digest(), got)
	}
}

// ─── Dispatch: fresh VM, exclusive creation, policy verification ────

// TestMSBDispatchRefusesPreexistingSandbox is the sandbox-reuse
// attack: a permissive VM already exists under the deterministic
// handle. The job must refuse it — never execute inside it, never
// adopt or destroy it.
func TestMSBDispatchRefusesPreexistingSandbox(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "reuse-1"; c.Nonce = "n-reuse" })
	name := backend.msbJobName(job.JobID)

	permissive := fakeDefaultConfig()
	permissive.Network.Policy = fakePublicPolicy()
	permissive.Network.Policy.DefaultEgress = "allow"
	writeFakeSandbox(t, stateDir, name, permissive)

	if _, err := backend.Dispatch(testContext(t), job, nil); err == nil {
		t.Fatal("dispatch reused a pre-existing sandbox")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, name+".exec")); err == nil {
		t.Fatal("the job executed inside the pre-existing sandbox")
	}
	if recs, _ := fakeReadJobs(stateDir, name); len(recs) != 0 {
		t.Fatal("the pre-existing sandbox received a job")
	}
	got := readFakeSandbox(t, stateDir, name)
	if got.Config.Network.Policy.DefaultEgress != "allow" {
		t.Fatal("the pre-existing sandbox was modified")
	}
}

// TestMSBDispatchVerifiesPolicyBeforeExec tampers with the booted
// VM's policy between create and exec: verification must destroy it
// before any guest command runs.
func TestMSBDispatchVerifiesPolicyBeforeExec(t *testing.T) {
	for _, tamper := range []string{"net_public", "ingress_allow"} {
		t.Run(tamper, func(t *testing.T) {
			key, _ := testAuthority(t)
			bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_TAMPER": tamper})
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "verify-1"; c.Nonce = "n-verify" })
			name := backend.msbJobName(job.JobID)

			_, err := backend.Dispatch(testContext(t), job, nil)
			if err == nil {
				t.Fatal("dispatch accepted a VM that failed policy verification")
			}
			if !strings.Contains(err.Error(), "policy verification") {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if _, err := os.Stat(filepath.Join(stateDir, name+".exec")); err == nil {
				t.Fatal("exec ran inside an unverified VM")
			}
			if _, err := os.Stat(fakeStatePath(stateDir, name)); err == nil {
				t.Fatal("the unverified VM was not destroyed")
			}
		})
	}
}

// TestMSBDispatchAmbiguousCreateLeaksNothing: a dispatch deadline
// that expires mid-create is ambiguous by construction (the VM may
// exist), but no launch was ever attempted — so no artifact may
// survive the stalled dispatch.
func TestMSBDispatchAmbiguousCreateLeaksNothing(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_CREATE_SLEEP": "5"})
	dir := t.TempDir()
	backend := testBackend(t, bin, filepath.Join(dir, "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ambig-create"; c.Nonce = "n-ambig" })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	disp, err := backend.Dispatch(ctx, job, nil)
	if err == nil || !errors.Is(err, ErrAmbiguousDispatch) {
		t.Fatalf("want an ambiguous dispatch, got handle=%q err=%v", disp.Handle, err)
	}
	if disp.Handle != backend.msbJobName(job.JobID) {
		t.Fatalf("ambiguous handle = %q", disp.Handle)
	}
	entries, rerr := os.ReadDir(filepath.Join(dir, "artifacts"))
	if rerr == nil && len(entries) != 0 {
		t.Fatalf("a stalled dispatch left %d artifact file(s)", len(entries))
	}
}

// TestMSBDispatchRefusesUnauthorizedPublicRules: `--net public`
// composes exactly the gateway DNS rule and the public egress allow —
// any extra rule is reachability the contract never authorized.
func TestMSBDispatchRefusesUnauthorizedPublicRules(t *testing.T) {
	t.Run("authorized public rules accepted", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, _ := fakeMSB(t, nil)
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		job := testContract(t, key, func(c *JobContractV2) {
			c.JobID = "pub-ok"
			c.Nonce = "n-pub-ok"
			c.Network = NetworkPolicy{Mode: NetworkPublic}
		})
		disp, err := backend.Dispatch(testContext(t), job, nil)
		if err != nil {
			t.Fatalf("authorized public network refused: %v", err)
		}
		if _, err := backend.Wait(testContext(t), job, disp); err != nil {
			t.Fatalf("wait: %v", err)
		}
	})
	t.Run("extra private rule refused", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_TAMPER": "public_plus_private"})
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		job := testContract(t, key, func(c *JobContractV2) {
			c.JobID = "pub-extra"
			c.Nonce = "n-pub-extra"
			c.Network = NetworkPolicy{Mode: NetworkPublic}
		})
		name := backend.msbJobName(job.JobID)
		_, err := backend.Dispatch(testContext(t), job, nil)
		if err == nil || !strings.Contains(err.Error(), "did not authorize") {
			t.Fatalf("an unauthorized public rule was accepted: %v", err)
		}
		if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr == nil {
			t.Fatal("the unauthorized VM was not destroyed")
		}
	})
}

// TestMSBDispatchVerifiesBootedConfiguration: the persisted config
// can say one thing while the booted VM runs another; verification
// must read the resolved active configuration too.
func TestMSBDispatchVerifiesBootedConfiguration(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_TAMPER": "active_diverges"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "active-1"; c.Nonce = "n-active" })
	name := backend.msbJobName(job.JobID)

	_, err := backend.Dispatch(testContext(t), job, nil)
	if err == nil || !strings.Contains(err.Error(), "booted configuration diverges") {
		t.Fatalf("a VM running an unauthorized booted policy was accepted: %v", err)
	}
	if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr == nil {
		t.Fatal("the divergent VM was not destroyed")
	}
}

// TestMSBDispatchFailedCreateRemovesItsOwnLeftover: a create can fail
// after the VM was booted (guest validation, for instance). The
// leftover carries this dispatch's identity label, so it is ours to
// remove — a failed dispatch must not orphan a VM.
func TestMSBDispatchFailedCreateRemovesItsOwnLeftover(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_CREATE_FAIL_AFTER": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "orphan-own"; c.Nonce = "n-orphan" })
	name := backend.msbJobName(job.JobID)

	if _, err := backend.Dispatch(testContext(t), job, nil); err == nil {
		t.Fatal("a failed create was accepted")
	}
	if _, err := os.Stat(fakeStatePath(stateDir, name)); err == nil {
		t.Fatal("a failed create left its own partially-created VM behind")
	}
}

// TestMSBDispatchFailedCreateLeavesForeignSandboxAlone: a failed
// create must not destroy a sandbox it did not create — the
// pre-existing trap belongs to whoever made it.
func TestMSBDispatchFailedCreateLeavesForeignSandboxAlone(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_CREATE_FAIL": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "orphan-foreign"; c.Nonce = "n-foreign" })
	name := backend.msbJobName(job.JobID)
	writeFakeSandbox(t, stateDir, name, fakeDefaultConfig())

	if _, err := backend.Dispatch(testContext(t), job, nil); err == nil {
		t.Fatal("a failed create was accepted")
	}
	if _, err := os.Stat(fakeStatePath(stateDir, name)); err != nil {
		t.Fatal("a failed create destroyed a sandbox it did not create")
	}
}

// TestMSBDispatchPullPolicy: the image fetch policy is pinned per
// dispatch — never by default, so a missing image refuses fast instead
// of fetching mid-dispatch and turning a launch into an ambiguity.
func TestMSBDispatchPullPolicy(t *testing.T) {
	t.Run("if-missing is passed through when configured", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, stateDir := fakeMSB(t, nil)
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		backend.PullPolicy = PullIfMissing
		job := testContract(t, key, func(c *JobContractV2) { c.JobID = "pull-1"; c.Nonce = "n-pull" })
		disp, err := backend.Dispatch(testContext(t), job, nil)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if got := readFakeSandbox(t, stateDir, disp.Handle).Config.PullPolicy; got != PullIfMissing {
			t.Fatalf("pull policy = %q, want %q", got, PullIfMissing)
		}
		if _, err := backend.Wait(testContext(t), job, disp); err != nil {
			t.Fatalf("wait: %v", err)
		}
	})
	t.Run("unknown policy refuses", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, stateDir := fakeMSB(t, nil)
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		backend.PullPolicy = "yolo"
		job := testContract(t, key, func(c *JobContractV2) { c.JobID = "pull-2"; c.Nonce = "n-pull-2" })
		_, err := backend.Dispatch(testContext(t), job, nil)
		if err == nil || !strings.Contains(err.Error(), "unknown image pull policy") {
			t.Fatalf("unknown pull policy accepted: %v", err)
		}
		entries, rerr := os.ReadDir(stateDir)
		if rerr == nil && len(entries) != 0 {
			t.Fatalf("a refused dispatch left %d sandbox record(s)", len(entries))
		}
	})
}

func TestMSBDispatchMapsContractToSandbox(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) {
		c.JobID = "mapped-1"
		c.Nonce = "n-mapped"
		c.Resources = ResourceBudget{TimeoutSeconds: 90, CPUs: 2, MemoryMB: 512, Pids: 64, DiskMB: 2048, MaxOutputBytes: 4096}
		c.Network = NetworkPolicy{Mode: NetworkAllowlist, Allow: []string{"api.example.com", "*.github.com"}}
		c.Filesystem = FilesystemPolicy{
			Workdir: "/workspace",
			Mounts:  []Mount{{Source: "/private/tmp/src", Dest: "/src"}},
		}
		c.Env = []string{"FOO=bar"}
		c.Security = SecurityRestricted
	})

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !jobIDPattern.MatchString(disp.RunID) {
		t.Fatalf("dispatch run id %q is not a runtime job id", disp.RunID)
	}
	// The VM's live configuration is inspected while it exists —
	// Cleanup removes it once the result is collected.
	conf := readFakeSandbox(t, stateDir, disp.Handle).Config
	// The dispatch recorded exactly the authorized argv under the
	// run identity Dispatch returned.
	recs, err := fakeReadJobs(stateDir, disp.Handle)
	if err != nil || len(recs) != 1 {
		t.Fatalf("job records = %+v (err %v), want exactly one", recs, err)
	}
	if recs[0].ID != disp.RunID || !sameArgv(recs[0].Command, job.Argv) {
		t.Fatalf("recorded job does not match the dispatch: %+v vs run id %s", recs[0], disp.RunID)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !res.ExitVerified || res.ExitCode != 0 {
		t.Fatalf("exit not verified: %+v", res)
	}
	if conf.Resources.CPUs != 2 || conf.Resources.MemoryMiB != 512 {
		t.Fatalf("resources not mapped: %+v", conf.Resources)
	}
	if conf.Image.Oci.RootDisk.SizeMiB != 2048 {
		t.Fatalf("root disk not mapped: %+v", conf.Image.Oci.RootDisk)
	}
	wantMax := uint32(90) + uint32(maxDurationGrace/time.Second)
	if conf.Lifecycle.MaxDurationSecs == nil || *conf.Lifecycle.MaxDurationSecs != wantMax {
		t.Fatalf("max duration = %+v, want the contract timeout %d plus the %s observation grace",
			conf.Lifecycle.MaxDurationSecs, 90, maxDurationGrace)
	}
	if conf.Runtime.Workdir == nil || *conf.Runtime.Workdir != "/workspace" {
		t.Fatalf("workdir not mapped: %+v", conf.Runtime)
	}
	if conf.SecurityProfile != SecurityRestricted {
		t.Fatalf("security profile not mapped: %q", conf.SecurityProfile)
	}
	if conf.Labels["crabedence.job"] != "mapped-1" || conf.Labels["crabedence.dispatch"] == "" {
		t.Fatalf("dispatch identity labels missing: %+v", conf.Labels)
	}
	if conf.ManifestDigest != testImageDigest {
		t.Fatalf("image digest not pinned: %q", conf.ManifestDigest)
	}
	if conf.PullPolicy != PullNever {
		t.Fatalf("image fetch policy = %q, want the deterministic default %q", conf.PullPolicy, PullNever)
	}
	if conf.DeploymentProfile != "single_tenant" {
		t.Fatalf("deployment profile not pinned: %q", conf.DeploymentProfile)
	}
	if len(conf.Mounts) != 1 || conf.Mounts[0].Guest != "/src" {
		t.Fatalf("mounts not mapped: %+v", conf.Mounts)
	}
	foundEnv := false
	for _, e := range conf.Env {
		if e.Key == "FOO" && e.Value == "bar" {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Fatalf("env not mapped: %+v", conf.Env)
	}
	if conf.Network.Policy.DefaultEgress != "deny" || len(conf.Network.Policy.Rules) != 2 {
		t.Fatalf("network policy not mapped: %+v", conf.Network.Policy)
	}
	// The artifact store is the durable evidence — the VM itself is
	// removed by Cleanup once the result is collected.
	if err := backend.Cleanup(testContext(t), disp.Handle); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(fakeStatePath(stateDir, disp.Handle)); err == nil {
		t.Fatal("sandbox left behind after cleanup")
	}
}

// TestMSBDispatchRefusalOnSpawnFailure: a command the guest rejects
// before it starts is a definitive dispatch refusal — nothing ran,
// no job exists, and the VM is removed.
func TestMSBDispatchRefusalOnSpawnFailure(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_LAUNCH_FAIL": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "spawn-fail"; c.Nonce = "n-spawn" })
	name := backend.msbJobName(job.JobID)

	_, err := backend.Dispatch(testContext(t), job, nil)
	if err == nil {
		t.Fatal("a spawn failure was accepted as a launch")
	}
	if errors.Is(err, ErrAmbiguousDispatch) {
		t.Fatalf("a definitive spawn refusal was classified ambiguous: %v", err)
	}
	if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr == nil {
		t.Fatal("the refused VM was not destroyed")
	}
	if recs, _ := fakeReadJobs(stateDir, name); len(recs) != 0 {
		t.Fatal("a refused launch recorded a job")
	}
}

// TestMSBDispatchAdoptsAdmittedUnnamedJob: a launch whose identity is
// lost in transport must not be duplicated — the runtime's own job
// list proves the job exists, and the adapter adopts it.
func TestMSBDispatchAdoptsAdmittedUnnamedJob(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_LAUNCH_FAIL_ADMITTED": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "adopt-1"; c.Nonce = "n-adopt" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("an admitted-but-unnamed launch must be adopted, got: %v", err)
	}
	if !jobIDPattern.MatchString(disp.RunID) {
		t.Fatalf("adopted run id %q is not a runtime job id", disp.RunID)
	}
	if recs, _ := fakeReadJobs(stateDir, disp.Handle); len(recs) != 1 {
		t.Fatalf("adoption must not duplicate the launch: %d job(s)", len(recs))
	}
}

// ─── Wait: structured observation ───────────────────────────────────

func TestMSBWaitVerifiesGuestExit(t *testing.T) {
	for _, code := range []int{0, 72} {
		t.Run(fmt.Sprintf("exit-%d", code), func(t *testing.T) {
			key, _ := testAuthority(t)
			bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_EXIT": strconv.Itoa(code)})
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = fmt.Sprintf("exit-%d", code); c.Nonce = "n-exit" })

			disp, err := backend.Dispatch(testContext(t), job, nil)
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			res, err := backend.Wait(testContext(t), job, disp)
			if err != nil {
				t.Fatalf("wait: %v", err)
			}
			if !res.ExitVerified || res.ExitCode != code {
				t.Fatalf("verified exit = %+v, want code %d", res, code)
			}
			if res.RuntimeState != "exited" || res.RunID != disp.RunID {
				t.Fatalf("result does not carry the runtime record: %+v", res)
			}
			if res.OutputBytes == 0 || res.OutputSHA256 == "" || res.OutputPath == "" {
				t.Fatalf("artifact not bound: %+v", res)
			}
			if res.OutputSHA256 != sha256File(t, res.OutputPath) {
				t.Fatal("artifact digest does not cover the published file")
			}
		})
	}
}

// TestMSBWaitTimeoutIsObservedNotInvented: the runtime killed the
// command at the contract deadline. The outcome is observed, but it
// is not a guest exit — no exit code may be fabricated for it.
func TestMSBWaitTimeoutIsObservedNotInvented(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_JOB_TIMEDOUT": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "timeout-1"; c.Nonce = "n-timeout" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !res.TimedOut || res.ExitVerified {
		t.Fatalf("timed-out job reported as %+v", res)
	}
	if res.ExitCode != 0 {
		t.Fatalf("a timed-out job fabricated exit code %d", res.ExitCode)
	}
}

// TestMSBWaitSpawnRejected: the runtime recorded that the guest
// rejected the command before it started — a definitive outcome in
// which the workload provably produced no effect.
func TestMSBWaitSpawnRejected(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_JOB_FAILURE": "not_found"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "spawn-rejected"; c.Nonce = "n-rej" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if res.FailureKind != "not_found" || res.ExitVerified {
		t.Fatalf("spawn rejection classified as %+v", res)
	}
}

// TestMSBWaitLostRuntimeIsUnobserved: the runtime lost the job
// without a confirmed exit. That is exactly the outcome the plan
// forbids inventing a result for — it must come back unobserved.
func TestMSBWaitLostRuntimeIsUnobserved(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_JOB_LOST": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "lost-1"; c.Nonce = "n-lost" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err == nil {
		t.Fatalf("a lost runtime produced a result: %+v", res)
	}
	if !errors.Is(err, ErrExecutionUnobserved) {
		t.Fatalf("lost runtime error = %v, want ErrExecutionUnobserved", err)
	}
}

// TestMSBWaitVanishedSandboxIsUnobserved: the sandbox (and with it
// the job record) is gone. No observation is possible, so none is
// invented — even though a CLI could have reported something.
func TestMSBWaitVanishedSandboxIsUnobserved(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.ObservationSlack = 300 * time.Millisecond
	job := testContract(t, key, func(c *JobContractV2) {
		c.JobID = "vanish-1"
		c.Nonce = "n-vanish"
		// A short contract timeout keeps the observation window
		// bounded for the test.
		c.Resources.TimeoutSeconds = 1
	})

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if err := os.Remove(fakeStatePath(stateDir, disp.Handle)); err != nil {
		t.Fatal(err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err == nil {
		t.Fatalf("a vanished sandbox produced a result: %+v", res)
	}
	if !errors.Is(err, ErrExecutionUnobserved) {
		t.Fatalf("vanished sandbox error = %v, want ErrExecutionUnobserved", err)
	}
}

// TestMSBWaitCorrelatesTheAuthorizedCommand: a job record whose
// command is not the authorized argv is not this contract's
// execution — it must never be reported as one.
func TestMSBWaitCorrelatesTheAuthorizedCommand(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_JOB_COMMAND_TAMPER": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "corr-1"; c.Nonce = "n-corr" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err == nil {
		t.Fatalf("a foreign job record was accepted: %+v", res)
	}
	if !errors.Is(err, ErrExecutionUnobserved) {
		t.Fatalf("correlation mismatch error = %v, want ErrExecutionUnobserved", err)
	}
}

// TestMSBWaitPollsUntilTerminal: a job that is still running is
// polled until the runtime records its terminal state.
func TestMSBWaitPollsUntilTerminal(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_JOB_RUNNING": "3", "MSB_FAKE_EXIT": "5"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "poll-1"; c.Nonce = "n-poll" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !res.ExitVerified || res.ExitCode != 5 {
		t.Fatalf("polled result = %+v, want verified exit 5", res)
	}
}

// ─── Capture ────────────────────────────────────────────────────────

func TestMSBCaptureBoundedAndTruncated(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_OUT": "burst", "MSB_FAKE_BYTES": "200000"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) {
		c.JobID = "capture-1"
		c.Nonce = "n-capture"
		c.Resources.MaxOutputBytes = 64 * 1024
	})

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	data, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("artifact unreadable: %v", err)
	}
	if len(data) != 64*1024 || res.OutputBytes != 64*1024 {
		t.Fatalf("artifact holds %d bytes (result says %d), want the contract bound", len(data), res.OutputBytes)
	}
	if !res.Truncated {
		t.Fatal("output beyond the bound must report truncation")
	}
	if res.OutputSHA256 != sha256File(t, res.OutputPath) {
		t.Fatal("artifact digest does not cover the published file")
	}
	if res.CaptureSource != "runtime-job-log" {
		t.Fatalf("capture source = %q, want the runtime's retained job log", res.CaptureSource)
	}
}

func TestMSBCaptureKeepsSmallOutputWhole(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "small-1"; c.Nonce = "n-small" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	data, _ := os.ReadFile(res.OutputPath)
	if string(data) != "hello\n" || res.Truncated || res.OutputBytes != 6 {
		t.Fatalf("small output mangled: %q truncated=%t bytes=%d", data, res.Truncated, res.OutputBytes)
	}
	if res.OutputSHA256 != sha256File(t, res.OutputPath) {
		t.Fatal("digest does not match the stored artifact")
	}
}

// TestMSBCaptureFailureIsNotFullyVerified: the exit was observed but
// the artifact could not be finalized — the result comes back with
// its observation and an error, never as a terminal claim.
func TestMSBCaptureFailureIsNotFullyVerified(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_LOGS_FAIL": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "capfail-1"; c.Nonce = "n-capfail" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), job, disp)
	if err == nil {
		t.Fatalf("an unfinalized artifact produced a clean result: %+v", res)
	}
	if res == nil || !res.ExitVerified || res.ExitCode != 0 {
		t.Fatalf("the observation was lost with the artifact: res=%+v err=%v", res, err)
	}
}

// ─── Cleanup ────────────────────────────────────────────────────────

func TestMSBCleanupRemovesSandbox(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "clean-1"; c.Nonce = "n-clean" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if err := backend.Cleanup(testContext(t), disp.Handle); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(fakeStatePath(stateDir, disp.Handle)); err == nil {
		t.Fatal("sandbox survived cleanup")
	}
	// A second cleanup of an already-removed sandbox is a success:
	// the goal is absence.
	if err := backend.Cleanup(testContext(t), disp.Handle); err != nil {
		t.Fatalf("cleanup of a missing sandbox: %v", err)
	}
}

func TestMSBCleanupFailureIsReported(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_RM_FAIL": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "cleanfail-1"; c.Nonce = "n-cleanfail" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if err := backend.Cleanup(testContext(t), disp.Handle); err == nil {
		t.Fatal("a failed removal reported success")
	}
	if _, err := os.Stat(fakeStatePath(stateDir, disp.Handle)); err != nil {
		t.Fatal("the sandbox vanished despite the failed removal")
	}
}

func TestMSBKeepSandboxesLeavesForensicVM(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.KeepSandboxes = true
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "keep-1"; c.Nonce = "n-keep" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if _, err := backend.Wait(testContext(t), job, disp); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if err := backend.Cleanup(testContext(t), disp.Handle); err != nil {
		t.Fatalf("cleanup under KeepSandboxes: %v", err)
	}
	if _, err := os.Stat(fakeStatePath(stateDir, disp.Handle)); err != nil {
		t.Fatal("KeepSandboxes did not leave the VM in place")
	}
}

// ─── Runtime version pin ────────────────────────────────────────────

func TestMSBVerifyRuntimeAcceptsPinnedVersion(t *testing.T) {
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, t.TempDir())
	got, err := backend.VerifyRuntime(testContext(t))
	if err != nil {
		t.Fatalf("pinned runtime refused: %v", err)
	}
	if got != PinnedMSBVersion {
		t.Fatalf("observed version %q, want %q", got, PinnedMSBVersion)
	}
}

func TestMSBVerifyRuntimeRefusesDrift(t *testing.T) {
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_VERSION": "0.7.7"})
	backend := testBackend(t, bin, t.TempDir())
	if _, err := backend.VerifyRuntime(testContext(t)); err == nil {
		t.Fatal("an unpinned runtime version was accepted")
	} else if !strings.Contains(err.Error(), "pinned runtime") {
		t.Fatalf("drift refusal = %v", err)
	}
}

// TestMSBVerifyRuntimeHonorsExplicitPin: an operator may pin a
// different version explicitly; the check is equality, not "at least".
func TestMSBVerifyRuntimeHonorsExplicitPin(t *testing.T) {
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_VERSION": "0.7.9"})
	backend := testBackend(t, bin, t.TempDir())
	backend.RequiredVersion = "0.7.9"
	backend.RuntimeManifest.Version = "0.7.9"
	if _, err := backend.VerifyRuntime(testContext(t)); err != nil {
		t.Fatalf("explicit pin refused: %v", err)
	}
}

// ─── Resume: recovering a run a restart left unresolved ─────────────

// TestMSBResumeAdoptsTheRuntimesOwnRecord: the crash window between
// the runtime admitting a job and the ledger naming it is recovered
// from the runtime's own job list — one matching record is adopted,
// and the run is observed to its terminal result exactly as a live
// monitor would have observed it.
func TestMSBResumeAdoptsTheRuntimesOwnRecord(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_EXIT": "7"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "resume-1"; c.Nonce = "n-resume" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The identity was lost with the crash: resume without one.
	run, res, err := backend.Resume(testContext(t), job, RunIdentity{Handle: disp.Handle})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if run.RunID != disp.RunID {
		t.Fatalf("adopted run %q, want %q", run.RunID, disp.RunID)
	}
	if run.BootID != disp.BootID {
		t.Fatalf("adopted boot generation %q, want %q", run.BootID, disp.BootID)
	}
	if res == nil || !res.ExitVerified || res.ExitCode != 7 {
		t.Fatalf("resumed result = %+v", res)
	}
	if res.OutputSHA256 == "" || res.OutputPath == "" {
		t.Fatalf("resumed artifact not captured: %+v", res)
	}
}

// TestMSBResumeRefusesAmbiguousAdoption: zero or several matching
// records are never guessed at — an unprovable run stays unobserved.
func TestMSBResumeRefusesAmbiguousAdoption(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "resume-2"; c.Nonce = "n-resume-2" })

	t.Run("no sandbox at all", func(t *testing.T) {
		if _, _, err := backend.Resume(testContext(t), job, RunIdentity{Handle: "sx-resume-absent"}); !errors.Is(err, ErrExecutionUnobserved) {
			t.Fatalf("resume without a sandbox = %v, want unobserved", err)
		}
	})

	t.Run("no matching job record", func(t *testing.T) {
		name := "sx-resume-empty"
		writeFakeSandbox(t, stateDir, name, fakeDefaultConfig())
		if err := fakeWriteJob(stateDir, name, []string{"some-other-command"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := backend.Resume(testContext(t), job, RunIdentity{Handle: name}); !errors.Is(err, ErrExecutionUnobserved) {
			t.Fatalf("resume with no match = %v, want unobserved", err)
		}
	})

	t.Run("several matching job records", func(t *testing.T) {
		disp, err := backend.Dispatch(testContext(t), job, nil)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		// A second identical launch on the same sandbox: two records
		// matching the authorized argv are ambiguous, never adopted.
		if err := fakeWriteJob(stateDir, disp.Handle, job.Argv); err != nil {
			t.Fatal(err)
		}
		if _, _, err := backend.Resume(testContext(t), job, RunIdentity{Handle: disp.Handle}); !errors.Is(err, ErrExecutionUnobserved) {
			t.Fatalf("resume with two matches = %v, want unobserved", err)
		}
	})
}

// ─── Host confinement: deployment profile + host readiness ──────────

// TestMSBPinsDeploymentProfile: every sandbox boots under the pinned
// host-runtime isolation profile, and the booted configuration must
// carry it — a runtime that quietly downgraded confinement refuses
// before any guest command runs.
func TestMSBPinsDeploymentProfile(t *testing.T) {
	t.Run("default single-tenant is pinned and verified", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, stateDir := fakeMSB(t, nil)
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		job := testContract(t, key, func(c *JobContractV2) { c.JobID = "prof-1"; c.Nonce = "n-prof" })
		disp, err := backend.Dispatch(testContext(t), job, nil)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if got := readFakeSandbox(t, stateDir, disp.Handle).Config.DeploymentProfile; got != "single_tenant" {
			t.Fatalf("deployment profile = %q, want single_tenant", got)
		}
		if _, err := backend.Wait(testContext(t), job, disp); err != nil {
			t.Fatalf("wait: %v", err)
		}
	})
	t.Run("downgraded booted profile refuses", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_TAMPER": "deployment_multi"})
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		job := testContract(t, key, func(c *JobContractV2) { c.JobID = "prof-2"; c.Nonce = "n-prof-2" })
		name := backend.msbJobName(job.JobID)
		_, err := backend.Dispatch(testContext(t), job, nil)
		if err == nil || !strings.Contains(err.Error(), "deployment profile") {
			t.Fatalf("a downgraded deployment profile was accepted: %v", err)
		}
		if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr == nil {
			t.Fatal("the downgraded VM was not destroyed")
		}
	})
	t.Run("explicit multi-tenant pin is honored", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, stateDir := fakeMSB(t, nil)
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		backend.DeploymentProfile = DeploymentMultiTenant
		job := testContract(t, key, func(c *JobContractV2) { c.JobID = "prof-3"; c.Nonce = "n-prof-3" })
		disp, err := backend.Dispatch(testContext(t), job, nil)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if got := readFakeSandbox(t, stateDir, disp.Handle).Config.DeploymentProfile; got != "multi_tenant" {
			t.Fatalf("deployment profile = %q, want multi_tenant", got)
		}
	})
	t.Run("unknown profile refuses", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, _ := fakeMSB(t, nil)
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		backend.DeploymentProfile = "yolo-tenant"
		job := testContract(t, key, func(c *JobContractV2) { c.JobID = "prof-4"; c.Nonce = "n-prof-4" })
		if _, err := backend.Dispatch(testContext(t), job, nil); err == nil || !strings.Contains(err.Error(), "unknown deployment profile") {
			t.Fatalf("unknown profile accepted: %v", err)
		}
	})
}

// TestMSBVerifyHost: the host's own prerequisite check gates startup —
// an executor that cannot prove its host is supported refuses to run.
func TestMSBVerifyHost(t *testing.T) {
	t.Run("ready host passes", func(t *testing.T) {
		bin, _ := fakeMSB(t, nil)
		backend := testBackend(t, bin, t.TempDir())
		out, err := backend.VerifyHost(testContext(t))
		if err != nil {
			t.Fatalf("ready host refused: %v", err)
		}
		if !strings.Contains(out, "Host setup is ready") {
			t.Fatalf("host check output = %q", out)
		}
	})
	t.Run("unsupported host refuses", func(t *testing.T) {
		bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_DOCTOR_FAIL": "1"})
		backend := testBackend(t, bin, t.TempDir())
		if _, err := backend.VerifyHost(testContext(t)); err == nil {
			t.Fatal("an unsupported host was accepted")
		} else if !strings.Contains(err.Error(), "host confinement check failed") {
			t.Fatalf("host refusal = %v", err)
		}
	})
}

// TestMSBBoundsUtilityCallOutput: the adapter's own CLI calls are
// bounded — a runtime that floods a utility call is refused, never
// accumulated without bound on the executor's behalf.
func TestMSBBoundsUtilityCallOutput(t *testing.T) {
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, t.TempDir())
	out, err := backend.runOnce(testContext(t), "flood")
	if err == nil {
		t.Fatalf("a flooding call was accepted (%d bytes)", len(out))
	}
	if !strings.Contains(err.Error(), "more than") {
		t.Fatalf("flood refusal = %v", err)
	}
	if len(out) > maxCLIOutputBytes {
		t.Fatalf("captured %d bytes, over the %d-byte bound", len(out), maxCLIOutputBytes)
	}
}

// ─── rc.6: runtime identity, effective policy, execution identity ───

// TestMSBRuntimeIdentityRefusesSubstitutedBytes: a runtime that reports
// the pinned version but hashes differently is a substituted runtime —
// the version string is a claim, the digest is the identity.
func TestMSBRuntimeIdentityRefusesSubstitutedBytes(t *testing.T) {
	bin, _ := fakeMSB(t, nil)
	t.Run("substituted executable", func(t *testing.T) {
		backend := testBackend(t, bin, t.TempDir())
		backend.RuntimeManifest.MSBSHA256 = strings.Repeat("0", 64)
		if _, err := backend.VerifyRuntime(testContext(t)); err == nil {
			t.Fatal("a substituted executable was accepted")
		} else if !strings.Contains(err.Error(), "substituted executable") {
			t.Fatalf("executable refusal = %v", err)
		}
	})
	t.Run("substituted firmware", func(t *testing.T) {
		backend := testBackend(t, bin, t.TempDir())
		backend.RuntimeManifest.LibkrunfwSHA256 = strings.Repeat("0", 64)
		if _, err := backend.VerifyRuntime(testContext(t)); err == nil {
			t.Fatal("substituted firmware was accepted")
		} else if !strings.Contains(err.Error(), "substituted virtualization component") {
			t.Fatalf("firmware refusal = %v", err)
		}
	})
	t.Run("missing manifest refuses", func(t *testing.T) {
		backend := testBackend(t, bin, t.TempDir())
		backend.RuntimeManifest = nil
		if _, err := backend.VerifyRuntime(testContext(t)); err == nil {
			t.Fatal("a runtime without a qualified manifest was accepted")
		} else if !strings.Contains(err.Error(), "runtime manifest is required") {
			t.Fatalf("manifest refusal = %v", err)
		}
	})
}

// TestMSBPolicyRefusesUnauthorizedSettings is the F-034 regression
// table: every security-sensitive setting the policy did not authorize
// refuses before any guest command runs.
func TestMSBPolicyRefusesUnauthorizedSettings(t *testing.T) {
	cases := []struct {
		tamper string
		want   string
	}{
		{"extra_env", "unauthorized variable"},
		{"init_hook", "initialization hook"},
		{"patches", "rootfs patch"},
		{"scripts", "runtime script binding"},
		{"rlimits", "sandbox-level rlimit"},
		{"mount_policy_loose", "external mount policy"},
		{"extra_interface", "network interface binding"},
		{"port_publish", "port(s)"},
		{"max_cpus_headroom", "max_cpus"},
		{"max_memory_headroom", "max_memory_mib"},
		{"ephemeral", "ephemeral"},
		{"idle_timeout", "idle timeout"},
		{"workdir", "workdir"},
		{"pending_changes", "pending configuration change"},
		{"paused", "paused"},
		{"recovery_required", "requires recovery"},
	}
	for _, tc := range cases {
		t.Run(tc.tamper, func(t *testing.T) {
			key, _ := testAuthority(t)
			bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_TAMPER": tc.tamper})
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "policy-" + tc.tamper; c.Nonce = "n-" + tc.tamper })
			name := backend.msbJobName(job.JobID)
			_, err := backend.Dispatch(testContext(t), job, nil)
			if err == nil {
				t.Fatalf("%s was accepted", tc.tamper)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err, tc.want)
			}
			if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr == nil {
				t.Fatal("the unauthorized VM was not destroyed")
			}
		})
	}
}

// TestMSBDispatchBindsBootGeneration: the runtime-owned job must run in
// the boot generation this dispatch verified — a job record naming a
// different VM instance refuses, and the VM is destroyed (F-037).
func TestMSBDispatchBindsBootGeneration(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_JOB_BOOT_MISMATCH": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "boot-mismatch"; c.Nonce = "n-boot" })
	name := backend.msbJobName(job.JobID)

	_, err := backend.Dispatch(testContext(t), job, nil)
	if err == nil {
		t.Fatal("a job in a substituted VM instance was accepted")
	}
	if !strings.Contains(err.Error(), "substituted VM instance") {
		t.Fatalf("refusal = %v", err)
	}
	if !errors.Is(err, ErrAmbiguousDispatch) {
		t.Fatalf("a launch whose VM identity could not be proven is %v — it must be uncertain, never a refusal", err)
	}
	if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr != nil {
		t.Fatal("the VM of a possibly-running workload was destroyed instead of left for reconciliation")
	}
}

// TestMSBWaitRefusesSubstitutedBootGeneration: a job record whose boot
// generation changes mid-observation is a different VM instance — the
// outcome is unobserved, never adopted.
func TestMSBWaitRefusesSubstitutedBootGeneration(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "wait-boot"; c.Nonce = "n-wait-boot" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// Substitute the VM the record belongs to: same job id, different
	// boot generation.
	recs, err := fakeReadJobs(stateDir, disp.Handle)
	if err != nil || len(recs) != 1 {
		t.Fatalf("job records = %+v (%v)", recs, err)
	}
	recs[0].RuntimeBoot = "boot_" + strings.Repeat("7", 32)
	if err := fakeWriteJobs(stateDir, disp.Handle, recs); err != nil {
		t.Fatal(err)
	}
	res, werr := backend.Wait(testContext(t), job, disp)
	if werr == nil {
		t.Fatalf("a substituted boot generation produced a result: %+v", res)
	}
	if !errors.Is(werr, ErrExecutionUnobserved) {
		t.Fatalf("substitution error = %v, want unobserved", werr)
	}
}

// TestMSBResumeRefusesSubstitutedBootGeneration: recovery adopts a job
// only when it runs in the boot generation the ledger recorded — a
// sandbox re-created under the same name is never adopted.
func TestMSBResumeRefusesSubstitutedBootGeneration(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "resume-boot"; c.Nonce = "n-resume-boot" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// A new boot under the same name: the sandbox's boot identity file
	// changes while the old job record remains.
	newBoot := "boot_" + strings.Repeat("8", 32)
	if err := os.WriteFile(filepath.Join(stateDir, disp.Handle+".storage", "runtime", "runtime-boot-id"), []byte(newBoot), 0o600); err != nil {
		t.Fatal(err)
	}
	run, res, rerr := backend.Resume(testContext(t), job, RunIdentity{Handle: disp.Handle, RunID: "", BootID: disp.BootID})
	if rerr == nil {
		t.Fatalf("a substituted boot generation was adopted: %+v %+v", run, res)
	}
	if !errors.Is(rerr, ErrExecutionUnobserved) || !strings.Contains(rerr.Error(), "substituted VM instance") {
		t.Fatalf("substitution error = %v", rerr)
	}
}

// TestMSBListJobsIsExhaustive: discovery follows every page — a job on
// a later page is found, so incomplete discovery is never mistaken for
// absence of execution (F-038).
func TestMSBListJobsIsExhaustive(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_JOBS_PAGE": "2"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "page-1"; c.Nonce = "n-page" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// Four more jobs on later pages; the authorized one is page 3.
	for i := 0; i < 4; i++ {
		if err := fakeWriteJob(stateDir, disp.Handle, []string{"other", fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := backend.listJobs(testContext(t), disp.Handle)
	if err != nil {
		t.Fatalf("listJobs: %v", err)
	}
	if len(recs) != 5 {
		t.Fatalf("discovered %d job(s), want all 5", len(recs))
	}
	found := false
	for _, rec := range recs {
		if rec.ID == disp.RunID {
			found = true
		}
	}
	if !found {
		t.Fatal("the authorized job on a later page was not discovered")
	}
}

// TestMSBListJobsRefusesStuckCursor: a cursor that repeats is an error —
// discovery that cannot complete is never treated as absence.
func TestMSBListJobsRefusesStuckCursor(t *testing.T) {
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_JOBS_PAGE": "1", "MSB_FAKE_JOBS_CURSOR_LOOP": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	name := "sx-stuck"
	writeFakeSandbox(t, stateDir, name, fakeDefaultConfig())
	for i := 0; i < 3; i++ {
		if err := fakeWriteJob(stateDir, name, []string{"cmd", fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := backend.listJobs(testContext(t), name); err == nil {
		t.Fatal("a stuck cursor was treated as the end of discovery")
	} else if !strings.Contains(err.Error(), "cursor") {
		t.Fatalf("stuck cursor error = %v", err)
	}
}

// TestSyncDirRefusesMissingDirectory: the artifact directory sync is a
// checked durability operation — a sync that cannot run is an error, not
// a silent success (F-036).
func TestSyncDirRefusesMissingDirectory(t *testing.T) {
	if err := syncDir(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("syncing an absent directory reported success")
	}
}

// ─── rc.7: dispatch truth and persisted authorization ───────────────

// TestMSBDispatchPostLaunchFailureIsUncertain (F-040): a launch that was
// admitted but cannot be verified is uncertain — never a refusal, and the
// VM is left for reconciliation rather than destroyed under a workload
// that may be running.
func TestMSBDispatchPostLaunchFailureIsUncertain(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_JOB_INSPECT_FAIL": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "post-launch"; c.Nonce = "n-post" })
	name := backend.msbJobName(job.JobID)

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err == nil {
		t.Fatalf("a post-launch verification failure produced a success: %+v", disp)
	}
	if !errors.Is(err, ErrAmbiguousDispatch) {
		t.Fatalf("post-launch failure classified as %v — it must be uncertain", err)
	}
	if errors.Is(err, ErrDispatchRefused) {
		t.Fatal("a launched job was classified as refused — a false no-effect claim")
	}
	if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr != nil {
		t.Fatal("the VM of a possibly-running workload was destroyed")
	}
	if !bootIDPattern.MatchString(disp.BootID) {
		t.Fatalf("the uncertain identity does not carry the verified boot generation: %+v", disp)
	}
}

// TestMSBDispatchRefusalsAreProven: the only errors that may produce a
// NO_EFFECT claim are the proven pre-launch refusals.
func TestMSBDispatchRefusalsAreProven(t *testing.T) {
	key, _ := testAuthority(t)
	cases := []struct {
		name   string
		env    map[string]string
		reason string
	}{
		{"synchronous launch refusal", map[string]string{"MSB_FAKE_LAUNCH_FAIL": "1"}, "exec -d failed"},
		{"pre-exec policy refusal", map[string]string{"MSB_FAKE_TAMPER": "extra_env"}, "policy verification"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, _ := fakeMSB(t, tc.env)
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "refuse"; c.Nonce = "n-refuse" })
			_, err := backend.Dispatch(testContext(t), job, nil)
			if err == nil {
				t.Fatal("a refusal was reported as success")
			}
			if !errors.Is(err, ErrDispatchRefused) {
				t.Fatalf("pre-launch refusal classified as %v", err)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("refusal %q does not name %q", err, tc.reason)
			}
		})
	}
}

// TestMSBPrepareIsSideEffectFree: Prepare computes the dispatch identity
// without creating anything — the plan exists before the VM does.
func TestMSBPrepareIsSideEffectFree(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "prepare-1"; c.Nonce = "n-prepare" })

	plan, err := backend.Prepare(testContext(t), job)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if plan.Handle != backend.msbJobName(job.JobID) || plan.Nonce == "" || plan.PolicyDigest == "" {
		t.Fatalf("incomplete plan: %+v", plan)
	}
	if plan.ImageDigest != job.ImageDigest || plan.RuntimeVersion != PinnedMSBVersion {
		t.Fatalf("plan does not carry the authorized identities: %+v", plan)
	}
	if _, serr := os.Stat(fakeStatePath(stateDir, plan.Handle)); serr == nil {
		t.Fatal("prepare created a sandbox")
	}

	// The launch uses exactly the plan's identity: the VM carries the
	// plan's nonce as its dispatch label.
	disp, derr := backend.Dispatch(testContext(t), job, plan)
	if derr != nil {
		t.Fatalf("dispatch under the plan: %v", derr)
	}
	if disp.Nonce != plan.Nonce || disp.PolicyDigest != plan.PolicyDigest || disp.Handle != plan.Handle {
		t.Fatalf("dispatch identity %+v does not match the plan %+v", disp, plan)
	}
	sb, serr := fakeReadSandbox(stateDir, plan.Handle)
	if serr != nil {
		t.Fatalf("read sandbox: %v", serr)
	}
	if sb.Config.Labels["crabedence.dispatch"] != plan.Nonce {
		t.Fatalf("the VM's dispatch label %q is not the plan's nonce %q",
			sb.Config.Labels["crabedence.dispatch"], plan.Nonce)
	}
}

// TestMSBResumeRefusesRewrittenAuthorization (F-041): recovery admits a
// discovered VM only when it still matches the persisted authorization —
// a rewritten nonce or policy digest refuses, whatever the command says.
func TestMSBResumeRefusesRewrittenAuthorization(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "auth-1"; c.Nonce = "n-auth" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	t.Run("rewritten nonce", func(t *testing.T) {
		run := disp
		run.Nonce = "nonce_" + strings.Repeat("9", 32)
		_, _, rerr := backend.Resume(testContext(t), job, run)
		if !errors.Is(rerr, ErrExecutionUnobserved) {
			t.Fatalf("a rewritten nonce was adopted: %v", rerr)
		}
		if !strings.Contains(rerr.Error(), "not the dispatch's approved") {
			t.Fatalf("refusal %q does not name the authorization mismatch", rerr)
		}
	})

	t.Run("rewritten policy digest", func(t *testing.T) {
		run := disp
		run.PolicyDigest = strings.Repeat("cd", 32)
		_, _, rerr := backend.Resume(testContext(t), job, run)
		if !errors.Is(rerr, ErrExecutionUnobserved) {
			t.Fatalf("a rewritten policy digest was adopted: %v", rerr)
		}
		if !strings.Contains(rerr.Error(), "approved") {
			t.Fatalf("refusal %q does not name the authorization mismatch", rerr)
		}
	})

	t.Run("intact authorization resumes", func(t *testing.T) {
		run, res, rerr := backend.Resume(testContext(t), job, disp)
		if rerr != nil {
			t.Fatalf("resume under the persisted authorization: %v", rerr)
		}
		if res == nil || !res.ExitVerified {
			t.Fatalf("resumed result = %+v", res)
		}
		if run.PolicyDigest != disp.PolicyDigest {
			t.Fatalf("resume changed the policy digest: %q → %q", disp.PolicyDigest, run.PolicyDigest)
		}
	})
}

// TestMSBRuntimeIdentityCoversTheComponentChain (F-042): every shared
// component the pinned runtime version ships must be the qualified
// bytes — an unpinned component, a substituted component or a pinned
// component that is missing all refuse.
func TestMSBRuntimeIdentityCoversTheComponentChain(t *testing.T) {
	bin, _ := fakeMSB(t, nil)
	newBackend := func(t *testing.T) (*MSBBackend, string) {
		t.Helper()
		backend := testBackend(t, bin, t.TempDir())
		fwPath, err := backend.firmwarePath(testContext(t))
		if err != nil {
			t.Fatalf("resolve firmware: %v", err)
		}
		componentDir := filepath.Join(filepath.Dir(fwPath), "v"+PinnedMSBVersion)
		if err := os.MkdirAll(componentDir, 0o700); err != nil {
			t.Fatal(err)
		}
		return backend, componentDir
	}

	t.Run("unpinned component refuses", func(t *testing.T) {
		backend, componentDir := newBackend(t)
		if err := os.WriteFile(filepath.Join(componentDir, "injected.dylib"), []byte("injected bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.VerifyRuntime(testContext(t)); err == nil {
			t.Fatal("an unpinned runtime component was accepted")
		} else if !strings.Contains(err.Error(), "unpinned dependency") {
			t.Fatalf("refusal = %v", err)
		}
	})

	t.Run("pinned component with the wrong bytes refuses", func(t *testing.T) {
		backend, componentDir := newBackend(t)
		path := filepath.Join(componentDir, "helper.dylib")
		if err := os.WriteFile(path, []byte("qualified bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		backend.RuntimeManifest.Components = map[string]string{"helper.dylib": strings.Repeat("0", 64)}
		if _, err := backend.VerifyRuntime(testContext(t)); err == nil {
			t.Fatal("a substituted runtime component was accepted")
		} else if !strings.Contains(err.Error(), "substituted dependency") {
			t.Fatalf("refusal = %v", err)
		}
	})

	t.Run("pinned component that is missing refuses", func(t *testing.T) {
		backend, _ := newBackend(t)
		backend.RuntimeManifest.Components = map[string]string{"absent.dylib": strings.Repeat("1", 64)}
		if _, err := backend.VerifyRuntime(testContext(t)); err == nil {
			t.Fatal("a missing pinned component was accepted")
		} else if !strings.Contains(err.Error(), "incomplete install") {
			t.Fatalf("refusal = %v", err)
		}
	})

	t.Run("the qualified chain is accepted", func(t *testing.T) {
		backend, componentDir := newBackend(t)
		path := filepath.Join(componentDir, "helper.dylib")
		if err := os.WriteFile(path, []byte("qualified bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256File(t, path)
		backend.RuntimeManifest.Components = map[string]string{"helper.dylib": sum}
		if _, err := backend.VerifyRuntime(testContext(t)); err != nil {
			t.Fatalf("the qualified component chain was refused: %v", err)
		}
	})
}
