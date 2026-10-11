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
	"sync"
	"testing"
	"time"
)

// ─── Fake msb helper process ─────────────────────────────────────────
//
// The backend tests exercise the real adapter against a fake msb
// binary that reimplements the CLI surfaces the adapter depends on:
// exclusive `create`, `inspect --format json`, `exec` and `rm` — plus
// the real CLI's silent-reuse behavior on `run`, so the regression
// that motivated the hardened adapter stays reproducible.
//
// The helper is this test binary re-invoked with MSB_FAKE_HELPER=1;
// TestMain intercepts before flag parsing, so msb-style argv never
// reaches the testing package. State lives under MSB_FAKE_DIR as one
// JSON file per sandbox, mirroring `msb inspect --format json`.

func TestMain(m *testing.M) {
	if os.Getenv("MSB_FAKE_HELPER") == "1" {
		os.Exit(fakeMSBMain())
	}
	os.Exit(m.Run())
}

type fakeSandbox struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Config fakeSandboxConfig `json:"config"`
}

type fakeSandboxConfig struct {
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	ManifestDigest  string            `json:"manifest_digest"`
	Env             []fakeEnvVar      `json:"env"`
	Resources       fakeResources     `json:"resources"`
	Lifecycle       fakeLifecycle     `json:"lifecycle"`
	Runtime         fakeRuntime       `json:"runtime"`
	SecurityProfile string            `json:"security_profile"`
	Network         fakeNetwork       `json:"network"`
	Mounts          []fakeMount       `json:"mounts"`
	Image           fakeImage         `json:"image"`
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
	MaxDurationSecs *uint32 `json:"max_duration_secs"`
}

type fakeRuntime struct {
	Workdir *string `json:"workdir"`
	Shell   string  `json:"shell"`
}

type fakeNetwork struct {
	Enabled bool       `json:"enabled"`
	Policy  fakePolicy `json:"policy"`
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

func fakeDefaultConfig() fakeSandboxConfig {
	return fakeSandboxConfig{
		Labels:          map[string]string{},
		ManifestDigest:  testImageDigest,
		Resources:       fakeResources{CPUs: 1, MaxCPUs: 1, MemoryMiB: 512, MaxMemoryMiB: 512},
		Lifecycle:       fakeLifecycle{},
		Runtime:         fakeRuntime{Shell: "/bin/sh"},
		SecurityProfile: SecurityDefault,
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
	case "create":
		return fakeCreate(dir, rest)
	case "run":
		return fakeRun(dir, rest)
	case "inspect":
		return fakeInspect(dir, rest)
	case "exec":
		return fakeExec(dir, rest)
	case "rm":
		return fakeRemove(dir, rest)
	case "list":
		return 0
	default:
		fmt.Fprintf(os.Stderr, "fake msb: unsupported command %q\n", cmd)
		return 2
	}
}

func fakeStatePath(dir, name string) string { return filepath.Join(dir, name+".json") }

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
		case "--pull", "--max-cpus", "--max-memory", "--hostname":
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
	if tamper := os.Getenv("MSB_FAKE_TAMPER"); tamper == "net_public" {
		conf.Network.Policy = fakePublicPolicy()
	} else if tamper == "ingress_allow" {
		conf.Network.Policy.DefaultIngress = "allow"
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
	raw, _ := json.Marshal(fakeSandbox{Name: name, Status: "Running", Config: conf})
	_, _ = f.Write(raw)
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
	return fakeExec(dir, []string{"--no-tty", "--no-stdin", name, "--"})
}

func fakeInspect(dir string, args []string) int {
	var name string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			name = a
		}
	}
	raw, err := os.ReadFile(fakeStatePath(dir, name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox not found: %s\n", name)
		return 1
	}
	os.Stdout.Write(raw)
	fmt.Fprintln(os.Stdout)
	return 0
}

func fakeExec(dir string, args []string) int {
	var name string
	command := []string{}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--":
			command = args[i+1:]
			i = len(args)
		case "--timeout", "--rlimit", "--env", "-w", "--workdir", "-u", "--user":
			i++
		case "--no-tty", "--no-stdin":
		default:
			if !strings.HasPrefix(a, "-") {
				name = a
			}
		}
	}
	_ = command
	if _, err := os.Stat(fakeStatePath(dir, name)); err != nil {
		fmt.Fprintf(os.Stderr, "error: sandbox not found: %s\n", name)
		return 1
	}
	_ = os.WriteFile(filepath.Join(dir, name+".exec"), []byte("executed"), 0o600)
	switch mode := os.Getenv("MSB_FAKE_OUT"); mode {
	case "burst":
		n := fakeEnvInt("MSB_FAKE_BYTES", 200000)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); fakeBurst(os.Stdout, 'A', n) }()
		go func() { defer wg.Done(); fakeBurst(os.Stderr, 'B', n) }()
		wg.Wait()
	case "quiet":
	default:
		fmt.Fprintln(os.Stdout, "hello")
	}
	return fakeEnvInt("MSB_FAKE_EXIT", 0)
}

func fakeRemove(dir string, args []string) int {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		_ = os.Remove(fakeStatePath(dir, a))
		_ = os.Remove(filepath.Join(dir, a+".exec"))
		fmt.Fprintf(os.Stdout, "  ✓ Removed %s\n", a)
	}
	return 0
}

func fakeBurst(w *os.File, ch byte, n int) {
	chunk := bytes.Repeat([]byte{ch}, 4096)
	for written := 0; written < n; written += len(chunk) {
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
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

func writeFakeSandbox(t *testing.T, dir, name string, conf fakeSandboxConfig) {
	t.Helper()
	conf.Name = name
	raw, err := json.Marshal(fakeSandbox{Name: name, Status: "Running", Config: conf})
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

// ─── PR-01: bounded output collector ────────────────────────────────

// TestOutputCollectorConcurrentWriters is the deterministic PR-01
// regression: two writers race into one collector, and the digest must
// still be the SHA-256 of exactly the bytes the artifact holds. The
// original implementation shared an unsynchronized capped writer and
// hashed bytes past the cap.
func TestOutputCollectorConcurrentWriters(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "artifact")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := newOutputCollector(f, 1000)

	var wg sync.WaitGroup
	for _, ch := range []byte{'A', 'B'} {
		wg.Add(1)
		go func(ch byte) {
			defer wg.Done()
			chunk := bytes.Repeat([]byte{ch}, 64)
			for i := 0; i < 40; i++ {
				if _, err := c.Write(chunk); err != nil {
					t.Errorf("collector write: %v", err)
					return
				}
			}
		}(ch)
	}
	wg.Wait()

	written, truncated := c.stats()
	if written != 1000 {
		t.Fatalf("stored %d bytes, want the 1000-byte bound", written)
	}
	if !truncated {
		t.Fatal("truncation not reported")
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 1000 {
		t.Fatalf("artifact size %d, want 1000", info.Size())
	}
	if got := sha256File(t, f.Name()); got != c.digest() {
		t.Fatalf("collector digest %s does not match the stored bytes %s", c.digest(), got)
	}
}

func TestMSBDispatchArtifactDigestMatchesFile(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_OUT": "burst", "MSB_FAKE_BYTES": "200000"})
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(t.TempDir(), "artifacts")}
	job := testContract(t, key, func(c *JobContractV2) {
		c.JobID = "digest-1"
		c.Nonce = "n-digest"
		c.Resources.MaxOutputBytes = 64 * 1024
	})

	handle, err := backend.Dispatch(testContext(t), job)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), handle)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	data, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("artifact unreadable: %v", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != res.OutputSHA256 {
		t.Fatalf("artifact digest %s does not match the stored bytes %s", res.OutputSHA256, hex.EncodeToString(sum[:]))
	}
	if int64(len(data)) != res.OutputBytes {
		t.Fatalf("artifact size %d does not match the reported %d", len(data), res.OutputBytes)
	}
	if res.OutputBytes > 64*1024 {
		t.Fatalf("artifact exceeded the contract bound: %d bytes", res.OutputBytes)
	}
	if !res.Truncated {
		t.Fatal("concurrent burst beyond the bound must report truncation")
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code %d", res.ExitCode)
	}
}

func TestMSBDispatchKeepsSmallOutputWhole(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(t.TempDir(), "artifacts")}
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "small-1"; c.Nonce = "n-small" })

	handle, err := backend.Dispatch(testContext(t), job)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Wait(testContext(t), handle)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	data, _ := os.ReadFile(res.OutputPath)
	if string(data) != "hello\n" || res.Truncated || res.OutputBytes != 6 {
		t.Fatalf("small output mangled: %q truncated=%t bytes=%d", data, res.Truncated, res.OutputBytes)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != res.OutputSHA256 {
		t.Fatal("digest does not match the stored artifact")
	}
}

// ─── PR-02: fresh VM, exclusive creation, policy verification ───────

// TestMSBDispatchRefusesPreexistingSandbox is the sandbox-reuse
// attack: a permissive VM already exists under the deterministic
// handle. The job must refuse it — never execute inside it, never
// adopt or destroy it.
func TestMSBDispatchRefusesPreexistingSandbox(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(t.TempDir(), "artifacts")}
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "reuse-1"; c.Nonce = "n-reuse" })
	name := backend.msbJobName(job.JobID)

	permissive := fakeDefaultConfig()
	permissive.Network.Policy = fakePublicPolicy()
	permissive.Network.Policy.DefaultEgress = "allow"
	writeFakeSandbox(t, stateDir, name, permissive)

	if _, err := backend.Dispatch(testContext(t), job); err == nil {
		t.Fatal("dispatch reused a pre-existing sandbox")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, name+".exec")); err == nil {
		t.Fatal("the job executed inside the pre-existing sandbox")
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
			backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(t.TempDir(), "artifacts")}
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "verify-1"; c.Nonce = "n-verify" })
			name := backend.msbJobName(job.JobID)

			_, err := backend.Dispatch(testContext(t), job)
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
// exist), but no exec was ever spawned — so the artifact file and its
// descriptor must not survive the stalled dispatch.
func TestMSBDispatchAmbiguousCreateLeaksNothing(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, map[string]string{"MSB_FAKE_CREATE_SLEEP": "5"})
	dir := t.TempDir()
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(dir, "artifacts")}
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ambig-create"; c.Nonce = "n-ambig" })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	handle, err := backend.Dispatch(ctx, job)
	if err == nil || !errors.Is(err, ErrAmbiguousDispatch) {
		t.Fatalf("want an ambiguous dispatch, got handle=%q err=%v", handle, err)
	}
	if handle != backend.msbJobName(job.JobID) {
		t.Fatalf("ambiguous handle = %q", handle)
	}
	entries, rerr := os.ReadDir(filepath.Join(dir, "artifacts"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Fatalf("a stalled dispatch left %d artifact file(s)", len(entries))
	}
}

func TestMSBDispatchMapsContractToSandbox(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(t.TempDir(), "artifacts")}
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

	handle, err := backend.Dispatch(testContext(t), job)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The VM's live configuration is inspected while it exists —
	// Wait removes it once the result is collected.
	conf := readFakeSandbox(t, stateDir, handle).Config
	res, err := backend.Wait(testContext(t), handle)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code %d", res.ExitCode)
	}
	if conf.Resources.CPUs != 2 || conf.Resources.MemoryMiB != 512 {
		t.Fatalf("resources not mapped: %+v", conf.Resources)
	}
	if conf.Image.Oci.RootDisk.SizeMiB != 2048 {
		t.Fatalf("root disk not mapped: %+v", conf.Image.Oci.RootDisk)
	}
	if conf.Lifecycle.MaxDurationSecs == nil || *conf.Lifecycle.MaxDurationSecs != 90 {
		t.Fatalf("max duration not mapped: %+v", conf.Lifecycle)
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
	// removed once the result is collected.
	if _, err := os.Stat(fakeStatePath(stateDir, handle)); err == nil {
		t.Fatal("sandbox left behind after result collection")
	}
}

func TestMSBKeepSandboxesLeavesForensicVM(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := &MSBBackend{Bin: bin, StateDir: filepath.Join(t.TempDir(), "artifacts"), KeepSandboxes: true}
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "keep-1"; c.Nonce = "n-keep" })

	handle, err := backend.Dispatch(testContext(t), job)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if _, err := backend.Wait(testContext(t), handle); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if _, err := os.Stat(fakeStatePath(stateDir, handle)); err != nil {
		t.Fatal("KeepSandboxes did not leave the VM in place")
	}
}
