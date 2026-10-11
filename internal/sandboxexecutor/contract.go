package sandboxexecutor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// contractSigningDomain separates executor job signatures from every
// other Ed25519 payload in the system — a signature minted for
// evidence receipts or release records can never be replayed as a job
// contract, and vice versa. The v2 domain also separates V2 contracts
// from every V1 signature ever minted: a V1 contract can never be
// replayed as V2, and vice versa.
const contractSigningDomain = "crabedence.sandbox-job.v2\x00"

// ContractVersion is the only job contract shape this executor
// honors. A contract that does not declare it is malformed, not
// "probably v1" — V1 contracts refused because they cannot pin an
// immutable image digest or a security profile, so honoring one would
// silently widen the policy the authority signed.
const ContractVersion = 2

// Sanity ceilings on contract fields. They catch malformed input —
// they are not the resource policy. The operator's configured
// ceilings (Config.ResourceCeiling) are the real bound, enforced at
// admission so a contract can never widen what the executor will
// launch beyond what the operator permitted.
const (
	maxContractJobIDBytes   = 256
	maxContractNonceBytes   = 128
	maxContractArgv         = 512
	maxContractArgBytes     = 4096
	maxContractEnv          = 128
	maxContractEnvBytes     = 4096
	maxContractMounts       = 32
	maxContractPathBytes    = 4096
	maxContractImageBytes   = 1024
	maxContractNetAllow     = 64
	maxContractCPUs         = 64
	maxContractMemoryMB     = 64 * 1024
	maxContractDiskMB       = 1 << 20
	maxContractTimeoutSecs  = 24 * 60 * 60
	maxContractOutputBytes  = 1 << 30
	contractClockSkewLeeway = 60 * time.Second
)

// Security profiles a contract may select. The profile is part of the
// signed policy — the backend passes it to the VM and verifies the
// booted sandbox carries it, so "the backend's default" is never
// silently substituted for what the authority approved.
const (
	SecurityDefault    = "default"
	SecurityRestricted = "restricted"
)

// Network modes a contract may select. Anything else is refused:
// "the contract forgot a network policy" is never silently permissive.
const (
	// NetworkNone gives the guest no reachability — the only mode an
	// executor should treat as safe by default.
	NetworkNone = "none"
	// NetworkAllowlist restricts egress to the contract's allow
	// entries (mapped onto backend net-rules).
	NetworkAllowlist = "allowlist"
	// NetworkPublic delegates to the backend's public egress policy.
	// An authority must say so explicitly; it is never implied.
	NetworkPublic = "public"
)

// ResourceBudget is the authority-approved upper bound on what one
// job may consume. Zero-valued optional fields mean "backend default"
// — the contract binds what it declares, and the executor enforces
// configured ceilings on top.
type ResourceBudget struct {
	// TimeoutSeconds bounds wall-clock execution. Required: an
	// unbounded job is an unbounded VM. It is also the VM's own
	// --max-duration, so an abandoned sandbox cannot outlive it.
	TimeoutSeconds uint32  `json:"timeout_seconds"`
	CPUs           float64 `json:"cpus,omitempty"`
	MemoryMB       uint64  `json:"memory_mb,omitempty"`
	Pids           uint32  `json:"pids,omitempty"`
	DiskMB         uint64  `json:"disk_mb,omitempty"`
	MaxOutputBytes uint64  `json:"max_output_bytes,omitempty"`
}

// Mount is one authority-approved host-to-guest mapping. The executor
// does not arbitrate whether the source is safe — that is the
// authority's signature — but it refuses structurally unusable mounts.
type Mount struct {
	Source  string `json:"source"`
	Dest    string `json:"dest"`
	Options string `json:"options,omitempty"`
}

// FilesystemPolicy declares the guest's filesystem shape.
type FilesystemPolicy struct {
	Workdir string  `json:"workdir,omitempty"`
	Mounts  []Mount `json:"mounts,omitempty"`
}

// NetworkPolicy declares the guest's reachability.
type NetworkPolicy struct {
	Mode  string   `json:"mode"`
	Allow []string `json:"allow,omitempty"`
}

// JobContractV2 is the signed unit of execution authority. The
// signature covers every field below — the image and its immutable
// digest, the exact argv, the environment, the filesystem, network
// and security policy, the resource budget, the validity window, and
// the replay nonce. Anything the signature does not cover, the
// executor does not honor.
type JobContractV2 struct {
	Version   int    `json:"version"`
	JobID     string `json:"job_id"`
	Principal string `json:"principal"`
	Submitter string `json:"submitter,omitempty"`
	Image     string `json:"image"`
	// ImageDigest pins the exact image the authority approved
	// ("sha256:<64 hex>"). The backend boots this digest and refuses
	// a VM whose manifest digest differs — a mutable tag can never
	// silently become the execution environment.
	ImageDigest string   `json:"image_digest"`
	Argv        []string `json:"argv"`
	// Env is the complete guest environment allowlist (KEY=VALUE).
	// The authority controls it — a submitter cannot add secrets the
	// contract did not name.
	Env        []string         `json:"env,omitempty"`
	Resources  ResourceBudget   `json:"resources"`
	Network    NetworkPolicy    `json:"network"`
	Filesystem FilesystemPolicy `json:"filesystem"`
	// Security is the in-guest security profile ("default" or
	// "restricted"). Required and signed: the backend passes it to
	// the VM and verifies it, so the profile is never implied.
	Security string `json:"security"`
	// IssuedAt/ExpiresAt bound the contract's validity window in
	// unix seconds. Expired or not-yet-valid contracts refuse.
	IssuedAt  int64 `json:"issued_at"`
	ExpiresAt int64 `json:"expires_at"`
	// Nonce makes every contract unique even across reissues of an
	// identical job; the ledger refuses a repeated contract hash.
	Nonce string `json:"nonce"`
	// Authority is the signer's public-key fingerprint (lowercase
	// hex SHA-256 of the raw key) — it selects the verification key
	// from the executor's configured set, so a foreign signature
	// fails closed instead of finding another key.
	Authority string `json:"authority"`
}

// ContractEnvelope carries a contract plus its detached Ed25519
// signature on the wire. The verification key is never taken from the
// envelope — that would let a forger supply their own key. The
// contract's Authority field selects from keys the operator
// configured.
type ContractEnvelope struct {
	Contract  json.RawMessage `json:"contract"`
	Signature string          `json:"signature"`
}

// contractSigningBytes builds the canonical signing payload: the
// domain prefix followed by length-prefixed field values in a fixed
// order — the same construction as evidence receipts, so signature
// verification never depends on JSON serialization details.
func contractSigningBytes(c *JobContractV2) []byte {
	var payload bytes.Buffer
	payload.WriteString(contractSigningDomain)
	var length [4]byte
	putString := func(s string) {
		binary.BigEndian.PutUint32(length[:], uint32(len(s)))
		payload.Write(length[:])
		payload.WriteString(s)
	}
	putBytes := func(b []byte) {
		binary.BigEndian.PutUint32(length[:], uint32(len(b)))
		payload.Write(length[:])
		payload.Write(b)
	}
	putInt := func(v int64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		payload.Write(b[:])
	}
	putStrings := func(ss []string) {
		putInt(int64(len(ss)))
		for _, s := range ss {
			putString(s)
		}
	}
	// Sub-structures sign their canonical struct encoding — Go
	// marshals struct fields in declaration order, so this is
	// deterministic for a fixed field set.
	putJSON := func(v any) {
		b, _ := json.Marshal(v)
		putBytes(b)
	}

	putInt(int64(c.Version))
	putString(c.JobID)
	putString(c.Principal)
	putString(c.Submitter)
	putString(c.Image)
	putString(c.ImageDigest)
	putStrings(c.Argv)
	putStrings(c.Env)
	putJSON(c.Resources)
	putJSON(c.Network)
	putJSON(c.Filesystem)
	putString(c.Security)
	putInt(c.IssuedAt)
	putInt(c.ExpiresAt)
	putString(c.Nonce)
	putString(c.Authority)
	return payload.Bytes()
}

// ContractHash is the stable content identity of a contract — what
// the ledger indexes to refuse replays and what execution evidence
// binds to.
func ContractHash(c *JobContractV2) string {
	sum := sha256.Sum256(contractSigningBytes(c))
	return hex.EncodeToString(sum[:])
}

// SignContract produces the wire envelope for a validated contract.
// The contract's Authority field must already name this key's
// fingerprint — a signer refuses to attest a contract that names a
// different authority.
func SignContract(key ed25519.PrivateKey, c *JobContractV2) (*ContractEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	fp := AuthorityFingerprint(pub)
	if c.Authority != fp {
		return nil, fmt.Errorf("contract authority %q does not match signer fingerprint %q", c.Authority, fp)
	}
	if err := c.ValidateStructure(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &ContractEnvelope{
		Contract:  raw,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, contractSigningBytes(c))),
	}, nil
}

// AuthorityFingerprint derives the key identity the contract's
// Authority field names — identical construction to the evidence
// signer's fingerprint.
func AuthorityFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// ParseContract decodes the contract half of an envelope with strict
// JSON handling: bounded size, single object, duplicate keys refused,
// unknown fields refused. A contract that hides fields from the
// verifier is a forgery surface.
func ParseContract(data json.RawMessage) (*JobContractV2, error) {
	var c JobContractV2
	if len(data) == 0 {
		return nil, fmt.Errorf("missing job contract")
	}
	if len(data) > 64*1024 {
		return nil, fmt.Errorf("job contract exceeds 64KiB")
	}
	if duplicate, err := hasDuplicateKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return nil, err
	} else if duplicate {
		return nil, fmt.Errorf("job contract contains duplicate keys")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("malformed job contract: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("job contract contains multiple JSON values")
		}
		return nil, fmt.Errorf("malformed job contract: %w", err)
	}
	return &c, nil
}

// ValidateStructure checks every field the executor's own integrity
// requires — before the signature is even consulted. It cannot prove
// authority (the signature does that) but it refuses contracts that
// could never be honored.
func (c *JobContractV2) ValidateStructure() error {
	if c == nil {
		return fmt.Errorf("missing job contract")
	}
	if c.Version != ContractVersion {
		return fmt.Errorf("unsupported contract version %d", c.Version)
	}
	if !isJobID(c.JobID) {
		return fmt.Errorf("job_id must be 1-%d bytes of [A-Za-z0-9._-] starting alphanumeric — it names backend objects and labels", maxContractJobIDBytes)
	}
	if strings.TrimSpace(c.Principal) == "" {
		return fmt.Errorf("principal is required")
	}
	if strings.TrimSpace(c.Image) == "" {
		return fmt.Errorf("image is required")
	}
	if len(c.Image) > maxContractImageBytes {
		return fmt.Errorf("image exceeds %d bytes", maxContractImageBytes)
	}
	if strings.ContainsAny(c.Image, "@\x00 \t\n") {
		return fmt.Errorf("image must be a bare repository reference — pin the digest in image_digest, not in the image string")
	}
	if !isSHA256Digest(c.ImageDigest) {
		return fmt.Errorf("image_digest must be a lowercase sha256:<64 hex> digest — an unpinned image is a mutable execution environment")
	}
	switch c.Security {
	case SecurityDefault, SecurityRestricted:
	default:
		return fmt.Errorf("security must be %q or %q", SecurityDefault, SecurityRestricted)
	}
	if len(c.Argv) == 0 {
		return fmt.Errorf("argv is required")
	}
	if len(c.Argv) > maxContractArgv {
		return fmt.Errorf("argv exceeds %d entries", maxContractArgv)
	}
	for i, arg := range c.Argv {
		if len(arg) > maxContractArgBytes {
			return fmt.Errorf("argv[%d] exceeds %d bytes", i, maxContractArgBytes)
		}
	}
	if len(c.Env) > maxContractEnv {
		return fmt.Errorf("env exceeds %d entries", maxContractEnv)
	}
	seenEnv := map[string]bool{}
	for i, kv := range c.Env {
		if len(kv) > maxContractEnvBytes {
			return fmt.Errorf("env[%d] exceeds %d bytes", i, maxContractEnvBytes)
		}
		key, _, found := strings.Cut(kv, "=")
		if !found || strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\x00=") {
			return fmt.Errorf("env[%d] is not KEY=VALUE", i)
		}
		if seenEnv[key] {
			return fmt.Errorf("env[%d] duplicates key %q", i, key)
		}
		seenEnv[key] = true
	}
	if c.Resources.TimeoutSeconds == 0 {
		return fmt.Errorf("resources.timeout_seconds is required — an unbounded job is an unbounded VM")
	}
	if c.Resources.TimeoutSeconds > maxContractTimeoutSecs {
		return fmt.Errorf("resources.timeout_seconds exceeds %d", maxContractTimeoutSecs)
	}
	if c.Resources.CPUs < 0 || c.Resources.CPUs > maxContractCPUs {
		return fmt.Errorf("resources.cpus out of range (0..%d)", maxContractCPUs)
	}
	if c.Resources.MemoryMB > maxContractMemoryMB {
		return fmt.Errorf("resources.memory_mb exceeds %d", maxContractMemoryMB)
	}
	if c.Resources.DiskMB > maxContractDiskMB {
		return fmt.Errorf("resources.disk_mb exceeds %d", maxContractDiskMB)
	}
	if c.Resources.MaxOutputBytes > maxContractOutputBytes {
		return fmt.Errorf("resources.max_output_bytes exceeds %d", maxContractOutputBytes)
	}
	switch c.Network.Mode {
	case NetworkNone:
		if len(c.Network.Allow) != 0 {
			return fmt.Errorf("network mode %q must not carry an allow list", NetworkNone)
		}
	case NetworkAllowlist:
		if len(c.Network.Allow) == 0 {
			return fmt.Errorf("network mode %q requires at least one allow entry", NetworkAllowlist)
		}
	case NetworkPublic:
		// Explicitly authorized open egress — allowed, and audited.
	default:
		return fmt.Errorf("unsupported network mode %q", c.Network.Mode)
	}
	if len(c.Network.Allow) > maxContractNetAllow {
		return fmt.Errorf("network allow list exceeds %d entries", maxContractNetAllow)
	}
	seenAllow := map[string]bool{}
	for i, a := range c.Network.Allow {
		if !isDomainPattern(a) {
			return fmt.Errorf("network allow[%d] %q must be a lowercase domain or *.domain pattern", i, a)
		}
		if seenAllow[a] {
			return fmt.Errorf("network allow[%d] duplicates %q", i, a)
		}
		seenAllow[a] = true
	}
	if len(c.Filesystem.Mounts) > maxContractMounts {
		return fmt.Errorf("filesystem mounts exceed %d entries", maxContractMounts)
	}
	seenDest := map[string]bool{}
	for i, m := range c.Filesystem.Mounts {
		if len(m.Source) == 0 || len(m.Source) > maxContractPathBytes {
			return fmt.Errorf("mount[%d] source is required and must be ≤ %d bytes", i, maxContractPathBytes)
		}
		if len(m.Dest) == 0 || len(m.Dest) > maxContractPathBytes {
			return fmt.Errorf("mount[%d] dest is required and must be ≤ %d bytes", i, maxContractPathBytes)
		}
		if !strings.HasPrefix(m.Dest, "/") || strings.Contains(m.Dest, "..") {
			return fmt.Errorf("mount[%d] dest %q must be an absolute path without '..'", i, m.Dest)
		}
		if strings.ContainsAny(m.Source+m.Options, "\x00,") {
			return fmt.Errorf("mount[%d] fields must not contain NUL or ','", i)
		}
		if seenDest[m.Dest] {
			return fmt.Errorf("mount[%d] duplicates dest %q", i, m.Dest)
		}
		seenDest[m.Dest] = true
	}
	if c.Filesystem.Workdir != "" && !strings.HasPrefix(c.Filesystem.Workdir, "/") {
		return fmt.Errorf("filesystem workdir must be absolute")
	}
	if c.IssuedAt <= 0 {
		return fmt.Errorf("issued_at is required")
	}
	if c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("expires_at must be after issued_at")
	}
	if strings.TrimSpace(c.Nonce) == "" {
		return fmt.Errorf("nonce is required")
	}
	if len(c.Nonce) > maxContractNonceBytes {
		return fmt.Errorf("nonce exceeds %d bytes", maxContractNonceBytes)
	}
	if !isHexFingerprint(c.Authority) {
		return fmt.Errorf("authority must be a lowercase hex public-key fingerprint")
	}
	return nil
}

// VerifyContract performs full admission verification of a signed
// contract at wall time `now`:
//
//  1. structural validity (can the executor honor this shape at all)
//  2. signer trust — the contract's authority fingerprint must name a
//     configured key; an empty trust set fails closed
//  3. the Ed25519 signature over the canonical payload
//  4. the validity window — not-yet-valid and expired contracts refuse
//  5. submitter binding — a contract that names a submitter only runs
//     for that authenticated peer
//
// keys is the configured authority set (fingerprint → public key).
// maxTTL bounds expires_at-issued_at; zero disables the bound.
func VerifyContract(env *ContractEnvelope, keys map[string]ed25519.PublicKey, submitter string, now time.Time, maxTTL time.Duration) (*JobContractV2, error) {
	if env == nil {
		return nil, fmt.Errorf("missing signed job")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid contract signature")
	}
	c, err := ParseContract(env.Contract)
	if err != nil {
		return nil, err
	}
	if err := c.ValidateStructure(); err != nil {
		return nil, err
	}
	pub, ok := keys[c.Authority]
	if !ok {
		return nil, fmt.Errorf("contract authority %q is not a configured signer", c.Authority)
	}
	if !ed25519.Verify(pub, contractSigningBytes(c), sig) {
		return nil, fmt.Errorf("contract signature mismatch")
	}
	if now.Unix() < c.IssuedAt-int64(contractClockSkewLeeway/time.Second) {
		return nil, fmt.Errorf("contract is not yet valid (issued_at %d)", c.IssuedAt)
	}
	if now.Unix() >= c.ExpiresAt {
		return nil, fmt.Errorf("contract expired at %d", c.ExpiresAt)
	}
	if maxTTL > 0 && time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > maxTTL {
		return nil, fmt.Errorf("contract lifetime exceeds the %s bound", maxTTL)
	}
	if c.Submitter != "" && c.Submitter != submitter {
		return nil, fmt.Errorf("contract is bound to submitter %q, not %q", c.Submitter, submitter)
	}
	return c, nil
}

// isHexFingerprint reports whether s is a lowercase 64-hex fingerprint.
func isHexFingerprint(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

// isJobID bounds job identities to a charset that is safe as a
// backend object name, a sandbox label value and an artifact
// filename: [A-Za-z0-9._-], starting alphanumeric.
func isJobID(s string) bool {
	if len(s) == 0 || len(s) > maxContractJobIDBytes {
		return false
	}
	for i, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case (ch == '.' || ch == '_' || ch == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// isSHA256Digest reports whether s is a lowercase "sha256:<64 hex>"
// image digest.
func isSHA256Digest(s string) bool {
	rest, ok := strings.CutPrefix(s, "sha256:")
	return ok && isHexFingerprint(rest)
}

// isDomainPattern reports whether s is a lowercase DNS name or
// "*.name" wildcard — the only allowlist targets the backend can map
// onto an msb rule and verify byte-for-byte after boot.
func isDomainPattern(s string) bool {
	rest, ok := strings.CutPrefix(s, "*.")
	if ok {
		s = rest
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, ch := range label {
			switch {
			case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			case ch == '-' && i > 0 && i < len(label)-1:
			default:
				return false
			}
		}
	}
	return true
}

// hasDuplicateKeys reports whether the top-level JSON object contains
// duplicate keys — same construction as the evidence receipt parser.
func hasDuplicateKeys(dec *json.Decoder) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return false, fmt.Errorf("job contract must be a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return false, err
		}
		key := keyTok.(string)
		if seen[key] {
			return true, nil
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return false, err
		}
	}
	return false, nil
}
