// Package evidence provides Ed25519-signed V3 effect receipts for the
// Effect Fabric durable execution contract.
//
// A ReceiptV3 binds a terminal outcome to:
//   - the execution identity (execution_id, capability, principal,
//     request_digest)
//   - the provider operation identity (provider_id, provider_run_id)
//   - the evidence artifact digest (evidence_sha256)
//
// The SHA-256 evidence digest is an integrity checksum. Authenticity
// comes from the Ed25519 signature over the canonical signing payload —
// the same construction used by the CLI's terminal run receipts
// (internal/cli/attest.go). A syntactically valid digest alone is not
// proof; the store rejects CRITICAL terminal transitions unless a
// signed receipt from a trusted signer verifies against the record.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReceiptV3SchemaVersion is the only accepted schema version.
const ReceiptV3SchemaVersion = 3

// ReceiptType identifies the effect-fabric terminal evidence receipt.
const ReceiptType = "crabedence-effect-receipt"

// signingDomain is the domain-separation prefix for the signing payload.
const signingDomain = "crabedence-effect-receipt-v3\x00"

// Outcome vocabulary — the semantic verdict the signer attests to about
// the external world, deliberately distinct from durable state names.
const (
	// OutcomeCompleted attests the external effect occurred. Required
	// for COMMITTED terminal transitions.
	OutcomeCompleted = "COMPLETED"
	// OutcomeNoEffect attests the external effect provably did not
	// occur. Required for FAILED terminal transitions — including
	// definitive provider failures and no-effect recovery proofs.
	OutcomeNoEffect = "NO_EFFECT"
)

// ReceiptV3 is the signed effect-fabric terminal evidence receipt.
type ReceiptV3 struct {
	SchemaVersion  int    `json:"schema_version"`
	ReceiptType    string `json:"receipt_type"`
	ExecutionID    string `json:"execution_id"`
	Capability     string `json:"capability"`
	Principal      string `json:"principal"`
	RequestDigest  string `json:"request_digest"`
	ProviderID     string `json:"provider_id"`
	ProviderRunID  string `json:"provider_run_id"`
	Outcome        string `json:"outcome"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	IssuedAt       string `json:"issued_at"`
	PublicKey      string `json:"public_key"`
	Signer         string `json:"signer"`
	Signature      string `json:"signature"`
}

// Binding is the authoritative record context a receipt must match.
// Every field is compared for equality — a receipt that binds to a
// different execution, request, provider, or outcome is rejected.
type Binding struct {
	ExecutionID    string
	Capability     string
	Principal      string
	RequestDigest  string
	ProviderID     string
	ProviderRunID  string
	Outcome        string // OutcomeCompleted or OutcomeNoEffect
	EvidenceSHA256 string
}

// Signer produces signed ReceiptV3 receipts with a single Ed25519 key.
type Signer struct {
	key ed25519.PrivateKey
}

// NewSigner wraps an Ed25519 private key as a receipt signer.
func NewSigner(key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key")
	}
	return &Signer{key: key}, nil
}

// GenerateSigner creates a signer with a freshly generated key.
func GenerateSigner() (*Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key}, nil
}

// Fingerprint returns the signer's public-key fingerprint
// (lowercase hex SHA-256 of the raw public key).
func (s *Signer) Fingerprint() string {
	return Fingerprint(s.key.Public().(ed25519.PublicKey))
}

// Fingerprint computes the signer fingerprint for a public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// PublicKey returns the signer's Ed25519 public key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// Sign produces a signed ReceiptV3 attesting to the given binding.
// The returned receipt is serialized to canonical JSON for storage.
func (s *Signer) Sign(b Binding) (json.RawMessage, error) {
	pub := s.key.Public().(ed25519.PublicKey)
	r := ReceiptV3{
		SchemaVersion:  ReceiptV3SchemaVersion,
		ReceiptType:    ReceiptType,
		ExecutionID:    b.ExecutionID,
		Capability:     b.Capability,
		Principal:      b.Principal,
		RequestDigest:  b.RequestDigest,
		ProviderID:     b.ProviderID,
		ProviderRunID:  b.ProviderRunID,
		Outcome:        b.Outcome,
		EvidenceSHA256: b.EvidenceSHA256,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey:      base64.StdEncoding.EncodeToString(pub),
		Signer:         Fingerprint(pub),
	}
	if err := validateFields(r); err != nil {
		return nil, err
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, signingBytes(r)))
	return json.Marshal(r)
}

// signingBytes builds the canonical signing payload: a domain-separation
// prefix followed by length-prefixed field values. This matches the
// construction used by the CLI's terminal run receipts.
func signingBytes(r ReceiptV3) []byte {
	values := []string{
		r.ExecutionID,
		r.Capability,
		r.Principal,
		r.RequestDigest,
		r.ProviderID,
		r.ProviderRunID,
		r.Outcome,
		r.EvidenceSHA256,
		r.IssuedAt,
		r.PublicKey,
		r.Signer,
	}
	var payload bytes.Buffer
	payload.WriteString(signingDomain)
	var length [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		payload.Write(length[:])
		payload.WriteString(value)
	}
	return payload.Bytes()
}

func validateFields(r ReceiptV3) error {
	if r.ReceiptType != ReceiptType {
		return fmt.Errorf("unsupported receipt_type %q", r.ReceiptType)
	}
	if r.SchemaVersion != ReceiptV3SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", r.SchemaVersion)
	}
	for name, value := range map[string]string{
		"execution_id":    r.ExecutionID,
		"capability":      r.Capability,
		"principal":       r.Principal,
		"request_digest":  r.RequestDigest,
		"provider_id":     r.ProviderID,
		"provider_run_id": r.ProviderRunID,
		"public_key":      r.PublicKey,
		"signer":          r.Signer,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("invalid %s", name)
		}
	}
	switch r.Outcome {
	case OutcomeCompleted, OutcomeNoEffect:
	default:
		return fmt.Errorf("invalid outcome %q", r.Outcome)
	}
	if !isHexDigest(r.EvidenceSHA256) {
		return fmt.Errorf("invalid evidence_sha256")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.IssuedAt); err != nil {
		return fmt.Errorf("invalid issued_at")
	}
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public_key")
	}
	if r.Signer != Fingerprint(ed25519.PublicKey(pub)) {
		return fmt.Errorf("signer does not match public_key")
	}
	if r.Signature != "" {
		sig, err := base64.StdEncoding.DecodeString(r.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("invalid signature")
		}
	}
	return nil
}

// ParseReceipt decodes a serialized ReceiptV3 with strict JSON handling:
// unknown fields rejected, duplicate keys rejected, single JSON value.
func ParseReceipt(data json.RawMessage) (ReceiptV3, error) {
	var r ReceiptV3
	if len(data) == 0 {
		return r, fmt.Errorf("missing evidence receipt")
	}
	if len(data) > 64*1024 {
		return r, fmt.Errorf("evidence receipt exceeds 64KiB")
	}
	if duplicate, err := hasDuplicateKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return r, err
	} else if duplicate {
		return r, fmt.Errorf("evidence receipt contains duplicate keys")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return r, fmt.Errorf("multiple JSON values")
		}
		return r, err
	}
	return r, nil
}

// VerifySignature validates the receipt structure and verifies the
// Ed25519 signature over the canonical signing payload. It does NOT
// check trust or binding — callers must also check VerifyBinding and
// signer trust.
func VerifySignature(r ReceiptV3) error {
	if err := validateFields(r); err != nil {
		return err
	}
	if r.Signature == "" {
		return fmt.Errorf("missing signature")
	}
	pub, _ := base64.StdEncoding.DecodeString(r.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(r.Signature)
	if !ed25519.Verify(ed25519.PublicKey(pub), signingBytes(r), sig) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// VerifyReceipt parses, validates, and verifies a serialized receipt
// against a binding and a set of trusted signer fingerprints. Every
// binding field must match the receipt exactly. The receipt's signer
// fingerprint must be in trustedSigners — an empty set fails closed.
func VerifyReceipt(data json.RawMessage, binding Binding, trustedSigners map[string]bool) error {
	r, err := ParseReceipt(data)
	if err != nil {
		return err
	}
	if err := VerifySignature(r); err != nil {
		return err
	}
	if len(trustedSigners) == 0 {
		return fmt.Errorf("no trusted evidence signers configured")
	}
	if !trustedSigners[r.Signer] {
		return fmt.Errorf("evidence receipt signer %s is not trusted", r.Signer)
	}
	if r.ExecutionID != binding.ExecutionID ||
		r.Capability != binding.Capability ||
		r.Principal != binding.Principal ||
		r.RequestDigest != binding.RequestDigest ||
		r.ProviderID != binding.ProviderID ||
		r.ProviderRunID != binding.ProviderRunID ||
		r.Outcome != binding.Outcome ||
		r.EvidenceSHA256 != binding.EvidenceSHA256 {
		return fmt.Errorf("evidence receipt binding mismatch")
	}
	return nil
}

func isHexDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// hasDuplicateKeys reports whether the top-level JSON object contains
// duplicate keys.
func hasDuplicateKeys(dec *json.Decoder) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return false, fmt.Errorf("evidence receipt must be a JSON object")
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

// ─── Key persistence ─────────────────────────────────────────────────

// LoadOrCreateSigner loads an Ed25519 signer from a PKCS8 PEM file,
// generating and persisting a new key (mode 0600, parent dir 0700)
// when the file does not exist.
func LoadOrCreateSigner(path string) (*Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		// A private key that is group/other-accessible may have been
		// copied — tighten it before trusting it. Fail closed if the
		// permissions cannot be corrected.
		if info, serr := os.Stat(path); serr == nil && info.Mode().Perm()&0o077 != 0 {
			if cerr := os.Chmod(path, 0o600); cerr != nil {
				return nil, fmt.Errorf("evidence key %s has permissive mode %04o and cannot be tightened: %w",
					path, info.Mode().Perm(), cerr)
			}
		}
		return ParseSignerPEM(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	signer, err := GenerateSigner()
	if err != nil {
		return nil, err
	}
	encoded, err := signer.MarshalPEM()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL avoids clobbering a key created concurrently.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil, rerr
			}
			return ParseSignerPEM(data)
		}
		return nil, err
	}
	if _, err := f.Write(encoded); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return signer, nil
}

// MarshalPEM encodes the signer's private key as PKCS8 PEM — the same
// format used by the CLI attest key (~/.config/crabbox/attest/), so a
// single key can serve both the CLI and the execution service.
func (s *Signer) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(s.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseSignerPEM parses a PKCS8 "PRIVATE KEY" PEM block.
func ParseSignerPEM(data []byte) (*Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("evidence signer key is not PEM encoded")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("evidence signer key is not a PKCS8 private key")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("evidence signer key has trailing data")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("evidence signer key is not an ed25519 key")
	}
	return NewSigner(ed)
}
