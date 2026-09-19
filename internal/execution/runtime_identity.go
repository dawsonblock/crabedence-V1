package execution

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// Runtime configuration identity.
//
// Two identities are deliberately distinct (see
// docs/architecture/capability-registry-semantics.md):
//
//   - registry_sha256 identifies the security policy a release ships:
//     the complete capability catalog, its classes, routes, assurance
//     profiles, schemas, authority policies, and adapter bindings.
//
//   - runtime_configuration_sha256 identifies the deployment state a
//     process runs in: the release, the registry it loaded, the effect
//     store backend, and the enabled adapters.
//
// Enabling an integration changes the configuration identity, never the
// policy identity. The configuration structure has no field for
// credentials — API keys, passwords, OAuth tokens, cookies, private
// keys, database credentials, and raw environment variables are
// excluded by construction, not by filtering. Values recorded here are
// normalized identities ("postgres", "github"), never raw configuration.

// RuntimeConfiguration is the safe, normalized deployment identity the
// runtime configuration digest covers.
type RuntimeConfiguration struct {
	// SchemaVersion versions the identity document itself.
	SchemaVersion int `json:"schema_version"`

	// Release is the release identity (e.g. "0.52.0-rc.1"); "dev" or
	// empty for unreleased builds.
	Release string `json:"release,omitempty"`

	// RegistrySHA256 is the capability registry digest this process
	// serves.
	RegistrySHA256 string `json:"registry_sha256"`

	// EffectStore is the selected durable store backend: "postgres",
	// "sqlite", or "none".
	EffectStore string `json:"effect_store"`

	// EnabledAdapters is the sorted set of adapter IDs this deployment
	// wired. It is a set of identities — never credentials.
	EnabledAdapters []string `json:"enabled_adapters"`
}

// RuntimeIdentityEnvelope is the verifiable runtime identity export: the
// digest plus the exact canonical bytes it covers, base64-encoded —
// the same idiom as the capability registry envelope, so a consumer
// verifies SHA-256 over the bytes it was given before parsing them.
type RuntimeIdentityEnvelope struct {
	// RuntimeConfigurationSHA256 is the SHA-256 of CanonicalPayload's
	// decoded bytes.
	RuntimeConfigurationSHA256 string `json:"runtime_configuration_sha256"`
	// CanonicalPayload is base64 of the canonical configuration JSON.
	CanonicalPayload string `json:"canonical_payload"`
}

// CanonicalRuntimeConfiguration returns the exact canonical bytes the
// runtime configuration digest covers: schema version defaulted,
// adapters sorted and de-duplicated.
func CanonicalRuntimeConfiguration(cfg RuntimeConfiguration) ([]byte, error) {
	if cfg.SchemaVersion == 0 {
		cfg.SchemaVersion = 1
	}
	seen := make(map[string]bool, len(cfg.EnabledAdapters))
	adapters := make([]string, 0, len(cfg.EnabledAdapters))
	for _, adapter := range cfg.EnabledAdapters {
		if adapter == "" || seen[adapter] {
			continue
		}
		seen[adapter] = true
		adapters = append(adapters, adapter)
	}
	sort.Strings(adapters)
	cfg.EnabledAdapters = adapters

	canonical, err := idempotency.CanonicalJSON(cfg)
	if err != nil {
		return nil, fmt.Errorf("canonicalize runtime configuration: %w", err)
	}
	return []byte(canonical), nil
}

// RuntimeConfigurationDigest returns the SHA-256 of the canonical
// runtime configuration.
func RuntimeConfigurationDigest(cfg RuntimeConfiguration) (string, error) {
	canonical, err := CanonicalRuntimeConfiguration(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// RuntimeIdentityEnvelopeFor returns the verifiable runtime identity
// export for a configuration.
func RuntimeIdentityEnvelopeFor(cfg RuntimeConfiguration) (RuntimeIdentityEnvelope, error) {
	canonical, err := CanonicalRuntimeConfiguration(cfg)
	if err != nil {
		return RuntimeIdentityEnvelope{}, err
	}
	sum := sha256.Sum256(canonical)
	return RuntimeIdentityEnvelope{
		RuntimeConfigurationSHA256: hex.EncodeToString(sum[:]),
		CanonicalPayload:           base64.StdEncoding.EncodeToString(canonical),
	}, nil
}

// JSON returns the canonical envelope bytes.
func (e RuntimeIdentityEnvelope) JSON() ([]byte, error) {
	canonical, err := idempotency.CanonicalJSON(e)
	if err != nil {
		return nil, fmt.Errorf("canonicalize runtime identity envelope: %w", err)
	}
	return []byte(canonical), nil
}
