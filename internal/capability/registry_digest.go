package capability

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// Registry identity and invariant scan.
//
// The registry digest is the stable identity of the exact capability
// policy set: descriptors sorted by ID, each canonicalized (sorted
// object keys, canonical numbers) through the same numeric
// normalization the request digest uses. Two registries with different
// policy produce different digests even when every individual
// descriptor is valid, so the digest is what a release qualifies and
// what runtime identity reports.

// canonicalDescriptor is the digest projection of a resolved
// descriptor. Schema is carried as its normalized parsed form so key
// order and numeric spelling cannot change the digest.
type canonicalDescriptor struct {
	ID                string           `json:"id"`
	DescriptorVersion int              `json:"descriptor_version"`
	PolicyRevision    string           `json:"policy_revision,omitempty"`
	ExecutionClass    ExecutionClass   `json:"execution_class"`
	AssuranceProfile  AssuranceProfile `json:"assurance_profile"`
	ExecutionRoute    ExecutionRoute   `json:"execution_route"`
	Schema            any              `json:"schema,omitempty"`
	AuthorityPolicy   AuthorityPolicy  `json:"authority_policy"`
	AdapterID         string           `json:"adapter_id"`
}

// Snapshot is the machine-readable registry export consumed by
// planner-side runtimes (NEMO). It carries the registry digest and the
// canonical descriptor projection — the same bytes the digest covers —
// so a planner can route on trusted descriptors instead of maintaining
// its own capability catalog.
type Snapshot struct {
	RegistrySHA256 string                `json:"registry_sha256"`
	Descriptors    []canonicalDescriptor `json:"descriptors"`
}

// Snapshot returns the canonical registry export.
func (r *Registry) Snapshot() (Snapshot, error) {
	digest, err := r.Digest()
	if err != nil {
		return Snapshot{}, err
	}

	r.mu.RLock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	descriptors := make([]canonicalDescriptor, 0, len(ids))
	for _, id := range ids {
		descriptor, err := canonicalDescriptorOf(r.entries[id])
		if err != nil {
			r.mu.RUnlock()
			return Snapshot{}, err
		}
		descriptors = append(descriptors, descriptor)
	}
	r.mu.RUnlock()

	return Snapshot{RegistrySHA256: digest, Descriptors: descriptors}, nil
}

// JSON returns the canonical snapshot bytes.
func (s Snapshot) JSON() ([]byte, error) {
	canonical, err := idempotency.CanonicalJSON(s)
	if err != nil {
		return nil, fmt.Errorf("canonicalize capability registry snapshot: %w", err)
	}
	return []byte(canonical), nil
}

// SnapshotEnvelope is the verifiable registry export: the digest plus
// the exact canonical bytes it covers, base64-encoded.
//
// The canonical bytes travel WITH the digest so a consumer never has to
// reproduce Go's canonicalization — it verifies SHA-256 over the bytes
// it was given and only then parses them. That removes the entire class
// of cross-language canonicalization mismatches (number representation,
// key order, escaping) from the trust boundary: a consumer that cannot
// reproduce the bytes byte-for-byte still verifies them cryptographically.
type SnapshotEnvelope struct {
	// RegistrySHA256 is the SHA-256 of CanonicalPayload's decoded bytes.
	RegistrySHA256 string `json:"registry_sha256"`
	// CanonicalPayload is base64 of the canonical descriptor array.
	CanonicalPayload string `json:"canonical_payload"`
}

// Envelope returns the verifiable registry export.
func (r *Registry) Envelope() (SnapshotEnvelope, error) {
	canonical, err := r.canonicalDescriptorBytes()
	if err != nil {
		return SnapshotEnvelope{}, err
	}
	sum := sha256.Sum256(canonical)
	return SnapshotEnvelope{
		RegistrySHA256:   hex.EncodeToString(sum[:]),
		CanonicalPayload: base64.StdEncoding.EncodeToString(canonical),
	}, nil
}

// JSON returns the canonical envelope bytes.
func (e SnapshotEnvelope) JSON() ([]byte, error) {
	canonical, err := idempotency.CanonicalJSON(e)
	if err != nil {
		return nil, fmt.Errorf("canonicalize capability registry envelope: %w", err)
	}
	return []byte(canonical), nil
}

// DescriptorDigest returns the canonical SHA-256 digest of this
// resolved descriptor — the capability policy identity bound into
// every request digest. A policy change (schema, class, assurance,
// route, authority policy, adapter, declared version) changes this
// digest.
func (d ResolvedDescriptor) DescriptorDigest() (string, error) {
	projection, err := canonicalDescriptorOf(d)
	if err != nil {
		return "", err
	}
	canonical, err := idempotency.CanonicalJSON(projection)
	if err != nil {
		return "", fmt.Errorf("canonicalize capability %s descriptor: %w", d.ID, err)
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

// canonicalDescriptorOf projects a resolved descriptor into its
// canonical digest form, failing closed on a malformed schema.
func canonicalDescriptorOf(d ResolvedDescriptor) (canonicalDescriptor, error) {
	version := d.DescriptorVersion
	if version == 0 {
		version = 1
	}
	out := canonicalDescriptor{
		ID:                d.ID,
		DescriptorVersion: version,
		PolicyRevision:    d.PolicyRevision,
		ExecutionClass:    d.ExecutionClass,
		AssuranceProfile:  d.AssuranceProfile,
		ExecutionRoute:    d.ExecutionRoute,
		AuthorityPolicy:   d.AuthorityPolicy,
		AdapterID:         d.AdapterID,
	}
	if len(d.Schema) > 0 {
		parsed, err := decodeUseNumber(d.Schema)
		if err != nil {
			return canonicalDescriptor{}, fmt.Errorf("capability %s: argument schema is not valid JSON: %w", d.ID, err)
		}
		normalized, err := idempotency.NormalizeNumbers(parsed)
		if err != nil {
			return canonicalDescriptor{}, fmt.Errorf("capability %s: argument schema numeric normalization failed: %w", d.ID, err)
		}
		out.Schema = normalized
	}
	return out, nil
}

// canonicalDescriptorBytes returns the exact canonical bytes the
// registry digest covers: the descriptor projection, sorted by ID,
// canonicalized once by the authoritative Go implementation.
func (r *Registry) canonicalDescriptorBytes() ([]byte, error) {
	r.mu.RLock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	projection := make([]canonicalDescriptor, 0, len(ids))
	for _, id := range ids {
		descriptor, err := canonicalDescriptorOf(r.entries[id])
		if err != nil {
			r.mu.RUnlock()
			return nil, err
		}
		projection = append(projection, descriptor)
	}
	r.mu.RUnlock()

	canonical, err := idempotency.CanonicalJSON(projection)
	if err != nil {
		return nil, fmt.Errorf("canonicalize capability registry: %w", err)
	}
	return []byte(canonical), nil
}

// Digest returns the SHA-256 digest of the canonical registry
// serialization.
func (r *Registry) Digest() (string, error) {
	canonical, err := r.canonicalDescriptorBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// Report summarizes the registry for the startup report.
type Report struct {
	Total       int
	ByClass     map[ExecutionClass]int
	ByAssurance map[AssuranceProfile]int
	ByRoute     map[ExecutionRoute]int
	Digest      string
}

// Report returns the registry summary and digest.
func (r *Registry) Report() (Report, error) {
	digest, err := r.Digest()
	if err != nil {
		return Report{}, err
	}
	report := Report{
		ByClass:     make(map[ExecutionClass]int),
		ByAssurance: make(map[AssuranceProfile]int),
		ByRoute:     make(map[ExecutionRoute]int),
		Digest:      digest,
	}
	r.mu.RLock()
	report.Total = len(r.entries)
	for _, descriptor := range r.entries {
		report.ByClass[descriptor.ExecutionClass]++
		report.ByAssurance[descriptor.AssuranceProfile]++
		report.ByRoute[descriptor.ExecutionRoute]++
	}
	r.mu.RUnlock()
	return report, nil
}

// String renders the startup report.
func (r Report) String() string {
	var builder strings.Builder
	builder.WriteString("Capability Registry\n")
	builder.WriteString("-------------------\n")
	fmt.Fprintf(&builder, "Descriptors: %d\n", r.Total)
	for _, class := range []ExecutionClass{ClassPure, ClassRead, ClassMutation, ClassCritical} {
		fmt.Fprintf(&builder, "%-10s %d\n", class, r.ByClass[class])
	}
	for _, assurance := range []AssuranceProfile{AssuranceNone, AssuranceStandard, AssuranceDurable, AssuranceHighAssurance} {
		fmt.Fprintf(&builder, "%-14s %d\n", assurance, r.ByAssurance[assurance])
	}
	for _, route := range []ExecutionRoute{RouteLocal, RouteDirect, RouteCrabedence} {
		fmt.Fprintf(&builder, "%-10s %d\n", route, r.ByRoute[route])
	}
	fmt.Fprintf(&builder, "Registry SHA-256: %s\n", r.Digest)
	return builder.String()
}

// supportedSchemaKeywords is the exact keyword subset the argument
// validator implements, plus inert annotation keywords. A schema using
// any other *validation* keyword would be silently under-validated, so
// the registry scan rejects it instead: fail the registry, not the
// request. Annotations (description, title, default, ...) carry no
// validation semantics and are accepted anywhere.
var supportedSchemaKeywords = map[string]bool{
	// Implemented validation keywords.
	"type":                 true,
	"required":             true,
	"properties":           true,
	"additionalProperties": true,
	"enum":                 true,
	"minimum":              true,
	"maximum":              true,
	"multipleOf":           true,
	"minLength":            true,
	"maxLength":            true,
	"items":                true,
	// Inert annotations.
	"description": true,
	"title":       true,
	"$schema":     true,
	"$id":         true,
	"$comment":    true,
	"examples":    true,
	"default":     true,
	"deprecated":  true,
	"readOnly":    true,
	"writeOnly":   true,
}

// Validate re-checks the whole registry as one invariant scan and
// fails the registry — not the individual request — for:
//
//   - invalid or incompatible dimension combinations
//   - a missing adapter binding (the service could never dispatch it)
//   - a malformed argument schema, or one using keywords outside the
//     validator's supported subset
//
// Call it at service startup.
func (r *Registry) Validate() error {
	r.mu.RLock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	descriptors := make([]ResolvedDescriptor, 0, len(ids))
	for _, id := range ids {
		descriptors = append(descriptors, r.entries[id])
	}
	r.mu.RUnlock()

	var findings []error
	for _, descriptor := range descriptors {
		if descriptor.DescriptorVersion < 0 {
			findings = append(findings, fmt.Errorf("capability %s: descriptor version must be >= 1, got %d", descriptor.ID, descriptor.DescriptorVersion))
		}
		if !descriptor.ExecutionClass.Valid() {
			findings = append(findings, fmt.Errorf("capability %s: invalid execution class %q", descriptor.ID, descriptor.ExecutionClass))
		}
		if !descriptor.AssuranceProfile.Valid() {
			findings = append(findings, fmt.Errorf("capability %s: invalid assurance profile %q", descriptor.ID, descriptor.AssuranceProfile))
		}
		if !descriptor.ExecutionRoute.Valid() {
			findings = append(findings, fmt.Errorf("capability %s: invalid execution route %q", descriptor.ID, descriptor.ExecutionRoute))
		}
		if err := ValidateDescriptorCompatibility(descriptor.ExecutionClass, descriptor.AssuranceProfile, descriptor.ExecutionRoute); err != nil {
			findings = append(findings, fmt.Errorf("capability %s: %w", descriptor.ID, err))
		}
		if descriptor.ExecutionRoute == RouteLocal && descriptor.AuthorityPolicy.GrantRequired {
			findings = append(findings, fmt.Errorf("capability %s: LOCAL route cannot require a grant — LOCAL execution never reaches the authority resolver", descriptor.ID))
		}
		if descriptor.AdapterID == "" {
			findings = append(findings, fmt.Errorf("capability %s: no adapter binding — the service cannot dispatch it", descriptor.ID))
		}
		if len(descriptor.Schema) > 0 {
			if err := validateSchemaDocument(descriptor.Schema); err != nil {
				findings = append(findings, fmt.Errorf("capability %s: %w", descriptor.ID, err))
			}
		}
	}
	return errors.Join(findings...)
}

// validateSchemaDocument checks that an argument schema parses as a
// JSON object and uses only supported keywords, recursively through
// properties, items, and schema-valued additionalProperties.
func validateSchemaDocument(schema []byte) error {
	decoded, err := decodeUseNumber(schema)
	if err != nil {
		return fmt.Errorf("argument schema is not valid JSON: %w", err)
	}
	document, ok := decoded.(map[string]any)
	if !ok {
		return errors.New("argument schema must be a JSON object")
	}
	return validateSchemaKeywords(document, "")
}

func validateSchemaKeywords(schema map[string]any, path string) error {
	var findings []error
	for keyword, value := range schema {
		if !supportedSchemaKeywords[keyword] {
			findings = append(findings, fmt.Errorf("argument schema uses unsupported keyword %q%s", keyword, path))
			continue
		}
		switch keyword {
		case "properties":
			properties, ok := value.(map[string]any)
			if !ok {
				findings = append(findings, fmt.Errorf("argument schema properties must be an object%s", path))
				continue
			}
			for name, property := range properties {
				propertySchema, ok := property.(map[string]any)
				if !ok {
					findings = append(findings, fmt.Errorf("argument schema property %q must be a schema object%s", name, path))
					continue
				}
				if err := validateSchemaKeywords(propertySchema, path+"."+name); err != nil {
					findings = append(findings, err)
				}
			}
		case "items":
			items, ok := value.(map[string]any)
			if !ok {
				findings = append(findings, fmt.Errorf("argument schema items must be a schema object%s", path))
				continue
			}
			if err := validateSchemaKeywords(items, path+"[]"); err != nil {
				findings = append(findings, err)
			}
		case "additionalProperties":
			additional, ok := value.(map[string]any)
			if !ok {
				continue // boolean form: allowed
			}
			if err := validateSchemaKeywords(additional, path); err != nil {
				findings = append(findings, err)
			}
		}
	}
	return errors.Join(findings...)
}

// ValidateAdapters checks that every registered capability is bound to
// an adapter the service can actually dispatch. A capability whose
// adapter is not wired could only ever produce
// CAPABILITY_UNIMPLEMENTED at execution time — refuse it at startup
// instead.
func (r *Registry) ValidateAdapters(known map[string]bool) error {
	r.mu.RLock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	descriptors := make([]ResolvedDescriptor, 0, len(ids))
	for _, id := range ids {
		descriptors = append(descriptors, r.entries[id])
	}
	r.mu.RUnlock()

	var findings []error
	for _, descriptor := range descriptors {
		if descriptor.AdapterID == "" || !known[descriptor.AdapterID] {
			findings = append(findings, fmt.Errorf("capability %s: adapter %q is not wired into the service", descriptor.ID, descriptor.AdapterID))
		}
	}
	return errors.Join(findings...)
}
