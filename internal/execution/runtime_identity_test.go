package execution

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func runtimeConfigFixture() RuntimeConfiguration {
	return RuntimeConfiguration{
		SchemaVersion:   1,
		Release:         "0.52.0-rc.1",
		RegistrySHA256:  strings.Repeat("a", 64),
		EffectStore:     "postgres",
		EnabledAdapters: []string{"github", "system"},
	}
}

func TestRuntimeConfigurationDigestIsStableAndOrderIndependent(t *testing.T) {
	base := runtimeConfigFixture()
	first, err := RuntimeConfigurationDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RuntimeConfigurationDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same configuration produced different digests: %s vs %s", first, second)
	}

	reordered := base
	reordered.EnabledAdapters = []string{"system", "github", "github"}
	third, err := RuntimeConfigurationDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if first != third {
		t.Fatalf("adapter order or duplicates changed the digest: %s vs %s", first, third)
	}
}

func TestRuntimeConfigurationDigestTracksEveryDimension(t *testing.T) {
	base := runtimeConfigFixture()
	baseline, err := RuntimeConfigurationDigest(base)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*RuntimeConfiguration){
		"release":         func(c *RuntimeConfiguration) { c.Release = "0.52.0-rc.2" },
		"registry digest": func(c *RuntimeConfiguration) { c.RegistrySHA256 = strings.Repeat("b", 64) },
		"effect store":    func(c *RuntimeConfiguration) { c.EffectStore = "sqlite" },
		"enabled adapters": func(c *RuntimeConfiguration) {
			c.EnabledAdapters = []string{"system"}
		},
		"schema version": func(c *RuntimeConfiguration) { c.SchemaVersion = 2 },
	}
	for name, mutate := range cases {
		changed := base
		mutate(&changed)
		digest, err := RuntimeConfigurationDigest(changed)
		if err != nil {
			t.Fatal(err)
		}
		if digest == baseline {
			t.Fatalf("%s change did not change the runtime configuration digest", name)
		}
	}
}

func TestRuntimeIdentityEnvelopeCoversItsPayload(t *testing.T) {
	envelope, err := RuntimeIdentityEnvelopeFor(runtimeConfigFixture())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.CanonicalPayload)
	if err != nil {
		t.Fatalf("canonical payload is not valid base64: %v", err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != envelope.RuntimeConfigurationSHA256 {
		t.Fatal("runtime configuration digest does not cover the payload it ships with")
	}

	var decoded RuntimeConfiguration
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("canonical payload is not the configuration: %v", err)
	}
	if decoded.Release != "0.52.0-rc.1" || decoded.EffectStore != "postgres" {
		t.Fatalf("canonical payload lost identity fields: %+v", decoded)
	}
	if !reflect.DeepEqual(decoded.EnabledAdapters, []string{"github", "system"}) {
		t.Fatalf("canonical payload must carry sorted adapters, got %v", decoded.EnabledAdapters)
	}

	bytes, err := envelope.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip RuntimeIdentityEnvelope
	if err := json.Unmarshal(bytes, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.RuntimeConfigurationSHA256 != envelope.RuntimeConfigurationSHA256 {
		t.Fatal("envelope JSON round-trip changed the digest")
	}
}

// TestRuntimeConfigurationHasNoCredentialFields pins the exclusion by
// construction: the identity structure carries normalized identities
// only, and a new field must be a deliberate decision, not a drive-by
// secret leak.
func TestRuntimeConfigurationHasNoCredentialFields(t *testing.T) {
	allowed := map[string]bool{
		"schema_version":   true,
		"release":          true,
		"registry_sha256":  true,
		"effect_store":     true,
		"enabled_adapters": true,
	}
	typ := reflect.TypeOf(RuntimeConfiguration{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if !allowed[name] {
			t.Fatalf("runtime configuration field %q is not an allowlisted non-secret identity field", name)
		}
		lower := strings.ToLower(field.Name)
		for _, forbidden := range []string{"token", "secret", "password", "key", "credential", "dsn", "url"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("runtime configuration field %q looks like credential material", field.Name)
			}
		}
	}
}

func TestRuntimeConfigurationNormalizesEmptyAdapters(t *testing.T) {
	cfg := RuntimeConfiguration{
		SchemaVersion:   1,
		RegistrySHA256:  strings.Repeat("c", 64),
		EffectStore:     "none",
		EnabledAdapters: []string{""},
	}
	canonical, err := CanonicalRuntimeConfiguration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RuntimeConfiguration
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.EnabledAdapters) != 0 {
		t.Fatalf("empty adapter IDs must normalize away, got %v", decoded.EnabledAdapters)
	}
	if decoded.SchemaVersion != 1 {
		t.Fatalf("zero schema version must default to 1, got %d", decoded.SchemaVersion)
	}
}
