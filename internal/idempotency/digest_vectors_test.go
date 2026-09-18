package idempotency

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// digest-vectors.json is the frozen cross-language conformance fixture
// for the idempotency request digest ABI. Each vector pins:
//
//   - the raw request arguments as a client could legitimately send
//     them (arbitrary key order, lexical number forms, escapes),
//   - the canonical argument bytes after parsing, number
//     normalization, and deterministic re-marshal, and
//   - the resulting request digest (SHA-256 of the canonical
//     DigestInput document, hex-encoded).
//
// Any implementation of the digest contract — Go, or a future
// TypeScript/Rust/Python binding — must produce byte-identical
// canonical_args and digest values for every vector. Changing the
// canonicalization or digest input schema changes digests and
// therefore idempotency identities; that is a deliberate ABI change
// and must be accompanied by regenerating this fixture with:
//
//	go test ./internal/idempotency -run TestDigestVectors -update-digest-vectors
//
// followed by review of every digest consumer.
var updateDigestVectors = flag.Bool("update-digest-vectors", false, "regenerate testdata/digest-vectors.json")

type digestVector struct {
	Name            string `json:"name"`
	ProtocolVersion int    `json:"protocol_version"`
	Principal       string `json:"principal"`
	Capability      string `json:"capability"`
	// RawArgs is the exact argument JSON a client sent — verbatim,
	// including key order and number lexemes.
	RawArgs             string `json:"raw_args"`
	GrantID             string `json:"grant_id"`
	ExecutionClass      string `json:"execution_class"`
	AuthorityGeneration int64  `json:"authority_generation,omitempty"`
	AuthorityDigest     string `json:"authority_digest,omitempty"`
	// CanonicalArgs is the canonical argument document bytes.
	CanonicalArgs string `json:"canonical_args"`
	// Digest is hex(SHA-256(canonical DigestInput document)).
	Digest string `json:"digest"`
}

type digestVectorFile struct {
	Description string         `json:"description"`
	Vectors     []digestVector `json:"vectors"`
}

// digestVectorCases are the fixture inputs. Expected canonical bytes
// and digests live in the JSON file so other language implementations
// can consume them without parsing Go.
var digestVectorCases = []digestVector{
	{
		Name:            "key-order",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"zebra":1,"apple":2,"mango":{"y":true,"a":null}}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "unicode",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"msg":"héllo 世界 🌏","combining":"é","rtl":"نص"}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "escaped-strings",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"q":"a\"b","nl":"line\nbreak","solidus":"a/b","ctrl":"A"}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "number-lexical-equivalence",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"a":1,"b":1.0,"c":1e0,"d":1.00e+0}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "number-decimals-and-exponents",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"x":1.5e3,"y":1.5e-3,"z":-0,"w":0.010,"v":2e+1}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "number-large-integers",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"big":9007199254740993,"bigger":18446744073709551616,"neg":-9007199254740993}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "containers-and-scalars",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"arr":[3,1,2],"empty_obj":{},"empty_arr":[],"t":true,"f":false,"n":null}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "deep-nesting",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"l1":{"l2":{"l3":[{"z":1.0,"a":[null,false,2e0]}]}}}`,
		GrantID: "grant-1", ExecutionClass: "MUTATION",
	},
	{
		Name:            "authority-binding",
		ProtocolVersion: 1, Principal: "alice@example.com", Capability: "example.send",
		RawArgs: `{"to":"bob@example.com","amount":100}`,
		GrantID: "grant-1", ExecutionClass: "CRITICAL",
		AuthorityGeneration: 3,
		AuthorityDigest:     "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
	},
}

func TestDigestVectors(t *testing.T) {
	path := filepath.Join("testdata", "digest-vectors.json")

	if *updateDigestVectors {
		out := digestVectorFile{
			Description: "Frozen cross-language conformance corpus for the idempotency request digest ABI. " +
				"canonical_args is the deterministic re-marshal of raw_args after canonicalJSONNumber " +
				"normalization (1, 1.0, 1e0 all → \"1\"; arbitrary precision preserved). " +
				"digest is hex(SHA-256(canonical DigestInput JSON)). Regenerate with " +
				"-update-digest-vectors only for a deliberate ABI change.",
			Vectors: digestVectorCases,
		}
		for i := range out.Vectors {
			v := &out.Vectors[i]
			canon, err := canonicalizeJSON(json.RawMessage(v.RawArgs))
			if err != nil {
				t.Fatalf("%s: canonicalize: %v", v.Name, err)
			}
			v.CanonicalArgs = string(canon)
			d, err := ComputeDigestFromRawWithAuthority(
				v.ProtocolVersion, v.Principal, v.Capability,
				json.RawMessage(v.RawArgs), v.GrantID, v.ExecutionClass,
				v.AuthorityGeneration, v.AuthorityDigest,
			)
			if err != nil {
				t.Fatalf("%s: digest: %v", v.Name, err)
			}
			v.Digest = d
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s", path)
		return
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture (run with -update-digest-vectors to create): %v", err)
	}
	var f digestVectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) != len(digestVectorCases) {
		t.Fatalf("fixture has %d vectors, test defines %d", len(f.Vectors), len(digestVectorCases))
	}

	for i, v := range f.Vectors {
		want := digestVectorCases[i]
		if v.Name != want.Name {
			t.Fatalf("vector %d: fixture name %q, test case %q — fixture and test out of sync", i, v.Name, want.Name)
		}
		t.Run(v.Name, func(t *testing.T) {
			canon, err := canonicalizeJSON(json.RawMessage(v.RawArgs))
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(canon) != v.CanonicalArgs {
				t.Errorf("canonical args mismatch:\n  got:      %s\n  expected: %s", canon, v.CanonicalArgs)
			}
			d, err := ComputeDigestFromRawWithAuthority(
				v.ProtocolVersion, v.Principal, v.Capability,
				json.RawMessage(v.RawArgs), v.GrantID, v.ExecutionClass,
				v.AuthorityGeneration, v.AuthorityDigest,
			)
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if d != v.Digest {
				t.Errorf("digest mismatch:\n  got:      %s\n  expected: %s", d, v.Digest)
			}
		})
	}
}
