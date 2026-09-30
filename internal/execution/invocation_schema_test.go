package execution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The published schema and the parser must not drift.
//
// schemas/capability-invocation-v1.json is the one canonical description of
// the wire contract; the parser in invocation_abi.go is what actually enforces
// it, and the TypeScript and Rust implementations are bound to the same file
// by their own tests. A field that appears in one place and not the others is
// a cross-language divergence — exactly the class of bug the shared
// conformance corpus exists to prevent — so it fails here first.

type invocationSchemaObject struct {
	Type                 string                    `json:"type"`
	AdditionalProperties bool                      `json:"additionalProperties"`
	Properties           map[string]invocationProp `json:"properties"`
	ServerResolved       []string                  `json:"x-crabedence-server-resolved"`
}

type invocationProp struct {
	Type                 string                    `json:"type"`
	AdditionalProperties bool                      `json:"additionalProperties"`
	Properties           map[string]invocationProp `json:"properties"`
}

func loadInvocationSchema(t *testing.T) invocationSchemaObject {
	t.Helper()
	path := filepath.Join("..", "..", "schemas", "capability-invocation-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the canonical invocation schema: %v", err)
	}
	var schema invocationSchemaObject
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse the canonical invocation schema: %v", err)
	}
	return schema
}

// schemaTypeOf maps a parser field type onto the schema's vocabulary.
func schemaTypeOf(field abiFieldType) string {
	switch field {
	case abiString:
		return "string"
	case abiObject:
		return "object"
	case abiInteger:
		return "integer"
	}
	return "unknown"
}

func TestInvocationSchemaMatchesTheParser(t *testing.T) {
	schema := loadInvocationSchema(t)

	if schema.Type != "object" {
		t.Errorf("the request must be described as an object, got %q", schema.Type)
	}
	if schema.AdditionalProperties {
		t.Error("the request must refuse unknown fields (additionalProperties: false)")
	}

	// Every field the parser knows must be described, with the same type...
	for name, field := range abiRootFields {
		described, ok := schema.Properties[name]
		if !ok {
			t.Errorf("the parser accepts %q but the schema does not describe it", name)
			continue
		}
		if want := schemaTypeOf(field); described.Type != want {
			t.Errorf("field %q: parser says %s, schema says %s", name, want, described.Type)
		}
	}
	// ...and the schema may not accept anything the parser would refuse.
	for name := range schema.Properties {
		if _, ok := abiRootFields[name]; !ok {
			t.Errorf("the schema describes %q but the parser refuses it as an unknown field", name)
		}
	}

	// The authority object is the only other object with a known-field set.
	authority, ok := schema.Properties["authority"]
	if !ok {
		t.Fatal("the schema must describe the authority object")
	}
	if authority.AdditionalProperties {
		t.Error("the authority object must refuse unknown fields")
	}
	for name, field := range abiAuthorityFields {
		described, ok := authority.Properties[name]
		if !ok {
			t.Errorf("the parser accepts authority.%s but the schema does not describe it", name)
			continue
		}
		if want := schemaTypeOf(field); described.Type != want {
			t.Errorf("authority.%s: parser says %s, schema says %s", name, want, described.Type)
		}
	}
	for name := range authority.Properties {
		if _, ok := abiAuthorityFields[name]; !ok {
			t.Errorf("the schema describes authority.%s but the parser refuses it", name)
		}
	}
}

func TestInvocationSchemaRefusesServerResolvedFields(t *testing.T) {
	schema := loadInvocationSchema(t)
	if len(schema.ServerResolved) == 0 {
		t.Fatal("the schema must name the fields the planner may not supply")
	}

	// Every server-resolved field must be absent from the accepted set: the
	// kernel refuses it, so a schema that accepted it would describe a
	// different contract than the one that runs.
	for _, name := range schema.ServerResolved {
		if _, accepted := schema.Properties[name]; accepted {
			t.Errorf("%q is declared server-resolved but the schema accepts it", name)
		}
		if _, accepted := abiRootFields[name]; accepted {
			t.Errorf("%q is declared server-resolved but the parser accepts it", name)
		}
	}

	// The list is documentation, so keep it ordered for reviewability.
	if !sort.StringsAreSorted(schema.ServerResolved) {
		t.Errorf("x-crabedence-server-resolved must be sorted: %v", schema.ServerResolved)
	}
}
