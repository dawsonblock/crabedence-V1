package capability

import "testing"

// TestSchemaMaxLengthUnicode verifies that maxLength counts Unicode
// code points (runes), not UTF-8 bytes. A 3-character Japanese string
// like "日本語" has 9 UTF-8 bytes but 3 code points.
func TestSchemaMaxLengthUnicode(t *testing.T) {
	// JSON unmarshaling produces float64 for numbers, so the schema
	// validator expects float64. Use float64() explicitly.
	schema := map[string]any{
		"type":      "string",
		"maxLength": float64(5),
	}

	// 3 Japanese characters = 3 code points = 9 UTF-8 bytes.
	// With byte-counting this would fail (9 > 5); with rune-counting
	// it passes (3 <= 5).
	if err := validateValue(schema, "日本語", "test"); err != nil {
		t.Errorf("expected 3-rune string to pass maxLength=5, got: %v", err)
	}

	// 6 Japanese characters = 6 code points = 18 UTF-8 bytes.
	// Should fail maxLength=5.
	if err := validateValue(schema, "日本語日本語", "test"); err == nil {
		t.Error("expected 6-rune string to fail maxLength=5")
	}
}

// TestSchemaMinLengthUnicode verifies that minLength counts Unicode
// code points (runes), not UTF-8 bytes.
func TestSchemaMinLengthUnicode(t *testing.T) {
	schema := map[string]any{
		"type":      "string",
		"minLength": float64(3),
	}

	// 3 Japanese characters = 3 code points = 9 UTF-8 bytes.
	if err := validateValue(schema, "日本語", "test"); err != nil {
		t.Errorf("expected 3-rune string to pass minLength=3, got: %v", err)
	}

	// 2 Japanese characters = 2 code points = 6 UTF-8 bytes.
	// With byte-counting this would pass (6 >= 3); with rune-counting
	// it fails (2 < 3).
	if err := validateValue(schema, "日本", "test"); err == nil {
		t.Error("expected 2-rune string to fail minLength=3")
	}
}

// TestSchemaAdditionalPropertiesFalse verifies that when
// additionalProperties is false, unknown properties are rejected.
func TestSchemaAdditionalPropertiesFalse(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
			"age":  map[string]any{"type": "integer"},
		},
		"additionalProperties": false,
	}

	// Valid: only declared properties.
	if err := validateObject(schema, map[string]any{
		"name": "alice",
		"age":  float64(30),
	}, ""); err != nil {
		t.Errorf("expected valid object to pass, got: %v", err)
	}

	// Invalid: unknown property "email".
	err := validateObject(schema, map[string]any{
		"name":  "alice",
		"email": "alice@example.com",
	}, "")
	if err == nil {
		t.Error("expected unknown property 'email' to be rejected")
	}

	// Invalid: unknown property at nested path.
	nestedSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"user": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string"},
				},
				"additionalProperties": false,
			},
		},
		"additionalProperties": false,
	}
	err = validateObject(nestedSchema, map[string]any{
		"user": map[string]any{
			"name":  "alice",
			"email": "alice@example.com",
		},
	}, "")
	if err == nil {
		t.Error("expected nested unknown property to be rejected")
	}
}

// TestSchemaAdditionalPropertiesDefault verifies that when
// additionalProperties is not set (default), unknown properties
// are allowed (JSON Schema default behavior).
func TestSchemaAdditionalPropertiesDefault(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
		},
	}

	// No additionalProperties set — unknown properties allowed.
	if err := validateObject(schema, map[string]any{
		"name":  "alice",
		"email": "alice@example.com",
	}, ""); err != nil {
		t.Errorf("expected unknown property to be allowed by default, got: %v", err)
	}
}
