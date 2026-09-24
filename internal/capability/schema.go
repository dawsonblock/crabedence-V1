package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"unicode/utf8"
)

// decodeUseNumber parses JSON preserving exact numeric text — the
// same numeric model as the request digest. Values like
// 9007199254740993 must not be rounded through float64 before bounds
// or integer checks.
func decodeUseNumber(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// ratValue converts a JSON-decoded number to an exact rational for
// comparison. It returns nil for non-numeric or malformed values.
// float64 is accepted for programmatic callers — its value is taken
// at face precision; the JSON path always produces json.Number.
func ratValue(v any) *big.Rat {
	switch num := v.(type) {
	case json.Number:
		r, ok := new(big.Rat).SetString(num.String())
		if !ok {
			return nil
		}
		return r
	case float64:
		return new(big.Rat).SetFloat64(num)
	}
	return nil
}

// ValidateArguments validates request arguments against a capability's
// JSON Schema. It supports the common subset needed for capability
// argument validation: type, required, properties, enum, minimum,
// maximum, minLength, maxLength, and items.
//
// An empty schema means no validation (any arguments accepted).
// A non-empty schema that fails to parse is a registration error and
// causes validation to fail closed.
func ValidateArguments(schema json.RawMessage, args json.RawMessage) error {
	if len(schema) == 0 {
		return nil // no schema declared — no validation
	}

	decoded, err := decodeUseNumber(schema)
	if err != nil {
		return fmt.Errorf("invalid capability schema (registration error): %w", err)
	}
	schemaMap, ok := decoded.(map[string]any)
	if !ok {
		return fmt.Errorf("invalid capability schema (registration error): schema must be a JSON object")
	}

	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}

	decodedArgs, err := decodeUseNumber(args)
	if err != nil {
		return fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	argsMap, ok := decodedArgs.(map[string]any)
	if !ok {
		return fmt.Errorf("arguments must be a JSON object")
	}

	return validateObject(schemaMap, argsMap, "")
}

// validateObject validates a JSON object against a schema map.
func validateObject(schema map[string]any, obj map[string]any, path string) error {
	// Check type
	if t, ok := schema["type"].(string); ok && t != "object" {
		return fmt.Errorf("%s: expected object, got schema type %s", path, t)
	}

	// Check required fields
	if required, ok := schema["required"].([]any); ok {
		for _, r := range required {
			name, ok := r.(string)
			if !ok {
				continue
			}
			if _, exists := obj[name]; !exists {
				if path == "" {
					return fmt.Errorf("missing required field: %s", name)
				}
				return fmt.Errorf("%s: missing required field: %s", path, name)
			}
		}
	}

	// Check properties
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}

	for name, propSchema := range props {
		propMap, ok := propSchema.(map[string]any)
		if !ok {
			continue
		}
		val, exists := obj[name]
		if !exists {
			continue // not present — required check above handles it
		}
		fieldPath := name
		if path != "" {
			fieldPath = path + "." + name
		}
		if err := validateValue(propMap, val, fieldPath); err != nil {
			return err
		}
	}

	// additionalProperties: false rejects unknown properties.
	// JSON Schema default is to allow additional properties, but
	// capability schemas should declare additionalProperties: false
	// to prevent unexpected arguments from silently passing.
	if ap, ok := schema["additionalProperties"]; ok {
		if allow, ok := ap.(bool); ok && !allow {
			for name := range obj {
				if _, declared := props[name]; !declared {
					if path == "" {
						return fmt.Errorf("unknown field: %s (additionalProperties is false)", name)
					}
					return fmt.Errorf("%s: unknown field: %s (additionalProperties is false)", path, name)
				}
			}
		}
	}

	return nil
}

// validateValue validates a single value against a property schema.
func validateValue(schema map[string]any, val any, path string) error {
	// Type check
	if t, ok := schema["type"].(string); ok {
		if err := checkType(t, val, path); err != nil {
			return err
		}
	}

	// Enum check — numbers compare by exact value so 1 and 1.0 match,
	// and >2^53 integers compare without float64 rounding.
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		valRat := ratValue(val)
		for _, e := range enum {
			if eRat := ratValue(e); eRat != nil && valRat != nil {
				if eRat.Cmp(valRat) == 0 {
					found = true
					break
				}
				continue
			}
			if fmt.Sprintf("%v", e) == fmt.Sprintf("%v", val) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: value %v not in enum %v", path, val, enum)
		}
	}

	// Number checks — exact rational comparison, never float64.
	if num := ratValue(val); num != nil {
		if min := ratValue(schema["minimum"]); min != nil && num.Cmp(min) < 0 {
			return fmt.Errorf("%s: value %v is less than minimum %v", path, val, schema["minimum"])
		}
		if max := ratValue(schema["maximum"]); max != nil && num.Cmp(max) > 0 {
			return fmt.Errorf("%s: value %v is greater than maximum %v", path, val, schema["maximum"])
		}
		if mult := ratValue(schema["multipleOf"]); mult != nil && mult.Sign() != 0 {
			if !new(big.Rat).Quo(num, mult).IsInt() {
				return fmt.Errorf("%s: value %v is not a multiple of %v", path, val, schema["multipleOf"])
			}
		}
	}

	// String checks
	// JSON Schema minLength/maxLength count Unicode code points
	// (runes), not UTF-8 bytes. A 3-character Japanese string like
	// "日本語" has 9 UTF-8 bytes but 3 code points.
	if s, ok := val.(string); ok {
		runeCount := utf8.RuneCountInString(s)
		countRat := new(big.Rat).SetInt64(int64(runeCount))
		if minLength := ratValue(schema["minLength"]); minLength != nil && countRat.Cmp(minLength) < 0 {
			return fmt.Errorf("%s: string length %d is less than minLength %v", path, runeCount, schema["minLength"])
		}
		if maxLength := ratValue(schema["maxLength"]); maxLength != nil && countRat.Cmp(maxLength) > 0 {
			return fmt.Errorf("%s: string length %d is greater than maxLength %v", path, runeCount, schema["maxLength"])
		}
	}

	// Array items check
	if arr, ok := val.([]any); ok {
		if items, ok := schema["items"].(map[string]any); ok {
			for i, item := range arr {
				itemPath := fmt.Sprintf("%s[%d]", path, i)
				if err := validateValue(items, item, itemPath); err != nil {
					return err
				}
			}
		}
	}

	// Nested object check
	if obj, ok := val.(map[string]any); ok {
		if err := validateObject(schema, obj, path); err != nil {
			return err
		}
	}

	return nil
}

// checkType checks that a value matches the JSON Schema type.
func checkType(expected string, val any, path string) error {
	var actual string
	switch val.(type) {
	case nil:
		actual = "null"
	case bool:
		actual = "boolean"
	case json.Number, float64:
		actual = "number"
	case string:
		actual = "string"
	case []any:
		actual = "array"
	case map[string]any:
		actual = "object"
	default:
		actual = fmt.Sprintf("%T", val)
	}

	if expected == "number" && actual == "number" {
		return nil
	}
	if expected == "integer" && actual == "number" {
		// Exact integer check — Rat.IsInt() works for values far
		// beyond float64/int64 range (1e100, 2^63+1). A float64 that
		// round-trips through int64 is also an integer.
		if r := ratValue(val); r != nil && r.IsInt() {
			return nil
		}
		if f, ok := val.(float64); ok && f == float64(int64(f)) {
			return nil
		}
		return fmt.Errorf("%s: expected integer, got non-integer number %v", path, val)
	}
	if expected != actual {
		return fmt.Errorf("%s: expected %s, got %s", path, expected, actual)
	}
	return nil
}
