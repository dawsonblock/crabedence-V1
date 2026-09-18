package capability

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

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

	var schemaMap map[string]any
	if err := json.Unmarshal(schema, &schemaMap); err != nil {
		return fmt.Errorf("invalid capability schema (registration error): %w", err)
	}

	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}

	var argsMap map[string]any
	if err := json.Unmarshal(args, &argsMap); err != nil {
		return fmt.Errorf("arguments must be a JSON object: %w", err)
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

	// Enum check
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if fmt.Sprintf("%v", e) == fmt.Sprintf("%v", val) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: value %v not in enum %v", path, val, enum)
		}
	}

	// Number checks
	if num, ok := val.(float64); ok {
		if min, ok := schema["minimum"].(float64); ok && num < min {
			return fmt.Errorf("%s: value %v is less than minimum %v", path, num, min)
		}
		if max, ok := schema["maximum"].(float64); ok && num > max {
			return fmt.Errorf("%s: value %v is greater than maximum %v", path, num, max)
		}
	}

	// String checks
	// JSON Schema minLength/maxLength count Unicode code points
	// (runes), not UTF-8 bytes. A 3-character Japanese string like
	// "日本語" has 9 UTF-8 bytes but 3 code points.
	if s, ok := val.(string); ok {
		runeCount := utf8.RuneCountInString(s)
		if minLength, ok := schema["minLength"].(float64); ok && int(minLength) > 0 && runeCount < int(minLength) {
			return fmt.Errorf("%s: string length %d is less than minLength %d", path, runeCount, int(minLength))
		}
		if maxLength, ok := schema["maxLength"].(float64); ok && int(maxLength) > 0 && runeCount > int(maxLength) {
			return fmt.Errorf("%s: string length %d is greater than maxLength %d", path, runeCount, int(maxLength))
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
	case float64:
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
		// Check that it's a whole number
		if n, ok := val.(float64); ok && n == float64(int64(n)) {
			return nil
		}
		return fmt.Errorf("%s: expected integer, got non-integer number %v", path, val)
	}
	if expected != actual {
		return fmt.Errorf("%s: expected %s, got %s", path, expected, actual)
	}
	return nil
}

// SchemaValidationError describes an argument validation failure
// with the offending path for diagnostics.
type SchemaValidationError struct {
	Path    string
	Message string
}

func (e *SchemaValidationError) Error() string {
	if e.Path == "" {
		return e.Message
	}
	return e.Path + ": " + e.Message
}

// ParseSchemaValidationError extracts the path from a validation error
// message for structured error reporting.
func ParseSchemaValidationError(err error) *SchemaValidationError {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if idx := strings.Index(msg, ": "); idx > 0 {
		return &SchemaValidationError{
			Path:    msg[:idx],
			Message: msg[idx+2:],
		}
	}
	return &SchemaValidationError{Message: msg}
}
