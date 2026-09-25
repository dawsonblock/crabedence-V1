package execution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// Capability invocation ABI parsing.
//
// encoding/json alone is permissive in ways that make the wire
// interpretation ambiguous: duplicate keys silently take the last
// value, unknown fields are ignored, explicit null decodes to the zero
// value, invalid UTF-8 is replaced rather than refused, and streaming
// decoders ignore trailing bytes. The request is therefore validated
// under explicit structural rules, mirrored by NEMO's validator over
// the shared conformance corpus
// (testdata/invocation-abi-conformance/vectors.json):
//
//	R1  the request is valid UTF-8
//	R2  exactly one JSON value; nothing follows it
//	R3  the request is a JSON object
//	R4  no object repeats a key
//	R5  nesting depth is at most maxInvocationDepth
//	R6  root and authority keys are from the known sets
//	R7  explicit null is rejected for every known field
//	R8  known fields carry their declared JSON types
const maxInvocationDepth = 64

// abiFieldType is the declared JSON type of a known ABI field.
type abiFieldType int

const (
	abiString abiFieldType = iota
	abiObject
	abiInteger
)

// abiRootFields and abiAuthorityFields are the complete known-field
// sets. Anything else in those objects is an unknown field, and every
// known field carries its declared type — there is no implicit
// coercion and no accidental compatibility surface.
var abiRootFields = map[string]abiFieldType{
	"capability":      abiString,
	"arguments":       abiObject,
	"authority":       abiObject,
	"execution_class": abiString,
	"idempotency_key": abiString,
	"deadline":        abiString,
}

var abiAuthorityFields = map[string]abiFieldType{
	"principal":            abiString,
	"authority_ref":        abiString,
	"grant_id":             abiString,
	"authority_generation": abiInteger,
	"authority_digest":     abiString,
}

// abiIntegerLiteral is the canonical JSON integer form. Fractions,
// exponents, and leading zeros are refused so both runtimes read the
// field identically.
var abiIntegerLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// parseInvocationRequest parses wire bytes into a Request under the
// strict ABI rules.
func parseInvocationRequest(data []byte) (Request, error) {
	var req Request
	if err := scanInvocationStructure(data); err != nil {
		return req, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return req, fmt.Errorf("trailing data after the invocation object")
	}
	return req, nil
}

// abiKind classifies one JSON value during the scan.
type abiKind int

const (
	abiKindNull abiKind = iota
	abiKindString
	abiKindNumber
	abiKindBool
	abiKindObject
	abiKindArray
)

// abiFrameKind identifies the root and authority objects — the only
// containers with a known-field set.
type abiFrameKind int

const (
	abiFrameUnknown abiFrameKind = iota
	abiFrameRoot
	abiFrameAuthority
)

// abiScanFrame is one open container during the structural scan.
type abiScanFrame struct {
	object bool
	kind   abiFrameKind
	// fields is the known-field set of a root or authority object;
	// nil for every other container (argument subtrees, arrays).
	fields map[string]abiFieldType
	keys   map[string]struct{}
	// pending reports whether an object key is awaiting its value.
	pending bool
	key     string
	path    string
}

// scanInvocationStructure walks the JSON token stream and enforces
// rules R1–R8. It never mutates the input and never allocates the
// request structure — it decides whether the bytes are unambiguous
// enough to decode.
func scanInvocationStructure(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("request is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var stack []*abiScanFrame
	completed := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// After the request object is complete, anything that is
			// not valid JSON is trailing data — the request itself
			// already parsed.
			if completed {
				return fmt.Errorf("trailing data after the request object")
			}
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if len(stack) == 0 {
			if completed {
				return fmt.Errorf("trailing data after the request object")
			}
			delim, ok := tok.(json.Delim)
			if !ok || delim != '{' {
				return fmt.Errorf("request must be a JSON object")
			}
			stack = append(stack, &abiScanFrame{object: true, kind: abiFrameRoot, fields: abiRootFields, path: "request"})
			continue
		}
		top := stack[len(stack)-1]

		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if len(stack) >= maxInvocationDepth {
					return fmt.Errorf("request nesting exceeds %d levels", maxInvocationDepth)
				}
				child := &abiScanFrame{object: delim == '{'}
				if top.object && top.pending {
					kind := abiKindArray
					if delim == '{' {
						kind = abiKindObject
					}
					if err := validateABIField(top, kind, ""); err != nil {
						return err
					}
					child.path = top.path + "." + top.key
					if top.kind == abiFrameRoot && top.key == "authority" {
						child.kind = abiFrameAuthority
						child.fields = abiAuthorityFields
					}
					top.pending = false
				} else if top.object {
					return fmt.Errorf("unexpected object in %s", top.path)
				} else {
					child.path = top.path + "[]"
				}
				stack = append(stack, child)
			case '}', ']':
				if (delim == '}') != top.object {
					return fmt.Errorf("mismatched JSON delimiter in %s", top.path)
				}
				if top.object && top.pending {
					return fmt.Errorf("key %q in %s has no value", top.key, top.path)
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					completed = true
				}
			}
			continue
		}

		switch value := tok.(type) {
		case string:
			if top.object && top.pending {
				if err := validateABIField(top, abiKindString, ""); err != nil {
					return err
				}
				top.pending = false
				continue
			}
			if top.object {
				if _, dup := top.keys[value]; dup {
					return fmt.Errorf("duplicate key %q in %s", value, top.path)
				}
				if top.fields != nil {
					if _, known := top.fields[value]; !known {
						return fmt.Errorf("unknown field %q in %s", value, top.path)
					}
				}
				if top.keys == nil {
					top.keys = make(map[string]struct{}, 4)
				}
				top.keys[value] = struct{}{}
				top.pending, top.key = true, value
			}
		case json.Number:
			if top.object && top.pending {
				if err := validateABIField(top, abiKindNumber, value.String()); err != nil {
					return err
				}
				top.pending = false
			}
		case bool:
			if top.object && top.pending {
				if err := validateABIField(top, abiKindBool, ""); err != nil {
					return err
				}
				top.pending = false
			}
		case nil:
			if top.object && top.pending {
				if err := validateABIField(top, abiKindNull, ""); err != nil {
					return err
				}
				top.pending = false
			}
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("invalid JSON: unexpected end of input")
	}
	if !completed {
		return fmt.Errorf("request must be a JSON object")
	}
	return nil
}

// validateABIField enforces R7 and R8 for one value bound to a known
// field. Unknown containers (argument subtrees, arrays) carry no rules:
// their shape belongs to the capability schema, not the wire ABI.
func validateABIField(frame *abiScanFrame, kind abiKind, numberLiteral string) error {
	if frame.fields == nil {
		return nil
	}
	want, known := frame.fields[frame.key]
	if !known {
		return nil
	}
	field := frame.path + "." + frame.key
	if kind == abiKindNull {
		return fmt.Errorf("null is not accepted for %s (omit the field instead)", field)
	}
	switch want {
	case abiString:
		if kind != abiKindString {
			return fmt.Errorf("%s must be a JSON string", field)
		}
	case abiObject:
		if kind != abiKindObject {
			return fmt.Errorf("%s must be a JSON object", field)
		}
	case abiInteger:
		if kind != abiKindNumber {
			return fmt.Errorf("%s must be a JSON integer", field)
		}
		if !abiIntegerLiteral.MatchString(numberLiteral) {
			return fmt.Errorf("%s must be a JSON integer literal", field)
		}
		if _, err := strconv.ParseInt(numberLiteral, 10, 64); err != nil {
			return fmt.Errorf("%s must fit in a signed 64-bit integer", field)
		}
	}
	return nil
}
