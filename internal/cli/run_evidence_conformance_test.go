package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conformanceFixture is a single case in the shared Go↔TypeScript evidence
// conformance corpus. Both runtimes must accept or reject each fixture
// identically.
type conformanceFixture struct {
	Name          string          `json:"name"`
	Evidence      json.RawMessage `json:"evidence"`
	Expected      string          `json:"expected"` // "accept" or "reject"
	ErrorContains string          `json:"error_contains,omitempty"`
}

type conformanceFile struct {
	Description string               `json:"description"`
	Fixtures    []conformanceFixture `json:"fixtures"`
}

// TestRunEvidenceConformanceCorpus loads the shared fixture file and verifies
// that the Go evidence parser/validator accepts or rejects each fixture as
// expected. The same fixture file is consumed by the TypeScript test
// (worker/test/run-evidence-conformance.test.ts), and both must agree.
//
// This is the protocol-conformance gate: it is more important than merely
// matching hashes. If Go accepts a fixture that TypeScript rejects (or vice
// versa), the wire contract is broken.
func TestRunEvidenceConformanceCorpus(t *testing.T) {
	path := filepath.Join("testdata", "run-evidence-conformance", "fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read conformance fixtures: %v", err)
	}
	var file conformanceFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse conformance fixtures: %v", err)
	}
	if len(file.Fixtures) == 0 {
		t.Fatal("no conformance fixtures found")
	}
	for _, fx := range file.Fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			// Parse the evidence with the strict parser.
			ev, parseErr := ParseRunEvidenceV1(fx.Evidence)
			// If parsing fails, check whether rejection was expected.
			if parseErr != nil {
				if fx.Expected == "reject" {
					if fx.ErrorContains != "" && !strings.Contains(parseErr.Error(), fx.ErrorContains) {
						t.Errorf("expected error containing %q, got: %v", fx.ErrorContains, parseErr)
					}
					return
				}
				t.Fatalf("unexpected parse error: %v", parseErr)
			}
			// Validate the parsed evidence semantically.
			validateErr := ValidateRunEvidenceV1(ev)
			if fx.Expected == "reject" {
				// Either parse or validation should have rejected it.
				var errStr string
				if validateErr != nil {
					errStr = validateErr.Error()
				} else {
					// If neither parse nor validation rejected it, but the
					// fixture expects rejection, the most common reason is
					// a digest mismatch (the zero digest won't match).
					// Check the digest.
					digestErr := VerifyRunEvidenceDigestError(ev)
					if digestErr != nil {
						errStr = digestErr.Error()
					}
				}
				if errStr == "" {
					t.Fatalf("expected rejection but evidence was accepted")
				}
				if fx.ErrorContains != "" && !strings.Contains(errStr, fx.ErrorContains) {
					t.Errorf("expected error containing %q, got: %s", fx.ErrorContains, errStr)
				}
				return
			}
			// Expected accept: validation should pass.
			if validateErr != nil {
				t.Fatalf("unexpected validation error: %v", validateErr)
			}
		})
	}
}
