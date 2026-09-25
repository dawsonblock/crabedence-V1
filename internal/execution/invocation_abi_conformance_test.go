package execution

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInvocationABIConformanceCorpus runs the shared Go↔NEMO corpus
// against the Go parser. NEMO runs the same corpus from
// nemo/test/invocation-abi-conformance.test.ts — both runtimes must
// accept or reject each raw wire request identically, and every
// rejection must include the corpus's rule-level error phrase.
func TestInvocationABIConformanceCorpus(t *testing.T) {
	type vector struct {
		Name          string `json:"name"`
		Wire          string `json:"wire"`
		WireB64       string `json:"wire_b64"`
		Expected      string `json:"expected"`
		ErrorContains string `json:"error_contains"`
	}
	var corpus struct {
		Vectors []vector `json:"vectors"`
	}
	data, err := os.ReadFile(filepath.Join("testdata", "invocation-abi-conformance", "vectors.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(corpus.Vectors) == 0 {
		t.Fatal("conformance corpus is empty")
	}
	for _, v := range corpus.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			wire := []byte(v.Wire)
			if v.WireB64 != "" {
				decoded, err := base64.StdEncoding.DecodeString(v.WireB64)
				if err != nil {
					t.Fatalf("decode wire_b64: %v", err)
				}
				wire = decoded
			}
			_, err := parseInvocationRequest(wire)
			switch v.Expected {
			case "accept":
				if err != nil {
					t.Fatalf("expected acceptance, got error: %v", err)
				}
			case "reject":
				if err == nil {
					t.Fatal("expected rejection, got acceptance")
				}
				if v.ErrorContains != "" && !strings.Contains(err.Error(), v.ErrorContains) {
					t.Fatalf("error %q does not contain %q", err, v.ErrorContains)
				}
			default:
				t.Fatalf("unknown expectation %q", v.Expected)
			}
		})
	}
}
