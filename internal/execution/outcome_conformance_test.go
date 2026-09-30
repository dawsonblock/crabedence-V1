package execution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/idempotency"
)

// The outcome corpus is shared with the TypeScript reference adapter and the
// Rust bridge. This test binds it to the kernel: every wire status in the
// corpus must be one the service can emit, and every vector that crossed the
// dispatch boundary must classify exactly as classifyPostDispatch decides.
//
// That is the direction the trust runs. The planners must agree with the
// kernel's table, not the other way around.

type outcomeVector struct {
	Name         string          `json:"name"`
	Response     json.RawMessage `json:"response"`
	Shape        string          `json:"shape"`
	ErrorPhrase  string          `json:"error_contains"`
	PostDispatch bool            `json:"post_dispatch"`
	KernelState  string          `json:"kernel_state"`
	NemoStatus   string          `json:"nemo_status"`
}

func loadOutcomeCorpus(t *testing.T) []outcomeVector {
	t.Helper()
	path := filepath.Join("testdata", "outcome-conformance", "vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shared outcome corpus: %v", err)
	}
	var document struct {
		Vectors []outcomeVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse the shared outcome corpus: %v", err)
	}
	if len(document.Vectors) == 0 {
		t.Fatal("the outcome corpus must not be empty")
	}
	return document.Vectors
}

func TestOutcomeCorpusUsesStatusesTheKernelCanEmit(t *testing.T) {
	emittable := map[string]bool{
		StatusSucceeded: true,
		StatusFailed:    true,
		StatusDenied:    true,
		StatusUnknown:   true,
		StatusInFlight:  true,
	}
	for _, vector := range loadOutcomeCorpus(t) {
		var response struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(vector.Response, &response); err != nil {
			t.Fatalf("vector %s: response is not an object: %v", vector.Name, err)
		}
		// A rejection vector deliberately carries a status the kernel cannot
		// emit; that is the point of it.
		if vector.Shape == "reject" {
			continue
		}
		if !emittable[response.Status] {
			t.Errorf("vector %s: %q is not a status the service can emit", vector.Name, response.Status)
		}
	}
}

func TestOutcomeCorpusMatchesThePostDispatchTable(t *testing.T) {
	descriptor, err := capability.Resolve(capability.CapabilityDescriptor{
		ID:             "test.counter.increment",
		ExecutionClass: capability.ClassMutation,
		AdapterID:      "test-counter",
		AuthorityPolicy: capability.AuthorityPolicy{
			ID:            "test.counter",
			GrantRequired: true,
		},
	})
	if err != nil {
		t.Fatalf("resolve descriptor: %v", err)
	}

	checked := 0
	for _, vector := range loadOutcomeCorpus(t) {
		if !vector.PostDispatch {
			continue
		}
		if vector.KernelState == "" {
			t.Errorf("vector %s: a post-dispatch vector must declare kernel_state", vector.Name)
			continue
		}
		var response Response
		if err := json.Unmarshal(vector.Response, &response); err != nil {
			t.Fatalf("vector %s: response does not decode: %v", vector.Name, err)
		}
		state, _ := classifyPostDispatch(response, descriptor)
		if got := string(state); got != vector.KernelState {
			t.Errorf("vector %s: classifyPostDispatch says %s, the corpus says %s",
				vector.Name, got, vector.KernelState)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("the corpus must cover the dispatch boundary, otherwise it proves nothing")
	}
}

func TestOutcomeCorpusKernelStatesAreRealStates(t *testing.T) {
	known := map[string]bool{
		string(idempotency.StateCommitted): true,
		string(idempotency.StateFailed):    true,
		string(idempotency.StateUnknown):   true,
		string(idempotency.StateDenied):    true,
	}
	for _, vector := range loadOutcomeCorpus(t) {
		if vector.KernelState == "" {
			continue
		}
		if !known[vector.KernelState] {
			t.Errorf("vector %s: %q is not a durable effect state", vector.Name, vector.KernelState)
		}
	}
}
