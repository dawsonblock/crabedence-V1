package execution

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/history"
)

// historyReads / historyMutations are the governed memory surface the
// release registers — reads must route DIRECT (observational,
// unaudited-effect-free), mutations must route CRABEDENCE under a grant.
var (
	historyReads = []string{
		"history.query", "history.verify", "history.explain",
		"research.diagnose", "research.propose",
	}
	historyMutations = []string{
		"history.append", "history.checkpoint", "research.record_decision",
	}
)

// TestHistoryCapabilitiesRegistration asserts the governed memory
// surface lands in the release registry with the right effect
// classes, routes, assurance, and authority posture — the contract
// that keeps memory observational and mutations governed.
func TestHistoryCapabilitiesRegistration(t *testing.T) {
	reg := capability.NewRegistry()
	if err := RegisterHistoryCapabilities(reg); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, id := range historyReads {
		d, ok := reg.Lookup(id)
		if !ok {
			t.Fatalf("%s not registered", id)
		}
		if d.ExecutionClass != capability.ClassRead {
			t.Fatalf("%s class = %s, want READ", id, d.ExecutionClass)
		}
		if d.ExecutionRoute != capability.RouteDirect {
			t.Fatalf("%s route = %s, want DIRECT", id, d.ExecutionRoute)
		}
		if d.AuthorityPolicy.GrantRequired {
			t.Fatalf("%s requires a grant — a governed read must not", id)
		}
	}
	for _, id := range historyMutations {
		d, ok := reg.Lookup(id)
		if !ok {
			t.Fatalf("%s not registered", id)
		}
		if d.ExecutionClass != capability.ClassMutation {
			t.Fatalf("%s class = %s, want MUTATION", id, d.ExecutionClass)
		}
		if d.ExecutionRoute != capability.RouteCrabedence {
			t.Fatalf("%s route = %s, want CRABEDENCE — a memory mutation must not bypass the durable fabric", id, d.ExecutionRoute)
		}
		if !d.AssuranceProfile.RequiresDurableStore() {
			t.Fatalf("%s assurance = %s, want durable or higher", id, d.AssuranceProfile)
		}
		if !d.AuthorityPolicy.GrantRequired {
			t.Fatalf("%s does not require a grant — memory writes are governed effects", id)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("registry invariant scan: %v", err)
	}
}

// TestBuiltinRegistryIncludesMemorySurface pins the release catalog:
// the governed memory capabilities are release policy, not an
// extension that can vary by deployment.
func TestBuiltinRegistryIncludesMemorySurface(t *testing.T) {
	reg := capability.NewRegistry()
	if err := RegisterBuiltinCapabilities(reg); err != nil {
		t.Fatalf("builtin registration: %v", err)
	}
	for _, id := range append(append([]string{}, historyReads...), historyMutations...) {
		if _, ok := reg.Lookup(id); !ok {
			t.Fatalf("%s missing from the release registry", id)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("release registry invariant scan: %v", err)
	}
}

// TestHistoryArgumentValidation checks the schemas reject malformed
// calls at admission, before any adapter sees them.
func TestHistoryArgumentValidation(t *testing.T) {
	reg := capability.NewRegistry()
	if err := RegisterHistoryCapabilities(reg); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id   string
		args string
		bad  bool
		why  string
	}{
		{"history.query", `{"limit": 10}`, false, "bounded query"},
		{"history.query", `{"limit": 501}`, true, "limit over the adapter ceiling"},
		{"history.query", `{"limit": 0}`, true, "zero limit"},
		{"history.query", `{"bogus": 1}`, true, "unknown field"},
		{"history.explain", `{"node": "a"}`, false, "required field present"},
		{"history.explain", `{}`, true, "node required"},
		{"research.propose", `{}`, true, "envelope+task required"},
		{"research.propose", `{"envelope": {}, "task": {}}`, false, "shape valid; envelope semantics are the adapter's job"},
		{"history.append", `{"subject": "s", "payload": {"x": 1}}`, false, "required fields present"},
		{"history.append", `{"subject": "s"}`, true, "payload required"},
		{"history.checkpoint", `{}`, true, "dir required"},
		{"history.checkpoint", `{"dir": "/tmp/x"}`, false, "required field present"},
	}
	for _, c := range cases {
		d, _ := reg.Lookup(c.id)
		err := capability.ValidateArguments(d.Schema, json.RawMessage(c.args))
		if c.bad && err == nil {
			t.Fatalf("%s %s: accepted but should fail (%s)", c.id, c.args, c.why)
		}
		if !c.bad && err != nil {
			t.Fatalf("%s %s: rejected (%v) but should pass (%s)", c.id, c.args, err, c.why)
		}
	}
}

func newTestHistoryAdapter(t *testing.T) (*HistoryAdapter, *history.Store) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "history.db")
	s, err := history.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewHistoryAdapter(db, "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); s.Close() })
	return a, s
}

// TestHistoryAdapterReadSurface exercises the governed reads against
// a real store: query filters, verify integrity, explain, diagnose.
func TestHistoryAdapterReadSurface(t *testing.T) {
	a, s := newTestHistoryAdapter(t)
	if _, err := s.Append(&history.Event{
		DedupeKey: "e1", Kind: history.KindExecution, Subject: "job-1",
		Correlation: "task-1", Source: "test", OccurredAt: 1000,
		Payload: json.RawMessage(`{"rc": 1}`),
	}); err != nil {
		t.Fatal(err)
	}

	// history.query filters to the seeded event.
	resp := a.Execute(context.Background(), Request{
		Capability: "history.query",
		Arguments:  json.RawMessage(`{"subject": "job-1"}`),
	}, capability.ResolvedDescriptor{})
	if resp.Status != StatusSucceeded {
		t.Fatalf("history.query: %s", resp.Error)
	}
	var qr struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(resp.Result, &qr); err != nil || qr.Count != 1 {
		t.Fatalf("query result = %s, want 1 event", resp.Result)
	}

	// history.verify reports a clean chain over the seeded store.
	resp = a.Execute(context.Background(), Request{Capability: "history.verify"}, capability.ResolvedDescriptor{})
	var vr struct {
		OK     bool `json:"ok"`
		Events int  `json:"events"`
	}
	if resp.Status != StatusSucceeded {
		t.Fatalf("history.verify: %s", resp.Error)
	}
	if err := json.Unmarshal(resp.Result, &vr); err != nil || !vr.OK || vr.Events != 1 {
		t.Fatalf("verify result = %s, want ok with 1 event", resp.Result)
	}

	// history.explain renders the node's position; unknown nodes
	// report unknown rather than fabricating.
	resp = a.Execute(context.Background(), Request{
		Capability: "history.explain",
		Arguments:  json.RawMessage(`{"node": "e1"}`),
	}, capability.ResolvedDescriptor{})
	if resp.Status != StatusSucceeded {
		t.Fatalf("history.explain: %s", resp.Error)
	}
	var er struct {
		Known bool `json:"known"`
	}
	if err := json.Unmarshal(resp.Result, &er); err != nil || !er.Known {
		t.Fatalf("explain result = %s, want known node", resp.Result)
	}

	// research.diagnose returns signatures (empty here — no failures
	// recorded as such) without inventing any.
	resp = a.Execute(context.Background(), Request{Capability: "research.diagnose"}, capability.ResolvedDescriptor{})
	if resp.Status != StatusSucceeded {
		t.Fatalf("research.diagnose: %s", resp.Error)
	}
}

// TestHistoryAdapterAppendAndDecision covers the two grant-gated
// mutations — at the adapter level they still enforce their semantic
// contracts (identity, envelope membership).
func TestHistoryAdapterAppendAndDecision(t *testing.T) {
	a, s := newTestHistoryAdapter(t)

	resp := a.Execute(context.Background(), Request{
		Capability: "history.append",
		Arguments:  json.RawMessage(`{"subject": "note-1", "payload": {"text": "hi"}}`),
	}, capability.ResolvedDescriptor{})
	if resp.Status != StatusSucceeded {
		t.Fatalf("history.append: %s", resp.Error)
	}
	// The event landed and the chain verifies.
	if findings := s.Verify(); len(findings) != 0 {
		t.Fatalf("post-append verify: %v", findings)
	}
	// Idempotent: a second identical append dedupes to zero appends.
	resp = a.Execute(context.Background(), Request{
		Capability: "history.append",
		Arguments:  json.RawMessage(`{"subject": "note-1", "payload": {"text": "hi"}}`),
	}, capability.ResolvedDescriptor{})
	var ar struct {
		Appended int `json:"appended"`
	}
	if err := json.Unmarshal(resp.Result, &ar); err != nil || ar.Appended != 0 {
		t.Fatalf("repeat append = %s, want deduped", resp.Result)
	}

	// record_decision without an envelope is refused at the adapter.
	resp = a.Execute(context.Background(), Request{
		Capability: "research.record_decision",
		Arguments:  json.RawMessage(`{"decision": {"arm": 0}}`),
	}, capability.ResolvedDescriptor{})
	if resp.Status != StatusFailed {
		t.Fatalf("envelope-less decision accepted: %s", resp.Result)
	}
}

// TestHistoryAdapterCheckpointTrust asserts witnessed state is never
// minted under an unnamed identity: no configured witness, no
// checkpoint — the refusal is explicit, not silent.
func TestHistoryAdapterCheckpointTrust(t *testing.T) {
	a, _ := newTestHistoryAdapter(t)
	resp := a.Execute(context.Background(), Request{
		Capability: "history.checkpoint",
		Arguments:  json.RawMessage(`{"dir": "/tmp/x"}`),
	}, capability.ResolvedDescriptor{})
	if resp.Status != StatusFailed || !strings.Contains(resp.Error, "witness") {
		t.Fatalf("unwitnessed checkpoint: status=%s err=%s", resp.Status, resp.Error)
	}
	if !resp.DefinitiveFailure {
		t.Fatal("witness refusal must be a definitive failure — no side effect occurred")
	}
}

// TestHistoryAdapterCheckpointRoundTrip exercises the witnessed
// checkpoint against a real witness key.
func TestHistoryAdapterCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "history.db")
	s, err := history.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Append(&history.Event{
		DedupeKey: "e1", Kind: history.KindExecution, Subject: "j",
		Source: "test", OccurredAt: 1, Payload: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	witnessPath := filepath.Join(dir, "witness.pem")
	if _, err := evidence.LoadOrCreateSigner(witnessPath); err != nil {
		t.Fatal(err)
	}
	a, err := NewHistoryAdapter(db, witnessPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	resp := a.Execute(context.Background(), Request{
		Capability: "history.checkpoint",
		Arguments:  json.RawMessage(`{"dir": "` + filepath.Join(dir, "cps") + `"}`),
	}, capability.ResolvedDescriptor{})
	if resp.Status != StatusSucceeded {
		t.Fatalf("witnessed checkpoint: %s", resp.Error)
	}
	var cr struct {
		Sequence int64  `json:"sequence"`
		Witness  string `json:"witness"`
	}
	if err := json.Unmarshal(resp.Result, &cr); err != nil || cr.Sequence < 1 || cr.Witness == "" {
		t.Fatalf("checkpoint result = %s", resp.Result)
	}
}
