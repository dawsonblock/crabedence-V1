// Package experience reconstructs causal experience from the
// unified history: not just what events occurred, but how they
// relate — which failures preceded which interventions, which
// interventions a later outcome followed, which records contradict
// each other, and which observations supersede earlier ones.
//
// The reconstruction is honest about what it knows: every edge
// carries the rule and the evidence that produced it (a shared
// subject, a shared correlation, a shared file path, a temporal
// bound), never a claim the store cannot back. A causal graph of
// provenance-verified history is what the research controller
// learns from; a graph of plausible-sounding guesses is noise
// wearing a lab coat.
package experience

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/openclaw/crabbox/internal/history"
)

// Node kinds — what role an event plays in the experience.
const (
	// NodeProblem is an observed failure: a failed test result, a
	// failed or interrupted execution, a rejected piece of evidence.
	NodeProblem = "problem"
	// NodeIntervention is a deliberate change: a code commit, an
	// explorer decision — something done that might alter outcomes.
	NodeIntervention = "intervention"
	// NodeOutcome is a realized result: an execution, a test run, a
	// receipt — the consequence record.
	NodeOutcome = "outcome"
	// NodeObservation is a factual sighting: job registry rows,
	// custody acks, archives, experiment records.
	NodeObservation = "observation"
	// NodeStatement is authored content: conversation messages,
	// trace actions, documents — the reasoning record.
	NodeStatement = "statement"
)

// Edge relations — the only links the reconstruction will claim.
const (
	// RelSupersedes: a newer observation replaces an earlier one of
	// the same subject (job state rollforward, corrected record).
	RelSupersedes = "supersedes"
	// RelResolves: a later passing result answers an earlier failure
	// of the same test — evidence the problem ended, not proof of
	// what ended it.
	RelResolves = "resolves"
	// RelCandidateCause: an intervention committed between a
	// failure and its resolution, sharing the failure's path — a
	// candidate, honestly labeled, never asserted as the cause.
	RelCandidateCause = "candidate_cause"
	// RelContradicts: two records of the same subject asserting
	// irreconcilable facts (conflicting experiment outcomes, a
	// version conflict inside one archive).
	RelContradicts = "contradicts"
	// RelReferences: a statement names the file path an
	// intervention changed — conversation linked to code.
	RelReferences = "references"
	// RelAttests: a custody ack or receipt binds its subject —
	// witnessed state, not content.
	RelAttests = "attests"
)

// Node is one event's place in the experience.
type Node struct {
	ID        string `json:"id"`   // the event's dedupe key
	Kind      string `json:"kind"` // experience role
	EventKind string `json:"event_kind"`
	Subject   string `json:"subject"`
	Summary   string `json:"summary"`
	Seq       int64  `json:"seq"`
	At        int64  `json:"at"`
	// Trust is the assessment the store currently reports for the
	// observation: VERIFIED/REJECTED/UNVERIFIED/CONFLICTED/STALE.
	// Consumers that need provenance-verified memory filter on it;
	// the graph does not silently hide untrusted nodes — it labels.
	Trust string `json:"trust"`
	// Paths are the file references the event commits to — the
	// structural link between reasoning (statements) and code
	// (interventions).
	Paths []string `json:"paths,omitempty"`
}

// Edge is one claimed relation between two nodes, with the evidence
// that produced it.
type Edge struct {
	From string `json:"from"` // node IDs
	To   string `json:"to"`
	Rel  string `json:"rel"`
	Why  string `json:"why"` // the rule + evidence — audit, not ornament
}

// Graph is the reconstructed experience.
type Graph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []*Edge          `json:"edges"`
}

// Reconstruct builds the experience graph from the event store.
// rulesVersion stamps the extraction rules — the same events under
// a newer rules version produce a different graph, and assessments
// of graph quality name which rules produced it.
const rulesVersion = "experience-v1"

// Reconstruct reads every event, classifies each into a node kind,
// and links them under the documented relations.
func Reconstruct(s *history.Store, trustSetSHA string) (*Graph, error) {
	events, err := s.Query(history.QueryOpts{})
	if err != nil {
		return nil, err
	}
	// Query returns newest-first; reconstruction walks chain order.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	g := &Graph{Nodes: map[string]*Node{}}
	for _, e := range events {
		n := &Node{
			ID:        e.DedupeKey,
			EventKind: e.Kind,
			Subject:   e.Subject,
			Seq:       e.Seq,
			At:        e.OccurredAt,
		}
		n.Kind = classify(e)
		n.Summary, n.Paths = summarize(e)
		if trustSetSHA != "" {
			if eff, err := s.EffectiveAssessment(e.DedupeKey, assessmentRules(e), trustSetSHA); err == nil {
				// No verdict under this ruleset is recorded as "" —
				// "never assessed" is honest absence, distinct from
				// a real UNVERIFIED verdict a verifier produced.
				if eff.Verifier != "" || eff.Result != history.AssessmentUnverified {
					n.Trust = eff.Result
				}
			}
		}
		g.Nodes[n.ID] = n
	}
	linkSameSubject(g, events)
	linkResolutions(g, events)
	linkPaths(g, events)
	linkAttestations(g, events)
	markContradictions(g, events)
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		if g.Edges[i].To != g.Edges[j].To {
			return g.Edges[i].To < g.Edges[j].To
		}
		return g.Edges[i].Rel < g.Edges[j].Rel
	})
	return g, nil
}

// assessmentRules maps an event kind to the assessment rules version
// its ingester records verdicts under.
func assessmentRules(e *history.Event) string {
	switch e.Kind {
	case history.KindReceipt:
		return "receipt-v1"
	case history.KindCheckpoint:
		return "checkpoint-v1"
	case history.KindCustodyAck:
		return "custody-v1"
	}
	return "observation-v1"
}

// classify assigns an event its experience role.
func classify(e *history.Event) string {
	switch e.Kind {
	case history.KindCodeChange, history.KindDecision:
		return NodeIntervention
	case history.KindTestRun, history.KindReceipt, history.KindExecution:
		return NodeOutcome
	case history.KindTestResult:
		var p struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(e.Payload, &p) == nil && p.Status == "fail" {
			return NodeProblem
		}
		return NodeOutcome
	case history.KindConversation, history.KindTrace, history.KindDocument:
		return NodeStatement
	default:
		return NodeObservation
	}
}

// summarize extracts a node's display summary and its file paths.
func summarize(e *history.Event) (string, []string) {
	var m map[string]json.RawMessage
	if json.Unmarshal(e.Payload, &m) != nil {
		return e.Subject, nil
	}
	paths := jsonStringSlice(m, "file_refs", "files", "paths")
	if fr, ok := m["file_refs"]; ok {
		var p []string
		if json.Unmarshal(fr, &p) == nil {
			paths = append(paths, p...)
		}
	}
	// code_change payloads carry per-file stats; pull their paths.
	if files, ok := m["files"]; ok {
		var arr []map[string]json.RawMessage
		if json.Unmarshal(files, &arr) == nil {
			for _, f := range arr {
				var p string
				if json.Unmarshal(f["path"], &p) == nil && p != "" {
					paths = append(paths, p)
				}
			}
		}
	}
	for _, key := range []string{"text", "message", "summary", "outcome", "state", "hypothesis", "detail"} {
		if v, ok := m[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" {
				if len(s) > 160 {
					s = s[:157] + "..."
				}
				return s, dedupeStrings(paths)
			}
		}
	}
	return e.Subject, dedupeStrings(paths)
}

func jsonStringSlice(m map[string]json.RawMessage, keys ...string) []string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			var out []string
			if json.Unmarshal(v, &out) == nil {
				return out
			}
		}
	}
	return nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// linkSameSubject chains each subject's observations in chain order:
// the newer observation supersedes the prior — the store keeps both,
// the graph records which one currently speaks.
func linkSameSubject(g *Graph, events []*history.Event) {
	last := map[string]*history.Event{}
	for _, e := range events {
		prev, ok := last[e.Subject+":"+e.Kind]
		last[e.Subject+":"+e.Kind] = e
		if !ok {
			continue
		}
		if prev.DedupeKey == e.DedupeKey {
			continue
		}
		g.Edges = append(g.Edges, &Edge{
			From: e.DedupeKey, To: prev.DedupeKey, Rel: RelSupersedes,
			Why: fmt.Sprintf("same subject %q kind %q, later in chain order", e.Subject, e.Kind),
		})
	}
}

// linkResolutions connects a failure to a later pass of the same
// test subject — the evidence the problem ended — and marks every
// intervention committed between them on a shared path as a
// candidate cause.
func linkResolutions(g *Graph, events []*history.Event) {
	// Group test results by subject.
	var fails, passes []*history.Event
	for _, e := range events {
		if e.Kind != history.KindTestResult {
			continue
		}
		n := g.Nodes[e.DedupeKey]
		if n != nil && n.Kind == NodeProblem {
			fails = append(fails, e)
		} else {
			passes = append(passes, e)
		}
	}
	for _, f := range fails {
		for _, p := range passes {
			if p.Subject != f.Subject || p.Seq <= f.Seq {
				continue
			}
			g.Edges = append(g.Edges, &Edge{
				From: p.DedupeKey, To: f.DedupeKey, Rel: RelResolves,
				Why: fmt.Sprintf("same test %q passed at seq %d after failing at seq %d", p.Subject, p.Seq, f.Seq),
			})
			// Interventions between the failure and the pass that
			// touch a shared path are candidate causes — labeled
			// candidates, never asserted.
			for _, e2 := range events {
				n2 := g.Nodes[e2.DedupeKey]
				if n2 == nil || n2.Kind != NodeIntervention || e2.Seq <= f.Seq || e2.Seq >= p.Seq {
					continue
				}
				if sharedPath(g.Nodes[f.DedupeKey], n2) {
					g.Edges = append(g.Edges, &Edge{
						From: n2.ID, To: f.DedupeKey, Rel: RelCandidateCause,
						Why: fmt.Sprintf("intervention seq %d sits between failure %d and resolution %d on a shared path", e2.Seq, f.Seq, p.Seq),
					})
				}
			}
		}
	}
}

// sharedPath reports whether two nodes name a common file path.
func sharedPath(a, b *Node) bool {
	if a == nil || b == nil {
		return false
	}
	for _, x := range a.Paths {
		for _, y := range b.Paths {
			if x == y {
				return true
			}
		}
	}
	return false
}

// linkPaths connects statements (conversation messages, traces) to
// interventions that changed a path the statement names — the
// reasoning ↔ code link.
func linkPaths(g *Graph, events []*history.Event) {
	var interventions []*Node
	for _, e := range events {
		if n := g.Nodes[e.DedupeKey]; n != nil && n.Kind == NodeIntervention && len(n.Paths) > 0 {
			interventions = append(interventions, n)
		}
	}
	if len(interventions) == 0 {
		return
	}
	for _, e := range events {
		n := g.Nodes[e.DedupeKey]
		if n == nil || n.Kind != NodeStatement || len(n.Paths) == 0 {
			continue
		}
		for _, iv := range interventions {
			if sharedPath(n, iv) {
				g.Edges = append(g.Edges, &Edge{
					From: n.ID, To: iv.ID, Rel: RelReferences,
					Why: "statement names a path the intervention changed",
				})
			}
		}
	}
}

// linkAttestations binds custody acks and receipts to their
// subjects through the correlation key.
func linkAttestations(g *Graph, events []*history.Event) {
	byCorrelation := map[string][]*history.Event{}
	for _, e := range events {
		if e.Correlation != "" {
			byCorrelation[e.Correlation] = append(byCorrelation[e.Correlation], e)
		}
	}
	for corr, es := range byCorrelation {
		var attest, others []*history.Event
		for _, e := range es {
			if e.Kind == history.KindCustodyAck || e.Kind == history.KindReceipt {
				attest = append(attest, e)
			} else {
				others = append(others, e)
			}
		}
		for _, a := range attest {
			for _, o := range others {
				g.Edges = append(g.Edges, &Edge{
					From: a.DedupeKey, To: o.DedupeKey, Rel: RelAttests,
					Why: fmt.Sprintf("attestation shares correlation %s", corr[:min(12, len(corr))]),
				})
			}
		}
	}
}

// markContradictions records conflicts the store itself flagged —
// archives whose content identity disagrees with their filename,
// and same-subject experiment records asserting different outcomes.
func markContradictions(g *Graph, events []*history.Event) {
	outcomes := map[string]map[string]string{} // subject -> dedupe -> outcome
	for _, e := range events {
		switch e.Kind {
		case history.KindArchive:
			var p struct {
				VersionConflict bool   `json:"version_conflict"`
				Supplied        string `json:"supplied_version"`
				Detected        string `json:"detected_version"`
			}
			if json.Unmarshal(e.Payload, &p) == nil && p.VersionConflict {
				// The node carries the conflict inside itself —
				// record it as a self-contradiction finding.
				g.Edges = append(g.Edges, &Edge{
					From: e.DedupeKey, To: e.DedupeKey, Rel: RelContradicts,
					Why: fmt.Sprintf("archive filename claims %s but content declares %s", p.Supplied, p.Detected),
				})
			}
		case history.KindExperiment:
			var p struct {
				Outcome string `json:"outcome"`
			}
			if json.Unmarshal(e.Payload, &p) != nil || p.Outcome == "" {
				continue
			}
			if outcomes[e.Subject] == nil {
				outcomes[e.Subject] = map[string]string{}
			}
			for otherID, otherOutcome := range outcomes[e.Subject] {
				if otherOutcome != p.Outcome {
					g.Edges = append(g.Edges, &Edge{
						From: e.DedupeKey, To: otherID, Rel: RelContradicts,
						Why: fmt.Sprintf("experiment %q recorded both %q and %q", e.Subject, otherOutcome, p.Outcome),
					})
				}
			}
			outcomes[e.Subject][e.DedupeKey] = p.Outcome
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
