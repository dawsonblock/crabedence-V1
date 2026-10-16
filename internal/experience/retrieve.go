package experience

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openclaw/crabbox/internal/history"
)

// Problems returns every node classified as an observed failure —
// the set the research controller diagnoses over.
func (g *Graph) Problems() []*Node {
	return g.byKind(NodeProblem)
}

// Interventions returns every intervention node.
func (g *Graph) Interventions() []*Node {
	return g.byKind(NodeIntervention)
}

func (g *Graph) byKind(kind string) []*Node {
	var out []*Node
	for _, n := range g.Nodes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// EdgesFor returns the edges touching a node, optionally filtered
// to one relation.
func (g *Graph) EdgesFor(nodeID string, rels ...string) []*Edge {
	want := map[string]bool{}
	for _, r := range rels {
		want[r] = true
	}
	var out []*Edge
	for _, e := range g.Edges {
		if e.From != nodeID && e.To != nodeID {
			continue
		}
		if len(want) > 0 && !want[e.Rel] {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Superseded reports whether a node's observation has been replaced
// by a newer one of the same subject — stale memory the caller
// should not act on.
func (g *Graph) Superseded(nodeID string) bool {
	for _, e := range g.Edges {
		if e.Rel == RelSupersedes && e.To == nodeID {
			return true
		}
	}
	return false
}

// Contradictions returns every contradiction edge — conflicts the
// record holds openly rather than resolving silently.
func (g *Graph) Contradictions() []*Edge {
	var out []*Edge
	for _, e := range g.Edges {
		if e.Rel == RelContradicts {
			out = append(out, e)
		}
	}
	return out
}

// CandidatesFor returns the intervention nodes linked to a problem
// as candidate causes — labeled candidates, each with its Why.
func (g *Graph) CandidatesFor(problemID string) []*Edge {
	var out []*Edge
	for _, e := range g.Edges {
		if e.Rel == RelCandidateCause && e.To == problemID {
			out = append(out, e)
		}
	}
	return out
}

// Explain renders a node's position in the experience: what it is,
// what it links to, and under what trust. The reasoning record an
// operator (or a controller's diagnosis prompt) actually sees.
func (g *Graph) Explain(nodeID string) string {
	n := g.Nodes[nodeID]
	if n == nil {
		return fmt.Sprintf("unknown node %s", nodeID)
	}
	var b strings.Builder
	trust := n.Trust
	if trust == "" {
		trust = "unassessed"
	}
	fmt.Fprintf(&b, "%s %s (%s, seq %d, trust %s): %s\n",
		n.Kind, n.ID, n.EventKind, n.Seq, trust, n.Summary)
	if g.Superseded(nodeID) {
		b.WriteString("  superseded by a later observation\n")
	}
	for _, e := range g.EdgesFor(nodeID) {
		dir := "→"
		other := e.To
		if e.To == nodeID {
			dir = "←"
			other = e.From
		}
		fmt.Fprintf(&b, "  %s %s %s — %s\n", dir, e.Rel, other, e.Why)
	}
	return b.String()
}

// RetrievalScore measures the graph's retrieval quality against a
// golden set: for each query node, the node IDs the expected
// relation must reach. Precision/recall across the golden set are
// the memory-quality metric — a reconstruction that retrieves the
// wrong neighbors is measurably wrong, not vaguely disappointing.
type RetrievalCase struct {
	Query  string   // node ID to query
	Rel    string   // relation to follow
	Expect []string // node IDs that must be reached
	Forbid []string // node IDs that must NOT be reached
}

// EvalRetrieval scores the graph against labeled cases and returns
// precision, recall, and the violated constraints — the evaluation
// harness's evidence that memory reconstructs the experience it
// claims to.
func (g *Graph) EvalRetrieval(cases []*RetrievalCase) (precision, recall float64, violations []string) {
	var hits, retrieved, expected int
	for _, c := range cases {
		reached := map[string]bool{}
		for _, e := range g.Edges {
			if e.Rel != c.Rel {
				continue
			}
			if e.From == c.Query {
				reached[e.To] = true
			}
			if e.To == c.Query && e.From != c.Query {
				reached[e.From] = true
			}
		}
		exp := map[string]bool{}
		for _, id := range c.Expect {
			exp[id] = true
			expected++
			if reached[id] {
				hits++
			} else {
				violations = append(violations,
					fmt.Sprintf("query %s rel %s missed expected %s", c.Query, c.Rel, id))
			}
		}
		for id := range reached {
			retrieved++
			if !exp[id] {
				violations = append(violations,
					fmt.Sprintf("query %s rel %s retrieved unexpected %s", c.Query, c.Rel, id))
			}
		}
		for _, id := range c.Forbid {
			if reached[id] {
				violations = append(violations,
					fmt.Sprintf("query %s rel %s reached forbidden %s", c.Query, c.Rel, id))
			}
		}
	}
	if retrieved > 0 {
		precision = float64(hits) / float64(retrieved)
	}
	if expected > 0 {
		recall = float64(hits) / float64(expected)
	}
	return precision, recall, violations
}

// Trusted filters the graph to nodes carrying no adverse verdict —
// VERIFIED, or never assessed (""). Nodes the assessment layer
// actively could not establish — REJECTED, CONFLICTED, STALE,
// UNVERIFIED — are excluded: they are not deleted from the graph,
// they are not offered to the learner.
func (g *Graph) Trusted() *Graph {
	out := &Graph{Nodes: map[string]*Node{}}
	for id, n := range g.Nodes {
		switch n.Trust {
		case history.AssessmentRejected, history.AssessmentConflicted,
			history.AssessmentStale, history.AssessmentUnverified:
			continue
		}
		out.Nodes[id] = n
	}
	for _, e := range g.Edges {
		if _, ok := out.Nodes[e.From]; !ok {
			continue
		}
		if _, ok := out.Nodes[e.To]; !ok {
			continue
		}
		out.Edges = append(out.Edges, e)
	}
	return out
}
