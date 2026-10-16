// Package research is the Dream-RSI research controller: it reads
// the reconstructed experience (internal/experience), diagnoses
// recurring failures, selects the next intervention inside an
// operator-declared envelope, and gates promotion on evidence the
// store actually holds.
//
// The controller proposes; it never executes, signs, or promotes.
// Its only output is advisory records — diagnoses and proposals —
// that carry the evidence pointers proving why they were made.
// Promotion requires independently verifiable advantage, and
// unverifiable memory counts against the proposal, not for it.
package research

import (
	"fmt"
	"sort"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/experience"
)

// Signature is one recurring failure as the experience records it:
// a subject that produced problem nodes, how often, when, whether
// anything resolved it, and which interventions the graph names as
// candidates.
type Signature struct {
	Subject    string   `json:"subject"`
	Count      int      `json:"count"` // problem nodes observed
	FirstSeq   int64    `json:"first_seq"`
	LastSeq    int64    `json:"last_seq"`
	Resolved   bool     `json:"resolved"`   // a later pass/outcome resolves the latest failure
	Trusted    bool     `json:"trusted"`    // the latest failure node carries no adverse verdict
	Candidates []string `json:"candidates"` // candidate_cause intervention IDs
	Problems   []string `json:"problems"`   // problem node IDs, chain order
}

// Diagnose groups problem nodes into failure signatures: the same
// subject failing repeatedly is one problem, not many. Only
// unresolved signatures need intervention — a resolved failure is
// already answered by whatever came after it.
func Diagnose(g *experience.Graph) []*Signature {
	bySubject := map[string]*Signature{}
	for _, n := range g.Problems() {
		sig := bySubject[n.Subject]
		if sig == nil {
			sig = &Signature{Subject: n.Subject, FirstSeq: n.Seq}
			bySubject[n.Subject] = sig
		}
		sig.Count++
		sig.LastSeq = n.Seq
		sig.Problems = append(sig.Problems, n.ID)
		sig.Trusted = n.Trust == "" || n.Trust == "VERIFIED"
	}
	var out []*Signature
	for _, sig := range bySubject {
		// Resolution: any resolves edge into the latest problem node.
		latest := sig.Problems[len(sig.Problems)-1]
		for _, e := range g.EdgesFor(latest, experience.RelResolves) {
			if e.To == latest {
				sig.Resolved = true
			}
		}
		// Candidates: interventions linked to any problem node.
		seen := map[string]bool{}
		for _, p := range sig.Problems {
			for _, e := range g.CandidatesFor(p) {
				if !seen[e.From] {
					seen[e.From] = true
					sig.Candidates = append(sig.Candidates, e.From)
				}
			}
		}
		sort.Strings(sig.Candidates)
		out = append(out, sig)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Resolved != out[j].Resolved {
			return !out[i].Resolved // unresolved first
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// Experiment is the canonical experiment identity: what to try, on
// what task family, under what memory state. The digest pins the
// proposal — two experiments differing in any field are different
// experiments, so replays and outcome comparisons are honest.
type Experiment struct {
	TaskID      string `json:"task_id"`      // task family the signature belongs to
	Arm         int    `json:"arm"`          // envelope arm proposed
	ArmParams   string `json:"arm_params"`   // canonical params for audit
	ModelDigest string `json:"model_digest"` // the fit state that proposed it
	Signature   string `json:"signature"`    // failure signature addressed
	Why         string `json:"why"`          // the diagnosis + selection rationale
}

// Proposal is the controller's advisory output for one signature.
type Proposal struct {
	Signature  *Signature  `json:"signature"`
	Experiment *Experiment `json:"experiment,omitempty"`
	Decision   string      `json:"decision"` // "experiment" | "escalate" | "resolved" | "untrusted"
	Reason     string      `json:"reason"`
}

// gate reasons — the promotion checks' vocabulary.
const (
	decideExperiment = "experiment"
	decideEscalate   = "escalate"
	decideResolved   = "resolved"
	decideUntrusted  = "untrusted"
)

// Plan selects the next action for each diagnosed signature inside
// the declared envelope:
//
//   - resolved signature → resolved (record only).
//   - untrusted latest failure → escalate? No — untrusted memory
//     must not drive experiments on authority it can't prove:
//     decide "untrusted", requiring new verification first.
//   - an arm the model estimates positively that history has not
//     already tried for this task family → experiment.
//   - every arm tried or the fit is too thin → escalate: the
//     envelope holds no untried reasonable intervention, which is
//     exactly what a human is for.
//
// Estimator is the slice of a fitted model the controller needs:
// per-arm expected reward for a task. *dream.model satisfies it.
type Estimator interface {
	Estimate(t dream.Task, arm int) float64
}

// fit may be nil (no model): then every untried arm is a candidate
// in envelope order — the controller still proposes, stating why.
func Plan(g *experience.Graph, env *dream.Envelope, fit Estimator, task dream.Task, triedArms map[int]bool) []*Proposal {
	sigs := Diagnose(g)
	var out []*Proposal
	for _, sig := range sigs {
		p := &Proposal{Signature: sig}
		switch {
		case sig.Resolved:
			p.Decision = decideResolved
			p.Reason = "a later outcome resolves the latest failure"
		case !sig.Trusted:
			p.Decision = decideUntrusted
			p.Reason = "the failure record carries an adverse verdict — verify the memory before intervening"
		default:
			arm := chooseArm(env, fit, task, triedArms)
			if arm < 0 {
				p.Decision = decideEscalate
				p.Reason = "no untried arm inside the envelope"
			} else {
				p.Decision = decideExperiment
				p.Experiment = &Experiment{
					TaskID:    task.ID,
					Arm:       arm,
					ArmParams: fmt.Sprintf("%+v", env.Arms[arm]),
					Signature: sig.Subject,
					Why:       fmt.Sprintf("signature %s recurred %dx unresolved; arm %d untried", sig.Subject, sig.Count, arm),
				}
				p.Reason = "proposing the untried envelope arm"
			}
		}
		out = append(out, p)
	}
	return out
}

// chooseArm picks the best untried arm: the fit's estimate when a
// model exists, else envelope order. A negative estimate is not a
// reason to skip when nothing else is untried — the caller gates
// promotion on evidence, selection only orders the attempts.
func chooseArm(env *dream.Envelope, fit Estimator, task dream.Task, tried map[int]bool) int {
	best := -1
	bestEst := -1e18
	for arm := range env.Arms {
		if tried[arm] {
			continue
		}
		est := 0.0
		if fit != nil {
			est = fit.Estimate(task, arm)
		}
		if best < 0 || est > bestEst {
			best, bestEst = arm, est
		}
	}
	return best
}

// PromotionCheck is the evidence gate between a proposal and its
// adoption: the proposal may only promote when the store holds
// enough realized evidence and the replay demonstrates advantage
// over the declared baseline. It returns the refusal reason or ""
// when the proposal may promote. Unverifiable memory counts against
// the proposal — the gate never fills gaps with optimism.
type PromotionEvidence struct {
	// RealizedOutcomes is the number of verified outcomes the
	// deciding model actually trained on.
	RealizedOutcomes int
	// UntrustedNodes counts memory nodes carrying adverse verdicts
	// — evidence the record itself is in question.
	UntrustedNodes int
	// ReplayDelta is the replay's verified efficiency gain over the
	// baseline arm on realized outcomes (0 = no gain).
	ReplayDelta float64
	// MinEvidence is the realized-outcome floor (default 3).
	MinEvidence int
	// MinDelta is the required verified gain (default > 0).
	MinDelta float64
}

// CheckPromotion evaluates the gate and returns a refusal reason or
// the empty string when promotion is allowed.
func CheckPromotion(ev PromotionEvidence) string {
	min := ev.MinEvidence
	if min == 0 {
		min = 3
	}
	if ev.RealizedOutcomes < min {
		return fmt.Sprintf("insufficient realized evidence: %d outcomes, need %d — promotion on unverified memory is refused", ev.RealizedOutcomes, min)
	}
	if ev.UntrustedNodes > 0 {
		return fmt.Sprintf("%d memory nodes carry adverse verdicts — promotion requires a clean trust basis", ev.UntrustedNodes)
	}
	delta := ev.MinDelta
	if delta == 0 {
		delta = 0.0001
	}
	if ev.ReplayDelta < delta {
		return fmt.Sprintf("no verified advantage: replay delta %.4f below required %.4f", ev.ReplayDelta, delta)
	}
	return ""
}
