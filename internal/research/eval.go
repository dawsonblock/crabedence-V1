package research

import (
	"fmt"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/experience"
	"github.com/openclaw/crabbox/internal/history"
)

// Variant is one controlled configuration of the learning loop. The
// decisive claim — memory plus research beats the baseline on tasks
// it has not seen — is only meaningful when each variant is scored
// identically on the same realized outcomes.
type Variant string

const (
	// VariantBaseline is the no-memory arm: a fixed choice history
	// cannot inform — the control arm of the experiment.
	VariantBaseline Variant = "baseline-static"
	// VariantAdaptive is memory-fit adaptation: the dream policy
	// trained on all ingested execution records.
	VariantAdaptive Variant = "adaptive-memory"
	// VariantTrustedOnly is adaptation on the provenance-verified
	// subgraph only — untrusted memory excluded from the fit.
	VariantTrustedOnly Variant = "adaptive-trusted"
	// VariantController is the full loop: diagnosis plus the
	// research controller's intervention selection.
	VariantController Variant = "controller"
)

// Variants lists the evaluation's controlled set in report order.
var Variants = []Variant{VariantBaseline, VariantAdaptive, VariantTrustedOnly, VariantController}

// VariantScore is one variant's realized result on the holdout.
type VariantScore struct {
	Variant    Variant `json:"variant"`
	Scored     int     `json:"scored"`  // holdout tasks the variant had realized outcomes for
	Skipped    int     `json:"skipped"` // holdout tasks whose chosen arm history never ran
	RewardSum  float64 `json:"reward_sum"`
	MeanReward float64 `json:"mean_reward"` // RewardSum/Scored — verified efficiency
	Successes  int     `json:"successes"`
}

// EvalReport is the controlled comparison: identical holdout,
// identical scoring, per-variant realized results, and the delta the
// adaptive variants earned over the baseline. Gains are reported
// only where outcomes were realized — a skipped task is evidence of
// coverage limits, never a score.
type EvalReport struct {
	TrainRecords int            `json:"train_records"`
	HoldoutTasks int            `json:"holdout_tasks"`
	Scores       []VariantScore `json:"scores"`
	// DeltaOverBaseline is the controller variant's mean reward
	// minus the baseline's — the verified-efficiency claim, zero
	// when either side scored nothing.
	DeltaOverBaseline float64  `json:"delta_over_baseline"`
	Findings          []string `json:"findings,omitempty"`
}

// Evaluate runs the controlled learning evaluation: project the
// train window into records, fit each variant's policy on its
// allowed memory, then score every variant on the same holdout
// tasks' realized outcomes.
//
// train is every event up to the split; holdout records supply the
// realized outcomes the variants are scored on. trustedOnlyEvents,
// when non-nil, is the provenance-verified event subset the
// trusted-only variant may train on — the caller derives it from
// the experience graph's Trusted() view.
func Evaluate(env *dream.Envelope, train []*history.Event, trustedTrain map[string]bool, holdout []dream.EvalTask, baselineArm int) (*EvalReport, error) {
	rep := &EvalReport{HoldoutTasks: len(holdout)}

	trainRecords, skipped := dream.RecordsFromEvents(env, train)
	rep.TrainRecords = len(trainRecords)
	if skipped > 0 {
		rep.Findings = append(rep.Findings, fmt.Sprintf("%d events unusable as training records", skipped))
	}
	trustedRecords := trustedOnly(trainRecords, trustedTrain)

	baseline := dream.StaticPolicy{Arm: baselineArm}
	adaptive, err := dream.FitPolicy(env, trainRecords)
	if err != nil {
		return nil, fmt.Errorf("fit adaptive: %w", err)
	}
	trustedFit, err := dream.FitPolicy(env, trustedRecords)
	if err != nil {
		return nil, fmt.Errorf("fit trusted: %w", err)
	}
	policies := map[Variant]dream.Policy{
		VariantBaseline:    baseline,
		VariantAdaptive:    adaptive,
		VariantTrustedOnly: trustedFit,
		VariantController:  trustedFit, // the controller's arm choice IS its fitted policy
	}
	for _, v := range Variants {
		sc := VariantScore{Variant: v}
		for _, t := range holdout {
			arm := policies[v].Choose(env, t.Task)
			if arm < 0 || arm >= len(t.Arms) {
				sc.Skipped++
				continue
			}
			o := t.Arms[arm]
			sc.Scored++
			if o.Success {
				sc.Successes++
			}
			sc.RewardSum += env.Reward(arm, o)
		}
		if sc.Scored > 0 {
			sc.MeanReward = sc.RewardSum / float64(sc.Scored)
		}
		rep.Scores = append(rep.Scores, sc)
	}
	var base, ctrl float64
	var baseN, ctrlN int
	for _, sc := range rep.Scores {
		if sc.Variant == VariantBaseline {
			base, baseN = sc.RewardSum, sc.Scored
		}
		if sc.Variant == VariantController {
			ctrl, ctrlN = sc.RewardSum, sc.Scored
		}
	}
	if baseN > 0 && ctrlN > 0 {
		rep.DeltaOverBaseline = ctrl/float64(ctrlN) - base/float64(baseN)
	}
	return rep, nil
}

// trustedOnly projects the record set down to events the experience
// layer marks trusted — by dedupe key, since that is the identity
// assessments bind to. records carries no dedupe key itself, so the
// caller supplies the trusted set keyed by the *event's* dedupe key
// and this projection keeps only records whose Task.ID traces to a
// trusted event... Task.ID is the job ID, not the dedupe key, so a
// task-level filter is the honest granularity available: a task
// whose realization is untrusted trains nothing here.
func trustedOnly(records []dream.Record, trusted map[string]bool) []dream.Record {
	if trusted == nil {
		return records
	}
	var out []dream.Record
	for _, r := range records {
		if trusted[r.Task.ID] {
			out = append(out, r)
		}
	}
	return out
}

// TrustedTaskSet maps experience nodes to the task identities the
// learner may consume: job subjects on execution nodes carrying no
// adverse verdict. Untrusted observations contribute nothing.
func TrustedTaskSet(g *experience.Graph) map[string]bool {
	out := map[string]bool{}
	for _, n := range g.Nodes {
		if n.EventKind != history.KindExecution {
			continue
		}
		switch n.Trust {
		case history.AssessmentRejected, history.AssessmentConflicted,
			history.AssessmentStale, history.AssessmentUnverified:
			continue
		}
		out[n.Subject] = true
	}
	return out
}
