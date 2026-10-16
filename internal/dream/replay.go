package dream

// ReplayReport is what a replayed policy earned on the logged
// record, honestly bounded: a policy can only be scored where the
// record actually ran the arm the policy would have chosen —
// counterfactual arms have no realized outcome, so pretending to
// score them would be inventing history.
type ReplayReport struct {
	// Matched is the count of logged records whose arm the policy
	// would also have chosen — the only decisions with a realized
	// outcome to score.
	Matched int `json:"matched"`
	// Total is the record count the policy was replayed against.
	Total int `json:"total"`
	// Coverage is Matched/Total — how much of history the replay
	// could honestly score.
	Coverage float64 `json:"coverage"`
	// MeanReward is the realized reward over matched records.
	MeanReward float64 `json:"mean_reward"`
	// SuccessRate is the realized success fraction over matched.
	SuccessRate float64 `json:"success_rate"`
}

// Replay scores a policy against logged records: for each record,
// ask what arm the policy would pick for that task; only where it
// picks the arm that actually ran does a realized outcome exist to
// score. The result is a lower-bound performance estimate — the
// policy's value on the part of its decision space that history
// covers.
func Replay(env *Envelope, records []Record, p Policy) ReplayReport {
	rep := ReplayReport{Total: len(records)}
	var rewards, successes float64
	for _, r := range records {
		if r.Arm < 0 || r.Arm >= len(env.Arms) {
			continue
		}
		if p.Choose(env, r.Task) != r.Arm {
			continue
		}
		rep.Matched++
		rewards += env.Reward(r.Arm, r.Outcome)
		if r.Outcome.Success {
			successes++
		}
	}
	if rep.Total > 0 {
		rep.Coverage = float64(rep.Matched) / float64(rep.Total)
	}
	if rep.Matched > 0 {
		rep.MeanReward = rewards / float64(rep.Matched)
		rep.SuccessRate = successes / float64(rep.Matched)
	}
	return rep
}

// PolicyScore is one policy's realized result on the holdout set.
type PolicyScore struct {
	Name        string  `json:"name"`
	Tasks       int     `json:"tasks"`
	MeanReward  float64 `json:"mean_reward"`
	SuccessRate float64 `json:"success_rate"`
	ChosenArms  []int   `json:"chosen_arms"`
}

// BenchmarkReport compares policies on tasks none of their fitting
// history covered — the "gains on unseen tasks" evidence. Improvement
// is the adaptive policy's mean reward minus the baseline's.
type BenchmarkReport struct {
	TrainRecords int         `json:"train_records"`
	HeldOut      int         `json:"held_out"`
	Baseline     PolicyScore `json:"baseline"`
	Adaptive     PolicyScore `json:"adaptive"`
	Improvement  float64     `json:"improvement"`
}

// Benchmark trains the adaptive policy on train records and scores
// both policies on the holdout set's realized per-arm outcomes —
// each EvalTask carries what the environment actually produced under
// every arm, so both policies are scored on truth, not on the
// model's own estimates.
func Benchmark(env *Envelope, train []Record, holdout []EvalTask, baseline Policy) (*BenchmarkReport, error) {
	adaptive, err := FitPolicy(env, train)
	if err != nil {
		return nil, err
	}
	rep := &BenchmarkReport{TrainRecords: len(train), HeldOut: len(holdout)}
	rep.Baseline = scorePolicy(env, "baseline", baseline, holdout)
	rep.Adaptive = scorePolicy(env, "adaptive", adaptive, holdout)
	rep.Improvement = rep.Adaptive.MeanReward - rep.Baseline.MeanReward
	return rep, nil
}

func scorePolicy(env *Envelope, name string, p Policy, holdout []EvalTask) PolicyScore {
	s := PolicyScore{Name: name}
	var rewards, successes float64
	for _, et := range holdout {
		arm := p.Choose(env, et.Task)
		if arm < 0 || arm >= len(et.Arms) {
			continue
		}
		s.ChosenArms = append(s.ChosenArms, arm)
		s.Tasks++
		rewards += env.Reward(arm, et.Arms[arm])
		if et.Arms[arm].Success {
			successes++
		}
	}
	if s.Tasks > 0 {
		s.MeanReward = rewards / float64(s.Tasks)
		s.SuccessRate = successes / float64(s.Tasks)
	}
	return s
}
