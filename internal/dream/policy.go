package dream

import "fmt"

// Policy chooses an arm of an Envelope for a task. Implementations
// are pure and deterministic — the same task under the same model
// always gets the same arm, so a Decision is reproducible from the
// record set that produced the model.
type Policy interface {
	Choose(env *Envelope, t Task) int
}

// StaticPolicy is the non-adaptive baseline: one fixed arm for every
// task, the shape an unlearned executor would run forever.
type StaticPolicy struct {
	Arm int
}

func (p StaticPolicy) Choose(_ *Envelope, _ Task) int { return p.Arm }

// AdaptivePolicy chooses the arm the fitted model estimates highest,
// breaking ties toward the cheaper arm — equal expected reward at
// less reserved headroom is strictly better.
type AdaptivePolicy struct {
	m *model
}

// FitPolicy builds the adaptive policy over records.
func FitPolicy(env *Envelope, records []Record) (Policy, error) {
	m, err := Fit(env, records)
	if err != nil {
		return nil, err
	}
	return &AdaptivePolicy{m: m}, nil
}

func (p *AdaptivePolicy) Choose(env *Envelope, t Task) int {
	best, bestV := -1, 0.0
	for i := range env.Arms {
		v := p.m.estimate(t, i)
		// Strictly greater value wins; equal value prefers the
		// cheaper arm (lower normalized cost).
		if best < 0 || v > bestV || (v == bestV && env.cost(i) < env.cost(best)) {
			best, bestV = i, v
		}
	}
	return best
}

// Decision is the explorer's entire output for one task: the arm it
// picked, the estimate that drove the pick, and the model state
// that produced it. A Decision is a record — it is never a contract,
// never signed, and carries no fields that could express one. Its
// only path to execution is an authority re-expressing it as a
// signed contract.
type Decision struct {
	TaskID       string    `json:"task_id"`
	Arm          int       `json:"arm"`
	Params       Params    `json:"params"`
	Estimate     float64   `json:"estimate"`
	Margin       float64   `json:"margin"`
	Alternatives []float64 `json:"alternatives,omitempty"`
	ModelDigest  string    `json:"model_digest"`
}

// Explorer is the adaptive controller: it fits models over memory
// and proposes arms for tasks. It is constructed with an Envelope —
// the operator's declaration of the entire explorable space — and
// cannot propose outside it.
type Explorer struct {
	env *Envelope
}

// NewExplorer validates the envelope once: every proposal the
// explorer makes is a member of it by construction.
func NewExplorer(env *Envelope) (*Explorer, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return &Explorer{env: env}, nil
}

// Envelope is the explorer's declared space.
func (x *Explorer) Envelope() *Envelope { return x.env }

// Propose asks the policy for an arm and packages the result as a
// Decision. The envelope check is repeated here — a policy that
// somehow named an outside arm fails closed rather than proposing
// it.
func (x *Explorer) Propose(p Policy, t Task) (*Decision, error) {
	if p == nil {
		return nil, fmt.Errorf("no policy")
	}
	arm := p.Choose(x.env, t)
	if arm < 0 || arm >= len(x.env.Arms) {
		return nil, fmt.Errorf("policy chose arm %d outside the envelope", arm)
	}
	d := &Decision{
		TaskID: t.ID,
		Arm:    arm,
		Params: x.env.Arms[arm],
	}
	if ap, ok := p.(*AdaptivePolicy); ok {
		best, second := -1.0, -1.0
		vals := make([]float64, len(x.env.Arms))
		for i := range x.env.Arms {
			v := ap.m.estimate(t, i)
			vals[i] = v
			if v > best {
				second, best = best, v
			} else if v > second {
				second = v
			}
		}
		d.Estimate = vals[arm]
		d.Alternatives = vals
		if len(x.env.Arms) > 1 {
			d.Margin = best - second
		}
		d.ModelDigest = ap.m.digest()
	}
	return d, nil
}
