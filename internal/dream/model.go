// Package dream is the learning layer over unified memory: it replays
// the system's historical record to fit a model of which execution
// parameters work for which tasks, and proposes parameters for new
// tasks from that model — the adaptive exploration controller.
//
// The boundary is structural, not procedural. A Params is a resource
// envelope and nothing else: it has no field that can name an
// authority, a signer, a security profile, a network policy, a
// verification rule, or a promotion gate. The explorer's only output
// is a Decision — an advisory record naming one arm of an
// operator-declared Envelope — which a human authority may turn into
// a signed contract. The explorer holds no keys and emits no
// contracts, receipts, or gates; it cannot widen what it can only
// describe.
//
// Dream-RSI: replay ("dream") over the append-only memory to improve
// ("RSI") the proposal policy — a self-improving *explorer*, never a
// self-modifying executor.
package dream

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// Params is the closed adaptive knob space: the resource envelope a
// task runs under. Every field is a quantity the authority already
// bounds in a contract; the explorer selects among declared points,
// it does not invent authority. The struct's field set is asserted
// by test — a new field is a boundary change requiring review, not
// an additive convenience.
type Params struct {
	TimeoutSeconds uint32  `json:"timeout_seconds"`
	MemoryMB       uint64  `json:"memory_mb"`
	CPUs           float64 `json:"cpus"`
	DiskMB         uint64  `json:"disk_mb"`
	MaxOutputBytes uint64  `json:"max_output_bytes"`
}

// Task is the thing being explored: a job's identity features as
// memory recorded them. Features are categorical — the model reasons
// over families of similar tasks.
type Task struct {
	ID       string            `json:"id"`
	Features map[string]string `json:"features"`
}

// Outcome is what the run produced.
type Outcome struct {
	Success    bool  `json:"success"`
	DurationMS int64 `json:"duration_ms"`
}

// Record is one logged data point: this task ran under this arm and
// produced this outcome. The arm indexes an Envelope, so a record is
// only meaningful against the envelope that declared its arms.
type Record struct {
	Task    Task    `json:"task"`
	Arm     int     `json:"arm"`
	Outcome Outcome `json:"outcome"`
	At      int64   `json:"at"`
}

// EvalTask is a holdout task with a realized outcome per arm — the
// environment's truth a benchmark scores policies against.
type EvalTask struct {
	Task Task      `json:"task"`
	Arms []Outcome `json:"arms"`
}

// Envelope is the operator-declared closed set of legal parameter
// arms — the whole exploration space. Arms outside it cannot be
// expressed, proposed, or learned from.
type Envelope struct {
	Arms []Params `json:"arms"`
}

// Validate checks the envelope is a usable exploration space.
func (e *Envelope) Validate() error {
	if e == nil || len(e.Arms) == 0 {
		return fmt.Errorf("envelope declares no arms")
	}
	if len(e.Arms) > 256 {
		return fmt.Errorf("envelope exceeds 256 arms")
	}
	seen := map[Params]bool{}
	for i, a := range e.Arms {
		if a.TimeoutSeconds == 0 {
			return fmt.Errorf("arm %d has no timeout — an unbounded run is not an explorable point", i)
		}
		if seen[a] {
			return fmt.Errorf("arm %d duplicates an earlier arm", i)
		}
		seen[a] = true
	}
	return nil
}

// Index reports p's position in the envelope, or -1 if p is outside
// it — a record whose parameters the operator did not declare cannot
// feed the model.
func (e *Envelope) Index(p Params) int {
	for i, a := range e.Arms {
		if a == p {
			return i
		}
	}
	return -1
}

// cost is the arm's normalized resource magnitude — the mean of each
// dimension's fraction of the envelope's maximum. It is what the
// reward charges a successful run for the headroom it reserved.
func (e *Envelope) cost(arm int) float64 {
	var maxT, maxM, maxC, maxD, maxO float64
	for _, a := range e.Arms {
		if v := float64(a.TimeoutSeconds); v > maxT {
			maxT = v
		}
		if v := float64(a.MemoryMB); v > maxM {
			maxM = v
		}
		if a.CPUs > maxC {
			maxC = a.CPUs
		}
		if v := float64(a.DiskMB); v > maxD {
			maxD = v
		}
		if v := float64(a.MaxOutputBytes); v > maxO {
			maxO = v
		}
	}
	a := e.Arms[arm]
	var sum, dims float64
	add := func(v, m float64) {
		if m > 0 {
			sum += v / m
			dims++
		}
	}
	add(float64(a.TimeoutSeconds), maxT)
	add(float64(a.MemoryMB), maxM)
	add(a.CPUs, maxC)
	add(float64(a.DiskMB), maxD)
	add(float64(a.MaxOutputBytes), maxO)
	if dims == 0 {
		return 0
	}
	return sum / dims
}

// efficiencyWeight sets how much of a successful run's reward its
// reserved headroom costs: 1 for merely succeeding minus this
// fraction of the arm's normalized cost.
const efficiencyWeight = 0.5

// Reward scores a realized outcome under an arm. A failed run is
// always worse than any success (it burned the run and produced
// nothing); among successes, cheaper headroom is better — the
// adaptive pressure is "smallest envelope that reliably works", not
// "biggest that never fails".
func (e *Envelope) Reward(arm int, o Outcome) float64 {
	if !o.Success {
		return -1
	}
	return 1 - efficiencyWeight*e.cost(arm)
}

// similarity is the categorical match between two feature vectors:
// the fraction of union keys whose values agree.
func similarity(a, b map[string]string) float64 {
	union := map[string]bool{}
	for k := range a {
		union[k] = true
	}
	for k := range b {
		union[k] = true
	}
	if len(union) == 0 {
		return 0
	}
	match := 0
	for k := range union {
		av, aok := a[k]
		bv, bok := b[k]
		if aok && bok && av == bv {
			match++
		}
	}
	return float64(match) / float64(len(union))
}

// model is the fitted value surface: per-arm, a similarity-weighted
// mean of realized rewards shrunk toward the arm's global mean.
// Fully deterministic — the same records always fit the same model.
type model struct {
	env     *Envelope
	records []Record
	global  []float64
	counts  []int
}

// Fit builds the model from logged records. Records whose arm index
// is outside the envelope are ignored — they cannot be learned from.
func Fit(env *Envelope, records []Record) (*model, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	m := &model{
		env:    env,
		global: make([]float64, len(env.Arms)),
		counts: make([]int, len(env.Arms)),
	}
	sum := make([]float64, len(env.Arms))
	for _, r := range records {
		if r.Arm < 0 || r.Arm >= len(env.Arms) {
			continue
		}
		m.records = append(m.records, r)
		sum[r.Arm] += env.Reward(r.Arm, r.Outcome)
		m.counts[r.Arm]++
	}
	for i := range m.global {
		if m.counts[i] > 0 {
			m.global[i] = sum[i] / float64(m.counts[i])
		}
	}
	return m, nil
}

// minEvidence is the weight below which similar history is too thin
// to estimate on — the arm then falls back to its global mean rather
// than extrapolating a near-miss.
const minEvidence = 1.0

// estimate is the arm's expected reward for this task: the
// similarity-weighted mean over the arm's logged outcomes when
// similar history carries enough weight, else the arm's global mean.
// Similarity is raised to the fourth power so near-identical tasks
// dominate and cross-family evidence contributes little — a cheap
// arm's failures on heavy tasks must not poison its estimate on
// light ones.
func (m *model) estimate(t Task, arm int) float64 {
	var num, den float64
	for _, r := range m.records {
		if r.Arm != arm {
			continue
		}
		s := similarity(t.Features, r.Task.Features)
		w := s * s
		w *= w
		num += w * m.env.Reward(r.Arm, r.Outcome)
		den += w
	}
	if den < minEvidence {
		return m.global[arm]
	}
	return num / den
}

// digest is the model's content identity — a SHA-256 over the
// envelope arms and the fitted record set in canonical order — so a
// Decision names the exact model state that produced it, and a
// replay can detect a policy built on different history.
func (m *model) digest() string {
	keys := make([]string, 0, len(m.records))
	for _, r := range m.records {
		feat := make([]string, 0, len(r.Task.Features))
		for k, v := range r.Task.Features {
			feat = append(feat, k+"="+v)
		}
		sort.Strings(feat)
		keys = append(keys, fmt.Sprintf("%s|%s|%d|%v|%d|%d",
			r.Task.ID, sortFeatJoin(feat), r.Arm, r.Outcome.Success, r.Outcome.DurationMS, r.At))
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, a := range m.env.Arms {
		fmt.Fprintf(h, "arm|%d|%d|%g|%d|%d\n", a.TimeoutSeconds, a.MemoryMB, a.CPUs, a.DiskMB, a.MaxOutputBytes)
	}
	for _, k := range keys {
		fmt.Fprintf(h, "rec|%s\n", k)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortFeatJoin(feat []string) string {
	out := ""
	for i, f := range feat {
		if i > 0 {
			out += ","
		}
		out += f
	}
	return out
}
