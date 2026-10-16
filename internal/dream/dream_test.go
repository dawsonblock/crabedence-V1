package dream

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/openclaw/crabbox/internal/history"
	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

// testEnvelope is a three-arm resource ladder: cheap, medium, fat.
// The fat arm is the incumbent default an unlearned executor would
// always take.
func testEnvelope() *Envelope {
	return &Envelope{Arms: []Params{
		{TimeoutSeconds: 60, MemoryMB: 128, CPUs: 1, DiskMB: 64, MaxOutputBytes: 1024},
		{TimeoutSeconds: 300, MemoryMB: 1024, CPUs: 2, DiskMB: 512, MaxOutputBytes: 8192},
		{TimeoutSeconds: 3600, MemoryMB: 8192, CPUs: 4, DiskMB: 4096, MaxOutputBytes: 65536},
	}}
}

func lightTask(id string) Task {
	return Task{ID: id, Features: map[string]string{
		FeatureImage: "img:light", FeaturePrincipal: "p", FeatureArgv0: "light-run"}}
}

func heavyTask(id string) Task {
	return Task{ID: id, Features: map[string]string{
		FeatureImage: "img:heavy", FeaturePrincipal: "p", FeatureArgv0: "heavy-run"}}
}

// ─── Safety boundary ───────────────────────────────────────────────

// The adaptive surface is a resource envelope and nothing else. This
// test asserts the COMPLETE field set of Params — a new field is not
// an additive convenience, it is a boundary change that must fail
// here until a human reviews it against the rule: the explorer may
// never express execution authority, safety gates, verification
// rules, or release-promotion policy.
func TestParamsClosedWorld(t *testing.T) {
	want := map[string]bool{
		"TimeoutSeconds": true, "MemoryMB": true, "CPUs": true,
		"DiskMB": true, "MaxOutputBytes": true,
	}
	ty := reflect.TypeOf(Params{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if !want[f.Name] {
			t.Fatalf("Params grew an unreviewed field %q — the adaptive surface must stay a resource envelope (authority, security, network, verification and promotion knobs are structurally forbidden)", f.Name)
		}
	}
	if ty.NumField() != len(want) {
		t.Fatalf("Params has %d fields, expected %d", ty.NumField(), len(want))
	}
	// Forbidden vocabulary — belt-and-suspenders over the exact-set
	// check, so the boundary's *meaning* is documented in the test.
	forbidden := []string{
		"Authority", "Signer", "Signature", "Key", "Nonce",
		"Security", "Network", "Mounts", "Env", "Image",
		"Verification", "Gate", "Promotion", "Policy", "Principal",
	}
	for _, name := range forbidden {
		if _, ok := ty.FieldByName(name); ok {
			t.Fatalf("Params carries forbidden field %q", name)
		}
	}
}

// A Decision is an advisory record: it serializes to parameter
// choices and model references only — nothing that could be re-used
// as a contract, a signature, or an authority claim.
func TestDecisionCarriesNoAuthority(t *testing.T) {
	x, err := NewExplorer(testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	recs := sparseHistory(20, 10)
	pol, err := FitPolicy(x.env, recs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := x.Propose(pol, lightTask("probe"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"task_id": true, "arm": true, "params": true, "estimate": true,
		"margin": true, "alternatives": true, "model_digest": true,
	}
	for k := range generic {
		if !allowed[k] {
			t.Fatalf("decision carries unexpected field %q — a proposal must be parameters and provenance only", k)
		}
	}
	var params map[string]any
	if err := json.Unmarshal(mustJSON(d.Params), &params); err != nil {
		t.Fatal(err)
	}
	for k := range params {
		switch k {
		case "timeout_seconds", "memory_mb", "cpus", "disk_mb", "max_output_bytes":
		default:
			t.Fatalf("decision params carry forbidden field %q", k)
		}
	}
}

// A policy that names an arm outside the envelope fails closed —
// the explorer refuses to express it.
func TestProposeRefusesOutOfEnvelope(t *testing.T) {
	x, err := NewExplorer(testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	rogue := roguePolicy{arm: 99}
	if _, err := x.Propose(rogue, lightTask("x")); err == nil {
		t.Fatal("out-of-envelope arm proposed")
	}
	if _, err := x.Propose(roguePolicy{arm: -1}, lightTask("x")); err == nil {
		t.Fatal("negative arm proposed")
	}
}

type roguePolicy struct{ arm int }

func (r roguePolicy) Choose(_ *Envelope, _ Task) int { return r.arm }

func TestEnvelopeValidation(t *testing.T) {
	if _, err := NewExplorer(&Envelope{}); err == nil {
		t.Fatal("empty envelope accepted")
	}
	if err := (&Envelope{Arms: []Params{{TimeoutSeconds: 0}}}).Validate(); err == nil {
		t.Fatal("unbounded-timeout arm accepted")
	}
	env := testEnvelope()
	dup := &Envelope{Arms: append(append([]Params{}, env.Arms...), env.Arms[0])}
	if err := dup.Validate(); err == nil {
		t.Fatal("duplicate arm accepted")
	}
	if env.Index(Params{TimeoutSeconds: 60, MemoryMB: 128, CPUs: 1, DiskMB: 64, MaxOutputBytes: 1024}) != 0 {
		t.Fatal("Index lost arm 0")
	}
	if env.Index(Params{TimeoutSeconds: 999}) != -1 {
		t.Fatal("undeclared params indexed")
	}
}

// ─── Learning and replay ───────────────────────────────────────────

// sparseHistory builds the shape real logs have: each task ran under
// ONE arm. Light tasks succeed everywhere; heavy tasks fail under
// the cheap arm (insufficient headroom) and succeed under medium+.
// This is the train set the benchmark proves gains from — the
// explorer must infer the per-family boundary from it.
func sparseHistory(lightN, heavyN int) []Record {
	var recs []Record
	at := int64(1)
	for i := 0; i < lightN; i++ {
		// Light tasks logged across all arms — all succeed.
		arm := i % 3
		recs = append(recs, Record{
			Task:    lightTask(fmt.Sprintf("light-%d", i)),
			Arm:     arm,
			Outcome: Outcome{Success: true, DurationMS: 1000},
			At:      at,
		})
		at++
	}
	for i := 0; i < heavyN; i++ {
		arm := i % 3
		recs = append(recs, Record{
			Task: heavyTask(fmt.Sprintf("heavy-%d", i)),
			Arm:  arm,
			// Arm 0 cannot hold a heavy task.
			Outcome: Outcome{Success: arm != 0, DurationMS: 9000},
			At:      at,
		})
		at++
	}
	return recs
}

// worldArms is the environment's truth for a holdout task: the
// realized outcome each arm would produce — light tasks succeed
// everywhere, heavy tasks only on medium+.
func worldArms(t Task) []Outcome {
	heavy := t.Features[FeatureImage] == "img:heavy"
	return []Outcome{
		{Success: !heavy, DurationMS: 900},
		{Success: true, DurationMS: 8500},
		{Success: true, DurationMS: 30000},
	}
}

func TestAdaptiveLearnsFamilies(t *testing.T) {
	env := testEnvelope()
	recs := sparseHistory(30, 30)
	pol, err := FitPolicy(env, recs)
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.Choose(env, lightTask("new-light")); got != 0 {
		t.Fatalf("light task picked arm %d — cheapest sufficient envelope is arm 0", got)
	}
	if got := pol.Choose(env, heavyTask("new-heavy")); got != 1 {
		t.Fatalf("heavy task picked arm %d — smallest sufficient envelope is arm 1", got)
	}
}

// The milestone assertion: on tasks never fitted on, the adaptive
// policy earns strictly more than the always-fat baseline — the same
// success at materially less reserved headroom. Gains are measured
// on the environment's realized outcomes, not the model's own
// estimates.
func TestBenchmarkDemonstratesGainsOnHeldOutTasks(t *testing.T) {
	env := testEnvelope()
	train := sparseHistory(30, 30)
	var holdout []EvalTask
	for i := 0; i < 10; i++ {
		lt := lightTask(fmt.Sprintf("holdout-light-%d", i))
		holdout = append(holdout, EvalTask{Task: lt, Arms: worldArms(lt)})
		ht := heavyTask(fmt.Sprintf("holdout-heavy-%d", i))
		holdout = append(holdout, EvalTask{Task: ht, Arms: worldArms(ht)})
	}
	rep, err := Benchmark(env, train, holdout, StaticPolicy{Arm: 2})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Improvement <= 0.15 {
		t.Fatalf("adaptive gain %.3f below margin — learned policy is not beating the default", rep.Improvement)
	}
	// The gain must be efficiency, not fabricated success: both
	// policies succeed at the same rate.
	if rep.Adaptive.SuccessRate < rep.Baseline.SuccessRate {
		t.Fatalf("adaptive success %.2f < baseline %.2f — gains must not trade away correctness",
			rep.Adaptive.SuccessRate, rep.Baseline.SuccessRate)
	}
	if rep.Baseline.SuccessRate != 1 || rep.Adaptive.SuccessRate != 1 {
		t.Fatalf("success rates baseline=%.2f adaptive=%.2f", rep.Baseline.SuccessRate, rep.Adaptive.SuccessRate)
	}
	// And the policy actually differentiates families — a constant
	// choice cannot earn the improvement honestly.
	lightArm, heavyArm := -1, -1
	for i, et := range holdout {
		arm := rep.Adaptive.ChosenArms[i]
		if et.Task.Features[FeatureImage] == "img:light" {
			lightArm = arm
		} else {
			heavyArm = arm
		}
	}
	if lightArm == heavyArm {
		t.Fatalf("adaptive picked arm %d for both families — no adaptation happened", lightArm)
	}
}

// Replay only scores decisions with a realized outcome: a policy
// whose choice was never actually run contributes nothing.
func TestReplayScoresOnlyLoggedArms(t *testing.T) {
	env := testEnvelope()
	recs := []Record{
		{Task: lightTask("a"), Arm: 2, Outcome: Outcome{Success: true}},
		{Task: heavyTask("b"), Arm: 2, Outcome: Outcome{Success: true}},
	}
	// A policy that always picks arm 0 matches nothing.
	rep := Replay(env, recs, StaticPolicy{Arm: 0})
	if rep.Matched != 0 || rep.Coverage != 0 {
		t.Fatalf("replay scored unmatched decisions: %+v", rep)
	}
	rep = Replay(env, recs, StaticPolicy{Arm: 2})
	if rep.Matched != 2 || rep.MeanReward <= 0 {
		t.Fatalf("replay lost matched decisions: %+v", rep)
	}
}

func TestFitDeterministic(t *testing.T) {
	env := testEnvelope()
	recs := sparseHistory(10, 10)
	m1, _ := Fit(env, recs)
	m2, _ := Fit(env, recs)
	if m1.digest() != m2.digest() {
		t.Fatal("same records produced different model digests")
	}
	m3, _ := Fit(env, recs[:len(recs)-1])
	if m3.digest() == m1.digest() {
		t.Fatal("different history produced same model digest")
	}
}

// ─── History projection ────────────────────────────────────────────

// execEvent builds a history execution event the projector reads.
func execEvent(t *testing.T, jobID, image, argv0 string, res sandboxexecutor.ResourceBudget, state string) *history.Event {
	t.Helper()
	payload := fmt.Sprintf(`{"job_id":%q,"state":%q,"principal":"p","image":%q,"argv":[%q],"resources":{"timeout_seconds":%d,"memory_mb":%d,"cpus":%v,"disk_mb":%d,"max_output_bytes":%d},"duration_ms":1000,"updated_at_ms":1}`,
		jobID, state, image, argv0,
		res.TimeoutSeconds, res.MemoryMB, res.CPUs, res.DiskMB, res.MaxOutputBytes)
	return &history.Event{
		DedupeKey: "job:x:" + jobID, Kind: history.KindExecution,
		Subject: jobID, Source: "test", Payload: json.RawMessage(payload),
	}
}

func TestRecordsFromEvents(t *testing.T) {
	env := testEnvelope()
	arm := env.Arms[1]
	res := sandboxexecutor.ResourceBudget{
		TimeoutSeconds: arm.TimeoutSeconds, MemoryMB: arm.MemoryMB,
		CPUs: arm.CPUs, DiskMB: arm.DiskMB, MaxOutputBytes: arm.MaxOutputBytes,
	}
	events := []*history.Event{
		execEvent(t, "ok-1", "img:x", "run", res, sandboxexecutor.JobStateSucceeded),
		execEvent(t, "fail-1", "img:x", "run", res, sandboxexecutor.JobStateFailed),
		// ambiguous — not a realized outcome
		execEvent(t, "amb-1", "img:x", "run", res, sandboxexecutor.JobStateDispatchAmbig),
		// outside the envelope — unlearnable
		execEvent(t, "wild-1", "img:x", "run", sandboxexecutor.ResourceBudget{
			TimeoutSeconds: 42, MemoryMB: 42, CPUs: 7, DiskMB: 42, MaxOutputBytes: 42,
		}, sandboxexecutor.JobStateSucceeded),
		// a non-execution kind is ignored
		{Kind: history.KindCodeChange, Payload: json.RawMessage(`{}`)},
	}
	recs, skipped := RecordsFromEvents(env, events)
	if len(recs) != 2 || skipped != 2 {
		t.Fatalf("projected %d records, skipped %d", len(recs), skipped)
	}
	if recs[0].Arm != 1 || !recs[0].Outcome.Success || recs[1].Outcome.Success {
		t.Fatalf("projected records %+v", recs)
	}
	if recs[0].Task.Features[FeatureArgv0] != "run" || recs[0].Task.Features[FeatureImage] != "img:x" {
		t.Fatalf("task features %+v", recs[0].Task.Features)
	}
}

// The end-to-end shape the milestone promises: executions land in
// memory, the explorer learns, proposals come back within the
// envelope — the full chain working on real records, not fixtures.
func TestEndToEndProjectionFitPropose(t *testing.T) {
	env := testEnvelope()
	var events []*history.Event
	for i := 0; i < 12; i++ {
		arm := env.Arms[i%3]
		events = append(events, execEvent(t, fmt.Sprintf("h-%d", i), "img:heavy", "hr",
			sandboxexecutor.ResourceBudget{
				TimeoutSeconds: arm.TimeoutSeconds, MemoryMB: arm.MemoryMB,
				CPUs: arm.CPUs, DiskMB: arm.DiskMB, MaxOutputBytes: arm.MaxOutputBytes,
			},
			map[bool]string{true: sandboxexecutor.JobStateSucceeded, false: sandboxexecutor.JobStateFailed}[i%3 != 0]))
	}
	recs, _ := RecordsFromEvents(env, events)
	if len(recs) != 12 {
		t.Fatalf("projected %d records", len(recs))
	}
	x, err := NewExplorer(env)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := FitPolicy(env, recs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := x.Propose(pol, heavyTask("next-heavy"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Arm != 1 {
		t.Fatalf("heavy task proposed arm %d, want 1", d.Arm)
	}
	if d.Params != env.Arms[1] {
		t.Fatalf("proposed params %+v are not envelope arm 1", d.Params)
	}
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}
