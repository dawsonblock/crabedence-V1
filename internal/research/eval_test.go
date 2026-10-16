package research

import (
	"encoding/json"
	"testing"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/history"
)

func execEvent(t *testing.T, jobID, state string, mem, cpus, timeout, disk, out int64, at int64) *history.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"job_id": jobID, "state": state, "principal": "root",
		"image": "img-a", "argv": []string{"run.sh"},
		"resources": map[string]any{
			"timeout_seconds": timeout, "memory_mb": mem, "cpus": cpus,
			"disk_mb": disk, "max_output_bytes": out,
		},
		"updated_at_ms": at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &history.Event{
		DedupeKey: "job:" + jobID, Kind: "execution", Subject: jobID,
		Correlation: jobID, Source: "test", OccurredAt: at, Payload: payload,
	}
}

// The decisive shape: light tasks succeed on the small arm, heavy
// history under the big arm shows worse efficiency — the adaptive
// variants must beat the fixed-big-arm baseline on held-out tasks.
func TestEvaluateVariants(t *testing.T) {
	env := testEnvelope(t)
	var train []*history.Event
	// Arm 0 = small, arm 1 = big. Light tasks succeed small; the
	// same tasks on the big arm also succeed but pay for headroom.
	for i := 0; i < 8; i++ {
		train = append(train,
			execEvent(t, "small-"+string(rune('a'+i)), "succeeded", 256, 1, 60, 512, 4096, int64(1000+i)),
			execEvent(t, "big-"+string(rune('a'+i)), "succeeded", 1024, 2, 300, 2048, 16384, int64(2000+i)))
	}
	// Holdout: light tasks where arm 0 is efficient and arm 1 also
	// succeeds — the realized truth both variants are scored on.
	var holdout []dream.EvalTask
	for i := 0; i < 4; i++ {
		holdout = append(holdout, dream.EvalTask{
			Task: dream.Task{ID: "h" + string(rune('a'+i)),
				Features: map[string]string{"image": "img-a", "principal": "root", "argv0": "run.sh"}},
			Arms: []dream.Outcome{
				{Success: true, DurationMS: 500}, // small arm succeeds
				{Success: true, DurationMS: 400}, // big arm succeeds, costs headroom
			},
		})
	}
	rep, err := Evaluate(env, train, nil, holdout, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Scores) != len(Variants) {
		t.Fatalf("scores %d, want %d", len(rep.Scores), len(Variants))
	}
	var base, adaptive *VariantScore
	for i := range rep.Scores {
		switch rep.Scores[i].Variant {
		case VariantBaseline:
			base = &rep.Scores[i]
		case VariantAdaptive:
			adaptive = &rep.Scores[i]
		}
	}
	if base.Scored != 4 || adaptive.Scored != 4 {
		t.Fatalf("scored base=%d adaptive=%d, want 4/4", base.Scored, adaptive.Scored)
	}
	// The baseline always picks the big arm — successful but
	// headroom-heavy. Adaptive picks the arm history rewards.
	if adaptive.MeanReward <= base.MeanReward {
		t.Fatalf("adaptive mean %.3f did not beat baseline %.3f", adaptive.MeanReward, base.MeanReward)
	}
	if rep.DeltaOverBaseline <= 0 {
		t.Fatalf("delta %.4f — no verified gain over baseline", rep.DeltaOverBaseline)
	}
}
