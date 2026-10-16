package dream

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/openclaw/crabbox/internal/history"
	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

// execPayload mirrors the execution-event payload history writes —
// decoded structurally rather than imported so the projector reads
// the record, not the writer's type.
type execPayload struct {
	JobID       string                         `json:"job_id"`
	State       string                         `json:"state"`
	Principal   string                         `json:"principal"`
	Image       string                         `json:"image"`
	Argv        []string                       `json:"argv"`
	Resources   sandboxexecutor.ResourceBudget `json:"resources"`
	DurationMS  int64                          `json:"duration_ms"`
	UpdatedAtMS int64                          `json:"updated_at_ms"`
}

// FeatureImage, FeaturePrincipal, FeatureArgv0 are the task-feature
// keys the projector emits — the task family an execution belongs to.
const (
	FeatureImage     = "image"
	FeaturePrincipal = "principal"
	FeatureArgv0     = "argv0"
)

// RecordsFromEvents projects execution events into learning records:
// each settled job becomes (task family, arm, outcome). A job whose
// parameters are outside the envelope, or whose state isn't a
// realized outcome (ambiguous, interrupted, still running), is
// skipped — the model trains only on outcomes the ledger actually
// proved, and counts what it could not use so a sparse fit is
// visible rather than silent.
func RecordsFromEvents(env *Envelope, events []*history.Event) (records []Record, skipped int) {
	for _, e := range events {
		if e.Kind != history.KindExecution {
			continue
		}
		var p execPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			skipped++
			continue
		}
		if p.State != sandboxexecutor.JobStateSucceeded && p.State != sandboxexecutor.JobStateFailed {
			skipped++
			continue
		}
		arm := env.Index(Params{
			TimeoutSeconds: p.Resources.TimeoutSeconds,
			MemoryMB:       p.Resources.MemoryMB,
			CPUs:           p.Resources.CPUs,
			DiskMB:         p.Resources.DiskMB,
			MaxOutputBytes: p.Resources.MaxOutputBytes,
		})
		if arm < 0 {
			skipped++
			continue
		}
		argv0 := ""
		if len(p.Argv) > 0 {
			argv0 = filepath.Base(p.Argv[0])
		}
		records = append(records, Record{
			Task: Task{
				ID: p.JobID,
				Features: map[string]string{
					FeatureImage:     p.Image,
					FeaturePrincipal: p.Principal,
					FeatureArgv0:     argv0,
				},
			},
			Arm: arm,
			Outcome: Outcome{
				Success:    p.State == sandboxexecutor.JobStateSucceeded,
				DurationMS: p.DurationMS,
			},
			At: p.UpdatedAtMS,
		})
	}
	return records, skipped
}

// RecordDecision appends an explorer Decision to memory as a
// decision event — the controller's own proposals are part of the
// historical record, so later fits and audits see what the explorer
// chose, for which task, from which model state.
func RecordDecision(s *history.Store, env *Envelope, d *Decision) error {
	if d == nil {
		return fmt.Errorf("missing decision")
	}
	if d.Arm < 0 || d.Arm >= len(env.Arms) {
		return fmt.Errorf("decision arm %d outside the envelope", d.Arm)
	}
	if d.Params != env.Arms[d.Arm] {
		return fmt.Errorf("decision params do not match its envelope arm — refusing to record a proposal outside the declared space")
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = s.Append(&history.Event{
		DedupeKey:   "decision:" + d.ModelDigest + ":" + d.TaskID + ":" + fmt.Sprint(d.Arm),
		Kind:        history.KindDecision,
		Subject:     d.TaskID,
		Correlation: d.ModelDigest,
		Source:      "explorer",
		Payload:     payload,
	})
	return err
}
