// sandbox-dream is the adaptive-exploration operator tool: it reads
// the unified memory's execution history, fits the parameter model,
// reports what the model learned, proposes parameters for a task,
// and benchmarks the adaptive policy against the static baseline on
// held-out tasks.
//
//	sandbox-dream -db history.db -envelope arms.json report
//	sandbox-dream -db history.db -envelope arms.json propose -task-image IMG [-task-principal P -task-argv0 A]
//	sandbox-dream -db history.db -envelope arms.json benchmark -holdout FILE [-baseline ARM]
//
// The envelope file is the operator's declaration of the explorable
// space: {"arms": [{timeout_seconds, memory_mb, cpus, disk_mb,
// max_output_bytes}, ...]}. Every proposal is an advisory Decision —
// it names an envelope arm and model digest, nothing more. It is not
// a contract, it is not signed, and it carries no authority: turning
// it into an execution still requires the signing authority the
// executor already demands.
//
// The holdout file is [{"task": {"id","features"}, "arms":
// [Outcome,...]}] — the realized outcome each arm produced for an
// unseen task, so the benchmark scores policies on truth.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/history"
)

func main() {
	dbPath := flag.String("db", "", "history store path (required)")
	envPath := flag.String("envelope", "", "envelope JSON path (required)")
	taskID := flag.String("task-id", "proposed-task", "propose: task identity")
	taskImage := flag.String("task-image", "", "propose: image feature")
	taskPrincipal := flag.String("task-principal", "", "propose: principal feature")
	taskArgv0 := flag.String("task-argv0", "", "propose: argv0 feature")
	holdoutPath := flag.String("holdout", "", "benchmark: holdout eval-task JSON file")
	baselineArm := flag.Int("baseline", -1, "benchmark: baseline arm index (default: largest arm)")
	record := flag.Bool("record", false, "propose: also append the decision to memory")
	flag.Parse()

	args := flag.Args()
	if *dbPath == "" || *envPath == "" || len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sandbox-dream -db PATH -envelope FILE <report|propose|benchmark> [args]")
		os.Exit(2)
	}
	env, err := loadEnvelope(*envPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "envelope:", err)
		os.Exit(2)
	}
	x, err := dream.NewExplorer(env)
	if err != nil {
		fmt.Fprintln(os.Stderr, "envelope:", err)
		os.Exit(2)
	}
	writable := len(args) > 0 && args[0] == "propose" && *record
	var s *history.Store
	if writable {
		s, err = history.OpenStore(*dbPath)
	} else {
		s, err = history.OpenReadOnly(*dbPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "open history:", err)
		os.Exit(1)
	}
	defer s.Close()
	events, err := s.Query(history.QueryOpts{Kinds: []string{history.KindExecution}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "query executions:", err)
		os.Exit(1)
	}
	records, skipped := dream.RecordsFromEvents(env, events)

	switch args[0] {
	case "report":
		pol, err := dream.FitPolicy(env, records)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fit:", err)
			os.Exit(1)
		}
		rep := dream.Replay(env, records, pol)
		out, _ := json.MarshalIndent(map[string]any{
			"envelope_arms": len(env.Arms),
			"records":       len(records),
			"skipped":       skipped,
			"replay":        rep,
		}, "", "  ")
		fmt.Println(string(out))

	case "propose":
		pol, err := dream.FitPolicy(env, records)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fit:", err)
			os.Exit(1)
		}
		task := dream.Task{ID: *taskID, Features: map[string]string{}}
		if *taskImage != "" {
			task.Features[dream.FeatureImage] = *taskImage
		}
		if *taskPrincipal != "" {
			task.Features[dream.FeaturePrincipal] = *taskPrincipal
		}
		if *taskArgv0 != "" {
			task.Features[dream.FeatureArgv0] = *taskArgv0
		}
		d, err := x.Propose(pol, task)
		if err != nil {
			fmt.Fprintln(os.Stderr, "propose:", err)
			os.Exit(1)
		}
		if *record {
			if err := dream.RecordDecision(s, env, d); err != nil {
				fmt.Fprintln(os.Stderr, "record decision:", err)
				os.Exit(1)
			}
		}
		out, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(out))

	case "benchmark":
		if *holdoutPath == "" {
			fmt.Fprintln(os.Stderr, "benchmark requires -holdout FILE")
			os.Exit(2)
		}
		raw, err := os.ReadFile(*holdoutPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "holdout:", err)
			os.Exit(1)
		}
		var holdout []dream.EvalTask
		if err := json.Unmarshal(raw, &holdout); err != nil {
			fmt.Fprintln(os.Stderr, "holdout malformed:", err)
			os.Exit(1)
		}
		arm := *baselineArm
		if arm < 0 {
			arm = len(env.Arms) - 1
		}
		if arm >= len(env.Arms) {
			fmt.Fprintf(os.Stderr, "baseline arm %d outside envelope\n", arm)
			os.Exit(2)
		}
		rep, err := dream.Benchmark(env, records, holdout, dream.StaticPolicy{Arm: arm})
		if err != nil {
			fmt.Fprintln(os.Stderr, "benchmark:", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintln(os.Stderr, "unknown op:", strings.Join(args, " "))
		os.Exit(2)
	}
}

func loadEnvelope(path string) (*dream.Envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env := &dream.Envelope{}
	if err := json.Unmarshal(raw, env); err != nil {
		return nil, fmt.Errorf("malformed envelope: %w", err)
	}
	return env, nil
}
