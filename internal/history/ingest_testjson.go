package history

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// goActions is the closed set of actions a real `go test -json`
// stream emits — the same set the release pipeline's normalizer
// enforces (scripts/go-test-case-evidence.py). Anything outside it
// is a fabricated or corrupted event, never a forward extension
// memory may silently accept.
var goActions = map[string]bool{
	"start": true, "run": true, "pause": true, "cont": true,
	"pass": true, "bench": true, "fail": true, "output": true,
	"skip": true,
}

var terminalActions = map[string]bool{"pass": true, "fail": true, "skip": true}

const benchAction = "bench"

// packageActions are legal at package scope (no Test field).
var packageActions = map[string]bool{"start": true, "output": true, "pass": true, "fail": true, "skip": true}

// Per-test lifecycle states.
const (
	testStateNew     = "new"
	testStateRunning = "running"
	testStatePaused  = "paused"
	testStateDone    = "done"
)

type testCase struct {
	Status         string
	Elapsed        float64
	TerminalEvents int
	Out            []byte
}

type streamScan struct {
	findings   []string
	cases      map[string]*testCase
	order      []string
	packages   map[string]bool
	testPkg    map[string]string
	pkgTerm    map[string]int
	pkgOutcome map[string]string
	pkgStarted map[string]bool
	donePkgs   map[string]bool
	state      map[string]string
}

type testEvent struct {
	Package string   `json:"Package"`
	Action  string   `json:"Action"`
	Test    *string  `json:"Test,omitempty"`
	Output  *string  `json:"Output,omitempty"`
	Elapsed *float64 `json:"Elapsed,omitempty"`
	Time    *string  `json:"Time,omitempty"`
}

// accumulate folds one well-formed event into a per-test record —
// the single derivation rule the Python normalizer shares between
// generation and verification: the last terminal action decides the
// outcome, terminal actions are counted, the duration is the largest
// terminal Elapsed, and the output digest covers every output event's
// bytes in stream order.
func accumulate(rec *testCase, ev *testEvent) {
	a := ev.Action
	if terminalActions[a] || a == benchAction {
		rec.Status = a
		rec.TerminalEvents++
		if ev.Elapsed != nil && *ev.Elapsed > rec.Elapsed {
			rec.Elapsed = *ev.Elapsed
		}
	} else if a == "output" && ev.Output != nil {
		rec.Out = append(rec.Out, *ev.Output...)
	}
}

// scanStream walks one raw go test -json stream under the canonical
// lifecycle — a Go port of scripts/go-test-case-evidence.py's
// _scan_stream. A finding is emitted for every malformed event and
// every impossible sequence; findings never stop the walk.
func scanStream(raw []byte) *streamScan {
	sc := &streamScan{
		cases:      map[string]*testCase{},
		packages:   map[string]bool{},
		testPkg:    map[string]string{},
		pkgTerm:    map[string]int{},
		pkgOutcome: map[string]string{},
		pkgStarted: map[string]bool{},
		donePkgs:   map[string]bool{},
		state:      map[string]string{},
	}
	lines := bufio.NewScanner(bytes.NewReader(raw))
	lines.Buffer(make([]byte, 0, 1<<20), 16<<20)
	lineno := 0
	for lines.Scan() {
		lineno++
		line := bytes.TrimSpace(lines.Bytes())
		if len(line) == 0 {
			continue
		}
		var generic map[string]any
		if err := json.Unmarshal(line, &generic); err != nil {
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: not a go test -json event line", lineno))
			continue
		}
		// Type-check fields exactly as the reference parser does —
		// a field of the wrong shape is a malformed event, not a
		// zero value.
		if a, ok := generic["Action"]; ok {
			if _, isStr := a.(string); !isStr {
				sc.findings = append(sc.findings, fmt.Sprintf("line %d: event carries no string Action", lineno))
				continue
			}
		}
		ev := &testEvent{}
		if err := json.Unmarshal(line, ev); err != nil {
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: not a go test -json event line", lineno))
			continue
		}
		if _, present := generic["Action"]; !present {
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: event carries no string Action", lineno))
			continue
		}
		action := ev.Action
		if !goActions[action] {
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: unknown go test action %q", lineno, action))
			continue
		}
		if t, ok := generic["Test"]; ok {
			if _, isStr := t.(string); !isStr {
				sc.findings = append(sc.findings, fmt.Sprintf("line %d: Test is not a string", lineno))
				continue
			}
		}
		if o, ok := generic["Output"]; ok {
			if _, isStr := o.(string); !isStr {
				sc.findings = append(sc.findings, fmt.Sprintf("line %d: Output is not a string", lineno))
				continue
			}
		}
		if el, ok := generic["Elapsed"]; ok {
			if _, isNum := el.(float64); !isNum {
				sc.findings = append(sc.findings, fmt.Sprintf("line %d: Elapsed is not numeric", lineno))
				continue
			}
		}
		pkgRaw, pkgPresent := generic["Package"]
		if pkgPresent {
			if _, isStr := pkgRaw.(string); !isStr {
				sc.findings = append(sc.findings, fmt.Sprintf("line %d: event carries no string Package", lineno))
				continue
			}
		}
		pkg := ev.Package
		if sc.donePkgs[pkg] {
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: event for package %s after its terminal outcome", lineno, pkg))
			continue
		}
		sc.packages[pkg] = true
		test := ""
		if ev.Test != nil {
			test = *ev.Test
		}
		if ev.Test == nil {
			if action == "start" {
				if sc.pkgStarted[pkg] {
					sc.findings = append(sc.findings, fmt.Sprintf("line %d: package %s records a second start event", lineno, pkg))
				} else {
					sc.pkgStarted[pkg] = true
				}
			} else if terminalActions[action] {
				sc.pkgTerm[pkg]++
				sc.pkgOutcome[pkg] = action
				sc.donePkgs[pkg] = true
			} else if !packageActions[action] {
				sc.findings = append(sc.findings, fmt.Sprintf("line %d: package %s records test-scoped action %s with no test name", lineno, pkg, action))
			}
			continue
		}
		if _, ok := sc.cases[test]; !ok {
			sc.cases[test] = &testCase{}
			sc.order = append(sc.order, test)
			sc.state[test] = testStateNew
			sc.testPkg[test] = pkg
		} else if sc.testPkg[test] != pkg {
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s records events under both %s and %s — conflicting package identity", lineno, test, sc.testPkg[test], pkg))
		}
		st := sc.state[test]
		switch {
		case st == testStateDone:
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s records an event (action=%s) after its terminal outcome", lineno, test, action))
		case st == testStateNew && action != "run":
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s records %s without a preceding run event — an outcome the run never started is not evidence it executed", lineno, test, action))
		case action == "run" && st != testStateNew:
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s records a duplicate run event", lineno, test))
		case action == "pause" && st != testStateRunning:
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s pauses while not running", lineno, test))
		case action == "cont" && st != testStatePaused:
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s continues while not paused", lineno, test))
		case action == "start":
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s records a test-scoped start event", lineno, test))
		case terminalActions[action] && st == testStatePaused:
			sc.findings = append(sc.findings, fmt.Sprintf("line %d: test %s records terminal outcome %s while paused", lineno, test, action))
		}
		// Transition: even a malformed event lands the state machine
		// where the action claims to take it, so one defect cannot
		// cascade into a fabricated history of the stream.
		switch {
		case action == "run":
			if st == testStateNew {
				sc.state[test] = testStateRunning
			}
		case action == "pause":
			sc.state[test] = testStatePaused
		case action == "cont":
			sc.state[test] = testStateRunning
		case terminalActions[action] || action == benchAction:
			sc.state[test] = testStateDone
		}
		accumulate(sc.cases[test], ev)
	}
	if err := lines.Err(); err != nil {
		sc.findings = append(sc.findings, fmt.Sprintf("read stream: %v", err))
	}
	// Post-walk checks — the same completeness rules verify_stream
	// enforces: every test exactly one terminal event, every package
	// exactly one terminal outcome that is honest.
	for _, name := range sc.order {
		if n := sc.cases[name].TerminalEvents; n != 1 {
			sc.findings = append(sc.findings, fmt.Sprintf("test %s recorded %d terminal events in the raw stream (a genuine go test run produces exactly one)", name, n))
		}
	}
	for pkg := range sc.packages {
		if pkg == "" {
			continue
		}
		n := sc.pkgTerm[pkg]
		if n == 0 {
			sc.findings = append(sc.findings, fmt.Sprintf("package %s has no terminal outcome — the run did not complete", pkg))
		} else if n > 1 {
			sc.findings = append(sc.findings, fmt.Sprintf("package %s recorded %d terminal outcomes", pkg, n))
		} else if sc.pkgOutcome[pkg] != "pass" {
			sc.findings = append(sc.findings, fmt.Sprintf("package %s finished with outcome %s — a failed or skipped package run is not passing evidence", pkg, sc.pkgOutcome[pkg]))
		} else {
			for t, p := range sc.testPkg {
				if p != pkg {
					continue
				}
				st := sc.cases[t].Status
				if st == "fail" || st == "" {
					sc.findings = append(sc.findings, fmt.Sprintf("package %s reports pass while the derived test outcomes contain a failed or incomplete case", pkg))
					break
				}
			}
		}
	}
	return sc
}

// testRunRecord is the run-level event payload; testResultRecord is
// the per-case payload.
type testRunRecord struct {
	StreamSHA256 string   `json:"stream_sha256"`
	Packages     []string `json:"packages"`
	Tests        int      `json:"tests"`
	Passed       int      `json:"passed"`
	Failed       int      `json:"failed"`
	Skipped      int      `json:"skipped"`
	Benched      int      `json:"benched"`
	Label        string   `json:"label,omitempty"`
}

type testResultRecord struct {
	Run            string  `json:"run"`
	Package        string  `json:"package"`
	Test           string  `json:"test"`
	Status         string  `json:"status"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	TerminalEvents int     `json:"terminal_events"`
	OutputSHA256   string  `json:"output_sha256"`
}

// IngestTestStream records one `go test -json` stream: a test_run
// event keyed on the stream's own digest plus one test_result event
// per case. The stream must satisfy the canonical lifecycle — a
// malformed stream is refused whole, never normalized into
// plausible-looking history.
func (s *Store) IngestTestStream(r io.Reader, label string) (int, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 256<<20))
	if err != nil {
		return 0, fmt.Errorf("read test stream: %w", err)
	}
	sc := scanStream(raw)
	if len(sc.findings) > 0 {
		return 0, fmt.Errorf("test stream malformed: %s (and %d more findings)", sc.findings[0], len(sc.findings)-1)
	}
	sum := sha256.Sum256(raw)
	runDigest := hex.EncodeToString(sum[:])

	run := testRunRecord{StreamSHA256: runDigest, Label: label}
	var events []*Event
	pkgs := map[string]bool{}
	for _, name := range sc.order {
		rec := sc.cases[name]
		outSum := sha256.Sum256(rec.Out)
		tr := testResultRecord{
			Run:            runDigest,
			Package:        sc.testPkg[name],
			Test:           name,
			Status:         rec.Status,
			ElapsedSeconds: rec.Elapsed,
			TerminalEvents: rec.TerminalEvents,
			OutputSHA256:   hex.EncodeToString(outSum[:]),
		}
		switch rec.Status {
		case "pass":
			run.Passed++
		case "fail":
			run.Failed++
		case "skip":
			run.Skipped++
		case benchAction:
			run.Benched++
		}
		pkgs[sc.testPkg[name]] = true
		payload, err := json.Marshal(tr)
		if err != nil {
			return 0, err
		}
		events = append(events, &Event{
			DedupeKey:   "test:" + runDigest + ":" + name,
			Kind:        KindTestResult,
			Subject:     sc.testPkg[name] + "/" + name,
			Correlation: runDigest,
			Source:      "teststream:" + label,
			Payload:     payload,
		})
	}
	run.Tests = len(sc.order)
	for p := range pkgs {
		run.Packages = append(run.Packages, p)
	}
	payload, err := json.Marshal(run)
	if err != nil {
		return 0, err
	}
	events = append(events, &Event{
		DedupeKey:   "testrun:" + runDigest,
		Kind:        KindTestRun,
		Subject:     runDigest,
		Correlation: runDigest,
		Source:      "teststream:" + label,
		Payload:     payload,
	})
	appended, err := s.Append(events...)
	if err != nil {
		return 0, err
	}
	return len(appended), nil
}
