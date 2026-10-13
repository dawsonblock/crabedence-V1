package sandboxexecutor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// adversarialTargets are the rc.7 release acceptance targets. They are
// counted, not asserted: every scenario runs and contributes to the
// tally, and the test fails if any target is violated.
type adversarialTargets struct {
	falseNoEffect     int // a NO_EFFECT receipt for a job that may have started
	unauthorizedAdopt int // a tampered or substituted execution identity that was adopted
	duplicateDispatch int // a scenario that left more than one runtime job record
	acceptedForbidden int // a forbidden policy change that was accepted
}

func (a adversarialTargets) assertZero(t *testing.T) {
	t.Helper()
	if a.falseNoEffect != 0 || a.unauthorizedAdopt != 0 || a.duplicateDispatch != 0 || a.acceptedForbidden != 0 {
		t.Fatalf("release targets violated: %+v", a)
	}
}

// TestAdversarialFaultMatrix is the rc.7 step-10 qualification: the
// fault-injection matrix runs every dispatch boundary, policy boundary
// and adoption boundary the plan names, and *measures* the four release
// targets across all of them — zero false NO_EFFECT receipts, zero
// unauthorized adoptions, zero duplicate dispatches and zero accepted
// forbidden policy changes.
// waitForLedgerState polls one row until it reaches want, so a case
// whose outcome is decided by the asynchronous monitor can be measured
// at its terminal state rather than at the dispatch response.
func waitForLedgerState(t *testing.T, l *Ledger, jobID, want string) *LedgerJob {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		lj, err := l.Get(jobID)
		if err != nil {
			t.Fatalf("ledger row: %v", err)
		}
		if lj != nil && lj.State == want {
			return lj
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s never reached %s: %+v", jobID, want, lj)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAdversarialFaultMatrix(t *testing.T) {
	targets := adversarialTargets{}

	// ── Dispatch boundaries ─────────────────────────────────────────
	type dispatchCase struct {
		name        string
		env         map[string]string
		dispatchTTL time.Duration
		wantState   string
		wantClass   string
		wantReceipt bool
		wantJobs    int
		// wantSettled is the terminal state the monitor reaches
		// asynchronously, for cases that outlive the dispatch call.
		// Empty means the dispatch call itself decides the outcome.
		wantSettled string
	}
	cases := []dispatchCase{
		{"create refused before boot", map[string]string{"MSB_FAKE_CREATE_FAIL": "1"}, 0,
			JobStateDispatchFailed, string(DispatchProvenRejected), true, 0, ""},
		{"create failed after boot", map[string]string{"MSB_FAKE_CREATE_FAIL_AFTER": "1"}, 0,
			JobStateDispatchFailed, string(DispatchProvenRejected), true, 0, ""},
		{"create deadline mid-boot", map[string]string{"MSB_FAKE_CREATE_SLEEP": "5"}, 500 * time.Millisecond,
			JobStateDispatchAmbig, string(DispatchUncertain), false, 0, ""},
		{"post-launch identity unprovable", map[string]string{"MSB_FAKE_JOB_INSPECT_FAIL": "1"}, 0,
			JobStateDispatchAmbig, string(DispatchUncertain), false, 1, ""},
		{"spawn rejected by the guest", map[string]string{"MSB_FAKE_LAUNCH_FAIL": "1"}, 0,
			JobStateRunning, string(DispatchStarted), true, 1, JobStateDispatchFailed},
		{"launch failed before admission", map[string]string{"MSB_FAKE_LAUNCH_NO_ADMIT_FAIL": "1"}, 0,
			JobStateDispatchAmbig, string(DispatchUncertain), false, 0, ""},
		{"launch admitted but unnamed", map[string]string{"MSB_FAKE_LAUNCH_FAIL_ADMITTED": "1"}, 0,
			JobStateRunning, string(DispatchStarted), false, 1, ""},
		{"launched job in a substituted VM", map[string]string{"MSB_FAKE_JOB_BOOT_MISMATCH": "1"}, 0,
			JobStateDispatchAmbig, string(DispatchUncertain), false, 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, stateDir := fakeMSB(t, tc.env)
			dir := socketDir(t)
			key, keys := testAuthority(t)
			backend := testBackend(t, bin, filepath.Join(dir, "artifacts"))
			cfg := Config{SocketDir: dir, Peers: selfPeer(t), AuthorityKeys: keys, Backend: backend}
			if tc.dispatchTTL > 0 {
				cfg.DispatchTimeout = tc.dispatchTTL
			}
			srv := startServer(t, cfg)
			jobID := "adv-" + strings.ReplaceAll(tc.name, " ", "-")
			conn, reader := connect(t, srv.SocketPath())
			resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
				c.JobID = jobID
				c.Nonce = "n-" + jobID
			}))
			if resp.State != tc.wantState {
				t.Fatalf("state = %s, want %s (%+v)", resp.State, tc.wantState, resp)
			}
			lj, err := srv.Ledger().Get(jobID)
			if err != nil || lj == nil {
				t.Fatalf("ledger row: %v", err)
			}
			if tc.wantSettled != "" {
				lj = waitForLedgerState(t, srv.Ledger(), jobID, tc.wantSettled)
			}
			if lj.DispatchClass != tc.wantClass {
				t.Fatalf("dispatch class = %q, want %q", lj.DispatchClass, tc.wantClass)
			}
			hasReceipt := lj.ReceiptSHA256 != ""
			if hasReceipt != tc.wantReceipt {
				t.Fatalf("receipt present = %t, want %t", hasReceipt, tc.wantReceipt)
			}
			// A NO_EFFECT receipt is sound only when the executor
			// proved nothing executed: a proven pre-launch refusal, or
			// a typed spawn rejection the runtime itself recorded. A
			// receipt on anything else is a false no-effect claim —
			// and an empty job list is never proof of either.
			sound := lj.DispatchClass == string(DispatchProvenRejected) ||
				strings.Contains(lj.Error, "command rejected before start")
			if hasReceipt && !sound {
				targets.falseNoEffect++
			}
			// Duplicate dispatch: at most one runtime job record, ever.
			if lj.BackendHandle != "" {
				if records, rerr := fakeReadJobs(stateDir, lj.BackendHandle); rerr == nil && len(records) > tc.wantJobs {
					targets.duplicateDispatch++
				}
			}
		})
	}

	// ── Policy boundaries ───────────────────────────────────────────
	tamperCases := []string{
		"extra_env", "duplicate_env", "init_hook", "patches", "scripts", "rlimits",
		"mount_policy_loose", "extra_interface", "port_publish",
		"max_cpus_headroom", "max_memory_headroom", "ephemeral", "idle_timeout",
		"workdir", "shell", "runtime_cmd", "entrypoint", "runtime_user", "hostname",
		"pending_changes", "paused", "recovery_required",
	}
	for _, tamper := range tamperCases {
		t.Run("policy/"+tamper, func(t *testing.T) {
			key, _ := testAuthority(t)
			bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_TAMPER": tamper})
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "adv-pol"; c.Nonce = "n-adv-pol" })
			name := backend.msbJobName(job.JobID)
			if _, err := backend.Dispatch(testContext(t), job, nil); err == nil {
				targets.acceptedForbidden++
				return
			}
			// The refused VM is destroyed, so nothing may remain for a
			// later dispatch to adopt.
			if _, serr := os.Stat(fakeStatePath(stateDir, name)); serr == nil {
				t.Fatalf("the refused VM %s was left behind", name)
			}
		})
	}

	// ── Adoption boundaries ─────────────────────────────────────────
	t.Run("adoption/substituted boot generation", func(t *testing.T) {
		key, _ := testAuthority(t)
		bin, stateDir := fakeMSB(t, nil)
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		job := testContract(t, key, func(c *JobContractV2) { c.JobID = "adv-adopt"; c.Nonce = "n-adv-adopt" })
		disp, err := backend.Dispatch(testContext(t), job, nil)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		recs, _ := fakeReadJobs(stateDir, disp.Handle)
		if len(recs) != 1 {
			t.Fatalf("runtime records = %d", len(recs))
		}
		recs[0].RuntimeBoot = "boot_" + strings.Repeat("9", 32)
		if err := fakeWriteJobs(stateDir, disp.Handle, recs); err != nil {
			t.Fatal(err)
		}
		if _, _, rerr := backend.Resume(testContext(t), job, disp); rerr == nil {
			targets.unauthorizedAdopt++
		} else if !errors.Is(rerr, ErrExecutionUnobserved) {
			t.Fatalf("substitution error = %v, want unobserved", rerr)
		}
	})

	for _, attack := range []struct {
		name   string
		mutate func(*RunIdentity)
	}{
		{"rewritten nonce", func(r *RunIdentity) { r.Nonce = "nonce_" + strings.Repeat("9", 32) }},
		{"rewritten policy digest", func(r *RunIdentity) { r.PolicyDigest = strings.Repeat("cd", 32) }},
		{"missing boot generation", func(r *RunIdentity) { r.BootID = "" }},
	} {
		t.Run("adoption/"+attack.name, func(t *testing.T) {
			key, _ := testAuthority(t)
			bin, _ := fakeMSB(t, nil)
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "adv-attack"; c.Nonce = "n-adv-attack" })
			disp, err := backend.Dispatch(testContext(t), job, nil)
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			attacked := disp
			attack.mutate(&attacked)
			if _, _, rerr := backend.Resume(testContext(t), job, attacked); rerr == nil {
				targets.unauthorizedAdopt++
			}
		})
	}

	targets.assertZero(t)
	t.Logf("adversarial matrix: %d dispatch scenarios, %d policy scenarios, 4 adoption scenarios — targets %+v",
		len(cases), len(tamperCases), targets)
}

// TestDispatchClassVocabulary pins the explicit outcome vocabulary and
// the fail-closed default: an unclassified error is never a refusal.
func TestDispatchClassVocabulary(t *testing.T) {
	if got := ClassifyDispatchError(nil); got != DispatchStarted {
		t.Fatalf("nil error class = %q", got)
	}
	if got := ClassifyDispatchError(fmt.Errorf("wrapped: %w", ErrDispatchRefused)); got != DispatchProvenRejected {
		t.Fatalf("refusal class = %q", got)
	}
	if got := ClassifyDispatchError(fmt.Errorf("wrapped: %w", ErrAmbiguousDispatch)); got != DispatchUncertain {
		t.Fatalf("ambiguous class = %q", got)
	}
	if got := ClassifyDispatchError(errors.New("something else")); got != DispatchUncertain {
		t.Fatalf("unclassified error class = %q — it must fail closed as uncertain", got)
	}
}
