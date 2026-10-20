package sandboxexecutor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Identity-bound destruction (INV-01/INV-04): the destructive path is
// exercised against the actual removal mechanism — the fake runtime's
// label-conditioned `rm` — not against a mocked Cleanup. Every case
// drives a real Dispatch so the sandbox, its labels and the request's
// persisted identity are exactly what production produces.

// substitute writes a foreign sandbox over the handle: a different
// instance — fresh boot generation, attacker/foreign labels — that
// must survive every cleanup aimed at the authorized one.
func substitute(t *testing.T, dir, name string, labels map[string]string) {
	t.Helper()
	conf := fakeDefaultConfig()
	conf.Labels = labels
	if labels == nil {
		conf.Labels = map[string]string{"foreign": "instance"}
	}
	conf.Name = name
	storagePath := filepath.Join(dir, name+".storage")
	if err := os.MkdirAll(filepath.Join(storagePath, "runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	boot := fakeBootID(name)
	if err := os.WriteFile(filepath.Join(storagePath, "runtime", "runtime-boot-id"), []byte(boot), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fakeSandbox{
		Name: name, Status: "Running", BootID: boot,
		Storage: fakeStorage{Path: storagePath}, Config: conf, ActiveConfig: &conf,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A substitute occupies the name: the authorized instance's
	// record is gone, the replacement's stands.
	if err := os.WriteFile(fakeStatePath(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// survive asserts the sandbox under name still stands — the
// destructive operation never touched it.
func survive(t *testing.T, dir, name string) {
	t.Helper()
	if _, err := os.Stat(fakeStatePath(dir, name)); err != nil {
		t.Fatalf("sandbox %s was destroyed — the identity fence failed", name)
	}
}

// TestCleanupSubstitutedVMSurvives is the core INV-01 adversarial
// case: the authorized VM is gone and a foreign instance occupies the
// handle. The cleanup must classify the substitution, refuse to
// destroy it, and prove nothing.
func TestCleanupSubstitutedVMSurvives(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "sub-1"; c.Nonce = "n-sub" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The attacker/operator replaces the VM under the same name:
	// different labels, different boot generation.
	substitute(t, stateDir, disp.Handle, map[string]string{"foreign": "yes"})

	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("substituted sandbox classified %s, want %s: %s", res.Outcome, CleanupIdentityMismatch, res.Detail)
	}
	survive(t, stateDir, disp.Handle)
	// The substitute's own state is untouched — the removal's label
	// condition never selected it.
	sb := readFakeSandbox(t, stateDir, disp.Handle)
	if sb.Config.Labels["foreign"] != "yes" {
		t.Fatalf("substitute was modified: %+v", sb.Config.Labels)
	}
}

// TestCleanupSubstitutionInsideRemovalWindow: the substitution lands
// after our pre-verification, inside the runtime's own remove — the
// residual window. Under nonce-bound handles the delete is scoped to
// this dispatch's unforgeable name, so whatever record the runtime
// resolves at that name is this dispatch's to remove — including a
// foreign payload swapped in mid-remove, a shape that can only occur
// if the runtime itself is compromised. What the delete can never
// reach is a *different* name: a same-job instance minted under
// another dispatch's nonce survives. MSB_FAKE_RM_SWAP makes the fake
// rewrite the state file mid-remove.
func TestCleanupSubstitutionInsideRemovalWindow(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_RM_SWAP": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "swap-1"; c.Nonce = "n-swap" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// A foreign record waits to take the name the instant the
	// authorized record leaves — the fake's rm swaps it in after our
	// pre-verification, inside its own remove.
	foreignStatePayload(t, stateDir, disp.Handle, map[string]string{"foreign": "yes"})
	// And a same-job sandbox under a different dispatch nonce — the
	// only instance that could ever share this job's name prefix.
	other := backend.msbJobName(job.JobID, "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a")
	writeFakeSandbox(t, stateDir, other, fakeDefaultConfig())

	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !res.Outcome.ProvesAbsent() {
		t.Fatalf("the authorized instance's absence could not be proven: %s — %s", res.Outcome, res.Detail)
	}
	// Whatever occupied our unforgeable name is gone — the swap
	// payload deleted with the record it overwrote.
	if _, serr := os.Stat(fakeStatePath(stateDir, disp.Handle)); serr == nil {
		t.Fatal("the nonce-bound name still names a record after removal")
	}
	// The different-named same-job instance is never a candidate.
	survive(t, stateDir, other)
}

// TestCleanupReusedNameWrongNonce: the handle is occupied by a
// sandbox created under a *different* dispatch nonce — e.g. a later
// job's VM. A cleanup carrying the stale nonce must refuse.
func TestCleanupReusedNameWrongNonce(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	jobA := testContract(t, key, func(c *JobContractV2) { c.JobID = "reuse-a"; c.Nonce = "n-a" })
	jobB := testContract(t, key, func(c *JobContractV2) { c.JobID = "reuse-b"; c.Nonce = "n-b" })

	dispA, err := backend.Dispatch(testContext(t), jobA, nil)
	if err != nil {
		t.Fatalf("dispatch A: %v", err)
	}
	// Replace A's instance with a different-nonce instance under the
	// same name — what B's VM occupying A's old handle looks like.
	substitute(t, stateDir, dispA.Handle, map[string]string{
		"crabedence.dispatch": "n-b", "crabedence.job": jobB.JobID})

	res, err := backend.Cleanup(testContext(t), cleanupReqFor(jobA, dispA))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("different-nonce occupant classified %s, want %s", res.Outcome, CleanupIdentityMismatch)
	}
	survive(t, stateDir, dispA.Handle)
}

// TestCleanupMissingIdentityFailsClosed: a request without the
// dispatch's ownership proof can never authorize destruction — the
// resource is quarantined, not name-removed.
func TestCleanupMissingIdentityFailsClosed(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "noid-1"; c.Nonce = "n-noid" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The ledger row that lost its persisted nonce: the name alone
	// must not be enough to destroy anything.
	req := cleanupReqFor(job, disp)
	req.DispatchNonce = ""
	res, err := backend.Cleanup(testContext(t), req)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("unidentified request classified %s, want %s", res.Outcome, CleanupIdentityUnverifiable)
	}
	survive(t, stateDir, disp.Handle)

	req = cleanupReqFor(job, disp)
	req.Handle = ""
	if err := req.Validate(); err == nil {
		t.Fatal("a request with no lookup name validated")
	}
	if res.Outcome.ProvesAbsent() {
		t.Fatal("an unverifiable outcome proved absence")
	}
}

// TestCleanupWrongJobLabel: the dispatch label matches (same nonce)
// but the job label does not — a request assembled from the wrong
// durable record refuses rather than destroying another job's VM.
func TestCleanupWrongJobLabel(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "wrongjob-1"; c.Nonce = "n-wj" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	req := cleanupReqFor(job, disp)
	req.JobID = "someone-elses-job"
	res, err := backend.Cleanup(testContext(t), req)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("wrong-job request classified %s, want %s", res.Outcome, CleanupIdentityMismatch)
	}
	survive(t, stateDir, disp.Handle)
}

// TestCleanupConcurrentJobsAreIndependent: two live sandboxes, two
// cleanups racing — each must remove only the instance carrying its
// own dispatch identity.
func TestCleanupConcurrentJobsAreIndependent(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	jobA := testContract(t, key, func(c *JobContractV2) { c.JobID = "conc-a"; c.Nonce = "n-conc-a" })
	jobB := testContract(t, key, func(c *JobContractV2) { c.JobID = "conc-b"; c.Nonce = "n-conc-b" })

	dispA, err := backend.Dispatch(testContext(t), jobA, nil)
	if err != nil {
		t.Fatalf("dispatch A: %v", err)
	}
	dispB, err := backend.Dispatch(testContext(t), jobB, nil)
	if err != nil {
		t.Fatalf("dispatch B: %v", err)
	}

	type outcome struct {
		res CleanupResult
		err error
	}
	done := make(chan outcome, 2)
	for _, tc := range [][2]any{{jobA, dispA}, {jobB, dispB}} {
		go func(j *JobContractV2, d RunIdentity) {
			res, err := backend.Cleanup(testContext(t), cleanupReqFor(j, d))
			done <- outcome{res, err}
		}(tc[0].(*JobContractV2), tc[1].(RunIdentity))
	}
	for i := 0; i < 2; i++ {
		o := <-done
		if o.err != nil {
			t.Fatalf("concurrent cleanup errored: %v", o.err)
		}
		if o.res.Outcome != CleanupRemovedVerified {
			t.Fatalf("concurrent cleanup outcome %s, want %s", o.res.Outcome, CleanupRemovedVerified)
		}
	}
	if _, err := os.Stat(fakeStatePath(stateDir, dispA.Handle)); err == nil {
		t.Fatal("job A's sandbox survived its own cleanup")
	}
	if _, err := os.Stat(fakeStatePath(stateDir, dispB.Handle)); err == nil {
		t.Fatal("job B's sandbox survived its own cleanup")
	}
}

// TestCleanupOneJobNeverTouchesAnother: cleanup of A while B's VM is
// live — B's instance must survive even though the CLI's label
// selection ran over the whole catalog.
func TestCleanupOneJobNeverTouchesAnother(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	jobA := testContract(t, key, func(c *JobContractV2) { c.JobID = "iso-a"; c.Nonce = "n-iso-a" })
	jobB := testContract(t, key, func(c *JobContractV2) { c.JobID = "iso-b"; c.Nonce = "n-iso-b" })

	dispA, err := backend.Dispatch(testContext(t), jobA, nil)
	if err != nil {
		t.Fatalf("dispatch A: %v", err)
	}
	dispB, err := backend.Dispatch(testContext(t), jobB, nil)
	if err != nil {
		t.Fatalf("dispatch B: %v", err)
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(jobA, dispA))
	if err != nil {
		t.Fatalf("cleanup A: %v", err)
	}
	if res.Outcome != CleanupRemovedVerified {
		t.Fatalf("cleanup A outcome %s: %s", res.Outcome, res.Detail)
	}
	survive(t, stateDir, dispB.Handle)
}

// TestCleanupTransportFailureIsUncertain: the removal failed after
// being issued — the post-check is the only verdict, and our labels
// still present makes the outcome uncertain, never absent.
func TestCleanupTransportFailureIsUncertain(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_RM_FAIL": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "xfail-1"; c.Nonce = "n-xfail" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup transport error must classify, not return: %v", err)
	}
	if res.Outcome != CleanupRemovalUncertain {
		t.Fatalf("failed removal classified %s, want %s: %s", res.Outcome, CleanupRemovalUncertain, res.Detail)
	}
	survive(t, stateDir, disp.Handle)
}

// TestCleanupIdentitySurvivesLedgerReopen: the destruction
// authorization is the *persisted* dispatch record — a reopened
// ledger builds the same request, so a restart's cleanup is bound to
// the same instance the live path was.
func TestCleanupIdentitySurvivesLedgerReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.InsertJob("reopen-1", "h-reopen", "alice", "alice", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("reopen-1", JobStateDispatching, []string{JobStateRecorded}, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("reopen-1", JobStateRunning, []string{JobStateDispatching}, func(j *LedgerJob) error {
		applyRunIdentity(j, "microsandbox", RunIdentity{
			Handle: "sx-reopen-1", RunID: "job_" + strings.Repeat("2", 32),
			BootID: "boot_" + strings.Repeat("2", 32), PolicyDigest: strings.Repeat("cd", 32),
			Nonce: "nonce_" + strings.Repeat("9", 32)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	j, err := l2.Get("reopen-1")
	if err != nil || j == nil {
		t.Fatalf("reopened ledger lost the job: %v", err)
	}
	req := cleanupRequestFor(j)
	if err := req.Validate(); err != nil {
		t.Fatalf("the persisted identity cannot authorize cleanup: %v", err)
	}
	if req.DispatchNonce != j.DispatchNonce || req.Handle != j.BackendHandle || req.BootID != j.BackendBootID || req.RunID != j.BackendJobID {
		t.Fatalf("reopened identity diverged: %+v vs row %+v", req, j)
	}
}

// TestCleanupResultNeverErasesTheOutcome: a cleanup that cannot
// prove absence is residue on the terminal row — the verified result,
// receipt and artifact binding are untouched.
func TestCleanupResultNeverErasesTheOutcome(t *testing.T) {
	key, keys := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_RM_FAIL": "1"})
	be := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	srv := startServer(t, Config{SocketDir: socketDir(t), Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID = "keep-res"
		c.Nonce = "n-keepres"
	}))
	if !resp.OK {
		t.Fatalf("submit: %+v", resp)
	}
	lj := waitLedgerState(t, srv, "keep-res", JobStateSucceeded)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lj.CleanupPending && lj.CleanupError != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
		lj, _ = srv.Ledger().Get("keep-res")
	}
	if !lj.CleanupPending {
		t.Fatalf("an uncertain removal was not kept pending: %+v", lj)
	}
	if lj.ReceiptSHA256 == "" || lj.ExitCode == nil || *lj.ExitCode != 0 || lj.ResultJSON == "" {
		t.Fatalf("the cleanup residue damaged the verified result: %+v", lj)
	}
	// The removal is still owed but the VM is still the authorized
	// instance — the retry will be the same identity-bound request.
	if _, err := os.Stat(fakeStatePath(stateDir, lj.BackendHandle)); err != nil {
		t.Fatal("the authorized VM vanished under an unproven removal")
	}
}

// TestCleanupOutsideNamespaceRefused: a handle this backend never
// issued — no shared prefix — is unverifiable by construction, never
// a candidate for removal.
func TestCleanupOutsideNamespaceRefused(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, t.TempDir())
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ns-1"; c.Nonce = "n-ns" })

	res, err := backend.Cleanup(testContext(t), CleanupRequest{
		JobID: job.JobID, BackendID: "microsandbox",
		Handle: "foreign-sandbox", DispatchNonce: "nonce_abc",
	})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("out-of-namespace handle classified %s, want %s", res.Outcome, CleanupIdentityUnverifiable)
	}
}

// TestRetentionInventoryTracksPolicyKeptResource: a cleanup resolved
// RETAINED_BY_POLICY discharges the removal obligation while the
// resource still exists. The obligation flag clears — but the live
// instance must land in the retained-resources inventory under its
// persisted dispatch identity, or cleanup accounting is correct while
// resource accounting silently loses a real VM.
func TestRetentionInventoryTracksPolicyKeptResource(t *testing.T) {
	key, keys := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	be := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	be.KeepSandboxes = true
	srv := startServer(t, Config{SocketDir: socketDir(t), Peers: selfPeer(t), AuthorityKeys: keys, Backend: be})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID = "retain-1"
		c.Nonce = "n-retain"
	}))
	if !resp.OK {
		t.Fatalf("submit: %+v", resp)
	}
	lj := waitLedgerState(t, srv, "retain-1", JobStateSucceeded)

	// Retention resolves the obligation — the flag clears — but the
	// live instance must enter the inventory first. Poll: the settle
	// path's cleanup runs after the terminal transition lands.
	deadline := time.Now().Add(5 * time.Second)
	var retained []*RetainedResource
	for time.Now().Before(deadline) {
		lj, _ = srv.Ledger().Get("retain-1")
		retained, _ = srv.Ledger().RetainedResources()
		if !lj.CleanupPending && len(retained) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lj.CleanupPending {
		t.Fatalf("a policy-discharge left the obligation pending: %+v", lj)
	}
	if len(retained) != 1 {
		t.Fatalf("the retained VM is not inventoried: %d records", len(retained))
	}
	rec := retained[0]
	if rec.JobID != "retain-1" || rec.Handle != lj.BackendHandle || rec.DispatchNonce != lj.DispatchNonce || rec.BackendID != "microsandbox" {
		t.Fatalf("retention record does not bind the persisted dispatch identity: %+v vs row %+v", rec, lj)
	}
	if !rec.DisposedAt.IsZero() {
		t.Fatalf("a live retention is already disposed: %+v", rec)
	}
	// The resource itself still exists — nothing was claimed absent.
	if _, err := os.Stat(fakeStatePath(stateDir, lj.BackendHandle)); err != nil {
		t.Fatal("the retained VM vanished under a policy discharge")
	}
	// Disposal closes the live record; the inventory empties and a
	// re-record for the disposed job is refused — disposal is final.
	if err := srv.Ledger().DisposeRetainedResource("retain-1"); err != nil {
		t.Fatalf("dispose: %v", err)
	}
	if retained, _ := srv.Ledger().RetainedResources(); len(retained) != 0 {
		t.Fatal("a disposed resource still lists as retained")
	}
	if err := srv.Ledger().RecordRetainedResource("retain-1", "microsandbox", "h", "n", "again"); err == nil {
		t.Fatal("a disposed retention record was silently rewritten")
	}
	srv.Stop()
}

// TestCleanupSubstituteAfterRemovalSurvives: the adversary cannot
// mint our nonce-bound name — but if the runtime itself is hostile,
// a foreign record could be planted under it between the delete
// returning and the post-removal inspect. The verdict must be exact:
// nothing carrying the authorized identity exists (verified absent),
// and the substitute is named in the evidence — never destroyed by
// us, never mistaken for our instance.
func TestCleanupSubstituteAfterRemovalSurvives(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_RM_RECREATE": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "post-1"; c.Nonce = "n-post" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The foreign record the fake plants under our handle the moment
	// its delete returns — post-verify sees it, not absence.
	conf := fakeDefaultConfig()
	conf.Name = disp.Handle
	conf.Labels = map[string]string{"foreign": "occupant"}
	raw, err := json.Marshal(fakeSandbox{
		Name: disp.Handle, Status: "Running", BootID: fakeBootID(disp.Handle),
		Config: conf, ActiveConfig: &conf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "rm-recreate-payload"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupRemovedVerified {
		t.Fatalf("post-remove substitute classified %s, want %s: %s", res.Outcome, CleanupRemovedVerified, res.Detail)
	}
	if !strings.Contains(res.Detail, "different instance") {
		t.Fatalf("the substitute's survival is not in the evidence: %s", res.Detail)
	}
	// The substitute itself was never destroyed — a foreign occupant
	// is an operator's problem, not ours to delete.
	survive(t, stateDir, disp.Handle)
	sb := readFakeSandbox(t, stateDir, disp.Handle)
	if sb.Config.Labels["foreign"] != "occupant" {
		t.Fatalf("the post-remove occupant was modified: %+v", sb.Config.Labels)
	}
}

// foreignStatePayload rewrites a sandbox's record inside the fake's
// own `rm` — the substitution-inside-the-window the label condition
// exists to defeat. MSB_FAKE_RM_SWAP makes fakeRemove move the
// payload over the state file before its label match runs.
func foreignStatePayload(t *testing.T, dir, name string, labels map[string]string) {
	t.Helper()
	conf := fakeDefaultConfig()
	conf.Name = name
	conf.Labels = labels
	raw, err := json.Marshal(fakeSandbox{
		Name: name, Status: "Running", BootID: fakeBootID(name),
		Config: conf, ActiveConfig: &conf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rm-swap-payload"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
