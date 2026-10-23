// sandbox-custody-drill runs the live custody drills a qualification
// bundle must contain: a real sandbox-custodyd process on a real unix
// socket, a real SQLite ledger, and the failure/attack paths the
// design claims to survive.
//
// The drills, in order:
//
//	baseline   emit + drain a recovery checkpoint through the daemon;
//	           the outbox row clears only after a verified ack.
//	outage     kill the witness mid-queue: the drain cannot reach it,
//	           the row stays pending; a restarted witness drains it.
//	replay     a captured valid ack re-presented for a different
//	           outbox row is refused by the recording boundary.
//	forgery    a rogue witness (key never approved by the operator
//	           trust root) mints a structurally valid ack; the boundary
//	           refuses it.
//	foreign    an ack minted under a different ledger's deployment
//	           scope is refused even though every field verifies.
//	audit      sandbox-custodyd -verify re-checks the custody store
//	           against the operator trust root.
//
// Usage:
//
//	sandbox-custody-drill -workdir <scratch dir> [-custodyd <binary>]
//
// With no -custodyd the harness builds ./cmd/sandbox-custodyd itself.
// Exit 0 only when every drill produced its required outcome.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sandboxcustody"
	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

var failures int

func report(name, detail string, ok bool) {
	mark := "PASS"
	if !ok {
		mark = "FAIL"
		failures++
	}
	fmt.Printf("%-4s  %-10s %s\n", mark, name, detail)
}

type custodyd struct {
	cmd       *exec.Cmd
	socket    string
	socketDir string
	custody   string
	key       string
}

func buildCustodyd(workdir string) (string, error) {
	bin := filepath.Join(workdir, "sandbox-custodyd")
	out, err := exec.Command("go", "build", "-o", bin, "./cmd/sandbox-custodyd").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build sandbox-custodyd: %v: %s", err, out)
	}
	return bin, nil
}

func startCustodyd(bin, root, name string) (*custodyd, error) {
	d := &custodyd{
		socketDir: filepath.Join(root, name+"-sock"),
		custody:   filepath.Join(root, name+"-custody"),
		key:       filepath.Join(root, name+"-witness.pem"),
	}
	for _, p := range []string{d.socketDir, d.custody} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, err
		}
	}
	d.socket = filepath.Join(d.socketDir, "custody.sock")
	// The key is created before launch so the operator trust root can
	// name the witness's public key — the deployment's trust posture
	// is fixed before the witness first speaks, never learned from it.
	if _, err := evidence.LoadOrCreateSigner(d.key); err != nil {
		return nil, fmt.Errorf("witness key: %w", err)
	}
	cmd := exec.Command(bin,
		"-socket-dir", d.socketDir,
		"-custody-dir", d.custody,
		"-key", d.key)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	d.cmd = cmd
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(d.socket); err == nil {
			conn, cerr := net.DialTimeout("unix", d.socket, time.Second)
			if cerr == nil {
				conn.Close()
				return d, nil
			}
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			return nil, fmt.Errorf("custodyd %s did not create its socket", name)
		}
		// ProcessState stays nil until Wait returns, so probe liveness
		// directly — an early custodyd exit must fail the drill now,
		// not after the deadline.
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			return nil, fmt.Errorf("custodyd %s exited during startup", name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (d *custodyd) kill() {
	if d.cmd != nil && d.cmd.Process != nil {
		d.cmd.Process.Signal(syscall.SIGKILL)
		d.cmd.Wait()
	}
}

func (d *custodyd) stop() {
	if d.cmd != nil && d.cmd.Process != nil {
		d.cmd.Process.Signal(syscall.SIGTERM)
		d.cmd.Wait()
	}
}

func writeTrust(path string, signers ...*evidence.Signer) (*sandboxcustody.TrustRoot, error) {
	wit := []map[string]string{}
	for _, s := range signers {
		wit = append(wit, map[string]string{
			"public_key": base64.StdEncoding.EncodeToString(s.PublicKey()),
		})
	}
	data, err := json.Marshal(map[string]any{"version": 1, "witnesses": wit})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return sandboxcustody.LoadTrustRoot(path)
}

// tapCustodian forwards to a real socket custodian and captures the
// acknowledgement — the replay drill's seized evidence.
type tapCustodian struct {
	inner *sandboxexecutor.SocketCustodian
	last  *sandboxexecutor.CustodyAck
}

func (t *tapCustodian) WitnessRecoveryCheckpoint(row *sandboxexecutor.RecoveryOutboxRow, dep string) (*sandboxexecutor.CustodyAck, error) {
	ack, err := t.inner.WitnessRecoveryCheckpoint(row, dep)
	if err == nil {
		t.last = ack
	}
	return ack, err
}

func (t *tapCustodian) CustodyTrustRoot() *sandboxcustody.TrustRoot {
	return t.inner.CustodyTrustRoot()
}

// replayCustodian returns a captured ack verbatim for whatever row it
// is offered — the adversary replaying seized evidence.
type replayCustodian struct {
	ack   *sandboxexecutor.CustodyAck
	trust *sandboxcustody.TrustRoot
}

func (r *replayCustodian) WitnessRecoveryCheckpoint(row *sandboxexecutor.RecoveryOutboxRow, dep string) (*sandboxexecutor.CustodyAck, error) {
	return r.ack, nil
}

func (r *replayCustodian) CustodyTrustRoot() *sandboxcustody.TrustRoot { return r.trust }

func pending(l *sandboxexecutor.Ledger) (int, error) {
	rows, err := l.PendingRecoveryCustody(0)
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

func audit(format string, args ...any) { fmt.Printf("      "+format+"\n", args...) }

func main() {
	workdir := flag.String("workdir", "", "scratch directory for ledger + custody stores (required)")
	custodydBin := flag.String("custodyd", "", "path to a sandbox-custodyd binary (default: build ./cmd/sandbox-custodyd)")
	keep := flag.Bool("keep", false, "leave the workdir in place for inspection")
	flag.Parse()
	if *workdir == "" {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill: -workdir is required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*workdir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill:", err)
		os.Exit(2)
	}
	if !*keep {
		defer os.RemoveAll(*workdir)
	}
	bin := *custodydBin
	if bin == "" {
		var err error
		if bin, err = buildCustodyd(*workdir); err != nil {
			fmt.Fprintln(os.Stderr, "sandbox-custody-drill:", err)
			os.Exit(2)
		}
	}

	// ── Deployment: an independently administered witness ────────────
	// The daemon's key, custody store, and socket dir live outside the
	// executor's ledger; the operator trust file names its public key.
	primary, err := startCustodyd(bin, *workdir, "primary")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill:", err)
		os.Exit(2)
	}
	witnessSigner, err := evidence.LoadOrCreateSigner(primary.key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill:", err)
		os.Exit(2)
	}
	trustPath := filepath.Join(*workdir, "custody-trust.json")
	trust, err := writeTrust(trustPath, witnessSigner)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill: trust root:", err)
		os.Exit(2)
	}

	execSigner, err := evidence.GenerateSigner()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill:", err)
		os.Exit(2)
	}

	openLedger := func(name string) *sandboxexecutor.Ledger {
		l, err := sandboxexecutor.OpenLedger(filepath.Join(*workdir, name+".db"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "sandbox-custody-drill: open ledger:", err)
			os.Exit(2)
		}
		l.SetCustodyTrust(trust)
		return l
	}
	emit := func(l *sandboxexecutor.Ledger, tag string) {
		for i := 0; i < 2; i++ {
			if err := l.RecordRecoveryEvent("drill", tag,
				fmt.Sprintf("%s event %d", tag, i), time.Now().UTC()); err != nil {
				fmt.Fprintln(os.Stderr, "sandbox-custody-drill: record:", err)
				os.Exit(2)
			}
		}
		if _, emitted, err := l.EmitRecoveryCheckpoint(execSigner); err != nil || !emitted {
			fmt.Fprintf(os.Stderr, "sandbox-custody-drill: emit %s: emitted=%v err=%v\n", tag, emitted, err)
			os.Exit(2)
		}
	}
	realCustodian := func(socket string) *sandboxexecutor.SocketCustodian {
		return &sandboxexecutor.SocketCustodian{Socket: socket, Trust: trust, Timeout: 10 * time.Second}
	}

	ledgerA := openLedger("ledger-a")
	defer ledgerA.Close()

	// ── baseline ─────────────────────────────────────────────────────
	tap := &tapCustodian{inner: realCustodian(primary.socket)}
	emit(ledgerA, "baseline")
	if err := ledgerA.DrainRecoveryCustody(tap, audit); err != nil {
		fmt.Fprintln(os.Stderr, "drain:", err)
		os.Exit(2)
	}
	n, _ := pending(ledgerA)
	report("baseline", fmt.Sprintf("checkpoint witnessed over unix socket, pending=%d (want 0)", n), n == 0 && tap.last != nil)

	// ── outage ───────────────────────────────────────────────────────
	emit(ledgerA, "outage")
	primary.kill()
	_ = ledgerA.DrainRecoveryCustody(tap, audit) // per-row failures are audited; the drain itself must not panic or record
	n, _ = pending(ledgerA)
	outageHeld := n == 1
	report("outage-hold", fmt.Sprintf("witness killed mid-queue: pending=%d (want 1, row must outlive the crash)", n), outageHeld)
	primary, err = startCustodyd(bin, *workdir, "primary")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill: restart:", err)
		os.Exit(2)
	}
	tap.inner = realCustodian(primary.socket)
	_ = ledgerA.DrainRecoveryCustody(tap, audit)
	n, _ = pending(ledgerA)
	report("outage-recover", fmt.Sprintf("witness restarted: pending=%d (want 0 — the queued obligation survived)", n), n == 0)

	// ── replay ───────────────────────────────────────────────────────
	seized := tap.last // a valid, verified ack — for a previous row
	emit(ledgerA, "replay")
	replayer := &replayCustodian{ack: seized, trust: trust}
	_ = ledgerA.DrainRecoveryCustody(replayer, audit)
	n, _ = pending(ledgerA)
	report("replay", fmt.Sprintf("seized ack re-presented for a new row: pending=%d (want 1 — binding refusal)", n), n == 1)
	_ = ledgerA.DrainRecoveryCustody(tap, audit) // clear the row legitimately for the next drill
	n, _ = pending(ledgerA)
	report("replay-clear", fmt.Sprintf("legitimate drain after refused replay: pending=%d (want 0)", n), n == 0)

	// ── forgery: unapproved witness ──────────────────────────────────
	rogue, err := startCustodyd(bin, *workdir, "rogue")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-custody-drill: rogue start:", err)
		os.Exit(2)
	}
	emit(ledgerA, "forgery")
	_ = ledgerA.DrainRecoveryCustody(realCustodian(rogue.socket), audit)
	n, _ = pending(ledgerA)
	report("forgery", fmt.Sprintf("ack from unapproved witness key: pending=%d (want 1 — trust root refusal)", n), n == 1)
	_ = ledgerA.DrainRecoveryCustody(tap, audit)
	n, _ = pending(ledgerA)
	report("forgery-clear", fmt.Sprintf("legitimate drain after refused forgery: pending=%d (want 0)", n), n == 0)
	rogue.stop()

	// ── foreign deployment scope ─────────────────────────────────────
	ledgerB := openLedger("ledger-b")
	defer ledgerB.Close()
	tapB := &tapCustodian{inner: realCustodian(primary.socket)}
	emit(ledgerB, "foreign")
	_ = ledgerB.DrainRecoveryCustody(tapB, audit)
	nB, _ := pending(ledgerB)
	report("foreign-mint", fmt.Sprintf("second ledger witnessed its checkpoint: pending=%d (want 0)", nB), nB == 0 && tapB.last != nil)
	emit(ledgerA, "foreign")
	foreignReplay := &replayCustodian{ack: tapB.last, trust: trust}
	_ = ledgerA.DrainRecoveryCustody(foreignReplay, audit)
	n, _ = pending(ledgerA)
	report("foreign", fmt.Sprintf("deployment-B ack replayed to ledger A: pending=%d (want 1 — scope binding refusal)", n), n == 1)
	_ = ledgerA.DrainRecoveryCustody(tap, audit)
	n, _ = pending(ledgerA)
	report("foreign-clear", fmt.Sprintf("legitimate drain after refused foreign ack: pending=%d (want 0)", n), n == 0)

	// ── independent audit ────────────────────────────────────────────
	out, err := exec.Command(bin, "-verify", "-custody-dir", primary.custody, "-trust-file", trustPath).CombinedOutput()
	report("audit", fmt.Sprintf("custody store verifies against the operator trust root (%s)", string(out)), err == nil)

	primary.stop()
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "\nsandbox-custody-drill: %d drill(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nsandbox-custody-drill: all drills produced their required outcomes")
}
