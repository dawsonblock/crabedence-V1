#!/usr/bin/env python3
"""Render per-test case evidence from a `go test -json` event stream.

The release qualification pipeline must prove that each required test
actually executed and passed — an aggregate "ok" or a positive test count
cannot show that. This tool normalizes the raw `go test -json` stream into
a case-evidence record that the shared gate validator
(scripts/lib/qualification-gates.sh) checks against the bundled
required-test inventory (qualification/required-tests.json).

Usage:
    go-test-case-evidence.py --stream RAW.json --out CASES.json \
        --suite live-microvm --lane apple-hypervisor-framework \
        --commit COMMIT --toolchain-go "go version go1.26.5 darwin/arm64" \
        [--inventory required-tests.json --source-root REPO_ROOT]

    go-test-case-evidence.py --verify --stream RAW.json \
        --results CASES.json [--expect-package PACKAGE]

When --inventory and --source-root are given, the tool also verifies that
every test function in the suite's package matching the inventory's
run_pattern is covered by the inventory (common or any lane's
platform-specific list): a new live test that was never inventoried is a
coverage failure, not silent evidence.

The emitted record carries the identity the validator cross-checks:
source commit, toolchain, runner os/arch, the lane, and per-test terminal
status, duration, and an output digest so a borrowed log cannot pose as
this run's evidence.

Verify mode is the same deterministic parser run the other way: it
re-derives the complete normalized record from the raw stream — case
identities, outcomes, terminal-event counts, durations, output digests,
counts, package identity, and the run's own terminal completeness — and
reports every point on which the supplied results file disagrees with
the stream, plus every way the stream itself is malformed. Findings are
printed one per line; a clean run prints nothing.

Both modes enforce the canonical per-test lifecycle a real `go test
-json` run produces:

    run -> (output | pause | cont)* -> exactly one terminal outcome
                                       (pass | fail | skip | bench)

A terminal outcome without a preceding run, a duplicate run, a pause
while not running, a cont while not paused, any event after the terminal
outcome, or a test that appears under two package identities is
malformed evidence — generation refuses to normalize it and verification
reports it.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import sys

TERMINAL_ACTIONS = ("pass", "fail", "skip")

# `bench` terminates a benchmark's lifecycle the way the terminal trio
# terminates a test's: a benchmark emits run -> output* -> bench. Its
# derived status is "bench" — never "pass" — so a benchmark can never
# satisfy a required-test slot.
BENCH_ACTION = "bench"

# The closed set of actions a real `go test -json` stream emits. Anything
# outside it is a fabricated or corrupted event, never a forward
# extension this pipeline may silently accept.
GO_ACTIONS = frozenset(
    ("start", "run", "pause", "cont", "pass", "bench", "fail", "output", "skip")
)

# Per-test lifecycle states. Events are only legal in the states named
# by TEST_TRANSITIONS below.
TEST_STATE_NEW = "new"
TEST_STATE_RUNNING = "running"
TEST_STATE_PAUSED = "paused"
TEST_STATE_DONE = "done"

# Actions legal at package scope (no Test field): a package starts,
# emits output, and reports exactly one terminal outcome. run/pause/
# cont/bench are per-test states a package can never hold.
PACKAGE_ACTIONS = frozenset(("start", "output") + TERMINAL_ACTIONS)

# The timestamp form a real `go test -json` event carries when it
# carries one: RFC3339 with optional fractional seconds and a Z or
# numeric offset. Anything else is a fabricated or corrupted field.
TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def _reject_constant(name):
    """json.loads hook: NaN and Infinity are not valid JSON evidence.

    Python's decoder admits these nonstandard literals by default; a
    qualification stream is not a place for permissive decoding — the
    constant is a fabrication, never a duration.
    """
    raise ValueError(f"nonstandard numeric constant {name!r} in event stream")


def _elapsed_finding(elapsed):
    """The strict numeric contract for a stream's Elapsed field.

    Returns the finding text for an unacceptable value, or None. A
    boolean is not a number here (Python types it as int); NaN and
    Infinity are not durations; a negative or float64-overflowing
    value cannot be a measured runtime.
    """
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
        return "Elapsed is not numeric"
    if isinstance(elapsed, float) and not math.isfinite(elapsed):
        return "Elapsed is not finite — NaN or Infinity is not a duration"
    if elapsed < 0:
        return "Elapsed is negative"
    # float() must succeed in accumulate: ints larger than a float64
    # can represent raise OverflowError there, so the bound lives
    # here where it can be a finding rather than a crash.
    if isinstance(elapsed, int) and elapsed.bit_length() > 1023:
        return "Elapsed overflows a float64"
    return None


def new_case():
    return {
        "status": None,
        "elapsed": 0.0,
        "terminal_events": 0,
        "out": hashlib.sha256(),
    }


def accumulate(rec, event):
    """Fold one well-formed event into a per-test record.

    This is the single derivation rule generation and verification share:
    the last terminal action decides the outcome, terminal actions are
    counted, the duration is the largest terminal Elapsed, and the output
    digest covers every output event's bytes in stream order. A change to
    what the stream means lands here — never in one caller alone.
    """
    action = event.get("Action")
    if action in TERMINAL_ACTIONS or action == BENCH_ACTION:
        rec["status"] = action
        rec["terminal_events"] += 1
        if event.get("Elapsed") is not None:
            rec["elapsed"] = max(rec["elapsed"], float(event["Elapsed"]))
    elif action == "output":
        rec["out"].update(event.get("Output", "").encode("utf-8"))


class _Scan:
    """The state one canonical stream walk produces.

    Shared by generation (parse_stream) and verification (verify_stream)
    so the normalized record and the re-derived record can never diverge
    in what the stream means.
    """

    def __init__(self):
        self.findings = []
        self.cases = {}
        self.order = []
        self.packages = set()
        self.test_pkg = {}
        self.pkg_terminal = {}
        self.pkg_outcome = {}
        self.pkg_started = set()
        self.done_pkgs = set()
        self.state = {}
        self.pkg_conflicts = set()


def _scan_stream(path):
    """Walk one raw go test -json stream under the canonical lifecycle.

    Returns a _Scan. A finding is emitted for every malformed event and
    every impossible sequence: a test-scoped event before its run, a
    duplicate run, an invalid pause/cont transition, a terminal outcome
    from a non-running state, any event after a test's or a package's
    terminal outcome, a test-scoped start, a package-scoped per-test
    action, a test straddling two package identities, or a duplicate
    package start. Findings never stop the walk — the derived record must
    describe all the bytes the bundle binds.
    """
    scan = _Scan()
    findings = scan.findings
    cases = scan.cases
    order = scan.order
    packages = scan.packages
    test_pkg = scan.test_pkg
    state = scan.state
    pkg_terminal = scan.pkg_terminal
    pkg_outcome = scan.pkg_outcome
    done_pkgs = scan.done_pkgs

    try:
        handle = open(path, "r", encoding="utf-8")
    except OSError as exc:
        findings.append(f"raw stream {path} cannot be read: {exc}")
        return scan
    with handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line, parse_constant=_reject_constant)
            except ValueError:
                findings.append(f"{path}:{lineno}: not a go test -json event line")
                continue
            if not isinstance(event, dict):
                findings.append(f"{path}:{lineno}: event is not a JSON object")
                continue
            action = event.get("Action")
            if not isinstance(action, str):
                findings.append(f"{path}:{lineno}: event carries no string Action")
                continue
            if action not in GO_ACTIONS:
                findings.append(f"{path}:{lineno}: unknown go test action {action!r}")
                continue
            test = event.get("Test")
            if test is not None and not isinstance(test, str):
                findings.append(f"{path}:{lineno}: Test is not a string")
                continue
            if isinstance(test, str) and not test.strip():
                findings.append(
                    f"{path}:{lineno}: test-scoped event carries an empty test identity"
                )
                continue
            if "Output" in event and not isinstance(event["Output"], str):
                findings.append(f"{path}:{lineno}: Output is not a string")
                continue
            if "Elapsed" in event:
                elapsed_finding = _elapsed_finding(event["Elapsed"])
                if elapsed_finding is not None:
                    findings.append(f"{path}:{lineno}: {elapsed_finding}")
                    continue
            if "Time" in event:
                tval = event["Time"]
                if not isinstance(tval, str) or not TIME_RE.match(tval):
                    findings.append(
                        f"{path}:{lineno}: Time is not an RFC3339 timestamp"
                    )
                    continue
            pkg = event.get("Package")
            if not isinstance(pkg, str):
                findings.append(f"{path}:{lineno}: event carries no string Package")
                continue
            if not pkg.strip():
                findings.append(
                    f"{path}:{lineno}: event carries an empty package identity"
                )
                continue
            if pkg in done_pkgs:
                findings.append(
                    f"{path}:{lineno}: event for package {pkg} after its terminal outcome"
                )
                continue
            if pkg:
                packages.add(pkg)
            if test is None:
                if action == "start":
                    if pkg in scan.pkg_started:
                        findings.append(
                            f"{path}:{lineno}: package {pkg} records a second start event"
                        )
                    else:
                        scan.pkg_started.add(pkg)
                else:
                    if pkg not in scan.pkg_started:
                        # A package outcome — or output — with no
                        # preceding start is a fabricated lifecycle:
                        # the run never announced this package.
                        findings.append(
                            f"{path}:{lineno}: package {pkg} records {action} "
                            "before its start event"
                        )
                    if action in TERMINAL_ACTIONS:
                        pkg_terminal[pkg] = pkg_terminal.get(pkg, 0) + 1
                        pkg_outcome[pkg] = action
                        done_pkgs.add(pkg)
                    elif action not in PACKAGE_ACTIONS:
                        findings.append(
                            f"{path}:{lineno}: package {pkg} records test-scoped "
                            f"action {action} with no test name"
                        )
                continue
            if pkg not in scan.pkg_started:
                findings.append(
                    f"{path}:{lineno}: test {test} records an event under "
                    f"package {pkg} before the package's start event"
                )
            if test not in cases:
                cases[test] = new_case()
                order.append(test)
                state[test] = TEST_STATE_NEW
                test_pkg[test] = pkg
            elif test_pkg[test] != pkg:
                if test not in scan.pkg_conflicts:
                    scan.pkg_conflicts.add(test)
                    findings.append(
                        f"{path}:{lineno}: test {test} records events under both "
                        f"{test_pkg[test]} and {pkg} — conflicting package identity"
                    )
            st = state[test]
            if st == TEST_STATE_DONE:
                findings.append(
                    f"{path}:{lineno}: test {test} records an event "
                    f"(action={action}) after its terminal outcome"
                )
            elif st == TEST_STATE_NEW and action != "run":
                findings.append(
                    f"{path}:{lineno}: test {test} records {action} without a "
                    "preceding run event — an outcome the run never started "
                    "is not evidence it executed"
                )
            elif action == "run" and st != TEST_STATE_NEW:
                findings.append(
                    f"{path}:{lineno}: test {test} records a duplicate run event"
                )
            elif action == "pause" and st != TEST_STATE_RUNNING:
                findings.append(
                    f"{path}:{lineno}: test {test} pauses while not running"
                )
            elif action == "cont" and st != TEST_STATE_PAUSED:
                findings.append(
                    f"{path}:{lineno}: test {test} continues while not paused"
                )
            elif action == "start":
                findings.append(
                    f"{path}:{lineno}: test {test} records a test-scoped start event"
                )
            elif action in TERMINAL_ACTIONS and st == TEST_STATE_PAUSED:
                findings.append(
                    f"{path}:{lineno}: test {test} records terminal outcome "
                    f"{action} while paused"
                )
            # Transition. Even a malformed event lands the state machine
            # where the action claims to take it, so one defect cannot
            # cascade into a fabricated history of the stream.
            if action == "run":
                if st == TEST_STATE_NEW:
                    state[test] = TEST_STATE_RUNNING
            elif action == "pause":
                state[test] = TEST_STATE_PAUSED
            elif action == "cont":
                state[test] = TEST_STATE_RUNNING
            elif action in TERMINAL_ACTIONS or action == BENCH_ACTION:
                state[test] = TEST_STATE_DONE
            accumulate(cases[test], event)
    return scan


def lifecycle_findings(scan):
    """The canonical lifecycle's completeness half — one authoritative
    implementation shared by generation and verification.

    _scan_stream enforces what the stream may contain (well-formed
    events in legal order); this enforces what it must contain: exactly
    one terminal outcome per test, exactly one terminal outcome per
    package, and outcomes that do not contradict each other. A stream
    missing any of these is truncated, fabricated, or describes a run
    that did not pass — none of which may be normalized into evidence.

    The package-outcome rule is part of lifecycle validity, not a
    verification preference: a package that reports fail or skip while
    its tests claim pass is an internally contradictory stream, and a
    package that reports pass while a test failed or never terminated
    launders failure into success. Neither can be evidence of a
    passing run.
    """
    findings = []
    if not scan.packages:
        # A successful test invocation must contain at least one
        # properly completed package. An empty stream — or one with no
        # package identity at all — is not a run that produced zero
        # tests; it is no run at all.
        findings.append(
            "the stream contains no package evidence — an empty or "
            "package-less stream is not a completed test invocation"
        )
    for name in scan.order:
        n = scan.cases[name]["terminal_events"]
        if n != 1:
            findings.append(
                f"test {name} recorded {n} terminal events in the raw stream "
                "(a genuine go test run produces exactly one)"
            )
    for pkg in sorted(p for p in scan.packages if p):
        n = scan.pkg_terminal.get(pkg, 0)
        pkg_tests = [t for t, p in scan.test_pkg.items() if p == pkg]
        if n == 0:
            findings.append(
                f"package {pkg} has no terminal outcome — the run did not complete"
            )
        elif n > 1:
            findings.append(f"package {pkg} recorded {n} terminal outcomes")
        elif scan.pkg_outcome[pkg] != "pass":
            # A package that failed or skipped is honest evidence of a
            # failed run, never of a qualified one — a build break, a
            # TestMain panic, or a skipped suite must not launder the
            # per-test cases into a passing record.
            findings.append(
                f"package {pkg} finished with outcome {scan.pkg_outcome[pkg]} — "
                "a failed or skipped package run is not passing evidence"
            )
        elif any(
            (scan.cases[t]["status"] or "incomplete") in ("fail", "incomplete")
            for t in pkg_tests
        ):
            findings.append(
                f"package {pkg} reports pass while the derived test outcomes "
                "contain a failed or incomplete case"
            )
    return findings


def parse_stream(path):
    """Parse a go test -json stream into {name: {status, elapsed, out_sha, terminal_events}}.

    Generation enforces the same canonical lifecycle verification does:
    a stream that cannot be a real `go test -json` run is refused, never
    normalized into plausible-looking evidence. Returns (cases, packages)
    where cases maps test name -> record and packages is the set of Go
    packages the events belonged to.
    """
    scan = _scan_stream(path)
    findings = scan.findings + lifecycle_findings(scan)
    if findings:
        for finding in findings:
            print(f"error: {finding}", file=sys.stderr)
        sys.exit(1)
    for rec in scan.cases.values():
        rec["output_sha256"] = rec["out"].hexdigest()
        del rec["out"]
    return (
        [dict(name=n, **scan.cases[n]) for n in scan.order],
        sorted(p for p in scan.packages if p),
    )


def verify_stream(path, expect_package=""):
    """Strictly re-derive the normalized record from a raw stream.

    Returns (findings, derived_tests, derived_counts, derived_packages).
    A finding is emitted for every malformed event, every impossible
    sequence (events after a test's or a package's terminal outcome,
    duplicate terminal outcomes, a package the run never completed), and
    every package identity that is not the suite package. Derivation uses
    the same `accumulate` rule as generation, so the derived record is by
    construction the record the stream actually supports.
    """
    scan = _scan_stream(path)
    # Scan findings (what the stream may contain) and lifecycle
    # findings (what it must contain) come from the same two
    # implementations generation uses — verify can never reject a
    # stream for a defect generation would have accepted.
    findings = scan.findings + lifecycle_findings(scan)
    cases = scan.cases
    order = scan.order
    packages = scan.packages

    if expect_package:
        for pkg in sorted(p for p in packages if p):
            if pkg != expect_package and not pkg.endswith("/" + expect_package):
                findings.append(
                    f"package {pkg} is not the declared suite package {expect_package}"
                )

    derived_tests = []
    for name in order:
        rec = cases[name]
        derived_tests.append(
            {
                "name": name,
                "status": rec["status"] or "incomplete",
                "elapsed_seconds": round(rec["elapsed"], 4),
                "terminal_events": rec["terminal_events"],
                "output_sha256": rec["out"].hexdigest(),
            }
        )
    derived_counts = {
        "passed": sum(1 for c in derived_tests if c["status"] == "pass"),
        "failed": sum(1 for c in derived_tests if c["status"] == "fail"),
        "skipped": sum(1 for c in derived_tests if c["status"] == "skip"),
        "incomplete": sum(1 for c in derived_tests if c["status"] == "incomplete"),
    }
    derived_packages = sorted(p for p in packages if p)
    return (findings, derived_tests, derived_counts, derived_packages)


def verify_results(stream_path, results_path, expect_package=""):
    """Re-derive the case record from the raw stream and compare it
    field-for-field to the supplied results file.

    The results file's own fields are never trusted: every value it
    asserts is checked against what the stream actually contains —
    case identities in stream order, per-case outcome, terminal-event
    count, duration, output digest, the aggregate counts, and the
    package set. Returns the list of findings; empty means the results
    record is an exact description of the raw stream.
    """
    findings, derived_tests, derived_counts, derived_packages = verify_stream(
        stream_path, expect_package
    )
    try:
        with open(results_path, "r", encoding="utf-8") as handle:
            claimed = json.load(handle, parse_constant=_reject_constant)
    except (OSError, ValueError) as exc:
        return findings + [f"results file {results_path} is not valid JSON: {exc}"]
    if not isinstance(claimed, dict):
        return findings + [f"results file {results_path} is not a JSON object"]
    if claimed.get("schema_version") != 1:
        findings.append(
            f"results schema_version {claimed.get('schema_version')!r} (want 1)"
        )
    claimed_tests = claimed.get("tests")
    if not isinstance(claimed_tests, list):
        findings.append("results carries no tests array")
    else:
        if len(claimed_tests) != len(derived_tests):
            findings.append(
                f"results records {len(claimed_tests)} cases; the raw stream "
                f"derives {len(derived_tests)}"
            )
        for i, (claimed_case, derived_case) in enumerate(
            zip(claimed_tests, derived_tests)
        ):
            if not isinstance(claimed_case, dict):
                findings.append(f"results case #{i} is not an object")
                continue
            label = claimed_case.get("name")
            label = label if isinstance(label, str) else f"#{i}"
            for field in (
                "name",
                "status",
                "terminal_events",
                "output_sha256",
            ):
                want = derived_case[field]
                got = claimed_case.get(field)
                if got != want:
                    findings.append(
                        f"results case {label} {field}={got!r} does not match "
                        f"the stream-derived {want!r}"
                    )
            got_elapsed = claimed_case.get("elapsed_seconds")
            try:
                elapsed_ok = got_elapsed is not None and abs(
                    float(got_elapsed) - derived_case["elapsed_seconds"]
                ) < 1e-9
            except (TypeError, ValueError, OverflowError):
                elapsed_ok = False
            if not elapsed_ok:
                findings.append(
                    f"results case {label} elapsed_seconds={got_elapsed!r} does "
                    f"not match the stream-derived {derived_case['elapsed_seconds']!r}"
                )
    claimed_counts = claimed.get("counts")
    if not isinstance(claimed_counts, dict):
        findings.append("results carries no counts record")
    else:
        for field, want in derived_counts.items():
            if claimed_counts.get(field) != want:
                findings.append(
                    f"results counts.{field}={claimed_counts.get(field)!r} does "
                    f"not match the stream-derived {want!r}"
                )
    if claimed.get("packages") != derived_packages:
        findings.append(
            f"results packages {claimed.get('packages')!r} do not match the "
            f"stream-derived {derived_packages!r}"
        )
    return findings


def ci_provenance():
    """Capture the CI-runner identity this evidence was produced under.

    Lane evidence is only trustworthy as a qualification input when it is
    bound to an authenticated run — a well-formed synthetic event stream
    produced off-CI must not impersonate a trusted live qualification
    run. Under GitHub Actions the runner environment carries the run's
    identity; the release pipeline binds these fields into the lane
    gate's evidence and the admission validator cross-checks them against
    the qualification record's own CI provenance. Outside CI the record
    carries no ci block — local lane evidence is still verifiable, but a
    release claiming CI provenance cannot admit it.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return None
    keys = {
        "server_url": "GITHUB_SERVER_URL",
        "repository": "GITHUB_REPOSITORY",
        "run_id": "GITHUB_RUN_ID",
        "run_attempt": "GITHUB_RUN_ATTEMPT",
        "job": "GITHUB_JOB",
        "workflow": "GITHUB_WORKFLOW",
        "workflow_ref": "GITHUB_WORKFLOW_REF",
        "sha": "GITHUB_SHA",
        "event_name": "GITHUB_EVENT_NAME",
        "runner_os": "RUNNER_OS",
        "runner_arch": "RUNNER_ARCH",
        "runner_environment": "RUNNER_ENVIRONMENT",
        "image_os": "ImageOS",
        "image_version": "ImageVersion",
    }
    return {k: os.environ[v] for k, v in keys.items() if os.environ.get(v)}


def inventory_coverage(inventory, source_root):
    """Return suite test names present in source but absent from the inventory."""
    covered = set(inventory.get("common_required_tests", []))
    for tests in inventory.get("platform_specific_tests", {}).values():
        covered.update(tests)
    pkg_dir = f"{source_root}/{inventory['package']}"
    pattern = re.compile(rf"func ({inventory['run_pattern']}\w*)\s*\(")
    discovered = set()
    import os
    for entry in sorted(os.listdir(pkg_dir)):
        if not entry.endswith("_test.go"):
            continue
        with open(f"{pkg_dir}/{entry}", "r", encoding="utf-8") as handle:
            discovered.update(pattern.findall(handle.read()))
    return sorted(discovered - covered), sorted(discovered)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stream", required=True, help="raw go test -json output file")
    parser.add_argument("--out", help="case-evidence JSON to write")
    parser.add_argument("--suite")
    parser.add_argument("--lane")
    parser.add_argument("--commit", help="source commit the run qualified")
    parser.add_argument("--toolchain-go", help="full `go version` string")
    parser.add_argument("--inventory", help="required-test inventory for coverage check")
    parser.add_argument("--source-root", help="repo root for source coverage check")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-derive the record from --stream and report every point the "
        "--results file or the stream itself fails to support",
    )
    parser.add_argument(
        "--results", help="normalized case-evidence record to check against --stream"
    )
    parser.add_argument(
        "--expect-package",
        default="",
        help="suite package path every package identity in the stream must name",
    )
    args = parser.parse_args()

    if args.verify:
        if not args.results:
            parser.error("--verify requires --results")
        findings = verify_results(args.stream, args.results, args.expect_package)
        for finding in findings:
            print(finding)
        sys.exit(1 if findings else 0)

    for required in ("out", "suite", "lane", "commit", "toolchain_go"):
        if getattr(args, required) is None:
            parser.error(f"--{required.replace('_', '-')} is required unless --verify")

    case_list, packages = parse_stream(args.stream)

    record = {
        "schema_version": 1,
        "suite": args.suite,
        "lane": args.lane,
        "source_commit": args.commit,
        "toolchain_go": args.toolchain_go,
        "runner": {
            "os": platform.system().lower(),
            # Canonical goarch spelling: the lane inventory pins goos/
            # goarch identities, so emit amd64/arm64 rather than the
            # platform.machine() aliases (x86_64, aarch64).
            "arch": {
                "x86_64": "amd64",
                "amd64": "amd64",
                "aarch64": "arm64",
                "arm64": "arm64",
            }.get(platform.machine().lower(), platform.machine().lower()),
        },
        "ci": ci_provenance(),
        "packages": packages,
        "tests": [
            {
                "name": c["name"],
                "status": c["status"] or "incomplete",
                "elapsed_seconds": round(c["elapsed"], 4),
                "terminal_events": c["terminal_events"],
                "output_sha256": c["output_sha256"],
            }
            for c in case_list
        ],
        "counts": {
            "passed": sum(1 for c in case_list if c["status"] == "pass"),
            "failed": sum(1 for c in case_list if c["status"] == "fail"),
            "skipped": sum(1 for c in case_list if c["status"] == "skip"),
            "incomplete": sum(1 for c in case_list if c["status"] is None),
        },
    }

    if args.inventory and args.source_root:
        with open(args.inventory, "r", encoding="utf-8") as handle:
            inventory = json.load(handle)
        uncovered, discovered = inventory_coverage(inventory, args.source_root)
        record["source_inventory"] = {
            "discovered": len(discovered),
            "covered": len(discovered) - len(uncovered),
            "uncovered": uncovered,
        }
        if uncovered:
            sys.exit(
                "error: suite test(s) missing from the required-test inventory: "
                + ", ".join(uncovered)
            )

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
