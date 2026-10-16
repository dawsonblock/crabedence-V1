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
"""

import argparse
import hashlib
import json
import platform
import re
import sys

TERMINAL_ACTIONS = ("pass", "fail", "skip")

# The closed set of actions a real `go test -json` stream emits. Anything
# outside it is a fabricated or corrupted event, never a forward
# extension this pipeline may silently accept.
GO_ACTIONS = frozenset(
    ("start", "run", "pause", "cont", "pass", "bench", "fail", "output", "skip")
)


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
    if action in TERMINAL_ACTIONS:
        rec["status"] = action
        rec["terminal_events"] += 1
        if event.get("Elapsed") is not None:
            rec["elapsed"] = max(rec["elapsed"], float(event["Elapsed"]))
    elif action == "output":
        rec["out"].update(event.get("Output", "").encode("utf-8"))


def parse_stream(path):
    """Parse a go test -json stream into {name: {status, elapsed, out_sha, terminal_events}}.

    Returns (cases, packages) where cases maps test name -> record and
    packages is the set of Go packages the events belonged to.
    """
    cases = {}
    order = []
    packages = set()
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # The stream is pure JSON by construction; a non-JSON line
                # means the producer wrote decorated output into the raw
                # file — reject rather than silently skip it.
                sys.exit(f"error: {path}:{lineno}: not a go test -json event line")
            test = event.get("Test")
            if event.get("Package"):
                packages.add(event["Package"])
            if not test:
                continue
            if test not in cases:
                cases[test] = new_case()
                order.append(test)
            accumulate(cases[test], event)
    for rec in cases.values():
        rec["output_sha256"] = rec["out"].hexdigest()
        del rec["out"]
    return ([dict(name=n, **cases[n]) for n in order], sorted(p for p in packages if p))


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
    findings = []
    cases = {}
    order = []
    packages = set()
    test_pkg = {}
    pkg_terminal = {}
    pkg_outcome = {}
    done_tests = set()
    done_pkgs = set()

    try:
        handle = open(path, "r", encoding="utf-8")
    except OSError as exc:
        return ([f"raw stream {path} cannot be read: {exc}"], [], {}, [])
    with handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
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
            if "Output" in event and not isinstance(event["Output"], str):
                findings.append(f"{path}:{lineno}: Output is not a string")
                continue
            if "Elapsed" in event and not isinstance(
                event["Elapsed"], (int, float)
            ):
                findings.append(f"{path}:{lineno}: Elapsed is not numeric")
                continue
            pkg = event.get("Package")
            if not isinstance(pkg, str):
                findings.append(f"{path}:{lineno}: event carries no string Package")
                continue
            if pkg in done_pkgs:
                findings.append(
                    f"{path}:{lineno}: event for package {pkg} after its terminal outcome"
                )
                continue
            if pkg:
                packages.add(pkg)
            if test is None:
                if action in TERMINAL_ACTIONS:
                    pkg_terminal[pkg] = pkg_terminal.get(pkg, 0) + 1
                    pkg_outcome[pkg] = action
                    done_pkgs.add(pkg)
                continue
            if test in done_tests:
                findings.append(
                    f"{path}:{lineno}: test {test} records an event "
                    f"(action={action}) after its terminal outcome"
                )
                # The event is still folded into the record: the derived
                # record must describe all the bytes the bundle binds.
            if test not in cases:
                cases[test] = new_case()
                order.append(test)
            test_pkg[test] = pkg
            accumulate(cases[test], event)
            if action in TERMINAL_ACTIONS:
                done_tests.add(test)

    for name in order:
        n = cases[name]["terminal_events"]
        if n != 1:
            findings.append(
                f"test {name} recorded {n} terminal events in the raw stream "
                "(a genuine go test run produces exactly one)"
            )
    for pkg in sorted(p for p in packages if p):
        n = pkg_terminal.get(pkg, 0)
        if n == 0:
            findings.append(
                f"package {pkg} has no terminal outcome — the run did not complete"
            )
        elif n > 1:
            findings.append(f"package {pkg} recorded {n} terminal outcomes")
        else:
            expected = (
                "fail"
                if any(
                    (cases[t]["status"] or "incomplete") in ("fail", "incomplete")
                    for t, p in test_pkg.items()
                    if p == pkg
                )
                else "pass"
            )
            if pkg_outcome[pkg] != expected:
                findings.append(
                    f"package {pkg} terminal outcome {pkg_outcome[pkg]} does not "
                    f"match the derived test outcomes (want {expected})"
                )
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
            claimed = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
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
            except (TypeError, ValueError):
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
            "arch": platform.machine().lower(),
        },
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
