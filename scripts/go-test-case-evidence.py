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

When --inventory and --source-root are given, the tool also verifies that
every test function in the suite's package matching the inventory's
run_pattern is covered by the inventory (common or any lane's
platform-specific list): a new live test that was never inventoried is a
coverage failure, not silent evidence.

The emitted record carries the identity the validator cross-checks:
source commit, toolchain, runner os/arch, the lane, and per-test terminal
status, duration, and an output digest so a borrowed log cannot pose as
this run's evidence.
"""

import argparse
import hashlib
import json
import platform
import re
import sys

TERMINAL_ACTIONS = ("pass", "fail", "skip")


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
            if not test:
                continue
            packages.add(event.get("Package", ""))
            if test not in cases:
                cases[test] = {
                    "status": None,
                    "elapsed": 0.0,
                    "terminal_events": 0,
                    "out": hashlib.sha256(),
                }
                order.append(test)
            rec = cases[test]
            action = event.get("Action")
            if action in TERMINAL_ACTIONS:
                rec["status"] = action
                rec["terminal_events"] += 1
                if event.get("Elapsed") is not None:
                    rec["elapsed"] = max(rec["elapsed"], float(event["Elapsed"]))
            elif action == "output":
                rec["out"].update(event.get("Output", "").encode("utf-8"))
    for rec in cases.values():
        rec["output_sha256"] = rec["out"].hexdigest()
        del rec["out"]
    return ([dict(name=n, **cases[n]) for n in order], sorted(p for p in packages if p))


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
    parser.add_argument("--out", required=True, help="case-evidence JSON to write")
    parser.add_argument("--suite", required=True)
    parser.add_argument("--lane", required=True)
    parser.add_argument("--commit", required=True, help="source commit the run qualified")
    parser.add_argument("--toolchain-go", required=True, help="full `go version` string")
    parser.add_argument("--inventory", help="required-test inventory for coverage check")
    parser.add_argument("--source-root", help="repo root for source coverage check")
    args = parser.parse_args()

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
