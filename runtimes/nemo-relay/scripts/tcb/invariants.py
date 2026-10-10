#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check that every citation the kernel-invariant document makes resolves.

``security/INVARIANTS.md`` backs each kernel invariant with ``Enforced by`` and
``Verified by`` lines naming the enforcing symbols, the tests that prove them,
and the files and line numbers they live at. Names are durable references; line
numbers are pointers, and pointers drift: a doc block inserted twenty lines up
moves every citation below it, and nothing about reading the prose shows the
drift. The document already had that failure once — its pointers were all wrong
by the same offset — which is the failure this gate exists to catch.

What the gate enforces:

* **Every ``crates/`` path cited exists.** A citation to a file that was moved
  or renamed is evidence that cannot be pointed at.
* **A ``path:line`` citation lands on a definition.** The line must be the line
  one of the symbols named just before the citation is defined on in that file.
  A line that points into a doc comment or a closing brace once pointed at the
  right item and no longer does.
* **A ``path`` citation covers its group.** The symbols and test names a
  citation follows must be defined in the cited file — a ``Verified by`` name
  must be a test there, matched the way ``matrix.py`` matches them (a test
  attribute above the function), because a function nobody runs is not a test.
  An ``Enforced by`` clause may describe neighbouring states by name — the
  ``match`` that is total, the ``Failed`` it refuses — so only the names the
  citation actually claims are required to define there, not every identifier
  the sentence happens to mention.
* **A ``Verified by`` name without a path resolves somewhere.** The name is a
  claim that a test exists; a renamed or deleted test is a claim nothing runs.

``Enforced by`` prose may name types a milestone intends rather than types that
exist — a hypothetical ``ProductionPostgresEffectStore`` is described as the
target, not the present — so an enforced-by symbol is only checked when a path
citation claims it. ``Verified by`` carries no such licence: whatever it names
is presented as a test.

``--write`` regenerates the line numbers. A citation whose line is still right
is left alone; a stale one with a single definition site is rewritten to it; a
stale one whose names have several sites is reported for a human to choose,
because guessing which of two definitions a reader meant is the same kind of
lie the gate exists to prevent.
"""

from __future__ import annotations

import argparse
import bisect
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = ROOT / "security" / "INVARIANTS.md"

#: A parenthesised citation: (`crates/path/file.rs`) or (`crates/path/file.rs:NN`)
#: possibly followed by prose inside the same parens, as in
#: (`crates/ledger/src/lib.rs`, trait contract around line 1240).
PAREN_CITE = re.compile(r"\(\s*`(crates/[^`:\s]+)(?::(\d+))?`[^)]*\)")

#: A bare path mention outside parentheses is still a path the file must have.
BARE_PATH = re.compile(r"`(crates/[^`:\s]+)`")

#: A backticked Rust identifier in claim position: `Foo::bar`, `name`,
#: optionally carrying call arguments (`Foo::bar(action)`). Paths are filtered
#: by position rather than the class — `crates/` reads as one identifier up to
#: the first `/`.
IDENT = re.compile(r"`([A-Za-z_][\w:]*)\s*(?:\([^`]*?\))?`")

#: A definition site for a Rust item in a file: `fn name(`, `enum Name`,
#: `impl Name`, `pub const NAME`, or an enum variant / record field line such
#: as `Unknown,` or `IdempotencyConflict,`. `=>` is deliberately outside the
#: trailing class so a `match` arm cannot pass for a variant declaration.
DEFINITION = (
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:const|async|unsafe)\s+)*"
    r"(?:fn|enum|struct|union|trait|impl|type|const|static|mod)\s+{name}\b"
    r"|^\s*(?:pub(?:\s*\([^)]*\))?\s+)?{name}\s*[,{{(:]"
    r"|^\s*{name}\s*$"
)

#: A test is a function with a test attribute above it — the same rule
#: ``matrix.py`` applies for the same reason: an unanchored `fn name(` matches a
#: commented-out test, and a gate a comment can satisfy reports what nobody is
#: checking. Other attributes may sit between the attribute and the function.
TEST = (
    r"^\s*#\[(?:[\w:]+::)?test\b[^\]]*\]\s*\n(?:\s*#\[[^\]]*\]\s*\n)*\s*"
    r"(?:pub\s+)?(?:async\s+)?fn {name}\s*\("
)

#: Claim paragraphs open with one of these markers.
MARKERS = ("**Enforced by**", "**Verified by**")


class InvariantError(Exception):
    """A document or tree this gate cannot use."""


@dataclass(frozen=True)
class Citation:
    """One `(`path`)` citation: the file, the optional line, and where it sits."""

    path: str
    line: int | None
    #: Document line the citation appears on, for error messages.
    doc_line: int
    #: Document-global span of the `:NN` digits, so --write can replace the
    #: number without touching the citation around it.
    digits_span: tuple[int, int] | None


@dataclass
class Claim:
    """One `**Enforced by**` or `**Verified by**` paragraph's citations."""

    verified: bool
    #: (citation, identifiers the citation claims) in document order.
    groups: list[tuple[Citation, list[str]]] = field(default_factory=list)
    #: Identifiers in the paragraph no citation claims.
    unclaimed: list[str] = field(default_factory=list)


def member(ident: str) -> str:
    """The resolvable piece of `Type::member` — the last segment."""
    return ident.rsplit("::", 1)[-1]


def line_offsets(text: str) -> list[int]:
    """Byte offsets at which each line starts, for match-to-line conversion."""
    return [0, *[m.end() for m in re.finditer("\n", text)]]


def definition_lines(text: str, name: str, test: bool) -> list[int]:
    """The 1-based lines ``name`` is defined on in ``text``.

    ``test`` selects the test-attribute pattern; otherwise any item or variant
    declaration counts.
    """
    pattern = TEST if test else DEFINITION
    starts = line_offsets(text)
    found = []
    for match in re.finditer(pattern.format(name=re.escape(name)), text, re.MULTILINE):
        target = match.group(0)
        if test:
            # The match covers the attribute block; the definition line is the
            # `fn` line at its end.
            offset = match.start() + target.rindex("fn ")
        else:
            offset = match.start() + (len(target) - len(target.lstrip()))
        found.append(bisect.bisect_right(starts, offset))
    return found


def read_file(root: Path, path: str) -> str | None:
    candidate = root / path
    return candidate.read_text() if candidate.is_file() else None


def _inside(span: int, intervals: list[tuple[int, int]]) -> bool:
    return any(start <= span < end for start, end in intervals)


def parse_document(text: str) -> tuple[list[Citation], list[Claim]]:
    """Split the document into citations and claim-paragraph groups.

    Every ``crates/`` path backticked anywhere is a citation. Inside a marker
    paragraph a citation also claims the identifiers since the previous
    citation — ```a`, `b` (`path`)`` claims both. Outside one, a citation only
    claims its own existence.
    """
    citations: list[Citation] = []
    claims: list[Claim] = []
    starts = line_offsets(text)

    cursor = 0
    for paragraph in re.split(r"\n\s*\n", text):
        if not paragraph.strip():
            continue
        origin = text.index(paragraph, cursor)
        cursor = origin + len(paragraph)
        marker = next((m for m in MARKERS if paragraph.lstrip().startswith(m)), None)
        verified = marker == MARKERS[1]
        claim = Claim(verified=verified) if marker else None

        paren_spans = [m.span() for m in PAREN_CITE.finditer(paragraph)]
        events: list[tuple[int, str, object]] = []
        for match in PAREN_CITE.finditer(paragraph):
            digits = None
            if match.group(2) is not None:
                digits = (origin + match.start(2), origin + match.end(2))
            cite = Citation(
                path=match.group(1),
                line=int(match.group(2)) if match.group(2) else None,
                doc_line=bisect.bisect_right(starts, origin + match.start()),
                digits_span=digits,
            )
            events.append((match.start(), "cite", cite))
            citations.append(cite)
        if marker:
            for match in IDENT.finditer(paragraph):
                if _inside(match.start(), paren_spans):
                    continue
                # A `name` followed directly by `/` is a path's first segment.
                if match.end() < len(paragraph) and paragraph[match.end()] == "/":
                    continue
                events.append((match.start(), "ident", match.group(1)))
        else:
            for match in BARE_PATH.finditer(paragraph):
                if _inside(match.start(), paren_spans):
                    continue
                cite = Citation(
                    path=match.group(1),
                    line=None,
                    doc_line=bisect.bisect_right(starts, origin + match.start()),
                    digits_span=None,
                )
                events.append((match.start(), "cite", cite))
                citations.append(cite)

        if claim is None:
            continue
        events.sort(key=lambda event: event[0])
        pending: list[str] = []
        for _, kind, value in events:
            if kind == "ident":
                pending.append(cast(str, value))
            else:
                claim.groups.append((cast(Citation, value), pending))
                pending = []
        claim.unclaimed = pending
        claims.append(claim)
    return citations, claims


def check(root: Path, text: str) -> list[str]:
    citations, claims = parse_document(text)
    problems: list[str] = []
    for cite in citations:
        if not (root / cite.path).is_file():
            problems.append(f"{cite.path} cited on line {cite.doc_line} does not exist")

    # One corpus for pathless `Verified by` names, built on first use — the
    # document cites paths the gate reads directly, so the walk only pays for
    # itself when a name has no path to stand on.
    corpus: list[str] | None = None

    def workspace_text() -> list[str]:
        nonlocal corpus
        if corpus is None:
            corpus = [
                file.read_text()
                for base in ("crates", "bridges")
                for file in (root / base).glob("**/*.rs")
                if file.is_file()
            ]
        return corpus

    for claim in claims:
        for cite, idents in claim.groups:
            source = read_file(root, cite.path)
            if source is None:
                continue  # the missing path is already reported
            sites = {ident: definition_lines(source, member(ident), test=claim.verified) for ident in idents}
            if claim.verified:
                for ident in idents:
                    if not sites[ident]:
                        problems.append(
                            f"Verified by names `{ident}` as a test in {cite.path} "
                            f"(line {cite.doc_line}), and no test attribute carries it there"
                        )
            elif idents and not any(sites.values()):
                problems.append(
                    f"`{', '.join(idents)}` is cited to {cite.path} (line "
                    f"{cite.doc_line}) and nothing it names defines there"
                )
            if cite.line is not None:
                wanted = sorted({line for lines in sites.values() for line in lines})
                if not idents:
                    problems.append(
                        f"`{cite.path}:{cite.line}` on line {cite.doc_line} names no symbol a line can point at"
                    )
                elif wanted and cite.line not in wanted:
                    problems.append(
                        f"`{cite.path}:{cite.line}` points at line {cite.line}, and "
                        f"{', '.join(idents)} is defined on {wanted} — run "
                        f"`python3 scripts/tcb/invariants.py --write`"
                    )
                elif not wanted:
                    problems.append(
                        f"`{cite.path}:{cite.line}` on line {cite.doc_line} pins a "
                        f"line for {', '.join(idents)}, none of which is defined there"
                    )
        if claim.verified:
            for ident in claim.unclaimed:
                if not any(definition_lines(source, member(ident), test=True) for source in workspace_text()):
                    problems.append(
                        f"Verified by names `{ident}` as a test, and no file in the workspace defines it as one"
                    )
    return problems


def write(root: Path, text: str) -> tuple[str, list[str]]:
    """Rewrite stale `path:line` digits to the symbol's definition line.

    Returns the rewritten document and the edits made, or raises
    ``InvariantError`` where a citation is ambiguous or unresolvable — a human
    chooses what a citation meant; the tool does not guess.
    """
    _, claims = parse_document(text)
    edits: list[tuple[tuple[int, int], str]] = []
    made: list[str] = []
    for claim in claims:
        for cite, idents in claim.groups:
            if cite.line is None or cite.digits_span is None:
                continue
            source = read_file(root, cite.path)
            if source is None:
                raise InvariantError(f"{cite.path} cited on line {cite.doc_line} does not exist")
            sites = sorted(
                {line for ident in idents for line in definition_lines(source, member(ident), claim.verified)}
            )
            if cite.line in sites:
                continue
            if not idents:
                raise InvariantError(
                    f"`{cite.path}:{cite.line}` on line {cite.doc_line} names no symbol a line can point at"
                )
            if len(sites) != 1:
                raise InvariantError(
                    f"`{cite.path}:{cite.line}` on line {cite.doc_line} is ambiguous: "
                    f"{', '.join(idents)} is defined on {sites or 'no lines'}, and a "
                    f"human must choose"
                )
            edits.append((cite.digits_span, str(sites[0])))
            made.append(f"{cite.path}:{cite.line} -> {sites[0]} ({', '.join(idents)}, document line {cite.doc_line})")
    for (start, end), replacement in sorted(edits, key=lambda e: e[0][0], reverse=True):
        text = text[:start] + replacement + text[end:]
    return text, made


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--document", type=Path, default=None)
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    document = (arguments.document or root / DOCUMENT.relative_to(ROOT)).resolve()
    try:
        text = document.read_text()
    except FileNotFoundError:
        print(f"error: {document} does not exist", file=sys.stderr)
        return 1
    if arguments.write:
        try:
            rewritten, made = write(root, text)
        except InvariantError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        if made:
            document.write_text(rewritten)
            for line in made:
                print(f"rewrote {line}")
        else:
            print("invariant citations: every line pointer already lands on a definition")
        return 0
    problems = check(root, text)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    citations, _ = parse_document(text)
    pinned = sum(1 for cite in citations if cite.line is not None)
    print(
        f"invariant citations: {len(citations)} paths exist, {pinned} line pointers "
        f"land on definitions, every claimed symbol and test resolves"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
