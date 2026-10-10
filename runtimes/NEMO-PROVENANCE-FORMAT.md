# NEMO runtime provenance — format 2

This document is the normative specification of the provenance format
`nemo-runtime-digest` computes and `runtimes/nemo-transfer-manifest.json`
declares. An independent implementation that follows it byte-for-byte
reproduces the same tree digests; `scripts/verify-nemo-transfer.py` is the
reference second implementation and is required to agree.

## Versions

| `provenance_format_version` | Meaning |
| --- | --- |
| absent / 1 | Format 1 — regular files only, record `sha256(content) + "  " + ./path + "\n"`, flat delta fields (`local_modifications` / `added_paths` / `removed_paths`). Verified for backward compatibility; never emitted by `-update`. |
| 2 | This document. Policy-bound canonical stream, typed delta. |
| anything else | Rejected outright. A verifier never reinterprets an unknown version. |

## The canonical tree model

Three artifact classes, kept distinct:

- **Canonical source** — authoritative source only: regular files and
  symlinks the project maintains. A clean checkout has exactly one
  canonical identity.
- **Generated build output** — files derived deterministically during a
  build or package step (protobuf bindings, native extensions, napi
  output). Enumerated out of canonical identity on *both* trees
  identically: presence or absence on disk changes neither the digest
  nor the delta, and declaring a generated path as source fails
  verification.
- **Release artifact** — the packaged distribution built from canonical
  source plus deterministic generation. Qualified, hashed, and signed
  as immutable bytes — never rebuilt between test and publish.

The machine-readable rules live in `runtimes/nemo-provenance-policy.json`.
The manifest binds the policy as `{path, sha256}`; a policy file whose
content hash differs from the binding fails verification closed, so the
enumeration rules a digest was computed under cannot drift silently.

## Canonical enumeration

Walking a tree under the policy:

1. **Directory prune** — a real directory whose *name* is in
   `excluded_dir_names`, whose name ends with an `excluded_dir_suffixes`
   entry, or which matches a `generated_paths` pattern ending in `/` is
   not descended into.
2. **Non-directory skip** — a non-directory entry whose *name* is in
   `excluded_file_names`, whose name ends with an
   `excluded_file_suffixes` entry, or whose tree-relative path matches a
   `generated_paths` pattern is skipped.
3. **Regular file** — recorded with its content digest and exec bit.
4. **Symlink** — recorded with its raw `readlink` target. A symlinked
   directory is an entry, not a traversal (link rules are the file-level
   skip rules, not the directory prune rules).
5. **Anything else** (fifo, socket, device) — the tree is malformed;
   enumeration fails. Provenance never silently skips an object type.

`generated_paths` are tree-relative slash patterns: `*` and `?` stay
within one path element, `**` crosses elements. A trailing `/` names a
directory subtree. A pattern without a trailing slash still excludes
every path below a matching directory via the file-level skip.

## The canonical stream

Each enumerated object produces exactly one record line, ASCII
tab-separated, LF-terminated:

```text
FILE<TAB>./path<TAB>sha256-hex-of-content<TAB>x|-
SYMLINK<TAB>./path<TAB>raw-readlink-target
```

- `path` is `./`-prefixed, slash-separated, relative to the tree root —
  the same spelling `find .` produces. Raw filesystem bytes are
  preserved; no Unicode normalization is applied.
- The exec field is `x` when any of owner/group/other execute bits is
  set, `-` otherwise. The bit is security-relevant for shipped scripts;
  it is recorded explicitly rather than left implicit.
- Records are emitted in byte-wise lexicographic order of the normalized
  path. A duplicated normalized path is a malformed enumeration, not a
  double-hashed entry.
- The tree digest is SHA-256 over the concatenated record stream.
- Timestamps are never hashed. File *content* is hashed byte-verbatim,
  so line endings inside files are bound by the content digest; record
  line endings are always LF.

## The transfer delta

`delta` in the manifest is the complete typed difference between the
frozen reference and the canonical tree — every object class reported
separately:

| Field | Meaning |
| --- | --- |
| `modified_files` | Same path, file→file, different content digest |
| `added_files` | File present in the runtime, absent in the source. A declared entry ending in `/` is a directory prefix covering a subtree |
| `removed_files` | File present in the source, absent in the runtime |
| `added_symlinks` / `removed_symlinks` | Symlink additions/removals (`/` prefixes allowed for additions) |
| `retargeted_symlinks` | Same path, symlink→symlink, different target |
| `retyped_paths` | Same path, different object kind (file↔symlink) |
| `mode_changes` | Same content, different exec bit — `{path, from, to}` with `from`/`to` ∈ {`-`, `x`} |

Verification requires the declared delta to equal the computed delta —
every class, in both directions: an actual difference with no
declaration fails, and a declaration covering no actual difference is
stale and fails.

## Verification modes

- **Shipping-tree verification** — does the runtime match its own
  declared canonical identity? May run without the frozen source; a
  missing source is reported as a note.
- **Transfer-provenance qualification** (`-require-source`, or
  `source.required: true`) — the frozen reference must be present, must
  recompute to its declared identity, and the declared delta must equal
  the computed one. Official release admission runs this mode; absence
  of the source is a hard failure, never a warning.

## Invariants a reader can rely on

1. A one-byte change to any enumerated file changes the tree digest.
2. Creating, removing, or retargeting any enumerated symlink changes the
   tree digest.
3. Flipping the executable bit on any enumerated file changes the tree
   digest.
4. Adding, modifying, or deleting a generated or excluded object changes
   nothing — deterministic build output cannot perturb source identity.
5. A one-object undeclared difference between the trees fails the delta
   check with a non-zero exit.
6. Regenerating the manifest is mechanical and idempotent: a second
   `-update` produces zero diff.
