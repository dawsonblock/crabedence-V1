#!/usr/bin/env python3
"""RC7.5 release-provenance tooling (INV-07).

Three operations, all mechanical, all fail closed:

  manifest  Build the canonical source-content manifest for a
            distributable tree: every entry records its relative path,
            entry type, size, SHA-256 (regular files), symlink target,
            and executable permission bit — the manifest schema the
            package embeds and the verifier re-checks byte for byte.
            The manifest never lists itself, and it is generated from
            the packaged tree, not a hand-maintained include list.

  attest    Write the sidecar attestation for a built archive: the
            outer ZIP's SHA-256 over its exact bytes, the archive's
            size, and the identity strings the release binds. The
            recursion problem — a manifest inside the archive cannot
            contain the archive's own digest — is resolved here: the
            internal manifest covers content, the sidecar covers the
            container.

  verify    Fresh-extraction verification a clean verifier can run
            without trusting the developer's workspace: unpack the
            archive into an empty directory, prove entry safety and
            manifest closure, re-hash every file, check symlinks,
            version consistency, dependency locks, qualification
            evidence presence, and the sidecar digest. Any failure is
            a release blocker; nothing is treated as pass by absence
            of evidence.

Usage:
  verify-rc75-release.py manifest <source-root> <out.json>
      [--exclude PATH ...]
  verify-rc75-release.py attest <archive> <attestation.json>
      --version V --source-manifest <m.json>
  verify-rc75-release.py verify <archive> --manifest <m.json>
      --attestation <a.json> --version V [--require PATH ...]
"""

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import zipfile

MANIFEST_SCHEMA = "rc75-source-manifest-v1"
ATTEST_SCHEMA = "rc75-release-attestation-v1"

BLOCKED_MANIFEST_PATHS = {"release-evidence/rc75-release-attestation.json"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------

def iter_tree_entries(root, excludes):
    """Yield every path under root, depth-first, without following
    directory symlinks. Excludes are manifest-relative paths and may
    name directories — an excluded directory skips its whole subtree."""
    root = os.path.abspath(root)

    def excluded(rel):
        return any(rel == e or rel.startswith(e + "/") for e in excludes)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        # prune excluded subtrees in place
        dirnames[:] = [d for d in dirnames
                       if not excluded(os.path.relpath(
                           os.path.join(dirpath, d), root).replace(os.sep, "/"))]
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if excluded(rel):
                continue
            yield full, rel


def build_manifest(root, version, excludes, file_list=None):
    """Canonical inventory of a packaged tree. Path-safety is enforced
    at generation: no absolute paths, no '..' components, no duplicate
    logical names — a manifest that cannot safely drive an extractor
    is rejected here rather than at verification.

    file_list, when given, is the authoritative package membership
    (e.g. `git ls-files --cached --others --exclude-standard`): the
    manifest covers exactly those paths — the bytes that ship, not
    whatever happens to be on the builder's disk."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        die(f"manifest root is not a directory: {root}")
    excludes = set(excludes)
    if file_list is not None:
        with open(file_list) as fh:
            rels = [l.strip() for l in fh if l.strip()]
        iterator = ((os.path.join(root, r), r) for r in rels)
    else:
        iterator = iter_tree_entries(root, excludes)
    entries = []
    seen = set()
    for full, rel in iterator:
        if any(rel == e or rel.startswith(e + "/") for e in excludes):
            continue
        if not os.path.lexists(full):
            die(f"package member does not exist on disk: {rel!r}")
        if rel in BLOCKED_MANIFEST_PATHS:
            continue
        if rel.startswith("/") or ".." in rel.split("/") or rel in ("", "."):
            die(f"unsafe manifest path generated: {rel!r}")
        if rel in seen:
            die(f"duplicate manifest path generated: {rel!r}")
        seen.add(rel)
        st = os.lstat(full)
        mode = st.st_mode
        if stat.S_ISDIR(mode):
            continue  # directories are structure, not content
        entry = {"path": rel}
        if stat.S_ISLNK(mode):
            target = os.readlink(full)
            entry.update(type="symlink", target=target, size=0,
                         sha256=sha256_bytes(target.encode()),
                         executable=False)
        elif stat.S_ISREG(mode):
            entry.update(type="file", size=st.st_size,
                         sha256=sha256_file(full),
                         executable=bool(mode & 0o111))
        else:
            die(f"unsupported entry type in manifest: {rel!r}")
        entries.append(entry)
    return {
        "schema": MANIFEST_SCHEMA,
        "version": version,
        "root_hash": hashlib.sha256(
            "".join(f"{e['path']}\x00{e['sha256']}\x00"
                    for e in entries).encode()).hexdigest(),
        "entry_count": len(entries),
        "entries": entries,
    }


def cmd_manifest(args):
    excludes = list(args.exclude or [])
    out_abs = os.path.abspath(args.out)
    root_abs = os.path.abspath(args.root)
    if out_abs.startswith(root_abs + os.sep):
        excludes.append(os.path.relpath(out_abs, root_abs).replace(os.sep, "/"))
    m = build_manifest(args.root, args.version, excludes,
                       file_list=args.from_list)
    with open(args.out, "w") as f:
        json.dump(m, f, indent=1, sort_keys=False)
        f.write("\n")
    print(f"manifest: {m['entry_count']} entries, root {m['root_hash'][:16]}…")


# ---------------------------------------------------------------------------
# pack
# ---------------------------------------------------------------------------

EMBEDDED_MANIFEST = "release-evidence/rc75-source-manifest.json"


def cmd_pack(args):
    """Build the distribution ZIP deterministically from the package
    membership list: fixed timestamps and sorted names so the same
    tree packs to the same bytes. Symlinks are not flattened into the
    container — the embedded manifest is their authority, and the
    verifier materializes them on extraction. The manifest travels
    inside the archive at a fixed, self-exempt path."""
    root = os.path.abspath(args.root)
    with open(args.from_list) as fh:
        rels = sorted({l.strip() for l in fh if l.strip()})
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as zf:
        epoch = (1980, 1, 1, 0, 0, 0)
        for rel in rels:
            full = os.path.join(root, rel)
            arc = os.path.join(args.topdir, rel).replace(os.sep, "/")
            if os.path.islink(full):
                continue  # carried by the manifest, not the container
            if not os.path.isfile(full):
                continue
            zi = zipfile.ZipInfo(arc, epoch)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (os.stat(full).st_mode & 0o777) << 16
            with open(full, "rb") as fh:
                zf.writestr(zi, fh.read())
        if args.manifest:
            zi = zipfile.ZipInfo(
                os.path.join(args.topdir, EMBEDDED_MANIFEST), epoch)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            with open(args.manifest, "rb") as fh:
                zf.writestr(zi, fh.read())
    print(f"packed: {args.out}")


# ---------------------------------------------------------------------------
# attest
# ---------------------------------------------------------------------------

def cmd_attest(args):
    archive = os.path.abspath(args.archive)
    if not os.path.isfile(archive):
        die(f"archive not found: {archive}")
    with open(args.source_manifest) as f:
        manifest = json.load(f)
    if manifest.get("schema") != MANIFEST_SCHEMA:
        die("source manifest schema mismatch")
    att = {
        "schema": ATTEST_SCHEMA,
        "version": args.version,
        "archive_name": os.path.basename(archive),
        "archive_sha256": sha256_file(archive),
        "archive_size": os.path.getsize(archive),
        "source_manifest_sha256": sha256_file(args.source_manifest),
        "source_manifest_root_hash": manifest["root_hash"],
        "source_entry_count": manifest["entry_count"],
    }
    with open(args.attestation, "w") as f:
        json.dump(att, f, indent=1)
        f.write("\n")
    print(f"attestation: {att['archive_sha256']}")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

class Findings:
    def __init__(self):
        self.errors = []

    def check(self, cond, msg):
        if not cond:
            self.errors.append(msg)
        return cond

    def require(self, cond, msg):
        if not cond:
            die(msg)


def safe_members(zf):
    """Every archive member must extract inside the target — no
    absolute paths, no drive letters, no '..' — and be a regular file
    or directory; archive symlinks are rejected (the source manifest
    covers symlinks, the zip must not smuggle new ones)."""
    for info in zf.infolist():
        name = info.filename
        if name.endswith("/"):
            continue
        norm = name.replace("\\", "/")
        parts = norm.split("/")
        if norm.startswith("/") or ".." in parts or ":" in parts[0]:
            yield None, f"unsafe archive member: {name!r}"
            continue
        # zip unix-mode symlink detection
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            yield None, f"archive member is a symlink: {name!r} — " \
                "symlinks belong to the source manifest, not the container"
            continue
        yield info, None


def verify_tree_against_manifest(root, manifest, findings):
    entries = manifest["entries"]
    # Manifest -> tree: every record exists and matches byte-for-byte.
    for e in entries:
        full = os.path.join(root, e["path"])
        if not findings.check(os.path.lexists(full),
                              f"manifest entry missing from tree: {e['path']}"):
            continue
        if e["type"] == "symlink":
            got = os.readlink(full) if os.path.islink(full) else None
            findings.check(got == e["target"],
                           f"symlink target mismatch: {e['path']}")
        else:
            if not findings.check(os.path.isfile(full) and not os.path.islink(full),
                                  f"manifest file is not a regular file: {e['path']}"):
                continue
            findings.check(sha256_file(full) == e["sha256"],
                           f"content hash mismatch: {e['path']}")
            findings.check(os.path.getsize(full) == e["size"],
                           f"size mismatch: {e['path']}")
            findings.check(bool(os.stat(full).st_mode & 0o111) == e["executable"],
                           f"executable bit mismatch: {e['path']}")
    # Tree -> manifest: no unpackaged content. The manifest's own
    # embedded copy is exempt — it cannot list itself.
    embedded = set(BLOCKED_MANIFEST_PATHS)
    embedded.add("release-evidence/rc75-source-manifest.json")
    seen = {e["path"] for e in entries}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.isdir(full) and not os.path.islink(full):
                continue  # directories are structure, not content
            if os.path.islink(full):
                findings.check(rel in seen,
                               f"unpackaged symlink in tree: {rel}")
            elif os.path.isfile(full):
                findings.check(rel in seen or rel in embedded,
                               f"unpackaged file in tree: {rel}")


def cmd_verify(args):
    f = Findings()
    archive = os.path.abspath(args.archive)
    f.require(os.path.isfile(archive), f"archive not found: {archive}")

    with open(args.manifest) as fh:
        manifest = json.load(fh)
    with open(args.attestation) as fh:
        att = json.load(fh)

    f.require(manifest.get("schema") == MANIFEST_SCHEMA,
              "source manifest schema mismatch")
    f.require(att.get("schema") == ATTEST_SCHEMA,
              "attestation schema mismatch")
    f.require(att.get("version") == args.version,
              f"attestation version {att.get('version')} != expected {args.version}")
    f.require(manifest.get("version") == args.version,
              f"manifest version {manifest.get('version')} != expected {args.version}")

    # The sidecar commits to the exact delivered bytes.
    f.require(sha256_file(archive) == att["archive_sha256"],
              "archive SHA-256 does not match the attestation — "
              "the distributed bytes are not the qualified bytes")
    f.require(os.path.getsize(archive) == att["archive_size"],
              "archive size does not match the attestation")
    f.require(sha256_file(args.manifest) == att["source_manifest_sha256"],
              "source manifest does not match the attestation")

    with tempfile.TemporaryDirectory(prefix="rc75-verify-") as tmp:
        with zipfile.ZipFile(archive) as zf:
            names = set()
            for info, err in safe_members(zf):
                if err:
                    f.check(False, err)
                    continue
                norm = info.filename.replace("\\", "/")
                if not f.check(norm not in names,
                               f"duplicate archive member: {norm}"):
                    continue
                names.add(norm)
                dest = zf.extract(info, tmp)
                # Python's extractor ignores the unix mode stored in
                # external_attr; apply it as unzip does so executable
                # permissions verify against the manifest.
                umode = (info.external_attr >> 16) & 0o777
                if umode:
                    os.chmod(dest, umode)
        if f.errors:
            for e in f.errors:
                print(f"FAIL: {e}", file=sys.stderr)
            sys.exit(1)

        # Locate the extracted tree: the archive may wrap content in
        # a single top-level directory.
        roots = [n for n in os.listdir(tmp)]
        if len(roots) == 1 and os.path.isdir(os.path.join(tmp, roots[0])):
            tree = os.path.join(tmp, roots[0])
        else:
            tree = tmp
        tree = os.path.abspath(tree)

        # Materialize the manifest's symlinks — the container carries
        # none; the manifest is their authority. A target must be
        # relative and resolve inside the tree, and it must not
        # collide with an extracted member.
        for e in manifest["entries"]:
            if e["type"] != "symlink":
                continue
            dest = os.path.join(tree, e["path"])
            resolved = os.path.normpath(
                os.path.join(os.path.dirname(dest), e["target"]))
            f.require(
                not os.path.isabs(e["target"])
                and resolved.startswith(tree + os.sep),
                f"symlink target escapes the tree: {e['path']}")
            f.require(not os.path.lexists(dest),
                      f"archive member collides with a manifest symlink: {e['path']}")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.symlink(e["target"], dest)

        verify_tree_against_manifest(tree, manifest, f)

        # Version consistency: the extracted VERSION file must declare
        # exactly the qualified version.
        vpath = os.path.join(tree, "VERSION")
        f.require(os.path.isfile(vpath), "extracted tree has no VERSION file")
        with open(vpath) as fh:
            declared = fh.read().strip()
        f.check(declared == args.version,
                f"VERSION declares {declared!r}, expected {args.version!r}")

        # Dependency locks must travel with the source.
        for lock in ("go.mod", "go.sum"):
            f.check(os.path.isfile(os.path.join(tree, lock)),
                    f"dependency lock missing from package: {lock}")

        # Required qualification evidence / entry points.
        for req in args.require or []:
            f.check(os.path.lexists(os.path.join(tree, req)),
                    f"required package entry missing: {req}")

    if f.errors:
        for e in f.errors:
            print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"verified: {att['archive_name']} "
          f"({att['entry_count'] if 'entry_count' in att else att['source_entry_count']} entries, "
          f"{att['archive_sha256'][:16]}…)")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pm = sub.add_parser("manifest", help="build the canonical source manifest")
    pm.add_argument("root")
    pm.add_argument("out")
    pm.add_argument("--version", required=True)
    pm.add_argument("--exclude", action="append")
    pm.add_argument("--from-list",
                    help="authoritative newline-separated package membership")
    pm.set_defaults(fn=cmd_manifest)

    pp = sub.add_parser("pack", help="build the deterministic distribution zip")
    pp.add_argument("root")
    pp.add_argument("out")
    pp.add_argument("--from-list", required=True)
    pp.add_argument("--topdir", required=True)
    pp.add_argument("--manifest", help="manifest to embed")
    pp.set_defaults(fn=cmd_pack)

    pa = sub.add_parser("attest", help="write the archive sidecar attestation")
    pa.add_argument("archive")
    pa.add_argument("attestation")
    pa.add_argument("--version", required=True)
    pa.add_argument("--source-manifest", required=True)
    pa.set_defaults(fn=cmd_attest)

    pv = sub.add_parser("verify", help="fresh-extraction verification")
    pv.add_argument("archive")
    pv.add_argument("--manifest", required=True)
    pv.add_argument("--attestation", required=True)
    pv.add_argument("--version", required=True)
    pv.add_argument("--require", action="append")
    pv.set_defaults(fn=cmd_verify)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
