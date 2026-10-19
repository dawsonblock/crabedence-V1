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
            container. With --sign-key the attestation is SSH-signed
            under the rc75-release namespace — the trusted anchor an
            attacker controlling archive + sidecar cannot forge.

  verify    Fresh-extraction verification a clean verifier can run
            without trusting the developer's workspace: unpack the
            archive into an empty directory, prove entry safety and
            manifest closure, re-hash every file, check symlinks,
            version consistency, dependency locks, qualification
            evidence presence, and the sidecar digest. With --signature
            + --allowed-signers + --sign-identity the attestation must
            first verify under a trusted principal; --require-signature
            makes that check mandatory. Any failure is a release
            blocker; nothing is treated as pass by absence of evidence.

Usage:
  verify-rc75-release.py manifest <source-root> <out.json>
      [--exclude PATH ...]
  verify-rc75-release.py attest <archive> <attestation.json>
      --version V --source-manifest <m.json> [--sign-key KEY]
  verify-rc75-release.py verify <archive> --manifest <m.json>
      --attestation <a.json> --version V [--require PATH ...]
      [--signature <a.json.sig> --allowed-signers <file>
       --sign-identity <principal>] [--require-signature]
"""

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

MANIFEST_SCHEMA = "rc75-source-manifest-v1"
ATTEST_SCHEMA = "rc75-release-attestation-v1"

# SSH signature namespace binding attestations to this release purpose —
# a signature minted for any other use cannot be replayed here.
SIGN_NAMESPACE = "rc75-release"

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
    tree packs to the same bytes. Symlinks ship as real symlink
    members — the transport artifact and the verified source identity
    agree without a reconstruction step, and the manifest remains the
    authority the verifier binds them against. The manifest travels
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
                # The container carries the link as a real symlink
                # member (unix S_IFLNK, link text as content) so an
                # ordinary extraction reproduces the declared tree —
                # the manifest remains the authority the verifier
                # binds, the container simply agrees with it.
                zi = zipfile.ZipInfo(arc, epoch)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(zi, os.readlink(full).encode())
                continue
            if not os.path.isfile(full):
                continue
            zi = zipfile.ZipInfo(arc, epoch)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3
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

def sign_file(path, key):
    """SSH-sign a file in place: writes <path>.sig under the release
    namespace. The signature binds the exact bytes — a modified
    attestation can never carry a valid original signature."""
    if shutil.which("ssh-keygen") is None:
        die("ssh-keygen is required to sign the attestation")
    sig = path + ".sig"
    if os.path.exists(sig):
        os.remove(sig)
    r = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", key,
         "-n", SIGN_NAMESPACE, path],
        capture_output=True, text=True)
    if r.returncode != 0:
        die(f"attestation signing failed: {r.stderr.strip()}")
    if not os.path.isfile(sig):
        die("ssh-keygen reported success but produced no signature")
    return sig


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
    if args.sign_key:
        print(f"signature: {sign_file(args.attestation, args.sign_key)}")


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


def member_is_symlink(info):
    """A zip member is a symlink when its unix mode declares S_IFLNK —
    the Info-ZIP convention pack uses and the verifier honors."""
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def safe_members(zf):
    """Every archive member must extract inside the target — no
    absolute paths, no drive letters, no '..' — and be a regular file,
    directory, or symlink. Symlink members pass member_is_symlink and
    are bound to manifest declarations by the verifier — the container
    cannot smuggle a link the manifest does not declare."""
    for info in zf.infolist():
        name = info.filename
        if name.endswith("/"):
            continue
        norm = name.replace("\\", "/")
        parts = norm.split("/")
        if norm.startswith("/") or ".." in parts or ":" in parts[0]:
            yield None, f"unsafe archive member: {name!r}"
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


def verify_signature(args):
    """The trusted anchor: the attestation sidecar is hash-binding
    evidence, not authority — whoever controls archive + sidecar can
    mint self-consistent hashes. A signature over the attestation from
    a separately controlled release key is the trust boundary. When a
    signature is supplied (or required) the attestation must verify
    under a principal the allowed-signers file authorizes, before any
    other check runs."""
    want = bool(args.signature or args.allowed_signers or
                args.sign_identity)
    if args.require_signature and not (
            args.signature and args.allowed_signers and
            args.sign_identity):
        die("signature verification required but --signature, "
            "--allowed-signers and --sign-identity were not all supplied")
    if not want:
        return
    if not (args.signature and args.allowed_signers and
            args.sign_identity):
        die("--signature, --allowed-signers and --sign-identity must be "
            "supplied together — a signature without its trust anchor "
            "proves nothing")
    if shutil.which("ssh-keygen") is None:
        die("ssh-keygen is required to verify the attestation signature")
    with open(args.attestation, "rb") as fh:
        attestation_bytes = fh.read()
    r = subprocess.run(
        ["ssh-keygen", "-Y", "verify",
         "-f", args.allowed_signers,
         "-I", args.sign_identity,
         "-n", SIGN_NAMESPACE,
         "-s", args.signature],
        input=attestation_bytes, capture_output=True)
    if r.returncode != 0:
        die("attestation signature verification failed — the release "
            "identity is not authenticated by a trusted key")


def cmd_verify(args):
    f = Findings()
    archive = os.path.abspath(args.archive)
    f.require(os.path.isfile(archive), f"archive not found: {archive}")
    verify_signature(args)

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
            container_links = {}
            for info, err in safe_members(zf):
                if err:
                    f.check(False, err)
                    continue
                norm = info.filename.replace("\\", "/")
                if not f.check(norm not in names,
                               f"duplicate archive member: {norm}"):
                    continue
                names.add(norm)
                if member_is_symlink(info):
                    # Link text is the member's content; it is
                    # materialized only once the tree is located and
                    # the manifest has declared it.
                    container_links[norm] = \
                        zf.read(info).decode("utf-8", "surrogateescape")
                    continue
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

        # Container symlink members are bound to the manifest's
        # declarations: a link the manifest does not declare is
        # refused, and a declared link whose container target differs
        # is refused. A target must be relative and resolve inside
        # the tree, and it must not collide with an extracted member.
        manifest_links = {e["path"]: e["target"]
                          for e in manifest["entries"]
                          if e["type"] == "symlink"}
        for member, target in container_links.items():
            dest = os.path.join(tmp, member)
            rel = os.path.relpath(dest, tree).replace(os.sep, "/")
            resolved = os.path.normpath(
                os.path.join(os.path.dirname(dest), target))
            f.require(
                not os.path.isabs(target)
                and resolved.startswith(tree + os.sep),
                f"archive symlink target escapes the tree: {member}")
            f.require(not os.path.lexists(dest),
                      f"archive symlink member collides with an extracted member: {member}")
            declared = manifest_links.get(rel)
            f.check(declared is not None,
                    f"undeclared archive symlink member: {member} — the "
                    "container cannot carry a link the manifest does not declare")
            if declared is None:
                continue
            if not f.check(target == declared,
                           f"archive symlink target differs from the "
                           f"manifest declaration: {member}"):
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.symlink(target, dest)

        # Manifest-declared links the container did not carry are
        # materialized from the manifest — the manifest remains their
        # authority for legacy containers built before the packer
        # shipped links as members. The same safety rules apply.
        for e in manifest["entries"]:
            if e["type"] != "symlink":
                continue
            dest = os.path.join(tree, e["path"])
            if os.path.lexists(dest):
                continue  # provided by the container and bound above
            resolved = os.path.normpath(
                os.path.join(os.path.dirname(dest), e["target"]))
            f.require(
                not os.path.isabs(e["target"])
                and resolved.startswith(tree + os.sep),
                f"symlink target escapes the tree: {e['path']}")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.symlink(e["target"], dest)

        verify_tree_against_manifest(tree, manifest, f)

        # The embedded manifest is exempt from the entry checks above —
        # a manifest cannot list itself — which means nothing has bound
        # its CONTENT yet. A package could ship an embedded manifest
        # asserting a different source root than the one this
        # verification ran against, and nothing would notice. Bind it:
        # the embedded commitment must equal the authenticated external
        # manifest field for field.
        embedded_path = os.path.join(tree, EMBEDDED_MANIFEST)
        if f.check(os.path.isfile(embedded_path),
                   f"embedded source manifest missing: {EMBEDDED_MANIFEST}"):
            embedded = None
            try:
                with open(embedded_path) as fh:
                    embedded = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                f.check(False,
                        f"embedded source manifest does not parse: {exc}")
            if embedded is not None:
                f.check(embedded.get("schema") == MANIFEST_SCHEMA,
                        "embedded source manifest schema mismatch")
                for field in ("version", "entry_count", "root_hash"):
                    f.check(embedded.get(field) == manifest.get(field),
                            f"embedded manifest {field} does not match the "
                            "authenticated external manifest")
                f.check(embedded.get("entries") == manifest.get("entries"),
                        "embedded manifest entry list differs from the "
                        "authenticated external manifest")

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
    pa.add_argument("--sign-key",
                    help="SSH private key; signs the attestation in place "
                         "(writes <attestation>.sig under the rc75-release "
                         "namespace)")
    pa.set_defaults(fn=cmd_attest)

    pv = sub.add_parser("verify", help="fresh-extraction verification")
    pv.add_argument("archive")
    pv.add_argument("--manifest", required=True)
    pv.add_argument("--attestation", required=True)
    pv.add_argument("--version", required=True)
    pv.add_argument("--require", action="append")
    pv.add_argument("--signature",
                    help="SSH signature file over the attestation")
    pv.add_argument("--allowed-signers",
                    help="ssh-keygen allowed_signers file naming trusted "
                         "release principals")
    pv.add_argument("--sign-identity",
                    help="principal the signature must verify under")
    pv.add_argument("--require-signature", action="store_true",
                    help="fail closed unless a trusted signature verifies")
    pv.set_defaults(fn=cmd_verify)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
