#!/usr/bin/env python3
"""Adversarial tests for verify-rc75-release.py (WP5, INV-07).

Each case builds a real archive in a temp dir and runs the verifier's
subcommands as a subprocess — the same path a clean-room verifier
runs. The positive case proves a properly built package verifies;
every other case proves a specific substitution or fabrication is
refused, never normalized into a pass.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "verify-rc75-release.py")
PY = sys.executable


def run_tool(*argv):
    return subprocess.run([PY, TOOL, *argv],
                          capture_output=True, text=True)


def build_source(root, version="0.54.0-rc.7.5-dev"):
    """A minimal but structurally complete package tree."""
    os.makedirs(os.path.join(root, "release-evidence"), exist_ok=True)
    os.makedirs(os.path.join(root, "internal", "x"), exist_ok=True)
    files = {
        "VERSION": version + "\n",
        "go.mod": "module example.com/rc75\n\ngo 1.26\n",
        "go.sum": "dep v1.0.0 h1:abc=\n",
        "internal/x/x.go": "package x\n",
        "build.sh": "#!/bin/sh\necho build\n",
    }
    for rel, content in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
    os.chmod(os.path.join(root, "build.sh"), 0o755)
    os.symlink("VERSION", os.path.join(root, "VERSION-link"))


def make_zip(src_root, zip_path, topdir="pkg"):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(src_root, followlinks=False):
            for name in sorted(dirnames + filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, src_root).replace(os.sep, "/")
                if os.path.islink(full):
                    # store the symlink as a regular file containing
                    # the target — the manifest is the authority on
                    # symlink-ness for the packaged form
                    zf.writestr(os.path.join(topdir, rel), os.readlink(full))
                else:
                    zf.write(full, os.path.join(topdir, rel))


class PackageFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "src")
        build_source(self.src)
        self.manifest = os.path.join(self.tmp.name, "manifest.json")
        self.zip_path = os.path.join(self.tmp.name, "pkg.zip")
        self.att = os.path.join(self.tmp.name, "att.json")

    def manifest_tree(self, root=None, version="0.54.0-rc.7.5-dev"):
        r = run_tool("manifest", root or self.src, self.manifest,
                     "--version", version)
        self.assertEqual(r.returncode, 0, r.stderr)

    def package_and_attest(self):
        self.manifest_tree()
        make_zip(self.src, self.zip_path)
        # The extracted form is what the manifest covers — rebuild the
        # manifest against the post-zip layout (topdir wrapper):
        extract_dir = os.path.join(self.tmp.name, "roundtrip")
        with zipfile.ZipFile(self.zip_path) as zf:
            zf.extractall(extract_dir)
        self.manifest_tree(root=os.path.join(extract_dir, "pkg"))
        r = run_tool("attest", self.zip_path, self.att,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--source-manifest", self.manifest)
        self.assertEqual(r.returncode, 0, r.stderr)

    def verify(self, zip_path=None, att=None, manifest=None,
               version="0.54.0-rc.7.5-dev"):
        # Fixture packages are development artifacts — unsigned by
        # construction. The explicit escape is what production
        # promotion can never supply by accident.
        return run_tool("verify", zip_path or self.zip_path,
                        "--manifest", manifest or self.manifest,
                        "--attestation", att or self.att,
                        "--version", version, "--allow-unsigned")

    def packed_fixture(self):
        """A package built through the real `pack` subcommand: the
        archive embeds the manifest and carries source symlinks as
        real symlink members — the positive fixture for any test that
        needs verification to reach the end."""
        src2 = os.path.join(self.tmp.name, "src2")
        build_source(src2)
        flist = os.path.join(self.tmp.name, "files.txt")
        rels = []
        for dirpath, dirnames, filenames in os.walk(src2, followlinks=False):
            for n in dirnames + filenames:
                rels.append(os.path.relpath(
                    os.path.join(dirpath, n), src2).replace(os.sep, "/"))
        with open(flist, "w") as fh:
            fh.write("\n".join(sorted(rels)) + "\n")
        r = run_tool("manifest", src2, self.manifest,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--from-list", flist)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_tool("pack", src2, self.zip_path,
                     "--from-list", flist, "--topdir", "pkg",
                     "--manifest", self.manifest)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_tool("attest", self.zip_path, self.att,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--source-manifest", self.manifest)
        self.assertEqual(r.returncode, 0, r.stderr)

    def forge_att(self, zip_path):
        """An attestation honestly computed over attacker bytes —
        the retained manifest is what keeps the forgery from passing."""
        att = os.path.join(self.tmp.name,
                           f"att-{os.path.basename(zip_path)}.json")
        r = run_tool("attest", zip_path, att,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--source-manifest", self.manifest)
        self.assertEqual(r.returncode, 0, r.stderr)
        return att


class TestPositive(PackageFixture):
    def test_clean_package_verifies(self):
        # pack + manifest + attest + verify — the real workflow,
        # including a source symlink carried by the container as a
        # real member and bound to the manifest on extraction.
        self.packed_fixture()
        res = self.verify()
        self.assertEqual(res.returncode, 0, res.stderr)


class TestAdversarial(PackageFixture):
    def test_archive_substitution_rejected(self):
        """A different archive under the same attestation is refused."""
        self.package_and_attest()
        other = os.path.join(self.tmp.name, "other.zip")
        with zipfile.ZipFile(other, "w") as zf:
            zf.writestr("pkg/VERSION", "0.54.0-rc.7.5-dev\n")
        res = self.verify(zip_path=other)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("SHA-256", res.stderr)

    def test_tampered_member_rejected(self):
        """One byte changed in a packaged file fails the hash check —
        even under an attestation forged to cover the tampered bytes,
        because the retained manifest still names the qualified
        content."""
        self.package_and_attest()
        # Rebuild the zip with a mutated source file.
        mutated = os.path.join(self.tmp.name, "mutated.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(mutated, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename.endswith("x.go"):
                    data = b"package x // tampered\n"
                zout.writestr(item, data)
        # First refusal: the outer digest does not match.
        res = self.verify(zip_path=mutated)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("SHA-256", res.stderr)
        # Deeper refusal: even an attestation forged over the tampered
        # bytes fails the retained manifest's content hash.
        forged_att = os.path.join(self.tmp.name, "forged-att.json")
        r = run_tool("attest", mutated, forged_att,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--source-manifest", self.manifest)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = self.verify(zip_path=mutated, att=forged_att)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("hash mismatch", res.stderr)

    def test_path_traversal_rejected(self):
        """An archive member escaping the extraction root is refused."""
        self.package_and_attest()
        evil = os.path.join(self.tmp.name, "evil.zip")
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../escape.txt", "owned")
            zf.writestr("pkg/VERSION", "0.54.0-rc.7.5-dev\n")
        res = self.verify(zip_path=evil, att=self.forge_att(evil))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("unsafe archive member", res.stderr)

    def test_symlink_member_rejected(self):
        """A zip symlink escaping the tree is refused — link targets
        must be relative and resolve inside the extraction."""
        self.package_and_attest()
        evil = os.path.join(self.tmp.name, "evilsl.zip")
        with zipfile.ZipFile(evil, "w") as zf:
            zi = zipfile.ZipInfo("pkg/link")
            zi.external_attr = (0o120777 << 16)
            zf.writestr(zi, "/etc/passwd")
        res = self.verify(zip_path=evil, att=self.forge_att(evil))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("symlink", res.stderr)

    def test_undeclared_symlink_member_rejected(self):
        """A container link the manifest does not declare is refused —
        the manifest remains the authority over what may be a link."""
        self.package_and_attest()
        evil = os.path.join(self.tmp.name, "undeclared.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(evil, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zi = zipfile.ZipInfo("pkg/internal/x/link.go")
            zi.external_attr = (0o120777 << 16)
            zout.writestr(zi, "x.go")
        res = self.verify(zip_path=evil, att=self.forge_att(evil))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("undeclared", res.stderr)

    def test_symlink_member_target_mismatch_rejected(self):
        """A container link whose target differs from the manifest's
        declaration is refused — container and authority must agree."""
        src2 = os.path.join(self.tmp.name, "src2")
        build_source(src2)
        flist = os.path.join(self.tmp.name, "files.txt")
        rels = []
        for dirpath, dirnames, filenames in os.walk(src2, followlinks=False):
            for n in dirnames + filenames:
                rels.append(os.path.relpath(
                    os.path.join(dirpath, n), src2).replace(os.sep, "/"))
        with open(flist, "w") as fh:
            fh.write("\n".join(sorted(rels)) + "\n")
        r = run_tool("manifest", src2, self.manifest,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--from-list", flist)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_tool("pack", src2, self.zip_path,
                     "--from-list", flist, "--topdir", "pkg",
                     "--manifest", self.manifest)
        self.assertEqual(r.returncode, 0, r.stderr)
        tampered = os.path.join(self.tmp.name, "tampered.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(tampered, "w") as zout:
            for item in zin.infolist():
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    zout.writestr(item, "go.mod")
                else:
                    zout.writestr(item, zin.read(item.filename))
        res = self.verify(zip_path=tampered, att=self.forge_att(tampered))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("differs from the manifest", res.stderr)

    def test_missing_member_rejected(self):
        """An archive short one manifest entry fails closure."""
        self.package_and_attest()
        short = os.path.join(self.tmp.name, "short.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(short, "w") as zout:
            for item in zin.infolist():
                if item.filename.endswith("go.sum"):
                    continue
                zout.writestr(item, zin.read(item.filename))
        res = self.verify(zip_path=short, att=self.forge_att(short))
        self.assertNotEqual(res.returncode, 0)

    def test_extra_member_rejected(self):
        """An unpackaged file inside the archive fails closure."""
        self.package_and_attest()
        extra = os.path.join(self.tmp.name, "extra.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(extra, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("pkg/backdoor.sh", "#!/bin/sh\n")
        res = self.verify(zip_path=extra, att=self.forge_att(extra))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("unpackaged file", res.stderr)

    def test_wrong_version_rejected(self):
        """A package declaring a different version is refused."""
        self.package_and_attest()
        wrong = os.path.join(self.tmp.name, "wrong.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(wrong, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "pkg/VERSION":
                    data = b"0.54.0-rc.7.4-dev\n"
                zout.writestr(item, data)
        res = self.verify(zip_path=wrong, att=self.forge_att(wrong))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("VERSION", res.stderr)

    def test_forged_attestation_rejected(self):
        """An attestation recomputed over attacker bytes still fails
        the version binding — and a stale one fails the digest."""
        self.package_and_attest()
        with open(self.att) as fh:
            att = json.load(fh)
        att["version"] = "0.0.0-forged"
        with open(self.att, "w") as fh:
            json.dump(att, fh)
        res = self.verify()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("version", res.stderr.lower())

    def test_missing_lockfile_rejected(self):
        """A package missing the dependency lock fails."""
        self.package_and_attest()
        nolock = os.path.join(self.tmp.name, "nolock.zip")
        with zipfile.ZipFile(self.zip_path) as zin, \
                zipfile.ZipFile(nolock, "w") as zout:
            for item in zin.infolist():
                if item.filename.endswith("go.mod"):
                    continue
                zout.writestr(item, zin.read(item.filename))
        res = self.verify(zip_path=nolock, att=self.forge_att(nolock))
        self.assertNotEqual(res.returncode, 0)

    def test_manifest_symlink_escape_rejected(self):
        """A manifest symlink whose target leaves the tree dies at
        verification — the manifest cannot launder an escape."""
        self.package_and_attest()
        with open(self.manifest) as fh:
            m = json.load(fh)
        m["entries"].append({
            "path": "pkg/escape-link", "type": "symlink",
            "target": "../../etc/passwd", "size": 0,
            "sha256": hashlib.sha256(b"../../etc/passwd").hexdigest(),
            "executable": False})
        m["entry_count"] = len(m["entries"])
        with open(self.manifest, "w") as fh:
            json.dump(m, fh)
        # The attestation's manifest digest must be forged along —
        # an attacker controlling both still dies at the target check.
        r = run_tool("attest", self.zip_path, self.att,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--source-manifest", self.manifest)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = self.verify()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("escapes the tree", res.stderr)

    def test_manifest_recursion_impossible(self):
        """The manifest refuses to list itself or the attestation."""
        mpath = os.path.join(self.src, "release-evidence",
                             "rc75-release-attestation.json")
        os.makedirs(os.path.dirname(mpath), exist_ok=True)
        with open(mpath, "w") as fh:
            fh.write("{}")
        self.manifest_tree()
        with open(self.manifest) as fh:
            m = json.load(fh)
        paths = {e["path"] for e in m["entries"]}
        self.assertNotIn("release-evidence/rc75-release-attestation.json", paths)


@unittest.skipUnless(shutil.which("ssh-keygen"),
                     "ssh-keygen is required for signature tests")
class TestSignature(PackageFixture):
    """The trusted-anchor boundary: hash-binding can be forged by
    anyone controlling archive + sidecar; the signature cannot."""

    IDENTITY = "release@nemo-control"

    def make_key(self, name="release"):
        keydir = os.path.join(self.tmp.name, "keys")
        os.makedirs(keydir, exist_ok=True)
        key = os.path.join(keydir, name)
        r = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        allowed = os.path.join(keydir, name + ".allowed")
        with open(key + ".pub") as fh:
            pub = fh.read().strip()
        with open(allowed, "w") as fh:
            fh.write(f"{self.IDENTITY} {pub}\n")
        return key, allowed

    def signed_attestation(self):
        self.packed_fixture()
        key, allowed = self.make_key()
        r = run_tool("attest", self.zip_path, self.att,
                     "--version", "0.54.0-rc.7.5-dev",
                     "--source-manifest", self.manifest,
                     "--sign-key", key)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(self.att + ".sig"))
        return allowed

    def verify_signed(self, allowed=None, sig=None, identity=None,
                      att=None, zip_path=None, require=False):
        argv = ["verify", zip_path or self.zip_path,
                "--manifest", self.manifest,
                "--attestation", att or self.att,
                "--version", "0.54.0-rc.7.5-dev"]
        if sig is not False:
            argv += ["--signature", sig or (self.att + ".sig"),
                     "--allowed-signers", allowed or "",
                     "--sign-identity", identity or self.IDENTITY]
        if require:
            argv.append("--require-signature")
        return run_tool(*argv)

    def test_signed_package_verifies(self):
        allowed = self.signed_attestation()
        res = self.verify_signed(allowed=allowed)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_tampered_attestation_rejected(self):
        """A modified attestation can never carry the original
        signature — hash self-consistency is not authenticity."""
        allowed = self.signed_attestation()
        with open(self.att) as fh:
            att = json.load(fh)
        att["version"] = "0.54.0-rc.7.5-dev"  # legal value, forged doc
        att["archive_size"] += 1
        with open(self.att, "w") as fh:
            json.dump(att, fh)
        res = self.verify_signed(allowed=allowed)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("signature", res.stderr)

    def test_wrong_signer_rejected(self):
        """A signature from a principal the allowed-signers file does
        not authorize is refused."""
        self.signed_attestation()
        _, allowed = self.make_key(name="other")
        res = self.verify_signed(allowed=allowed)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("signature", res.stderr)

    def test_wrong_identity_rejected(self):
        """The signature must verify under the claimed principal, not
        just any trusted key."""
        allowed = self.signed_attestation()
        res = self.verify_signed(allowed=allowed,
                                 identity="other@nemo-control")
        self.assertNotEqual(res.returncode, 0)

    def test_missing_signature_rejected_when_required(self):
        """--require-signature fails closed when the signature sidecar
        is absent — policy, not presence, decides."""
        self.package_and_attest()
        res = self.verify_signed(sig=False, require=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("signature", res.stderr)

    def test_unsigned_rejected_by_default(self):
        """Fail-closed is the default posture: a candidate with no
        signature and no explicit --allow-unsigned is refused before
        any content check — an omitted flag can never admit an
        unauthenticated artifact."""
        self.packed_fixture()
        res = run_tool("verify", self.zip_path,
                       "--manifest", self.manifest,
                       "--attestation", self.att,
                       "--version", "0.54.0-rc.7.5-dev")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("signature", res.stderr)

    def test_unsigned_verifies_without_requirement(self):
        """Unsigned verification still works for development flow —
        the explicit escape flag is what makes the omission a choice."""
        self.packed_fixture()
        res = self.verify()
        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
