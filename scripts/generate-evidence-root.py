#!/usr/bin/env python3
"""Generate or verify evidence-root.json — the semantic closure of the
release evidence bundle.

SHA256SUMS proves the bundle's files match their checksums, and
evidence-manifest.json proves SHA256SUMS itself. Neither answers the
release question semantically: "were THESE gate results, THIS source
manifest, THIS runtime digest, THIS registry digest and THESE artifact
digests the things that were qualified?" evidence-root.json binds each
of those identities by name, then reduces the whole closure to a single
root_sha256 computed over the canonical serialization of every binding.
Signing that one digest attests the entire qualification run.

Two phases share the document:

  generate        after qualification: every binding except the
                  release artifacts (the packaged archives do not exist
                  yet) — artifacts.status = "pending".
  generate        after finalization (artifact.json present):
                  artifacts.status = "bound", entries carry each
                  artifact's declared digest.

Verification (--verify) rebuilds every binding from the files in the
evidence directory — never trusting the stored document — then:

  1. the stored document must equal the rebuilt one, except
     generated_at;
  2. root_sha256 must equal sha256 over the canonical serialization of
     the stored document with root_sha256 and generated_at removed.

A root that names a digest the files do not produce, or a root_sha256
that does not cover the document, fails verification.

Usage:
  generate-evidence-root.py <evidence-dir> [--repo-root DIR]
  generate-evidence-root.py --verify <evidence-dir> [--repo-root DIR]
"""

import hashlib
import json
import os
import sys

SCHEMA_VERSION = 1

# Evidence files whose digests the root binds by name. Anything absent
# is recorded as null rather than invented — a missing input is a
# weaker document, never a forged one.
SOURCE_FILES = {
    "source_manifest": "source-tree-sha256.txt",
    "git_blob_manifest": "source-tree-git-blobs.txt",
}
COMPONENT_FILES = {
    "capability_registry": "registry.json",
    "qualification_registry": "qualification-registry.json",
    "nemo_runtime_record": "nemo-runtime.json",
    "sbom": "sbom.spdx.json",
}
VOLATILE_FIELDS = ("generated_at", "root_sha256")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_sha(evidence_dir, name):
    path = os.path.join(evidence_dir, name)
    return sha256_file(path) if os.path.isfile(path) else None


def load_json(path):
    with open(path, "rb") as fh:
        return json.load(fh)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def build(evidence_dir, repo_root):
    prov = load_json(os.path.join(evidence_dir, "provenance.json"))
    qual = load_json(os.path.join(evidence_dir, "qualification.json"))
    relman_path = os.path.join(evidence_dir, "release-manifest.json")
    relman = load_json(relman_path) if os.path.isfile(relman_path) else {}

    source = {
        "commit": prov.get("commit"),
        "tree": prov.get("tree"),
        "branch": prov.get("branch"),
    }
    for key, fname in SOURCE_FILES.items():
        source[key] = {"file": fname, "sha256": file_sha(evidence_dir, fname)}

    components = {}
    for key, fname in COMPONENT_FILES.items():
        components[key] = {"file": fname, "sha256": file_sha(evidence_dir, fname)}

    # The NEMO transfer manifest is component metadata of the source
    # tree; the evidence copy is authoritative when present, otherwise
    # the repository copy is bound at generation time.
    transfer_candidates = [
        os.path.join(evidence_dir, "nemo-transfer-manifest.json"),
        os.path.join(repo_root, "runtimes", "nemo-transfer-manifest.json"),
    ]
    transfer = next((p for p in transfer_candidates if os.path.isfile(p)), None)
    if transfer is not None:
        tm = load_json(transfer)
        components["nemo_transfer_manifest"] = {
            "file": os.path.relpath(transfer, evidence_dir)
            if transfer.startswith(evidence_dir)
            else "runtimes/nemo-transfer-manifest.json",
            "sha256": sha256_file(transfer),
            "shipped_tree_sha256": tm.get("shipped_tree_sha256"),
            "baseline_source_sha256": (tm.get("source") or {}).get("sha256"),
        }
    else:
        components["nemo_transfer_manifest"] = {"sha256": None}

    nrt_path = os.path.join(evidence_dir, "nemo-runtime.json")
    if os.path.isfile(nrt_path):
        components["nemo_runtime_digest"] = load_json(nrt_path).get(
            "nemo_runtime_sha256"
        )
    else:
        components["nemo_runtime_digest"] = None

    gates = [
        {
            "gate_id": g.get("gate_id"),
            "status": g.get("status"),
            "log_sha256": (g.get("evidence") or {}).get("sha256"),
        }
        for g in qual.get("gates", [])
    ]
    gates.sort(key=lambda g: g.get("gate_id") or "")

    qualification = {
        "file": "qualification.json",
        "sha256": file_sha(evidence_dir, "qualification.json"),
        "release_status": qual.get("release_status"),
        "gate_count": len(gates),
        "gates": gates,
    }

    artifact_path = os.path.join(evidence_dir, "artifact.json")
    if os.path.isfile(artifact_path):
        art = load_json(artifact_path)
        entries = [
            {"name": a["filename"], "sha256": a["sha256"], "size": a["size"]}
            for a in [
                {"filename": (art.get("artifact") or {}).get("filename"),
                 "sha256": (art.get("artifact") or {}).get("sha256"),
                 "size": (art.get("artifact") or {}).get("size")},
                {"filename": (art.get("artifact") or {}).get("zip_filename"),
                 "sha256": (art.get("artifact") or {}).get("zip_sha256"),
                 "size": (art.get("artifact") or {}).get("zip_size")},
            ]
            if a["filename"] and a["sha256"]
        ]
        artifacts = {
            "status": "bound",
            "file": "artifact.json",
            "sha256": sha256_file(artifact_path),
            "entries": entries,
        }
    else:
        artifacts = {"status": "pending", "entries": []}

    import datetime
    doc = {
        "schema_version": SCHEMA_VERSION,
        "document": "evidence-root",
        "release_name": relman.get("release_name"),
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "components": components,
        "qualification": qualification,
        "artifacts": artifacts,
    }
    bound = {k: v for k, v in doc.items() if k not in VOLATILE_FIELDS}
    doc["root_sha256"] = hashlib.sha256(canonical(bound).encode()).hexdigest()
    return doc


def verify(evidence_dir, repo_root):
    root_path = os.path.join(evidence_dir, "evidence-root.json")
    if not os.path.isfile(root_path):
        print("evidence-root: evidence-root.json is missing", file=sys.stderr)
        return False
    stored = load_json(root_path)
    expected = build(evidence_dir, repo_root)

    ok = True
    stored_bound = {k: v for k, v in stored.items() if k not in VOLATILE_FIELDS}
    expected_bound = {k: v for k, v in expected.items() if k not in VOLATILE_FIELDS}
    if stored_bound != expected_bound:
        for key in sorted(set(stored_bound) | set(expected_bound)):
            if stored_bound.get(key) != expected_bound.get(key):
                print(
                    f"evidence-root: binding '{key}' does not match the "
                    f"evidence files (stored={json.dumps(stored_bound.get(key))[:200]} "
                    f"recomputed={json.dumps(expected_bound.get(key))[:200]})",
                    file=sys.stderr,
                )
        ok = False

    recomputed = hashlib.sha256(canonical(stored_bound).encode()).hexdigest()
    if stored.get("root_sha256") != recomputed:
        print(
            "evidence-root: root_sha256 does not cover the stored bindings "
            f"(stored={stored.get('root_sha256')} recomputed={recomputed})",
            file=sys.stderr,
        )
        ok = False
    return ok


def main(argv):
    verify_mode = False
    repo_root = os.getcwd()
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--verify":
            verify_mode = True
            i += 1
        elif a == "--repo-root":
            repo_root = argv[i + 1]
            i += 2
        elif a.startswith("--repo-root="):
            repo_root = a.split("=", 1)[1]
            i += 1
        else:
            positional.append(a)
            i += 1
    if len(positional) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    evidence_dir = os.path.abspath(positional[0])
    if not os.path.isdir(evidence_dir):
        print(f"evidence-root: not a directory: {evidence_dir}", file=sys.stderr)
        return 2
    if verify_mode:
        if verify(evidence_dir, repo_root):
            print("evidence-root: verified")
            return 0
        return 1
    doc = build(evidence_dir, repo_root)
    out = os.path.join(evidence_dir, "evidence-root.json")
    with open(out, "w") as fh:
        json.dump(doc, fh, indent=1, sort_keys=False)
        fh.write("\n")
    print(f"evidence-root: {out} root_sha256={doc['root_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
