# Verifying a Crabedence Release Artifact

This document describes how to independently verify a Crabedence release
artifact. Every release ships with cryptographic provenance that binds the
artifact to a specific Git commit, qualification record, and build environment.

## Prerequisites

- [GitHub CLI](https://cli.github.com/) (`gh`) for artifact attestation verification
- `shasum` (or `sha256sum`) for checksum verification
- `jq` for JSON inspection
- `git` for source verification

A release publishes exactly three artifacts plus their checksums and
attestations:

| Asset | Contents |
|---|---|
| `crabedence-<version>.tar.gz` | source archive |
| `crabedence-<version>.zip` | source archive (same source, zip format) |
| `crabedence-<version>-release-evidence.tar.gz` | the **complete** finalized evidence directory |

The evidence bundle is the whole finalized tree, not a subset: its
`SHA256SUMS` references every evidence file, so a partial upload could
not be verified by anyone. Everything below is verifiable from these
published files alone — no CI artifact store is involved.

## Verification chain

```
downloaded tar.gz + zip + release-evidence.tar.gz
    ↓
SHA-256 of all three (recomputed from the bytes)
    ↓
GitHub artifact attestation (SLSA provenance)
    ↓
workflow + repository + commit
    ↓
evidence bundle self-checks (shasum -c SHA256SUMS)
    ↓
final evidence manifest (covers artifact.json and every evidence file)
    ↓
registry policy identity (recomputed from the canonical envelope)
    ↓
qualification.json
    ↓
source manifest (both extracted archives)
```

## Step 1: Verify the SHA-256 checksums

Each release includes `.sha256` files alongside the archives:

```bash
# The release you are verifying (current candidate: 0.52.0-rc.1)
VERSION=0.52.0-rc.1

sha256sum -c "crabedence-${VERSION}.tar.gz.sha256"
sha256sum -c "crabedence-${VERSION}.zip.sha256"
sha256sum -c "crabedence-${VERSION}-release-evidence.tar.gz.sha256"
```

All three must match the hashes in `artifact.json` (for the archives) and
the release notes (for the evidence bundle). The zip is an official
artifact with its own identity — `artifact.json` binds it separately as
`artifact.zip_sha256`, and the standalone verifier recomputes it rather
than assuming the tar digest applies to both.

## Step 2: Extract and self-check the evidence bundle

```bash
mkdir -p evidence
tar xzf "crabedence-${VERSION}-release-evidence.tar.gz" -C evidence --strip-components=1
cd evidence
shasum -a 256 -c SHA256SUMS
```

Every checksum must verify. If any file referenced by `SHA256SUMS` is
absent, the published evidence set is incomplete and the release cannot
be independently verified.

### The release object (artifact.json v2)

`artifact.json` is the final release object and binds, by digest, every
object this artifact was qualified against:

```json
{
  "schema_version": 2,
  "release": "0.52.0-rc.1",
  "source": { "commit": "...", "tree": "...", "manifest_sha256": "..." },
  "artifact": { "filename": "...tar.gz", "sha256": "...", "size": 12345,
                "zip_filename": "...zip", "zip_sha256": "..." },
  "policy": { "registry_sha256": "..." },
  "qualification": { "sha256": "...", "schema_version": 2 },
  "sbom": { "sha256": "..." },
  "provenance": { "sha256": "..." },
  "toolchain": { "go": "go1.26.5", "node": "...", "npm": "..." }
}
```

Every digest is recomputed from the bytes it claims to cover — the
archive, the source manifest, `provenance.json`, `qualification.json`,
and the SBOM — never trusted as a string. An unknown `schema_version`
fails closed rather than being interpreted with the wrong semantics.

## Step 3: Verify the GitHub artifact attestations

GitHub attests that the artifact was built from a specific repository,
workflow, commit, and trigger. This is signed Sigstore-backed SLSA build
provenance.

```bash
# Verify the tar.gz attestation
gh attestation verify "crabedence-${VERSION}.tar.gz" \
  --repo dawsonblock/crabedence-V1

# Verify the zip attestation
gh attestation verify "crabedence-${VERSION}.zip" \
  --repo dawsonblock/crabedence-V1

# Verify the evidence bundle attestation
gh attestation verify "crabedence-${VERSION}-release-evidence.tar.gz" \
  --repo dawsonblock/crabedence-V1
```

This proves the artifact was produced by the repository's GitHub Actions
workflow, not by an untrusted source.

## Step 4: Verify the source commit

The attestation binds the artifact to a specific commit SHA. Cross-reference
this with `release-evidence/provenance.json`:

```bash
# Extract the commit from provenance.json
jq -r '.commit' release-evidence/provenance.json

# Verify it matches the attestation
# The attestation output includes the commit SHA in the provenance
```

## Step 5: Verify qualification status

Check that all mandatory gates passed:

```bash
# Check release status
jq -r '.release_status' release-evidence/qualification.json

# Check artifact promotability
jq -r '.artifact_promotable' release-evidence/qualification.json

# List all gate statuses (qualification schema v2 keys gates by gate_id)
jq -r '.gates[] | "\(.gate_id): \(.status)"' release-evidence/qualification.json
```

All gates must show `PASS`. The `release_status` must be `PASS` and
`artifact_promotable` must be `true`.

## Step 6: Verify the source manifest (both archives)

The source manifest is the release source **inventory**: it is derived from
the Git HEAD tree — the same tree `git archive HEAD` packages — so it cannot
diverge from the archive. Each record carries the Git mode, the object type,
the SHA-256 of the exact bytes, and the path:

```
100644 file    <sha256>  README.md
100755 file    <sha256>  scripts/verify-release-artifact.sh
120000 symlink <sha256>  CLAUDE.md
```

A symlink's digest covers its **target bytes**, never the contents of the
file it points to, so verification checks the link itself rather than
dereferencing it. Verification is bidirectional and type- and mode-aware:
it fails closed on a missing entry, a symlink replaced by a regular file or
repointed, a cleared or unexpected executable bit, or any packaged entry
absent from the manifest.

Because the manifest is the Git HEAD tree identity, it is only equal to
`git archive` output while no archive-transforming attributes are in play.
RC1 is qualified on the basis that tracked `.gitattributes` uses no
`export-ignore` or `export-subst`; if one is ever introduced, the manifest
generator must gain explicit support for those semantics first, or the tree
identity and the packaged archive diverge silently.

```bash
# Extract BOTH archives into separate directories
mkdir -p tar-source zip-source
tar xzf "crabedence-${VERSION}.tar.gz" -C tar-source
unzip -q "crabedence-${VERSION}.zip" -d zip-source

# Each tree must independently reproduce the manifest
for tree in tar-source zip-source; do
  bash "${tree}/crabedence-${VERSION}/scripts/verify-source-manifest.sh" \
    evidence/source-tree-sha256.txt "${tree}/crabedence-${VERSION}"
done
```

Each must show `missing=0`, `mismatched=0`, `unexpected=0`, and
`malformed=0`, with `status=PASS`. The two archives must also carry the
same normalized inventory (path, type, mode, content digest) — the clean
room enforces this directly, which catches format-specific packaging drift.

## Step 7: Verify release invariants

The qualification record includes 21 named release invariants:

```bash
jq -r '.invariants[] | "\(.id): \(.description)"' release-evidence/qualification.json
```

These invariants encode the security and correctness properties that the
release proves:

| ID | Description |
|------|-------------|
| CRAB-V1-001 | V3 receipt always binds evidence_sha256 |
| CRAB-V1-002 | V2 receipt can never contain evidence_sha256 |
| CRAB-V1-003 | receipt evidence digest equals canonical RunEvidenceV1 SHA-256 |
| CRAB-V1-004 | Go and TypeScript produce identical canonical evidence |
| CRAB-V1-005 | Go and TypeScript accept/reject identical receipt/evidence domains |
| CRAB-V1-006 | startup confirmation failure evidence survives to RunEvidenceV1 |
| CRAB-V1-007 | detached providers never advertise exit observability |
| CRAB-V1-008 | persistence failure cannot alter FinalRunOutcome |
| CRAB-V1-009 | new mutations fail after coordinator authority loss |
| CRAB-V1-010 | replacement mutations cannot overlap pre-admitted old-coordinator mutations |
| CRAB-V1-011 | qualified source tree equals packaged source tree |
| CRAB-V1-012 | every mandatory qualification gate was executed and passed |
| CRAB-V1-013 | Go capability registry is authoritative for execution class |
| CRAB-V1-014 | durable idempotency prevents duplicate side effects |
| CRAB-V1-015 | UNKNOWN is a first-class terminal state for post-dispatch ambiguity |
| CRAB-V1-016 | crabbox exec never returns fake success for undispatched operations |
| CRAB-V1-017 | expired IN_FLIGHT work is never blindly redispatched |
| CRAB-V1-018 | only an unexpired active lease generation may mutate execution state |
| CRAB-V1-019 | terminal finalization is immutable and conflict-aware |
| CRAB-V1-020 | post-dispatch uncertainty cannot become retryable without evidence |
| CRAB-V1-021 | concurrent identical mutations cause at most one provider dispatch |

## Step 8: Verify evidence bundle integrity

The `release-evidence/SHA256SUMS` file contains checksums for every evidence
file — including `artifact.json`, the binding between the release archive,
the qualified source, and the capability registry digest. Verify the bundle:

```bash
cd release-evidence
sha256sum -c SHA256SUMS
```

All files must verify, and `artifact.json` must be listed — a bundle whose
checksum manifest does not cover the artifact binding is rejected by
`scripts/verify-release-artifact.sh`.

`evidence-manifest.json` is the bundle's identity: its `sha256` is the
SHA-256 of `SHA256SUMS`, and its `file_count` must equal the number of
entries. Verify it independently:

```bash
shasum -a 256 SHA256SUMS
jq -r '.sha256' evidence-manifest.json
```

The release qualification attestation has `evidence-manifest.json` as its
subject and records the manifest digest in its predicate. Verify the
attestation and that the digest it binds is the manifest you hold:

```bash
gh attestation verify release-evidence/evidence-manifest.json \
  --repo dawsonblock/crabedence-V1
jq -r '.evidence_sha256' release-evidence/attestation/attestation.json
```

The attested digest must equal `jq -r '.sha256' evidence-manifest.json`.

### Registry policy identity

The release binds the exact capability policy it was qualified against.
`release-evidence/registry.json` is the verifiable envelope (the digest
plus the canonical descriptor bytes it covers), and `registry.sha256` is
the digest the artifact binds:

```bash
# Recompute the registry digest from the canonical bytes
jq -r '.canonical_payload' release-evidence/registry.json | base64 --decode | shasum -a 256
jq -r '.registry_sha256' release-evidence/registry.json
jq -r '.registry_sha256' release-evidence/artifact.json
```

All three values must be equal — qualified policy = released policy. The
running service prints the same digest in its startup report and exports
it in `capabilities.json` next to its socket, completing the chain:
qualified = released = runtime.

## Summary

If all eight steps pass, the artifact is cryptographically attributable to a
specific Git commit, built through a specific GitHub Actions workflow, and
qualified against the full release matrix. The proof chain is:

```
Git commit → clean qualification → artifact → SHA-256 → GitHub attestation
    → final evidence manifest → published release
```

No step in this chain is self-asserted. Each is independently verifiable.
