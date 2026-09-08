# Verifying a Crabedence Release Artifact

This document describes how to independently verify a Crabedence release
artifact. Every release ships with cryptographic provenance that binds the
artifact to a specific Git commit, qualification record, and build environment.

## Prerequisites

- [GitHub CLI](https://cli.github.com/) (`gh`) for artifact attestation verification
- `shasum` (or `sha256sum`) for checksum verification
- `jq` for JSON inspection
- `git` for source verification

## Verification chain

```
downloaded archive
    ↓
SHA-256 checksum
    ↓
GitHub artifact attestation (SLSA provenance)
    ↓
workflow + repository + commit
    ↓
qualification.json
    ↓
source manifest
```

## Step 1: Verify the SHA-256 checksum

Each release includes `.sha256` files alongside the archives:

```bash
# Verify the tar.gz
sha256sum -c crabedence-v1.0.0-rc.2.tar.gz.sha256

# Verify the zip
sha256sum -c crabedence-v1.0.0-rc.2.zip.sha256
```

The checksum must match the hash recorded in `release-evidence/artifact.json`.

## Step 2: Verify the GitHub artifact attestation

GitHub attests that the artifact was built from a specific repository,
workflow, commit, and trigger. This is signed Sigstore-backed SLSA build
provenance.

```bash
# Verify the tar.gz attestation
gh attestation verify crabedence-v1.0.0-rc.2.tar.gz \
  --repo dawsonblock/crabedence-V1

# Verify the zip attestation
gh attestation verify crabedence-v1.0.0-rc.2.zip \
  --repo dawsonblock/crabedence-V1
```

This proves the artifact was produced by the repository's GitHub Actions
workflow, not by an untrusted source.

## Step 3: Verify the source commit

The attestation binds the artifact to a specific commit SHA. Cross-reference
this with `release-evidence/provenance.json`:

```bash
# Extract the commit from provenance.json
jq -r '.commit' release-evidence/provenance.json

# Verify it matches the attestation
# The attestation output includes the commit SHA in the provenance
```

## Step 4: Verify qualification status

Check that all mandatory gates passed:

```bash
# Check release status
jq -r '.release_status' release-evidence/qualification.json

# Check artifact promotability
jq -r '.artifact_promotable' release-evidence/qualification.json

# List all gate statuses
jq -r '.gates[] | "\(.name): \(.status)"' release-evidence/qualification.json
```

All gates must show `PASS`. The `release_status` must be `PASS` and
`artifact_promotable` must be `true`.

## Step 5: Verify the source manifest

The source manifest records the SHA-256 of every source file at qualification
time. Verify that the archive contents match:

```bash
# Extract the archive
tar xzf crabedence-v1.0.0-rc.2.tar.gz

# Verify the source manifest
cd crabedence-v1.0.0-rc.2
bash scripts/verify-source-manifest.sh release-evidence/source-tree-sha256.txt .
```

The output must show `missing=0` and `mismatched=0`.

## Step 6: Verify release invariants

The qualification record includes 12 named release invariants:

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

## Step 7: Verify evidence bundle integrity

The `release-evidence/SHA256SUMS` file contains checksums for every evidence
file. Verify the bundle:

```bash
cd release-evidence
sha256sum -c SHA256SUMS
```

All files must verify.

## Summary

If all seven steps pass, the artifact is cryptographically attributable to a
specific Git commit, built through a specific GitHub Actions workflow, and
qualified against the full release matrix. The proof chain is:

```
Git commit → clean qualification → artifact → SHA-256 → GitHub attestation → release
```

No step in this chain is self-asserted. Each is independently verifiable.
