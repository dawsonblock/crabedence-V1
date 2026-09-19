#!/usr/bin/env bash
# Verify a release artifact's evidence bundle.
#
# Works standalone on an extracted archive — does NOT require .git.
#
# Usage:
#   ./scripts/verify-release-artifact.sh --mode qualification [options]
#   ./scripts/verify-release-artifact.sh --mode release --archive PATH [options]
#
# Options:
#   --mode qualification|release  Explicit verification contract (see below).
#   --evidence DIR                Evidence bundle (default: dist/release-evidence/)
#   --source DIR                  Source tree to verify (default: repo root)
#   --archive PATH                Release archive; its SHA-256 is recomputed
#                                 from the bytes and required to equal
#                                 artifact.json's binding
#
# Legacy positional form: [evidence-dir] [source-dir] [archive]
#   Without --mode the contract is derived from whether an archive was
#   supplied, and a notice is printed. Pass --mode explicitly.
#
# Contracts:
#   qualification  Requires qualification evidence, source identity, the
#                  registry policy identity, and provenance metadata. An
#                  archive and artifact.json are optional — no distributable
#                  artifact exists yet; whatever is present is validated,
#                  but no archive digest is claimed to have been recomputed.
#   release        Requires the archive, artifact.json, source manifest,
#                  qualification, SBOM, registry policy identity,
#                  provenance, and the final evidence manifest. The archive
#                  digest is recomputed from its bytes — never read from a
#                  supplied checksum file — and must equal artifact.json's
#                  binding.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE=""
EVIDENCE_DIR=""
SOURCE_DIR=""
ARCHIVE_PATH=""
POSITIONAL=()

usage() {
  sed -n '2,32p' "$0"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --mode=*) MODE="${1#*=}"; shift ;;
    --evidence) EVIDENCE_DIR="${2:-}"; shift 2 ;;
    --evidence=*) EVIDENCE_DIR="${1#*=}"; shift ;;
    --source) SOURCE_DIR="${2:-}"; shift 2 ;;
    --source=*) SOURCE_DIR="${1#*=}"; shift ;;
    --archive) ARCHIVE_PATH="${2:-}"; shift 2 ;;
    --archive=*) ARCHIVE_PATH="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

if [ "${#POSITIONAL[@]}" -gt 0 ]; then EVIDENCE_DIR="${POSITIONAL[0]}"; fi
if [ "${#POSITIONAL[@]}" -gt 1 ]; then SOURCE_DIR="${POSITIONAL[1]}"; fi
if [ "${#POSITIONAL[@]}" -gt 2 ]; then ARCHIVE_PATH="${POSITIONAL[2]}"; fi

EVIDENCE_DIR="${EVIDENCE_DIR:-$REPO_ROOT/dist/release-evidence}"
SOURCE_DIR="${SOURCE_DIR:-$REPO_ROOT}"

MODE_INFERRED=false
if [ -n "$MODE" ]; then
  case "$MODE" in
    qualification|release) ;;
    *)
      echo "ERROR: --mode must be qualification or release, got: $MODE" >&2
      exit 2
      ;;
  esac
else
  if [ -n "$ARCHIVE_PATH" ]; then MODE="release"; else MODE="qualification"; fi
  MODE_INFERRED=true
fi

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "ERROR: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 1
fi
if [ ! -d "$SOURCE_DIR" ]; then
  echo "ERROR: source directory not found: $SOURCE_DIR" >&2
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

check() {
  local label="$1" result="$2"
  if [ "$result" = "PASS" ]; then
    printf "  %-40s PASS\n" "$label"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "  %-40s FAIL\n" "$label"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

echo ""
echo "=== Release Artifact Verification ==="
echo "  mode:     $MODE"
echo "  evidence: $EVIDENCE_DIR"
echo "  source:   $SOURCE_DIR"
if [ -n "$ARCHIVE_PATH" ]; then
  echo "  archive:  $ARCHIVE_PATH"
fi
if [ "$MODE_INFERRED" = true ]; then
  echo "  note: mode was inferred from the supplied arguments; pass --mode qualification|release explicitly"
fi
echo ""

# ─── Mode contract ──────────────────────────────────────────────────────────
# A mode is a contract, not a hint: a required input that is missing is a
# hard error, so a release verification can never silently degrade into a
# qualification run (or the reverse). qualification.json is required in
# both modes; its absence is reported as its own FAIL below, and a
# present record must validate against the schema.
CONTRACT_FAILURES=0
require_file() {
  if [ ! -f "$1" ]; then
    echo "  ERROR: $MODE mode requires $2 ($1)" >&2
    CONTRACT_FAILURES=$((CONTRACT_FAILURES + 1))
  fi
}

require_file "$EVIDENCE_DIR/provenance.json" "provenance metadata"
require_file "$EVIDENCE_DIR/source-tree-sha256.txt" "the source manifest"
require_file "$EVIDENCE_DIR/registry.sha256" "the registry policy identity"
require_file "$EVIDENCE_DIR/registry.json" "the verifiable registry envelope"
if [ "$MODE" = "release" ]; then
  require_file "$EVIDENCE_DIR/artifact.json" "artifact.json (the release artifact binding)"
  require_file "$ARCHIVE_PATH" "the release archive (--archive)"
fi

if [ "$CONTRACT_FAILURES" -gt 0 ]; then
  echo ""
  echo "MODE CONTRACT VIOLATED: $CONTRACT_FAILURES missing requirement(s)" >&2
  exit 1
fi

# 0. artifact.json binding — the release archive must be the archive the
# qualified evidence describes. Nothing here trusts a stored digest
# string: the archive's SHA-256 is recomputed from its bytes, and the
# binding is cross-checked against the qualified source identity.
ARTIFACT_JSON="$EVIDENCE_DIR/artifact.json"
if [ -f "$ARTIFACT_JSON" ]; then
  ARTIFACT_SHA="$(jq -r '.sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_COMMIT="$(jq -r '.source_commit // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_TREE="$(jq -r '.source_tree // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_VERSION="$(jq -r '.release_version // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_REGISTRY="$(jq -r '.registry_sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"

  if [ -n "$ARTIFACT_SHA" ] && [ -n "$ARTIFACT_COMMIT" ] && [ -n "$ARTIFACT_TREE" ] && [ -n "$ARTIFACT_VERSION" ]; then
    check "artifact.json complete" "PASS"
  else
    check "artifact.json complete" "FAIL"
    echo "  ERROR: artifact.json is missing sha256/source_commit/source_tree/release_version" >&2
  fi

  # The capability policy the release was qualified against must be bound.
  if [ -n "$ARTIFACT_REGISTRY" ]; then
    check "artifact.json binds the capability registry" "PASS"
  else
    check "artifact.json binds the capability registry" "FAIL"
    echo "  ERROR: artifact.json has no registry_sha256 binding" >&2
  fi

  # artifact.json must describe the qualified source, not a different one.
  if [ -f "$EVIDENCE_DIR/provenance.json" ]; then
    PROV_COMMIT="$(jq -r '.commit // empty' "$EVIDENCE_DIR/provenance.json" 2>/dev/null || true)"
    PROV_TREE="$(jq -r '.tree // empty' "$EVIDENCE_DIR/provenance.json" 2>/dev/null || true)"
    if [ -n "$PROV_COMMIT" ] && [ "$ARTIFACT_COMMIT" = "$PROV_COMMIT" ] && [ "$ARTIFACT_TREE" = "$PROV_TREE" ]; then
      check "artifact.json binds the qualified source" "PASS"
    else
      check "artifact.json binds the qualified source" "FAIL"
      echo "  ERROR: artifact.json source $ARTIFACT_COMMIT/$ARTIFACT_TREE does not match provenance $PROV_COMMIT/$PROV_TREE" >&2
    fi
  fi

  # Recompute the archive digest — never trust the stored string.
  if [ -n "$ARCHIVE_PATH" ]; then
    if [ ! -f "$ARCHIVE_PATH" ]; then
      check "Release archive present" "FAIL"
      echo "  ERROR: archive not found: $ARCHIVE_PATH" >&2
    else
      ACTUAL_ARCHIVE_SHA="$(shasum -a 256 "$ARCHIVE_PATH" | cut -d ' ' -f1)"
      if [ -n "$ARTIFACT_SHA" ] && [ "$ACTUAL_ARCHIVE_SHA" = "$ARTIFACT_SHA" ]; then
        check "Archive matches artifact.json (recomputed)" "PASS"
      else
        check "Archive matches artifact.json (recomputed)" "FAIL"
        echo "  ERROR: archive SHA-256 $ACTUAL_ARCHIVE_SHA does not equal artifact.json $ARTIFACT_SHA" >&2
      fi
      if [ "$(basename "$ARCHIVE_PATH")" = "crabedence-${ARTIFACT_VERSION}.tar.gz" ]; then
        check "Archive filename matches release version" "PASS"
      else
        check "Archive filename matches release version" "FAIL"
        echo "  ERROR: archive name does not carry release_version $ARTIFACT_VERSION" >&2
      fi
    fi
  fi
else
  # No artifact.json. That is only a failure when an archive was
  # supplied — the release-verification path, where the artifact binding
  # must exist. A qualification run that builds no archive has no
  # artifact binding to verify, so the absence is informational.
  if [ -n "$ARCHIVE_PATH" ]; then
    check "artifact.json (missing)" "FAIL"
    echo "  ERROR: artifact.json is not part of the evidence bundle" >&2
  else
    echo "  note: artifact.json not present; artifact binding not verified (no archive supplied)"
  fi
fi

# 1. SHA256SUMS verification.
if [ -f "$EVIDENCE_DIR/SHA256SUMS" ]; then
  if (cd "$EVIDENCE_DIR" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then
    check "Artifact checksums" "PASS"
  else
    check "Artifact checksums" "FAIL"
  fi
else
  check "Artifact checksums (missing)" "FAIL"
fi

# 1b. artifact.json must be COVERED by the checksum manifest, not merely
# present next to it. The artifact binding is what ties the release
# archive to the qualified source and the capability registry; a bundle
# whose digest does not cover it could ship a swapped binding that every
# later cross-check would still accept.
if [ -f "$ARTIFACT_JSON" ]; then
  if [ -f "$EVIDENCE_DIR/SHA256SUMS" ] && grep -qE '[[:space:]]\./artifact\.json$' "$EVIDENCE_DIR/SHA256SUMS"; then
    check "artifact.json covered by checksums" "PASS"
  else
    check "artifact.json covered by checksums" "FAIL"
    echo "  ERROR: artifact.json is not listed in SHA256SUMS — the evidence bundle does not bind the release artifact" >&2
  fi
fi

# 1c. Registry policy identity — the capability catalog the release was
# qualified against. The envelope carries the exact canonical descriptor
# bytes, so the digest is recomputed HERE from the bytes; a stored digest
# string is never trusted on its own. artifact.json must bind exactly
# this value: qualified policy = released policy.
REGISTRY_SHA_FILE="$EVIDENCE_DIR/registry.sha256"
REGISTRY_ENVELOPE="$EVIDENCE_DIR/registry.json"
REGISTRY_SHA="$(tr -d '[:space:]' < "$REGISTRY_SHA_FILE")"
if [[ "$REGISTRY_SHA" =~ ^[0-9a-f]{64}$ ]]; then
  check "Registry digest format" "PASS"
else
  check "Registry digest format" "FAIL"
  echo "  ERROR: registry.sha256 is not a SHA-256 digest: $REGISTRY_SHA" >&2
fi

ENVELOPE_SHA="$(jq -r '.registry_sha256 // empty' "$REGISTRY_ENVELOPE" 2>/dev/null || true)"
ENVELOPE_PAYLOAD="$(jq -r '.canonical_payload // empty' "$REGISTRY_ENVELOPE" 2>/dev/null || true)"
RECOMPUTED_REGISTRY=""
if [ -n "$ENVELOPE_PAYLOAD" ]; then
  RECOMPUTED_REGISTRY="$(printf '%s' "$ENVELOPE_PAYLOAD" | base64 --decode 2>/dev/null | shasum -a 256 | awk '{print $1}')"
fi
if [ -n "$RECOMPUTED_REGISTRY" ] && [ "$RECOMPUTED_REGISTRY" = "$ENVELOPE_SHA" ] && [ "$ENVELOPE_SHA" = "$REGISTRY_SHA" ]; then
  check "Registry digest recomputed (envelope)" "PASS"
else
  check "Registry digest recomputed (envelope)" "FAIL"
  echo "  ERROR: registry envelope digest=$ENVELOPE_SHA recomputed=$RECOMPUTED_REGISTRY does not match registry.sha256=$REGISTRY_SHA" >&2
fi

if [ -f "$ARTIFACT_JSON" ]; then
  ARTIFACT_REGISTRY="$(jq -r '.registry_sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  if [ -n "$ARTIFACT_REGISTRY" ] && [ "$ARTIFACT_REGISTRY" = "$REGISTRY_SHA" ]; then
    check "artifact.json binds the qualified registry" "PASS"
  else
    check "artifact.json binds the qualified registry" "FAIL"
    echo "  ERROR: artifact.json registry_sha256=$ARTIFACT_REGISTRY does not match the qualified registry $REGISTRY_SHA" >&2
  fi
fi

# 2. Source manifest present.
if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
  check "Source SHA-256 manifest present" "PASS"
else
  check "Source SHA-256 manifest present" "FAIL"
fi

# 2b. Verify manifest against actual source tree by delegating to
# verify-source-manifest.sh. This guarantees a single source of truth
# for exclusion logic — the artifact verifier no longer reimplements
# the bidirectional manifest check (which previously diverged from the
# generator's exclusions on nested bin/dist/node_modules paths).
if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
  SOURCE_VERIFIER="$SCRIPT_DIR/verify-source-manifest.sh"
  if [ ! -x "$SOURCE_VERIFIER" ]; then
    check "Source manifest equality (verifier missing)" "FAIL"
    echo "  ERROR: verify-source-manifest.sh not found or not executable" >&2
  else
    # verify-source-manifest.sh prints a summary; capture and surface it.
    if "$SOURCE_VERIFIER" "$EVIDENCE_DIR/source-tree-sha256.txt" "$SOURCE_DIR" >"$EVIDENCE_DIR/.source-verify.tmp" 2>&1; then
      check "Source manifest equality" "PASS"
    else
      check "Source manifest equality" "FAIL"
    fi
    # Surface the verifier's detail (missing/mismatched/unexpected) to stderr.
    sed 's/^/    /' "$EVIDENCE_DIR/.source-verify.tmp" >&2
    rm -f "$EVIDENCE_DIR/.source-verify.tmp"
  fi
else
  check "Source manifest equality (missing)" "FAIL"
fi

# 3. Commit/tree metadata consistency.
if [ -f "$EVIDENCE_DIR/provenance.json" ] && [ -f "$EVIDENCE_DIR/source-commit.txt" ]; then
  PROV_COMMIT="$(jq -r '.commit' "$EVIDENCE_DIR/provenance.json" 2>/dev/null || echo "")"
  FILE_COMMIT="$(cat "$EVIDENCE_DIR/source-commit.txt" 2>/dev/null || echo "")"
  if [ -n "$PROV_COMMIT" ] && [ "$PROV_COMMIT" = "$FILE_COMMIT" ]; then
    check "Commit/tree consistency" "PASS"
  else
    check "Commit/tree consistency" "FAIL"
  fi
else
  check "Commit/tree consistency (missing)" "FAIL"
fi

# 4. qualification.json — independently recompute gate summary.
if [ -f "$EVIDENCE_DIR/qualification.json" ]; then
  # 4a. Validate against schema — no fallback. A missing validator is a
  # qualification failure, not a warning.
  SCHEMA_FILE="$EVIDENCE_DIR/schemas/qualification.schema.json"
  if [ ! -f "$SCHEMA_FILE" ]; then
    SCHEMA_FILE="$REPO_ROOT/schemas/qualification.schema.json"
  fi
  if [ ! -f "$SCHEMA_FILE" ]; then
    check "Qualification schema (missing)" "FAIL"
    echo "  ERROR: qualification.schema.json not found" >&2
    exit 1
  fi
  # Resolve the JSON Schema validator from the PINNED repository
  # dependency first: the archive ships nemo/package-lock.json, so
  # `npm ci --prefix nemo` (or an equivalent install) provides an
  # exactly-pinned validator. A mutable global `ajv` is only a
  # fallback, and no validator at all is a qualification failure.
  AJV_BIN=""
  for candidate in \
    "$REPO_ROOT/nemo/node_modules/.bin/ajv" \
    "$(dirname "$EVIDENCE_DIR")/nemo/node_modules/.bin/ajv"; do
    if [ -x "$candidate" ]; then
      AJV_BIN="$candidate"
      break
    fi
  done
  if [ -z "$AJV_BIN" ] && command -v ajv >/dev/null 2>&1; then
    AJV_BIN="$(command -v ajv)"
  fi
  if [ -z "$AJV_BIN" ]; then
    check "Qualification schema (validator missing)" "FAIL"
    echo "  ERROR: no JSON Schema validator found. Install the pinned dependency with:" >&2
    echo "         npm ci --prefix nemo" >&2
    exit 1
  fi
  if "$AJV_BIN" validate -s "$SCHEMA_FILE" -d "$EVIDENCE_DIR/qualification.json" >/dev/null 2>&1; then
    check "Qualification schema valid" "PASS"
  else
    check "Qualification schema valid" "FAIL"
    echo "  ERROR: qualification.json does not validate against schema" >&2
    "$AJV_BIN" validate -s "$SCHEMA_FILE" -d "$EVIDENCE_DIR/qualification.json" >&2 || true
    exit 1
  fi

  # 4b. Independently recompute gate summary from individual gates.
  GATE_COUNT="$(jq '.gates | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_PASS="$(jq '[.gates[] | select(.status == "PASS")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_FAIL="$(jq '[.gates[] | select(.status == "FAIL")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_SKIP="$(jq '[.gates[] | select(.status == "SKIP")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"

  # Check every mandatory gate is PASS
  FAILED_MANDATORY="$(jq -r '.gates[] | select(.mandatory == true and .status != "PASS") | .id' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"

  if [ "$GATE_COUNT" -gt 0 ] && [ -z "$FAILED_MANDATORY" ]; then
    check "All mandatory gates PASS ($GATE_COUNT)" "PASS"
  else
    echo "  Failed mandatory gates: $FAILED_MANDATORY" >&2
    check "All mandatory gates PASS" "FAIL"
  fi

  # 4c. Cross-check declared vs derived summary.
  DECLARED_TOTAL="$(jq -r '.gate_summary.total' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DECLARED_PASSED="$(jq -r '.gate_summary.passed' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DECLARED_FAILED="$(jq -r '.gate_summary.failed' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"

  if [ "$DECLARED_TOTAL" = "$GATE_COUNT" ] && \
     [ "$DECLARED_PASSED" = "$DERIVED_PASS" ] && \
     [ "$DECLARED_FAILED" = "$DERIVED_FAIL" ]; then
    check "Gate summary consistency" "PASS"
  else
    check "Gate summary consistency" "FAIL"
  fi

  # 4d. Cross-check release_status matches derived.
  RELEASE_STATUS="$(jq -r '.release_status' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ "$DERIVED_FAIL" -eq 0 ]; then
    DERIVED_STATUS="PASS"
  else
    DERIVED_STATUS="FAIL"
  fi
  if [ "$RELEASE_STATUS" = "$DERIVED_STATUS" ]; then
    check "Release status consistency" "PASS"
  else
    check "Release status consistency" "FAIL"
  fi

  # 4e. Cross-check artifact_promotable.
  PROMOTABLE="$(jq -r '.artifact_promotable' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "false")"
  if [ "$RELEASE_STATUS" = "PASS" ] && [ "$PROMOTABLE" = "true" ]; then
    check "Artifact promotable" "PASS"
  elif [ "$RELEASE_STATUS" != "PASS" ] && [ "$PROMOTABLE" = "false" ]; then
    check "Artifact promotable (correctly blocked)" "PASS"
  else
    check "Artifact promotable (mismatch)" "FAIL"
  fi

  # 4f. Cross-check: mandatory gate with exit_code != 0 must not be PASS.
  INCONSISTENT_GATES="$(jq -r '.gates[] | select(.status == "PASS" and .exit_code != 0) | .id' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ -z "$INCONSISTENT_GATES" ]; then
    check "Gate exit-code consistency" "PASS"
  else
    echo "  PASS gates with nonzero exit: $INCONSISTENT_GATES" >&2
    check "Gate exit-code consistency" "FAIL"
  fi

  # 4g. Cross-check: mandatory test gate with tests_executed == 0 must not be PASS.
  # Only applies to gates whose names contain "tests" or start with "postgres-".
  # Non-test gates (vet, typecheck, format, lint, build) legitimately have tests_executed == 0.
  ZERO_EXECUTION_GATES="$(jq -r '.gates[] | select(.mandatory == true and .status == "PASS" and ((.name | test("tests")) or (.name | startswith("postgres-")))) | select(.tests_executed == 0 or .tests_executed == null) | .id' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo "")"
  if [ -z "$ZERO_EXECUTION_GATES" ]; then
    check "Gate execution consistency" "PASS"
  else
    echo "  PASS gates with 0 executed tests: $ZERO_EXECUTION_GATES" >&2
    check "Gate execution consistency" "FAIL"
  fi

  # 4h. Verify each gate's evidence file exists.
  GATE_LOG_MISSING=false
  for log in $(jq -r '.gates[].evidence_file' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo ""); do
    if [ ! -f "$EVIDENCE_DIR/$log" ]; then
      GATE_LOG_MISSING=true
      echo "  Missing evidence file: $log" >&2
    fi
  done
  if [ "$GATE_LOG_MISSING" = false ]; then
    check "Gate evidence files present" "PASS"
  else
    check "Gate evidence files present" "FAIL"
  fi
else
  check "Qualification JSON (missing)" "FAIL"
fi

# 5. evidence-manifest.json — verify evidence bundle digest.
# The digest claim (digest_of: "SHA256SUMS") is independently verified:
# recompute SHA256(SHA256SUMS) and compare with the stored sha256.
if [ -f "$EVIDENCE_DIR/evidence-manifest.json" ]; then
  EVIDENCE_SHA="$(jq -r '.sha256' "$EVIDENCE_DIR/evidence-manifest.json" 2>/dev/null || echo "")"
  if [ -n "$EVIDENCE_SHA" ] && [[ "$EVIDENCE_SHA" =~ ^[0-9a-f]{64}$ ]]; then
    check "Evidence manifest digest format" "PASS"
    # Independently verify the digest claim: SHA256(SHA256SUMS) must match.
    if [ -f "$EVIDENCE_DIR/SHA256SUMS" ]; then
      ACTUAL_SHA="$(shasum -a 256 "$EVIDENCE_DIR/SHA256SUMS" | awk '{print $1}')"
      if [ "$EVIDENCE_SHA" = "$ACTUAL_SHA" ]; then
        check "Evidence manifest digest verified" "PASS"
      else
        check "Evidence manifest digest verified" "FAIL"
        echo "  ERROR: evidence-manifest.json claims sha256=$EVIDENCE_SHA but actual SHA256(SHA256SUMS)=$ACTUAL_SHA" >&2
      fi
      # The declared file count must equal the checksum manifest length —
      # a count that disagrees with the manifest is a stale or edited claim.
      MANIFEST_FILE_COUNT="$(jq -r '.file_count // empty' "$EVIDENCE_DIR/evidence-manifest.json" 2>/dev/null || true)"
      ACTUAL_FILE_COUNT="$(wc -l < "$EVIDENCE_DIR/SHA256SUMS" | tr -d ' ')"
      if [ -n "$MANIFEST_FILE_COUNT" ] && [ "$MANIFEST_FILE_COUNT" = "$ACTUAL_FILE_COUNT" ]; then
        check "Evidence manifest file count" "PASS"
      else
        check "Evidence manifest file count" "FAIL"
        echo "  ERROR: evidence-manifest.json file_count=$MANIFEST_FILE_COUNT but SHA256SUMS has $ACTUAL_FILE_COUNT entries" >&2
      fi
    fi
  else
    check "Evidence manifest digest format" "FAIL"
  fi
else
  check "Evidence manifest (missing)" "FAIL"
fi

# 5b. Release manifest — verify release metadata is present and consistent.
if [ -f "$EVIDENCE_DIR/release-manifest.json" ]; then
  RM_STATUS="$(jq -r '.status' "$EVIDENCE_DIR/release-manifest.json" 2>/dev/null || echo "")"
  RM_COMMIT="$(jq -r '.provenance.commit' "$EVIDENCE_DIR/release-manifest.json" 2>/dev/null || echo "")"
  if [ "$RM_STATUS" = "PASS" ] && [ -n "$RM_COMMIT" ] && [[ "$RM_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    check "Release manifest" "PASS"
  else
    check "Release manifest" "FAIL"
  fi
else
  check "Release manifest (missing)" "FAIL"
fi

# 5c. SBOM — verify Software Bill of Materials is present and valid JSON.
if [ -f "$EVIDENCE_DIR/sbom.spdx.json" ]; then
  SBOM_VER="$(jq -r '.spdxVersion' "$EVIDENCE_DIR/sbom.spdx.json" 2>/dev/null || echo "")"
  SBOM_PKG_COUNT="$(jq '.packages | length' "$EVIDENCE_DIR/sbom.spdx.json" 2>/dev/null || echo 0)"
  if [ "$SBOM_VER" = "SPDX-2.3" ] && [ "$SBOM_PKG_COUNT" -ge 1 ]; then
    check "SBOM (SPDX-2.3, $SBOM_PKG_COUNT packages)" "PASS"
  else
    check "SBOM (invalid)" "FAIL"
  fi
else
  check "SBOM (missing)" "FAIL"
fi

# 5d. Attestation — verify the attestation reference binds the FINAL
# evidence manifest. The reference alone (a URL) is not closure: an
# attestation of a superseded manifest would still carry a URL, so the
# recorded subject and the manifest digest it attested must match the
# bundle being verified.
if [ -f "$EVIDENCE_DIR/attestation/attestation.json" ]; then
  ATT_URL="$(jq -r '.attestation_url // empty' "$EVIDENCE_DIR/attestation/attestation.json" 2>/dev/null)"
  if [ -n "$ATT_URL" ]; then
    check "GitHub attestation" "PASS"
  else
    check "GitHub attestation (no URL)" "FAIL"
  fi

  if [ -f "$EVIDENCE_DIR/evidence-manifest.json" ]; then
    ATT_SUBJECT="$(jq -r '.subject // empty' "$EVIDENCE_DIR/attestation/attestation.json" 2>/dev/null || true)"
    ATT_EVIDENCE_SHA="$(jq -r '.evidence_sha256 // empty' "$EVIDENCE_DIR/attestation/attestation.json" 2>/dev/null || true)"
    FINAL_MANIFEST_SHA="$(jq -r '.sha256 // empty' "$EVIDENCE_DIR/evidence-manifest.json" 2>/dev/null || true)"
    SUBJECT_MATCHES=false
    case "$ATT_SUBJECT" in
      *evidence-manifest.json) SUBJECT_MATCHES=true ;;
    esac
    if [ "$SUBJECT_MATCHES" = true ] && [ -n "$ATT_EVIDENCE_SHA" ] && [ "$ATT_EVIDENCE_SHA" = "$FINAL_MANIFEST_SHA" ]; then
      check "Attestation binds the final evidence manifest" "PASS"
    else
      check "Attestation binds the final evidence manifest" "FAIL"
      echo "  ERROR: attestation subject=$ATT_SUBJECT evidence_sha256=$ATT_EVIDENCE_SHA does not bind evidence-manifest.json ($FINAL_MANIFEST_SHA)" >&2
    fi
  fi
else
  check "GitHub attestation (missing)" "FAIL"
fi

# 6. Release invariants documented.
if [ -f "$EVIDENCE_DIR/qualification.json" ]; then
  INV_COUNT="$(jq '.invariants | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  if [ "$INV_COUNT" -ge 12 ]; then
    check "Release invariants ($INV_COUNT)" "PASS"
  else
    check "Release invariants ($INV_COUNT)" "FAIL"
  fi
else
  check "Release invariants (missing)" "FAIL"
fi

echo ""
echo "  $PASS_COUNT passed, $FAIL_COUNT failed"
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "ARTIFACT VERIFIED"
  exit 0
else
  echo "ARTIFACT VERIFICATION FAILED" >&2
  exit 1
fi
