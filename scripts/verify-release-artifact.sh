#!/usr/bin/env bash
# Verify a release artifact's evidence bundle.
#
# Works standalone on an extracted archive — does NOT require .git.
#
# Usage:
#   ./scripts/verify-release-artifact.sh --mode qualification [options]
#   ./scripts/verify-release-artifact.sh --mode release --archive PATH --zip PATH [options]
#
# Options:
#   --mode qualification|release  Explicit verification contract (see below).
#   --evidence DIR                Evidence bundle (default: dist/release-evidence/)
#   --source DIR                  Source tree to verify (default: repo root)
#   --archive PATH                Release tar.gz; its SHA-256 is recomputed
#                                 from the bytes and required to equal
#                                 artifact.json's artifact.sha256 binding
#   --zip PATH                    Release zip; its SHA-256 is recomputed
#                                 from the bytes and required to equal
#                                 artifact.json's artifact.zip_sha256
#                                 binding (required in release mode)
#   --sbom PATH                   SBOM file; its digest must equal the
#                                 binding in artifact.json (required in
#                                 release mode)
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

# Gate semantics live in exactly one validator, shared with release
# admission. The archive ships it next to this script.
# shellcheck source=lib/qualification-gates.sh
source "$SCRIPT_DIR/lib/qualification-gates.sh"

MODE=""
EVIDENCE_DIR=""
SOURCE_DIR=""
ARCHIVE_PATH=""
ZIP_PATH=""
SBOM_PATH=""
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
    --zip) ZIP_PATH="${2:-}"; shift 2 ;;
    --zip=*) ZIP_PATH="${1#*=}"; shift ;;
    --sbom) SBOM_PATH="${2:-}"; shift 2 ;;
    --sbom=*) SBOM_PATH="${1#*=}"; shift ;;
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
  require_file "$ARCHIVE_PATH" "the release tar.gz (--archive)"
  require_file "$ZIP_PATH" "the release zip (--zip)"
  require_file "$SBOM_PATH" "the SBOM (--sbom)"
fi

if [ "$CONTRACT_FAILURES" -gt 0 ]; then
  echo ""
  echo "MODE CONTRACT VIOLATED: $CONTRACT_FAILURES missing requirement(s)" >&2
  exit 1
fi

# 0. artifact.json binding — the release archive must be the archive the
# qualified evidence describes, and the record must bind the exact
# evidence objects it was qualified against. Nothing here trusts a stored
# digest string: digests are recomputed from the bytes they claim to
# cover. Schema version 2 is the final release object; an unknown version
# fails closed rather than being interpreted with the wrong semantics.
ARTIFACT_JSON="$EVIDENCE_DIR/artifact.json"
if [ -f "$ARTIFACT_JSON" ]; then
  ARTIFACT_SCHEMA="$(jq -r '.schema_version // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  if [ "$ARTIFACT_SCHEMA" = "2" ]; then
    check "artifact.json schema version" "PASS"
  else
    check "artifact.json schema version" "FAIL"
    echo "  ERROR: artifact.json schema_version=${ARTIFACT_SCHEMA:-missing} (want 2) — refusing to interpret an unknown release object" >&2
    exit 1
  fi

  ARTIFACT_SHA="$(jq -r '.artifact.sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_NAME="$(jq -r '.artifact.filename // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_SIZE="$(jq -r '.artifact.size // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_ZIP_SHA="$(jq -r '.artifact.zip_sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_ZIP_NAME="$(jq -r '.artifact.zip_filename // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_ZIP_SIZE="$(jq -r '.artifact.zip_size // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_COMMIT="$(jq -r '.source.commit // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_TREE="$(jq -r '.source.tree // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_MANIFEST_SHA="$(jq -r '.source.manifest_sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_RELEASE="$(jq -r '.release // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_REGISTRY="$(jq -r '.policy.registry_sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_QUAL_SHA="$(jq -r '.qualification.sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_QUAL_SCHEMA="$(jq -r '.qualification.schema_version // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_SBOM_SHA="$(jq -r '.sbom.sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  ARTIFACT_PROV_SHA="$(jq -r '.provenance.sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"

  if [ -n "$ARTIFACT_SHA" ] && [ -n "$ARTIFACT_NAME" ] && [ -n "$ARTIFACT_SIZE" ] && \
     [ -n "$ARTIFACT_ZIP_SHA" ] && [ -n "$ARTIFACT_ZIP_NAME" ] && [ -n "$ARTIFACT_ZIP_SIZE" ] && \
     [ -n "$ARTIFACT_COMMIT" ] && [ -n "$ARTIFACT_TREE" ] && [ -n "$ARTIFACT_MANIFEST_SHA" ] && \
     [ -n "$ARTIFACT_RELEASE" ] && [ -n "$ARTIFACT_REGISTRY" ] && [ -n "$ARTIFACT_QUAL_SHA" ] && \
     [ -n "$ARTIFACT_SBOM_SHA" ] && [ -n "$ARTIFACT_PROV_SHA" ]; then
    check "artifact.json complete (v2)" "PASS"
  else
    check "artifact.json complete (v2)" "FAIL"
    echo "  ERROR: artifact.json v2 is missing one of: artifact.{filename,sha256,size,zip_filename,zip_sha256,zip_size}, source.{commit,tree,manifest_sha256}, release, policy.registry_sha256, qualification.sha256, sbom.sha256, provenance.sha256" >&2
  fi

  # The capability policy the release was qualified against must be bound.
  if [ -n "$ARTIFACT_REGISTRY" ]; then
    check "artifact.json binds the capability registry" "PASS"
  else
    check "artifact.json binds the capability registry" "FAIL"
    echo "  ERROR: artifact.json has no policy.registry_sha256 binding" >&2
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

  # The evidence objects the record binds must be the objects present,
  # recomputed from their bytes.
  if [ -f "$EVIDENCE_DIR/source-tree-sha256.txt" ]; then
    ACTUAL_MANIFEST_SHA="$(shasum -a 256 "$EVIDENCE_DIR/source-tree-sha256.txt" | awk '{print $1}')"
    if [ -n "$ARTIFACT_MANIFEST_SHA" ] && [ "$ACTUAL_MANIFEST_SHA" = "$ARTIFACT_MANIFEST_SHA" ]; then
      check "artifact.json binds the source manifest" "PASS"
    else
      check "artifact.json binds the source manifest" "FAIL"
      echo "  ERROR: source manifest digest $ACTUAL_MANIFEST_SHA does not match artifact.json $ARTIFACT_MANIFEST_SHA" >&2
    fi
  fi
  if [ -f "$EVIDENCE_DIR/provenance.json" ]; then
    ACTUAL_PROV_SHA="$(shasum -a 256 "$EVIDENCE_DIR/provenance.json" | awk '{print $1}')"
    if [ -n "$ARTIFACT_PROV_SHA" ] && [ "$ACTUAL_PROV_SHA" = "$ARTIFACT_PROV_SHA" ]; then
      check "artifact.json binds provenance" "PASS"
    else
      check "artifact.json binds provenance" "FAIL"
      echo "  ERROR: provenance digest $ACTUAL_PROV_SHA does not match artifact.json $ARTIFACT_PROV_SHA" >&2
    fi
  fi
  if [ -f "$EVIDENCE_DIR/qualification.json" ]; then
    ACTUAL_QUAL_SHA="$(shasum -a 256 "$EVIDENCE_DIR/qualification.json" | awk '{print $1}')"
    ACTUAL_QUAL_SCHEMA="$(jq -r '.schema_version // empty' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || true)"
    if [ -n "$ARTIFACT_QUAL_SHA" ] && [ "$ACTUAL_QUAL_SHA" = "$ARTIFACT_QUAL_SHA" ] && [ "$ACTUAL_QUAL_SCHEMA" = "$ARTIFACT_QUAL_SCHEMA" ]; then
      check "artifact.json binds the qualification record" "PASS"
    else
      check "artifact.json binds the qualification record" "FAIL"
      echo "  ERROR: qualification digest/schema $ACTUAL_QUAL_SHA/$ACTUAL_QUAL_SCHEMA does not match artifact.json $ARTIFACT_QUAL_SHA/$ARTIFACT_QUAL_SCHEMA" >&2
    fi
  fi
  if [ -n "$SBOM_PATH" ]; then
    if [ ! -f "$SBOM_PATH" ]; then
      check "SBOM present (--sbom)" "FAIL"
      echo "  ERROR: SBOM not found: $SBOM_PATH" >&2
    else
      ACTUAL_SBOM_SHA="$(shasum -a 256 "$SBOM_PATH" | awk '{print $1}')"
      if [ -n "$ARTIFACT_SBOM_SHA" ] && [ "$ACTUAL_SBOM_SHA" = "$ARTIFACT_SBOM_SHA" ]; then
        check "artifact.json binds the SBOM" "PASS"
      else
        check "artifact.json binds the SBOM" "FAIL"
        echo "  ERROR: SBOM digest $ACTUAL_SBOM_SHA does not match artifact.json $ARTIFACT_SBOM_SHA" >&2
      fi
    fi
  fi

  # The declared toolchain must equal the toolchain the qualification
  # actually ran on — checked here, independently of the gate's
  # self-report, and against the source tree's own go.mod directive.
  ARTIFACT_GO="$(jq -r '.toolchain.go // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  if [[ "$ARTIFACT_GO" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    check "artifact.json toolchain declaration" "PASS"
  else
    check "artifact.json toolchain declaration" "FAIL"
    echo "  ERROR: artifact.json toolchain.go is missing or malformed: '${ARTIFACT_GO:-<empty>}'" >&2
  fi
  if [ -f "$EVIDENCE_DIR/qualification.json" ]; then
    QUAL_GO_RAW="$(jq -r '.toolchains.go // empty' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || true)"
    QUAL_GO=""
    if [[ "$QUAL_GO_RAW" =~ (go[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      QUAL_GO="${BASH_REMATCH[1]}"
    fi
    if [ -n "$ARTIFACT_GO" ] && [ -n "$QUAL_GO" ] && [ "$ARTIFACT_GO" = "$QUAL_GO" ]; then
      check "Declared toolchain = qualified toolchain" "PASS"
    else
      check "Declared toolchain = qualified toolchain" "FAIL"
      echo "  ERROR: artifact.json declares toolchain '${ARTIFACT_GO:-<missing>}' but qualification ran on '${QUAL_GO:-<missing>}'" >&2
    fi
  fi
  # The source's own declaration (the go.mod toolchain directive) must
  # agree with the toolchain the artifact claims it was built under.
  if [ -f "$SOURCE_DIR/go.mod" ]; then
    GO_MOD_TOOLCHAIN="$(sed -n 's/^toolchain \(go[0-9][0-9.]*\).*/\1/p' "$SOURCE_DIR/go.mod")"
    GO_MOD_TOOLCHAIN="${GO_MOD_TOOLCHAIN%%$'\n'*}"
    if [ -n "$ARTIFACT_GO" ] && [ -n "$GO_MOD_TOOLCHAIN" ] && [ "$ARTIFACT_GO" = "$GO_MOD_TOOLCHAIN" ]; then
      check "Declared toolchain = go.mod toolchain" "PASS"
    else
      check "Declared toolchain = go.mod toolchain" "FAIL"
      echo "  ERROR: artifact.json declares '${ARTIFACT_GO:-<missing>}' but go.mod declares '${GO_MOD_TOOLCHAIN:-<none>}'" >&2
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
      ACTUAL_ARCHIVE_SIZE="$(wc -c < "$ARCHIVE_PATH" | tr -d ' ')"
      if [ -n "$ARTIFACT_SIZE" ] && [ "$ACTUAL_ARCHIVE_SIZE" = "$ARTIFACT_SIZE" ]; then
        check "Archive size matches artifact.json" "PASS"
      else
        check "Archive size matches artifact.json" "FAIL"
        echo "  ERROR: archive size $ACTUAL_ARCHIVE_SIZE does not equal artifact.json $ARTIFACT_SIZE" >&2
      fi
      if [ "$(basename "$ARCHIVE_PATH")" = "$ARTIFACT_NAME" ]; then
        check "Archive filename matches artifact.json" "PASS"
      else
        check "Archive filename matches artifact.json" "FAIL"
        echo "  ERROR: archive name does not match artifact.json filename $ARTIFACT_NAME" >&2
      fi
    fi
  fi

  # The zip is an official artifact with its own identity: recompute its
  # digest from its bytes and require it to equal artifact.json's
  # zip_sha256. A zip that is never recomputed is an unverified artifact
  # that merely shares a release with the tarball.
  if [ -n "$ZIP_PATH" ]; then
    if [ ! -f "$ZIP_PATH" ]; then
      check "Release zip present" "FAIL"
      echo "  ERROR: zip not found: $ZIP_PATH" >&2
    else
      ACTUAL_ZIP_SHA="$(shasum -a 256 "$ZIP_PATH" | cut -d ' ' -f1)"
      if [ -n "$ARTIFACT_ZIP_SHA" ] && [ "$ACTUAL_ZIP_SHA" = "$ARTIFACT_ZIP_SHA" ]; then
        check "Zip matches artifact.json (recomputed)" "PASS"
      else
        check "Zip matches artifact.json (recomputed)" "FAIL"
        echo "  ERROR: zip SHA-256 $ACTUAL_ZIP_SHA does not equal artifact.json zip_sha256 $ARTIFACT_ZIP_SHA" >&2
      fi
      ACTUAL_ZIP_SIZE="$(wc -c < "$ZIP_PATH" | tr -d ' ')"
      if [ -n "$ARTIFACT_ZIP_SIZE" ] && [ "$ACTUAL_ZIP_SIZE" = "$ARTIFACT_ZIP_SIZE" ]; then
        check "Zip size matches artifact.json" "PASS"
      else
        check "Zip size matches artifact.json" "FAIL"
        echo "  ERROR: zip size $ACTUAL_ZIP_SIZE does not equal artifact.json zip_size $ARTIFACT_ZIP_SIZE" >&2
      fi
      if [ "$(basename "$ZIP_PATH")" = "$ARTIFACT_ZIP_NAME" ]; then
        check "Zip filename matches artifact.json" "PASS"
      else
        check "Zip filename matches artifact.json" "FAIL"
        echo "  ERROR: zip name does not match artifact.json zip_filename $ARTIFACT_ZIP_NAME" >&2
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
  ARTIFACT_REGISTRY="$(jq -r '.policy.registry_sha256 // empty' "$ARTIFACT_JSON" 2>/dev/null || true)"
  if [ -n "$ARTIFACT_REGISTRY" ] && [ "$ARTIFACT_REGISTRY" = "$REGISTRY_SHA" ]; then
    check "artifact.json binds the qualified registry" "PASS"
  else
    check "artifact.json binds the qualified registry" "FAIL"
    echo "  ERROR: artifact.json registry_sha256=$ARTIFACT_REGISTRY does not match the qualified registry $REGISTRY_SHA" >&2
  fi
fi

# 1d. Qualification registry extension — the qualification registry must
# be the release registry plus explicit extensions, with every release
# descriptor byte-identical and only the declared descriptors added. The
# record binds both identities, so a harness can never silently replace
# or modify production policy while exercising test-only capabilities.
QUAL_REGISTRY_SHA_FILE="$EVIDENCE_DIR/qualification-registry.sha256"
QUAL_REGISTRY_ENVELOPE="$EVIDENCE_DIR/qualification-registry.json"
EXTENSIONS_FILE="$EVIDENCE_DIR/qualification-registry-extensions.json"
if [ -f "$QUAL_REGISTRY_SHA_FILE" ] && [ -f "$QUAL_REGISTRY_ENVELOPE" ] && [ -f "$EXTENSIONS_FILE" ]; then
  QUAL_REGISTRY_SHA="$(tr -d '[:space:]' < "$QUAL_REGISTRY_SHA_FILE")"
  QUAL_ENVELOPE_SHA="$(jq -r '.registry_sha256 // empty' "$QUAL_REGISTRY_ENVELOPE" 2>/dev/null || true)"
  QUAL_PAYLOAD="$(jq -r '.canonical_payload // empty' "$QUAL_REGISTRY_ENVELOPE" 2>/dev/null || true)"
  RECOMPUTED_QUAL=""
  if [ -n "$QUAL_PAYLOAD" ]; then
    RECOMPUTED_QUAL="$(printf '%s' "$QUAL_PAYLOAD" | base64 --decode 2>/dev/null | shasum -a 256 | awk '{print $1}')"
  fi
  if [ -n "$RECOMPUTED_QUAL" ] && [ "$RECOMPUTED_QUAL" = "$QUAL_ENVELOPE_SHA" ] && [ "$QUAL_ENVELOPE_SHA" = "$QUAL_REGISTRY_SHA" ]; then
    check "Qualification registry digest recomputed" "PASS"
  else
    check "Qualification registry digest recomputed" "FAIL"
    echo "  ERROR: qualification registry envelope digest=$QUAL_ENVELOPE_SHA recomputed=$RECOMPUTED_QUAL does not match qualification-registry.sha256=$QUAL_REGISTRY_SHA" >&2
  fi

  EXTENSION_BASE="$(jq -r '.base_registry_sha256 // empty' "$EXTENSIONS_FILE" 2>/dev/null || true)"
  if [ -n "$EXTENSION_BASE" ] && [ "$EXTENSION_BASE" = "$REGISTRY_SHA" ]; then
    check "Extension record binds the release registry" "PASS"
  else
    check "Extension record binds the release registry" "FAIL"
    echo "  ERROR: extension record base_registry_sha256=$EXTENSION_BASE does not match the release registry $REGISTRY_SHA" >&2
  fi

  EXTENSION_QUAL="$(jq -r '.qualification_registry_sha256 // empty' "$EXTENSIONS_FILE" 2>/dev/null || true)"
  if [ -n "$EXTENSION_QUAL" ] && [ "$EXTENSION_QUAL" = "$QUAL_REGISTRY_SHA" ]; then
    check "Extension record binds the qualification registry" "PASS"
  else
    check "Extension record binds the qualification registry" "FAIL"
    echo "  ERROR: extension record qualification_registry_sha256=$EXTENSION_QUAL does not match the qualification registry $QUAL_REGISTRY_SHA" >&2
  fi

  if [ -n "$QUAL_PAYLOAD" ] && [ -n "$ENVELOPE_PAYLOAD" ]; then
    EXTENSION_IDS="$(jq -c '[.qualification_extensions[]?.capability_id]' "$EXTENSIONS_FILE" 2>/dev/null || echo '[]')"
    RELEASE_DESCRIPTORS="$(printf '%s' "$ENVELOPE_PAYLOAD" | base64 --decode 2>/dev/null | jq -cS 'sort_by(.id)' 2>/dev/null || true)"
    QUALIFIED_DESCRIPTORS="$(printf '%s' "$QUAL_PAYLOAD" | base64 --decode 2>/dev/null | jq -cS --argjson ids "$EXTENSION_IDS" '[.[] | select((.id as $id | $ids | index($id)) | not)] | sort_by(.id)' 2>/dev/null || true)"
    if [ -n "$RELEASE_DESCRIPTORS" ] && [ "$QUALIFIED_DESCRIPTORS" = "$RELEASE_DESCRIPTORS" ]; then
      check "Extensions add without replacing release policy" "PASS"
    else
      check "Extensions add without replacing release policy" "FAIL"
      echo "  ERROR: the qualification registry is not the release registry plus the declared extensions" >&2
    fi
  fi

  # 1e. Extension descriptor digests — recomputed from the qualification
  # registry's canonical bytes, never trusted from the record. Go marshals
  # each descriptor independently, so a descriptor's canonical bytes are a
  # contiguous span of the payload; hashing that span reproduces the
  # descriptor digest without a second canonicalizer entering the trust
  # boundary. Each declared extension must name a capability that occurs
  # exactly once in the qualification registry, is absent from the release
  # registry, and whose recomputed digest equals the recorded
  # descriptor_sha256 — so a harness can only ADD declared test
  # capabilities, never replace or mislabel production policy.
  if [ -n "$QUAL_PAYLOAD" ] && [ -n "$ENVELOPE_PAYLOAD" ] && [ -n "$EXTENSIONS_FILE" ]; then
    SPAN_HELPER="$SCRIPT_DIR/lib/registry-spans.mjs"
    EXT_COUNT="$(jq '.qualification_extensions | length' "$EXTENSIONS_FILE" 2>/dev/null || echo 0)"
    if [ ! -f "$SPAN_HELPER" ]; then
      check "Extension descriptor digests recomputed" "FAIL"
      echo "  ERROR: registry span helper not found: $SPAN_HELPER" >&2
    elif ! command -v node >/dev/null 2>&1; then
      check "Extension descriptor digests recomputed" "FAIL"
      echo "  ERROR: node is required to recompute extension descriptor bytes" >&2
    else
      QUAL_PAYLOAD_FILE="$EVIDENCE_DIR/.qual-payload.json"
      RELEASE_PAYLOAD_FILE="$EVIDENCE_DIR/.release-payload.json"
      printf '%s' "$QUAL_PAYLOAD" | base64 --decode > "$QUAL_PAYLOAD_FILE" 2>/dev/null || true
      printf '%s' "$ENVELOPE_PAYLOAD" | base64 --decode > "$RELEASE_PAYLOAD_FILE" 2>/dev/null || true
      if QUAL_SPANS="$(node "$SPAN_HELPER" "$QUAL_PAYLOAD_FILE" 2>/dev/null)" && \
         RELEASE_SPANS="$(node "$SPAN_HELPER" "$RELEASE_PAYLOAD_FILE" 2>/dev/null)"; then
        EXT_IDS="$(jq -c '[.qualification_extensions[]?.capability_id]' "$EXTENSIONS_FILE" 2>/dev/null || echo '[]')"
        UNIQUE_IDS="$(printf '%s' "$EXT_IDS" | jq 'unique | length' 2>/dev/null || echo 0)"
        TOTAL_IDS="$(printf '%s' "$EXT_IDS" | jq 'length' 2>/dev/null || echo 0)"
        UNIQUE_RECORDS="$(jq -c '[.qualification_extensions[]?] | unique | length' "$EXTENSIONS_FILE" 2>/dev/null || echo 0)"
        if [ "$UNIQUE_IDS" = "$TOTAL_IDS" ] && [ "$UNIQUE_RECORDS" = "$TOTAL_IDS" ]; then
          check "Extension records unique" "PASS"
        else
          check "Extension records unique" "FAIL"
          echo "  ERROR: the qualification extension record repeats a capability id or a descriptor record" >&2
        fi

        EXT_DIGEST_OK=true
        EXT_SCOPE_OK=true
        EXT_INDEX=0
        while [ "$EXT_INDEX" -lt "$EXT_COUNT" ]; do
          EXT_ID="$(jq -r ".qualification_extensions[$EXT_INDEX].capability_id // empty" "$EXTENSIONS_FILE" 2>/dev/null || true)"
          EXT_DECLARED="$(jq -r ".qualification_extensions[$EXT_INDEX].descriptor_sha256 // empty" "$EXTENSIONS_FILE" 2>/dev/null || true)"
          if [ -z "$EXT_ID" ] || ! printf '%s' "$EXT_DECLARED" | grep -qE '^[0-9a-f]{64}$'; then
            EXT_DIGEST_OK=false
            echo "  ERROR: qualification_extensions[$EXT_INDEX] lacks a capability_id or a well-formed descriptor_sha256" >&2
            EXT_INDEX=$((EXT_INDEX + 1))
            continue
          fi
          if printf '%s\n' "$RELEASE_SPANS" | awk -F'\t' -v id="$EXT_ID" '$2 == id { found = 1 } END { exit found ? 0 : 1 }'; then
            EXT_SCOPE_OK=false
            echo "  ERROR: extension $EXT_ID is a release capability — qualification may not redeclare production policy" >&2
          fi
          EXT_MATCHES="$(printf '%s\n' "$QUAL_SPANS" | awk -F'\t' -v id="$EXT_ID" '$2 == id { print $1 }')"
          EXT_OCCURRENCES="$(printf '%s\n' "$EXT_MATCHES" | grep -c . || true)"
          if [ "$EXT_OCCURRENCES" -ne 1 ]; then
            EXT_DIGEST_OK=false
            echo "  ERROR: extension $EXT_ID occurs $EXT_OCCURRENCES times in the qualification registry (want exactly 1)" >&2
            EXT_INDEX=$((EXT_INDEX + 1))
            continue
          fi
          if [ "$EXT_MATCHES" != "$EXT_DECLARED" ]; then
            EXT_DIGEST_OK=false
            echo "  ERROR: extension $EXT_ID descriptor_sha256=$EXT_DECLARED but its canonical bytes hash to $EXT_MATCHES" >&2
          fi
          EXT_INDEX=$((EXT_INDEX + 1))
        done
        if [ "$EXT_DIGEST_OK" = true ]; then
          check "Extension descriptor digests recomputed" "PASS"
        else
          check "Extension descriptor digests recomputed" "FAIL"
        fi
        if [ "$EXT_SCOPE_OK" = true ]; then
          check "Extensions are qualification-only" "PASS"
        else
          check "Extensions are qualification-only" "FAIL"
        fi
      else
        check "Extension descriptor digests recomputed" "FAIL"
        echo "  ERROR: the registry envelopes are not canonical descriptor arrays" >&2
      fi
      rm -f "$QUAL_PAYLOAD_FILE" "$RELEASE_PAYLOAD_FILE"
    fi
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

  # 4b. Gate semantics — the shared validator, the same rules release
  # admission consumes. No gate semantics are re-derived here from gate
  # IDs or names.
  GATE_COUNT="$(jq '.gates | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_PASS="$(jq '[.gates[] | select(.status == "PASS")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"
  DERIVED_FAIL="$(jq '[.gates[] | select(.status == "FAIL")] | length' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || echo 0)"

  SEMANTIC_FINDINGS=""
  if ! SEMANTIC_FINDINGS="$(validate_qualification_gates "$EVIDENCE_DIR/qualification.json")"; then
    check "Gate semantics ($GATE_COUNT gates)" "FAIL"
    echo "$SEMANTIC_FINDINGS" | sed 's/^/    /' >&2
  else
    check "Gate semantics ($GATE_COUNT gates)" "PASS"
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
  if [ "$DERIVED_FAIL" -eq 0 ] && [ -z "$SEMANTIC_FINDINGS" ]; then
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

  # 4f. Every gate's evidence file must exist and match the digest the
  # record binds. A gate claiming PASS without intact proof is not
  # admissible evidence.
  GATE_EVIDENCE_FAILED=false
  while IFS=$'\t' read -r gate_id evidence_file evidence_sha; do
    [ -z "$gate_id" ] && continue
    if [ -z "$evidence_file" ] || [ ! -f "$EVIDENCE_DIR/$evidence_file" ]; then
      GATE_EVIDENCE_FAILED=true
      echo "  Missing evidence file for gate $gate_id: ${evidence_file:-<none>}" >&2
      continue
    fi
    actual_sha="$(shasum -a 256 "$EVIDENCE_DIR/$evidence_file" | awk '{print $1}')"
    if [ "$actual_sha" != "$evidence_sha" ]; then
      GATE_EVIDENCE_FAILED=true
      echo "  Gate $gate_id evidence digest $actual_sha does not match the recorded $evidence_sha" >&2
    fi
  done < <(jq -r '.gates[]? | [(.gate_id // ""), (.evidence.file // ""), (.evidence.sha256 // "")] | @tsv' "$EVIDENCE_DIR/qualification.json" 2>/dev/null || true)
  if [ "$GATE_EVIDENCE_FAILED" = false ]; then
    check "Gate evidence bound (file + digest)" "PASS"
  else
    check "Gate evidence bound (file + digest)" "FAIL"
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
  # An attestation is an EXTERNAL statement about the frozen evidence
  # object, not a member of it. Writing a reference back into the
  # finalized closure would make the manifest cover an attestation of that
  # same manifest — a recursive object that can never be packaged. Its
  # absence is therefore informational here: external attestations are
  # verified with `gh attestation verify`, not from inside the bundle.
  echo "  note: no embedded attestation reference (external attestations are verified with 'gh attestation verify')"
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
