#!/usr/bin/env bash
set -euo pipefail

# Publishes the nemo-control_* artifact family as its own governed release.
#
# The family is produced and qualified by .github/workflows/nemo-distribution.yml
# under the dedicated signed tag nemo-vX.Y.Z: four per-target tarballs, each
# carrying a bound qualification attestation, plus a signed SHA256SUMS. This
# script is the proof-gated publication of that family — it verifies the
# protected release source (signed tag, rulesets, authorization record), the
# exact distribution run, and the signed checksum/attestation chain, creates
# the draft release on the family tag, uploads the verified bytes, and
# publishes only after the remote inventory is re-read and matches.
#
# Run it from a clean checkout whose HEAD is the protected workflow commit that
# merged release/records/<family-tag>.json:
#
#   scripts/publish-nemo-release.sh \
#     nemo-vX.Y.Z <family-tag-object> <source-commit> <verifier-commit> \
#     [<workflow-commit>] <distribution-run-id> nemo-vX.Y.Z

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

usage() {
  echo "usage: $0 <family-tag> <family-tag-object> <source-commit> <verifier-commit> [<workflow-commit>] <distribution-run-id> <confirm-tag>" >&2
  exit 2
}

[[ $# -eq 6 || $# -eq 7 ]] || usage
TAG=$1
TAG_OBJECT=$2
SOURCE_COMMIT=$3
VERIFIER_COMMIT=$4
if [[ $# -eq 7 ]]; then
  WORKFLOW_COMMIT=$5
  RUN_ID=$6
  CONFIRM_TAG=$7
else
  WORKFLOW_COMMIT=$VERIFIER_COMMIT
  RUN_ID=$5
  CONFIRM_TAG=$6
fi

[[ "$TAG" =~ ^nemo-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || usage
[[ "$TAG_OBJECT" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$VERIFIER_COMMIT" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$WORKFLOW_COMMIT" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$RUN_ID" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$CONFIRM_TAG" == "$TAG" ]] || {
  echo "publication confirmation must exactly equal $TAG" >&2
  exit 2
}

for tool in cmp gh git jq node shasum ssh-keygen unzip; do
  command -v "$tool" >/dev/null || {
    echo "missing required tool: $tool" >&2
    exit 1
  }
done

PROTECTED_TOOLING=(
  .github/release-allowed-signers
  .github/workflows/nemo-distribution.yml
  "release/records/$TAG.json"
  scripts/publish-nemo-release.sh
  scripts/release-config.sh
  scripts/verify-github-release-policy.mjs
  scripts/verify-release-source.sh
)
actual_head=$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')
[[ "$actual_head" == "$WORKFLOW_COMMIT" ]] || {
  echo "local HEAD must exactly equal protected workflow commit $WORKFLOW_COMMIT" >&2
  exit 1
}
git -C "$ROOT" merge-base --is-ancestor "$SOURCE_COMMIT" "$VERIFIER_COMMIT" || {
  echo "release source commit is not an ancestor of the provenance verifier" >&2
  exit 1
}
git -C "$ROOT" merge-base --is-ancestor "$VERIFIER_COMMIT" "$WORKFLOW_COMMIT" || {
  echo "provenance verifier commit is not an ancestor of protected workflow tooling" >&2
  exit 1
}
tooling_status=$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all -- "${PROTECTED_TOOLING[@]}")
[[ -z "$tooling_status" ]] || {
  echo "protected release tooling is dirty; publish only from the exact clean workflow commit" >&2
  printf '%s\n' "$tooling_status" >&2
  exit 1
}
git -C "$ROOT" diff --quiet "$WORKFLOW_COMMIT" -- "${PROTECTED_TOOLING[@]}" || {
  echo "protected release tooling does not match workflow commit $WORKFLOW_COMMIT" >&2
  exit 1
}
# shellcheck source=release-config.sh
# shellcheck disable=SC1091
source "$ROOT/scripts/release-config.sh"

REPOSITORY=$CRABBOX_RELEASE_REPOSITORY
DEFAULT_BRANCH=$CRABBOX_RELEASE_DEFAULT_BRANCH
NEMO_RELEASE_SIGNER=dawsonblock@users.noreply.github.com
NEMO_RELEASE_NAMESPACE=nemo-control-release
version=${TAG#nemo-v}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/nemo-publish-release.XXXXXX")
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
git -C "$ROOT" show "$WORKFLOW_COMMIT:release/records/$TAG.json" >"$WORK/protected-release-record.json" || {
  echo "protected workflow commit does not contain the release record for $TAG" >&2
  exit 1
}
git -C "$ROOT" show "$WORKFLOW_COMMIT:.github/release-allowed-signers" >"$WORK/protected-release-allowed-signers" || {
  echo "protected workflow commit does not contain the release signer policy" >&2
  exit 1
}

api_get() {
  gh api --method GET \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    "$1"
}

verify_protected_source() {
  local prefix=$1
  api_get "repos/$REPOSITORY" >"$WORK/$prefix-repository.json"
  api_get "repos/$REPOSITORY/branches/$DEFAULT_BRANCH" >"$WORK/$prefix-branch.json"
  api_get "repos/$REPOSITORY/rulesets?per_page=100" >"$WORK/$prefix-ruleset-list.json"
  mkdir -m 700 "$WORK/$prefix-rulesets"
  while IFS= read -r ruleset_id; do
    [[ "$ruleset_id" =~ ^[1-9][0-9]*$ ]] || {
      echo "release ruleset inventory contains an invalid ID" >&2
      exit 1
    }
    api_get "repos/$REPOSITORY/rulesets/$ruleset_id" \
      >"$WORK/$prefix-rulesets/$ruleset_id.json"
  done < <(jq -r '.[].id' "$WORK/$prefix-ruleset-list.json")
  ruleset_count=$(find "$WORK/$prefix-rulesets" -type f -name '*.json' | wc -l | tr -d '[:space:]')
  [[ "$ruleset_count" -gt 0 ]] || {
    echo "repository has no release protection rulesets" >&2
    exit 1
  }
  jq -s '.' "$WORK/$prefix-rulesets"/*.json >"$WORK/$prefix-rulesets.json"
  api_get "repos/$REPOSITORY/git/ref/tags/$TAG" >"$WORK/$prefix-tag-ref.json"
  api_get "repos/$REPOSITORY/git/tags/$TAG_OBJECT" >"$WORK/$prefix-tag-object.json"

  jq -e \
    --arg repository "$REPOSITORY" \
    --arg branch "$DEFAULT_BRANCH" '
      .full_name == $repository and .default_branch == $branch
    ' "$WORK/$prefix-repository.json" >/dev/null || {
    echo "repository default branch does not match the protected release contract" >&2
    exit 1
  }
  node "$ROOT/scripts/verify-github-release-policy.mjs" \
    "$WORK/$prefix-repository.json" "$WORK/$prefix-rulesets.json" \
    "$REPOSITORY" "$DEFAULT_BRANCH" "$TAG" "nemo-" >/dev/null
  jq -e \
    --arg branch "$DEFAULT_BRANCH" \
    --arg commit "$WORKFLOW_COMMIT" '
      .name == $branch and .protected == true and .commit.sha == $commit
    ' "$WORK/$prefix-branch.json" >/dev/null || {
    echo "protected default-branch head does not match the workflow commit" >&2
    exit 1
  }
  jq -e \
    --arg ref "refs/tags/$TAG" \
    --arg object "$TAG_OBJECT" \
    --arg url "https://api.github.com/repos/$REPOSITORY/git/tags/$TAG_OBJECT" '
      .ref == $ref and .object.type == "tag" and .object.sha == $object and .object.url == $url
    ' "$WORK/$prefix-tag-ref.json" >/dev/null || {
    echo "remote annotated family tag object drifted" >&2
    exit 1
  }
  jq -e \
    --arg tag "$TAG" \
    --arg commit "$SOURCE_COMMIT" \
    --arg url "https://api.github.com/repos/$REPOSITORY/git/commits/$SOURCE_COMMIT" '
      .tag == $tag and
      .object.type == "commit" and
      .object.sha == $commit and
      .object.url == $url and
      .verification.verified == true and
      .verification.reason == "valid"
    ' "$WORK/$prefix-tag-object.json" >/dev/null || {
    echo "family tag signature or peeled commit does not match the pinned source" >&2
    exit 1
  }

  DEFAULT_BRANCH=$DEFAULT_BRANCH \
  RELEASE_TAG=$TAG \
  RELEASE_TAG_PREFIX="nemo-" \
  EXPECTED_TAG_OBJECT=$TAG_OBJECT \
  EXPECTED_TAG_COMMIT=$SOURCE_COMMIT \
  TRUSTED_HEAD=$WORKFLOW_COMMIT \
  RELEASE_RECORD="$WORK/protected-release-record.json" \
  ALLOWED_SIGNERS="$WORK/protected-release-allowed-signers" \
  REQUIRE_PUBLISHABLE=1 \
    "$ROOT/scripts/verify-release-source.sh" >/dev/null
}

# The artifacts the distribution run must have produced: four qualified
# per-target tarballs plus the signed checksum manifest.
expected_artifact_names() {
  printf '%s\n' \
    "nemo-control_${version}_darwin_amd64" \
    "nemo-control_${version}_darwin_arm64" \
    "nemo-control_${version}_linux_amd64" \
    "nemo-control_${version}_linux_arm64" \
    "nemo-control_SHA256SUMS"
}

# Initial trust check, repeated after every remote byte is re-downloaded.
verify_protected_source initial

api_get "repos/$REPOSITORY/actions/runs/$RUN_ID" >"$WORK/run.json"
jq -e \
  --arg commit "$SOURCE_COMMIT" '
    .conclusion == "success" and
    .event == "push" and
    .head_sha == $commit
  ' "$WORK/run.json" >/dev/null || {
  echo "distribution run is not a successful push run at the pinned source commit" >&2
  exit 1
}
workflow_id=$(jq -er '.workflow_id | select(type == "number" and . > 0)' "$WORK/run.json")
api_get "repos/$REPOSITORY/actions/workflows/$workflow_id" >"$WORK/workflow.json"
jq -e '.path == ".github/workflows/nemo-distribution.yml"' \
  "$WORK/workflow.json" >/dev/null || {
  echo "the supplied run is not the NEMO distribution workflow" >&2
  exit 1
}

api_get "repos/$REPOSITORY/actions/runs/$RUN_ID/artifacts?per_page=100" >"$WORK/artifacts.json"
artifact_names=$(jq -r '.artifacts[].name' "$WORK/artifacts.json" | LC_ALL=C sort)
[[ "$artifact_names" == "$(expected_artifact_names | LC_ALL=C sort)" ]] || {
  echo "distribution artifact inventory is missing or ambiguous:" >&2
  printf '%s\n' "$artifact_names" >&2
  exit 1
}

mkdir -m 700 "$WORK/family"
while IFS= read -r artifact_name; do
  artifact_id=$(jq -er --arg name "$artifact_name" '
    [.artifacts[] | select(.name == $name)] |
    if length == 1 then .[0].id else error("ambiguous artifact") end
  ' "$WORK/artifacts.json")
  expected_zip_size=$(jq -er --arg name "$artifact_name" '
    [.artifacts[] | select(.name == $name)] |
    if length == 1 then .[0].size_in_bytes else error("ambiguous artifact") end
  ' "$WORK/artifacts.json")
  expected_zip_digest=$(jq -er --arg name "$artifact_name" '
    [.artifacts[] | select(.name == $name)] |
    if length == 1 then .[0].digest else error("ambiguous artifact") end
  ' "$WORK/artifacts.json")
  api_get "repos/$REPOSITORY/actions/artifacts/$artifact_id/zip" >"$WORK/$artifact_name.zip"
  actual_zip_size=$(wc -c <"$WORK/$artifact_name.zip" | tr -d '[:space:]')
  actual_zip_digest="sha256:$(shasum -a 256 "$WORK/$artifact_name.zip" | awk '{print $1}')"
  [[ "$actual_zip_size" == "$expected_zip_size" && "$actual_zip_digest" == "$expected_zip_digest" ]] || {
    echo "downloaded artifact $artifact_name does not match its exact GitHub digest" >&2
    exit 1
  }
  mkdir -m 700 "$WORK/family/$artifact_name"
  unzip -qq "$WORK/$artifact_name.zip" -d "$WORK/family/$artifact_name"
done < <(expected_artifact_names)

# The signed checksum manifest is the family's integrity root: authenticate it
# under the protected signer policy before trusting a single digest in it.
sums_dir="$WORK/family/nemo-control_SHA256SUMS"
sums="$sums_dir/nemo-control_${version}_SHA256SUMS"
sig="$sums.sig"
[[ "$(find "$sums_dir" -type f -exec basename {} \; | LC_ALL=C sort)" == \
   "$(printf '%s\n' "$(basename "$sig")" "$(basename "$sums")" | LC_ALL=C sort)" ]] || {
  echo "the SHA256SUMS artifact must carry exactly the manifest and its signature" >&2
  exit 1
}
ssh-keygen -Y verify \
  -f "$WORK/protected-release-allowed-signers" \
  -I "$NEMO_RELEASE_SIGNER" \
  -n "$NEMO_RELEASE_NAMESPACE" -s "$sig" <"$sums" >/dev/null || {
  echo "SHA256SUMS does not authenticate under the release signer policy" >&2
  exit 1
}

# Each target: the tarball digests to its signed manifest line, and its bound
# attestation records the same archive digest, the pinned source commit, and
# all-pass gates.
assets=()
for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
  tarball="nemo-control_${version}_${target}.tar.gz"
  attestation="$tarball.qualification.json"
  asset_dir="$WORK/family/nemo-control_${version}_${target}"
  [[ "$(find "$asset_dir" -type f -exec basename {} \; | LC_ALL=C sort)" == \
     "$(printf '%s\n' "$attestation" "$tarball" | LC_ALL=C sort)" ]] || {
    echo "artifact $target must carry exactly the tarball and its attestation" >&2
    exit 1
  }
  archive_sha=$(shasum -a 256 "$asset_dir/$tarball" | awk '{print $1}')
  declared_sha=$(awk -v name="$tarball" '$2 == name {print $1}' "$sums")
  [[ -n "$declared_sha" && "$declared_sha" == "$archive_sha" ]] || {
    echo "$tarball does not match the signed SHA256SUMS entry" >&2
    exit 1
  }
  jq -e \
    --arg target "$target" \
    --arg version "$version" \
    --arg sha "$archive_sha" \
    --arg commit "$SOURCE_COMMIT" '
      .attestation_version == 1 and
      .subject.name == "nemo-control" and
      .subject.platform == $target and
      .subject.version == $version and
      .subject.archive_sha256 == $sha and
      (.subject.component_manifest_sha256 | test("^[0-9a-f]{64}$")) and
      (.subject.transfer_manifest_sha256 | test("^[0-9a-f]{64}$")) and
      .source.commit == $commit and
      (.gates | length > 0) and
      ([.gates[].result] | all(. == "pass"))
    ' "$asset_dir/$attestation" >/dev/null || {
    echo "attestation for $tarball does not bind these bytes at the pinned source" >&2
    exit 1
  }
  assets+=("$asset_dir/$tarball" "$asset_dir/$attestation")
done
[[ "$(grep -c . "$sums")" == 4 ]] || {
  echo "signed SHA256SUMS must bind exactly four tarballs" >&2
  exit 1
}
assets+=("$sums" "$sig")

# The release body is a deterministic bound stub: it names the family, pins the
# source and the digest of the signed checksum manifest — the same stub any
# recomputation produces.
sums_sha=$(shasum -a 256 "$sums" | awk '{print $1}')
{
  printf 'nemo-control %s\n\n' "$TAG"
  printf 'The governed agent-execution distribution — crabbox, the NEMO effect\n'
  printf 'runtime, and the plugin host — assembled and qualified per target.\n\n'
  printf 'Source commit: %s\n' "$SOURCE_COMMIT"
  printf 'Distribution run: %s\n' "$RUN_ID"
  printf 'Checksum manifest: nemo-control_%s_SHA256SUMS\n' "$version"
  printf 'Manifest SHA-256: %s\n' "$sums_sha"
  printf 'Signature namespace: %s (signer %s)\n\n' "$NEMO_RELEASE_NAMESPACE" "$NEMO_RELEASE_SIGNER"
  printf 'Each tarball ships its bound qualification attestation as\n'
  printf '<tarball>.qualification.json beside the archive.\n'
} >"$WORK/notes.md"

# Immutable releases apply to the family release exactly as to the kernel one.
api_get "repos/$REPOSITORY/immutable-releases" >"$WORK/immutable-releases.json"
jq -e '.enabled == true' \
  "$WORK/immutable-releases.json" >/dev/null || {
  echo "repository release immutability is required before publication" >&2
  exit 1
}

# Refuse to guess at an existing release for the tag: a release object already
# bound to the family tag is not this script's to publish.
if api_get "repos/$REPOSITORY/releases/tags/$TAG" >"$WORK/existing-release.json" 2>/dev/null; then
  echo "a release already exists for $TAG — refusing to mutate it" >&2
  exit 1
fi

gh release create "$TAG" \
  --repo "$REPOSITORY" \
  --draft \
  --verify-tag \
  --title "nemo-control $TAG" \
  --notes-file "$WORK/notes.md" >/dev/null

api_get "repos/$REPOSITORY/releases/tags/$TAG" >"$WORK/draft.json"
RELEASE_ID=$(jq -er '.id | select(type == "number" and . > 0)' "$WORK/draft.json")
jq -e \
  --arg tag "$TAG" \
  --arg commit "$SOURCE_COMMIT" '
    .tag_name == $tag and .draft == true and .prerelease == false and
    .target_commitish == $commit
  ' "$WORK/draft.json" >/dev/null || {
  echo "draft family release does not match the pinned tag identity" >&2
  exit 1
}

gh release upload "$TAG" --repo "$REPOSITORY" "${assets[@]}" >/dev/null

# Read the draft back and require the remote inventory to equal the verified
# local bytes — names, sizes and GitHub-side digests all bound.
verify_remote_assets() {
  local release_json=$1 expected
  expected=$(mktemp "$WORK/expected-assets.XXXXXX")
  : >"$expected"
  local file name size sha
  for file in "${assets[@]}"; do
    name=$(basename "$file")
    size=$(wc -c <"$file" | tr -d '[:space:]')
    sha=$(shasum -a 256 "$file" | awk '{print $1}')
    printf '%s\t%s\t%s\n' "$name" "$size" "sha256:$sha" >>"$expected"
  done
  LC_ALL=C sort -o "$expected" "$expected"
  jq -r '.assets[] | [.name, (.size | tostring), .digest] | @tsv' "$release_json" \
    | LC_ALL=C sort >"$expected.actual"
  cmp "$expected" "$expected.actual" || {
    echo "remote asset inventory does not match the verified family bytes" >&2
    exit 1
  }
}

verify_protected_source final
api_get "repos/$REPOSITORY/releases/$RELEASE_ID" >"$WORK/predownload-release.json"
jq -e --arg tag "$TAG" '.tag_name == $tag and .draft == true and .prerelease == false' \
  "$WORK/predownload-release.json" >/dev/null || {
  echo "release $RELEASE_ID is no longer the pinned draft — refusing to publish" >&2
  exit 1
}
verify_remote_assets "$WORK/predownload-release.json"

printf '{"draft":false}\n' >"$WORK/publish.json"
gh api --method PATCH \
  --header 'Accept: application/vnd.github+json' \
  --header 'X-GitHub-Api-Version: 2022-11-28' \
  "repos/$REPOSITORY/releases/$RELEASE_ID" \
  --input "$WORK/publish.json" >"$WORK/publish-response.json"

api_get "repos/$REPOSITORY/releases/$RELEASE_ID" >"$WORK/public-release.json"
jq -e --arg tag "$TAG" '.tag_name == $tag and .draft == false' \
  "$WORK/public-release.json" >/dev/null || {
  echo "family release did not publish as $TAG" >&2
  exit 1
}
verify_remote_assets "$WORK/public-release.json"
verify_protected_source published

echo "Published exact verified nemo-control release $TAG (release $RELEASE_ID) from distribution run $RUN_ID"
