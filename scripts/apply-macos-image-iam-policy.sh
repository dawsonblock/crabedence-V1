#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/aws-account-guard.sh"

usage() {
  cat <<'USAGE'
Usage: scripts/apply-macos-image-iam-policy.sh --identity <provider-identity.json> --policy <policy.json> [--profile <aws-profile|auto>] [--policy-name <name>] [--apply]

Safely applies the macOS image lifecycle IAM policy to the coordinator AWS
principal captured by the lifecycle smoke artifact. The script is dry-run by
default and refuses to write unless the local AWS caller account matches the
coordinator account in --identity.

Options:
  --identity <file>       provider-identity.json from lifecycle evidence
  --policy <file>         combined policy JSON, usually macos-image-policy.json
  --profile <name|auto>   AWS profile to use for sts/iam commands; auto scans local profiles
  --policy-name <name>    inline policy name; default CrabboxMacOSImageLifecycle
  --apply                 perform aws iam put-user-policy/put-role-policy
  -h, --help              show this help
USAGE
}

identity_file=""
policy_file=""
profile=""
policy_name="CrabboxMacOSImageLifecycle"
apply=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity)
      identity_file="${2:?missing value for --identity}"
      shift 2
      ;;
    --policy)
      policy_file="${2:?missing value for --policy}"
      shift 2
      ;;
    --profile)
      profile="${2:?missing value for --profile}"
      shift 2
      ;;
    --policy-name)
      policy_name="${2:?missing value for --policy-name}"
      shift 2
      ;;
    --apply)
      apply=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$identity_file" || -z "$policy_file" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -s "$identity_file" ]]; then
  echo "identity file is missing or empty: $identity_file" >&2
  exit 2
fi
if [[ ! -s "$policy_file" ]]; then
  echo "policy file is missing or empty: $policy_file" >&2
  exit 2
fi
if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required" >&2
  exit 127
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 127
fi

policy_abs="$(cd "$(dirname "$policy_file")" && pwd -P)/$(basename "$policy_file")"
coordinator_account="$(jq -r '.account // empty' "$identity_file")"
target_type="$(jq -r '.policyTarget.type // empty' "$identity_file")"
target_name="$(jq -r '.policyTarget.name // empty' "$identity_file")"

if [[ -z "$coordinator_account" ]]; then
  echo "identity file does not include .account" >&2
  exit 2
fi
if [[ -z "$target_type" || -z "$target_name" ]]; then
  echo "identity file does not include .policyTarget.type and .policyTarget.name" >&2
  exit 2
fi

if [[ "$profile" == "auto" ]]; then
  profile="$(aws_guard_select_profile_for_account "$coordinator_account" "apply IAM policy")"
fi

aws_base=(aws)
if [[ -n "$profile" ]]; then
  aws_base+=(--profile "$profile")
fi

local_account="$(aws_guard_account_for_selected_profile "$profile" "$coordinator_account" "apply IAM policy")"

case "$target_type" in
  role)
    cmd=("${aws_base[@]}" iam put-role-policy --role-name "$target_name" --policy-name "$policy_name" --policy-document "file://$policy_abs")
    ;;
  user)
    cmd=("${aws_base[@]}" iam put-user-policy --user-name "$target_name" --policy-name "$policy_name" --policy-document "file://$policy_abs")
    ;;
  *)
    printf 'unsupported policy target type: %s\n' "$target_type" >&2
    exit 2
    ;;
esac

printf 'coordinator_account=%s\n' "$coordinator_account"
printf 'local_account=%s\n' "$local_account"
if [[ -n "$profile" ]]; then
  printf 'aws_profile=%s\n' "$profile"
fi
printf 'policy_target=%s/%s\n' "$target_type" "$target_name"

if [[ "$apply" != 1 ]]; then
  printf 'dry-run: '
  printf '%q ' "${cmd[@]}"
  printf '\n'
  printf 'rerun with --apply to attach the policy.\n'
  exit 0
fi

printf '+'
printf ' %q' "${cmd[@]}"
printf '\n'
"${cmd[@]}"
