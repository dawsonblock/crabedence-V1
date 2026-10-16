#!/usr/bin/env bash
# verify-msb-runtime-pins.sh — assert the INSTALLED Microsandbox runtime
# is byte-for-byte the pinned, trusted release before a qualification
# lane runs on it.
#
# install-msb-runtime.sh anchors the download path; this script anchors
# whatever is already installed — a lane must not qualify on a runtime
# placed by any other means (a pre-existing install, a substituted file,
# a different release tag). The pins live in the repository at
# qualification/msb-runtime-pins.json: they were established by hashing
# the genuine upstream assets, so a host whose bytes differ — however
# they got there — fails here, before a single test runs.
#
# Checks, all fail-closed:
#   1. `msb doctor` is healthy on this host.
#   2. `msb --version` reports the pinned version.
#   3. sha256(<msb executable>)        == assets[msb-<os>-<arch>]
#   4. sha256(<firmware doctor resolves>) == assets[libkrunfw-<os>-<arch>.(dylib|so)]
#      The firmware filename is whatever msb itself resolves (upstream
#      installs it versioned, e.g. libkrunfw.5.dylib); the pin compares
#      content, not the filename.
#
# Usage:
#   bash scripts/verify-msb-runtime-pins.sh [path-to-msb]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TRUSTED_PINS="$REPO_ROOT/qualification/msb-runtime-pins.json"

# Qualifying verification uses ONLY the repository-bound trusted
# manifest — an MSB_PINS_FILE environment override would let a forged
# manifest make forged bytes "match", so it is refused outright here.
# The override survives in exactly one form: MSB_PINS_NONQUALIFYING=1,
# an explicit declaration that the result is NOT qualification evidence.
fail() { echo "ERROR: $*" >&2; exit 1; }

QUALIFYING=1
case "${MSB_PINS_NONQUALIFYING:-}" in
  1|true|yes) QUALIFYING=0 ;;
esac
if [ "$QUALIFYING" = 1 ]; then
  if [ -n "${MSB_PINS_FILE:-}" ] && [ "$MSB_PINS_FILE" != "$TRUSTED_PINS" ]; then
    fail "MSB_PINS_FILE=$MSB_PINS_FILE attempts to substitute the trusted pin manifest — qualifying verification always uses $TRUSTED_PINS (set MSB_PINS_NONQUALIFYING=1 for an explicitly non-qualifying check)"
  fi
  PINS_FILE="$TRUSTED_PINS"
else
  PINS_FILE="${MSB_PINS_FILE:-$TRUSTED_PINS}"
  echo "WARNING: NON-QUALIFYING runtime verification — pins read from $PINS_FILE; this result can never be release evidence" >&2
fi

MSB_BIN="${1:-${CRABBOX_MSB_BIN:-$HOME/.microsandbox/bin/msb}}"
if [ ! -x "$MSB_BIN" ]; then
  MSB_BIN="$(command -v msb 2>/dev/null || true)"
fi
[ -n "$MSB_BIN" ] && [ -x "$MSB_BIN" ] || fail "no executable msb found (looked for \$1, CRABBOX_MSB_BIN, ~/.microsandbox/bin/msb, PATH)"
command -v jq >/dev/null 2>&1 || fail "jq is required to verify the trusted runtime pins"
[ -f "$PINS_FILE" ] || fail "trusted runtime pins not found: $PINS_FILE"

# Trusted-pin provenance: in qualifying mode the manifest must be the
# checked-in file at HEAD — an uncommitted or hand-edited pin file is a
# pin change that never passed through source review, which is exactly
# the substitution this gate exists to refuse.
if [ "$QUALIFYING" = 1 ] && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  prefix="$(git -C "$REPO_ROOT" rev-parse --show-prefix 2>/dev/null || true)"
  committed_sha="$(git -C "$REPO_ROOT" show "HEAD:${prefix}qualification/msb-runtime-pins.json" 2>/dev/null | shasum -a 256 | awk '{print $1}')"
  working_sha="$(shasum -a 256 "$PINS_FILE" | awk '{print $1}')"
  if [ -n "$committed_sha" ] && [ "$committed_sha" != "$working_sha" ]; then
    fail "trusted pins differ from the committed manifest (uncommitted or modified trusted pins) — a pin change cannot qualify outside a reviewed source revision"
  fi
fi

case "$(uname -s)" in
  Darwin) os="darwin" ;;
  Linux)  os="linux" ;;
  *)      fail "unsupported host OS $(uname -s) for pinned runtime verification" ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch="aarch64" ;;
  x86_64)        arch="x86_64" ;;
  *)             fail "unsupported host arch $(uname -m) for pinned runtime verification" ;;
esac

pin() { jq -r --arg n "$1" '.assets[$n] // empty' "$PINS_FILE"; }
pinned_version="$(jq -r '.version // empty' "$PINS_FILE")"
[ -n "$pinned_version" ] || fail "$PINS_FILE declares no pinned version"

# 1. The runtime must be healthy on this host — doctor is also what
#    resolves the real firmware path below.
"$MSB_BIN" doctor >/dev/null 2>&1 || fail "msb doctor is not healthy on this host"

# 2. The installed binary must report the pinned version — a different
#    release is unqualified no matter how healthy it is.
reported="$("$MSB_BIN" --version 2>/dev/null || true)"
printf '%s' "$reported" | grep -q "$pinned_version" \
  || fail "installed msb reports '${reported:-<unreadable>}' — the qualification pins version $pinned_version"

# 3. The executable's bytes must be the pinned asset's bytes.
msb_key="msb-${os}-${arch}"
msb_pin="$(pin "$msb_key")"
[ -n "$msb_pin" ] || fail "$PINS_FILE carries no trusted digest for $msb_key"
msb_actual="$(shasum -a 256 "$MSB_BIN" | awk '{print $1}')"
[ "$msb_actual" = "$msb_pin" ] \
  || fail "msb executable digest $msb_actual does not match the trusted pin $msb_pin — refusing to qualify a substituted runtime"

# 4. The firmware msb actually resolves must be the pinned asset's
#    bytes. doctor names the concrete file (a versioned name such as
#    libkrunfw.5.dylib, or a symlink target); content is compared.
case "$os" in
  darwin) fw_key="libkrunfw-${os}-${arch}.dylib" ;;
  linux)  fw_key="libkrunfw-${os}-${arch}.so" ;;
esac
fw_pin="$(pin "$fw_key")"
[ -n "$fw_pin" ] || fail "$PINS_FILE carries no trusted digest for $fw_key"
# doctor prints its report on stderr; the last field of the libkrunfw
# line is the resolved path.
fw_path="$("$MSB_BIN" doctor 2>&1 | awk '/libkrunfw/ {print $NF}' | tail -1)"
[ -n "$fw_path" ] && [ -f "$fw_path" ] \
  || fail "msb doctor did not resolve a libkrunfw firmware file (got '${fw_path:-<none>}')"
fw_actual="$(shasum -a 256 "$fw_path" | awk '{print $1}')"
[ "$fw_actual" = "$fw_pin" ] \
  || fail "firmware $fw_path digest $fw_actual does not match the trusted pin $fw_pin — refusing to qualify a substituted virtualization backend"

if [ "$QUALIFYING" = 1 ]; then
  echo "msb runtime verified against trusted pins: $MSB_BIN (v$pinned_version) + $fw_path"
else
  echo "NON-QUALIFYING: $MSB_BIN (v$pinned_version) + $fw_path matched $PINS_FILE — development check only, never release evidence"
fi
