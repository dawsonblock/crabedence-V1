#!/usr/bin/env bash
# install-msb-runtime.sh — install the pinned Microsandbox runtime for a
# live qualification lane.
#
# The release pipeline qualifies the EXACT pinned runtime (the executor's
# PinnedMSBVersion), so the installer never resolves "latest": the version
# comes from MSB_VERSION or the default below, which must equal the pin in
# internal/sandboxexecutor/backend_msb.go. After install the script asserts
# the binary reports the pinned version and that `msb doctor` passes —
# a wrong or unhealthy runtime fails the lane before any test runs.
#
# Every downloaded artifact is verified twice: against the repository's
# independent trusted pins (qualification/msb-runtime-pins.json) AND the
# release's own checksums.sha256. The checksum file verifies transit
# integrity from the release; the repository pins are the trust anchor —
# a substituted release serving forged assets alongside a forged
# checksum file still fails, because the bytes cannot match the digests
# the qualification repository pins. An asset with no repository pin
# refuses: a lane never qualifies on unanchored bytes.
#
# Layout (matches the executor's discovery):
#   $HOME/.microsandbox/bin/msb
#   $HOME/.microsandbox/lib/libkrunfw.(dylib|so)
#
# Usage:
#   bash scripts/install-msb-runtime.sh            # pinned default
#   MSB_VERSION=0.7.8 bash scripts/install-msb-runtime.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MSB_VERSION="${MSB_VERSION:-0.7.8}"
DEST_BIN="$HOME/.microsandbox/bin"
DEST_LIB="$HOME/.microsandbox/lib"
REPO="superradcompany/microsandbox"
PINS_FILE="${MSB_PINS_FILE:-$REPO_ROOT/qualification/msb-runtime-pins.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required to verify the trusted runtime pins" >&2
  exit 1
fi
if [ ! -f "$PINS_FILE" ]; then
  echo "ERROR: trusted runtime pins not found: $PINS_FILE" >&2
  exit 1
fi
pinned_version="$(jq -r '.version // empty' "$PINS_FILE")"
if [ "$pinned_version" != "$MSB_VERSION" ]; then
  echo "ERROR: $PINS_FILE pins msb '$pinned_version' — refusing to install unanchored version $MSB_VERSION" >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin) os="darwin" ;;
  Linux)  os="linux" ;;
  *) echo "ERROR: unsupported OS for msb install: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch="aarch64" ;;
  x86_64)        arch="x86_64" ;;
  *) echo "ERROR: unsupported arch for msb install: $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$DEST_BIN" "$DEST_LIB"

base="https://github.com/${REPO}/releases/download/v${MSB_VERSION}"
sums="$(mktemp -t msb-sums.XXXXXX)"
trap 'rm -f "$sums"' EXIT
curl -fsSL --retry 3 -o "$sums" "${base}/checksums.sha256"

# verify_asset <downloaded-file> <asset-name>
# Asserts the downloaded bytes match the repository's trusted pin AND
# the release's checksums.sha256. The pin is checked first — it is the
# independent anchor; the checksum entry is consistency with upstream's
# own manifest, so drift between the pinned bytes and a recut release is
# surfaced rather than silently adopted.
verify_asset() {
  local file="$1" name="$2" want pin actual
  pin="$(jq -r --arg n "$name" '.assets[$n] // empty' "$PINS_FILE")"
  if [ -z "$pin" ]; then
    echo "ERROR: $PINS_FILE carries no trusted digest for $name — refusing to install unanchored bytes" >&2
    exit 1
  fi
  want="$(awk -v n="$name" '$NF == n {print $1}' "$sums")"
  if [ -z "$want" ]; then
    echo "ERROR: checksums.sha256 for v${MSB_VERSION} has no entry for $name" >&2
    exit 1
  fi
  actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  if [ "$actual" != "$pin" ]; then
    echo "ERROR: $name digest $actual does not match the repository-pinned trusted digest $pin — refusing a substituted runtime" >&2
    exit 1
  fi
  if [ "$actual" != "$want" ]; then
    echo "ERROR: $name digest $actual does not match the pinned release checksum $want — the upstream asset drifted from the qualified pin" >&2
    exit 1
  fi
}

msb_asset="msb-${os}-${arch}"
curl -fsSL --retry 3 -o "$DEST_BIN/msb" "${base}/${msb_asset}"
verify_asset "$DEST_BIN/msb" "$msb_asset"
chmod +x "$DEST_BIN/msb"

# libkrunfw is the Hypervisor.framework virtualization backend msb needs
# on Apple Silicon (and its counterpart on Linux). It is part of the
# pinned release; a lane is not qualified without the verified backend.
case "$os" in
  darwin) lib_asset="libkrunfw-${os}-${arch}.dylib" ;;
  linux)  lib_asset="libkrunfw-${os}-${arch}.so" ;;
esac
curl -fsSL --retry 3 -o "$DEST_LIB/$lib_asset" "${base}/${lib_asset}"
verify_asset "$DEST_LIB/$lib_asset" "$lib_asset"

actual="$("$DEST_BIN/msb" --version 2>/dev/null || true)"
echo "installed: $actual"
if ! printf '%s' "$actual" | grep -q "$MSB_VERSION"; then
  echo "ERROR: installed msb reports '${actual:-<unreadable>}' — expected version $MSB_VERSION" >&2
  exit 1
fi

"$DEST_BIN/msb" doctor

# Final as-installed assertion: the runtime msb actually resolves —
# binary AND the firmware doctor reports — must be byte-identical to
# the repository's trusted pins, so a lane can never qualify on bytes
# that merely downloaded cleanly once.
bash "$REPO_ROOT/scripts/verify-msb-runtime-pins.sh" "$DEST_BIN/msb"
