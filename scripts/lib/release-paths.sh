# shellcheck shell=bash
# Release-path filename policy, shared by the source packager and the
# source-manifest generator/verifier.
#
# A release path is a slash-separated sequence of components where every
# component:
#   * is non-empty and not "." or ".."
#   * contains no byte below 0x20 and no 0x7F — no control characters
#     (tab, newline, CR, escape), which corrupt line-oriented manifests
#     and option parsing alike
#   * contains no backslash (a path separator on other platforms and a
#     shell escape initiator)
#   * does not begin with "-" (an option-injection vector wherever a
#     filename reaches an argv)
#   * does not begin or end with whitespace (survives IFS-trimming
#     consumers byte-for-byte)
#
# Spaces inside a component and non-ASCII (UTF-8) names are legal.
#
# Git permits filenames outside this policy. The release path does not:
# anything outside it fails before packaging, manifesting, or
# verification — never silently mangled by a line-oriented step.

release_path_check() {
  local p="$1"
  [ -n "$p" ] || return 1
  case "$p" in
    *[[:cntrl:]]*) return 1 ;;
    *\\*) return 1 ;;
  esac
  local IFS='/'
  local -a comps=()
  # IFS="/" is not an IFS-whitespace character, so read -a preserves
  # empty fields: "a//b" and "a/" surface their empty components.
  read -r -a comps <<< "$p"
  local c
  for c in ${comps[@]+"${comps[@]}"}; do
    case "$c" in
      ""|.|..) return 1 ;;
      -*|" "*|*" ") return 1 ;;
    esac
  done
  return 0
}
