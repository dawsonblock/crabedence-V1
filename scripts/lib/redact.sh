#!/usr/bin/env bash
# Redaction for gate evidence logs.
#
# Every gate log records the command line that produced it. Some gates
# pass credentials through the environment — a database URL, a provider
# token — and an unredacted argv would persist the secret into the
# evidence bundle that is uploaded with the release. Redact the value of
# any KEY=value token whose key looks credential-bearing, keeping the key
# so the log still shows what was configured.

# redact_command <arg...> — prints the argv with secret values replaced.
redact_command() {
  local arg out=""
  for arg in "$@"; do
    case "$arg" in
      *TOKEN=*|*SECRET=*|*PASSWORD=*|*PASSWD=*|*DATABASE_URL=*|*API_KEY=*|*_KEY=*|*CREDENTIAL=*)
        arg="${arg%%=*}=<redacted>"
        ;;
    esac
    out="${out}${out:+ }${arg}"
  done
  printf '%s' "$out"
}
