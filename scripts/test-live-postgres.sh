#!/usr/bin/env bash
# test-live-postgres.sh — run tests that need CRABBOX_TEST_DATABASE_URL
# against an ephemeral local PostgreSQL, with no pre-existing server
# required. Mirrors the CI postgres:16 service
# (.github/workflows/ci.yml) so local results match the gate.
#
# Usage:
#   scripts/test-live-postgres.sh              # default: Go live suites
#   scripts/test-live-postgres.sh -- <cmd...>  # any command needing the env
#
# If CRABBOX_TEST_DATABASE_URL is already set, it is used as-is and no
# server is managed. Otherwise Docker is preferred (postgres:16, the CI
# image); when no Docker daemon is reachable a local initdb/pg_ctl
# PostgreSQL is started on a free loopback port with trust auth.
#
# The managed server is always torn down on exit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_IMAGE="${CRABBOX_TEST_PG_IMAGE:-postgres:16}"
PG_DB="${CRABBOX_TEST_PG_DB:-crabbox_test}"

usage() {
  sed -n '2,17p' "$0"
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "${1:-}" = "--" ]; then
  shift
fi

if [ "$#" -gt 0 ]; then
  CMD=("$@")
else
  # Default: the live PostgreSQL suites — the same tests the
  # effect-fabric-postgres and authority-postgres release gates run.
  CMD=(go test -race -count=1 -timeout=20m -run 'TestLive'
    ./internal/idempotency/ ./internal/reconcile/
    ./internal/execution/ ./internal/authority/)
fi

if [ -n "${CRABBOX_TEST_DATABASE_URL:-}" ]; then
  echo "==> Using existing CRABBOX_TEST_DATABASE_URL"
  cd "$REPO_ROOT"
  "${CMD[@]}"
  exit $?
fi

# Free loopback port without needing python/node/lsof: ask the kernel
# for one by binding port 0 via /dev/tcp is not portable, so probe
# candidates and let the server bind retry on a race.
pick_port() {
  local p
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    p=$((20000 + RANDOM % 30000))
    if ! (echo >"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
  echo "55432"
}

DOCKER_CONTAINER=""
PG_DATA=""
PG_PORT=""
PG_LOG=""

cleanup() {
  if [ -n "$DOCKER_CONTAINER" ]; then
    docker rm -f "$DOCKER_CONTAINER" >/dev/null 2>&1 || true
  fi
  if [ -n "$PG_DATA" ]; then
    pg_ctl -D "$PG_DATA/data" -m fast stop >/dev/null 2>&1 || true
    rm -rf "$PG_DATA"
  fi
}
trap cleanup EXIT

wait_ready() {
  local i
  for i in $(seq 1 60); do
    if [ -n "$DOCKER_CONTAINER" ]; then
      if docker exec "$DOCKER_CONTAINER" pg_isready -U postgres -d "$PG_DB" >/dev/null 2>&1; then
        return 0
      fi
    else
      if pg_isready -h 127.0.0.1 -p "$PG_PORT" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.5
  done
  echo "ERROR: PostgreSQL did not become ready" >&2
  return 1
}

# docker_reachable reports whether a Docker daemon answers quickly.
# `docker info` can hang for a long time while Docker Desktop starts,
# so bound the probe — GNU timeout is not a default macOS tool. Poll
# the probe's liveness so a fast answer returns fast.
docker_reachable() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 &
  local pid=$!
  local i
  for i in $(seq 1 80); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"
      return $?
    fi
    sleep 0.1
  done
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 1
}

start_docker_postgres() {
  docker_reachable || return 1
  PG_PORT="$(pick_port)"
  DOCKER_CONTAINER="crabbox-test-pg-$$-$RANDOM"
  echo "==> Starting $PG_IMAGE in Docker on 127.0.0.1:$PG_PORT"
  docker run -d --rm \
    --name "$DOCKER_CONTAINER" \
    -p "127.0.0.1:$PG_PORT:5432" \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_DB="$PG_DB" \
    "$PG_IMAGE" >/dev/null
  CRABBOX_TEST_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:$PG_PORT/$PG_DB"
}

start_local_postgres() {
  command -v initdb >/dev/null 2>&1 || return 1
  command -v pg_ctl >/dev/null 2>&1 || return 1
  PG_DATA="$(mktemp -d "${TMPDIR:-/tmp}/crabbox-test-pg.XXXXXX")"
  PG_LOG="$PG_DATA/server.log"
  # Trust auth on loopback only — throwaway data dir, no credentials.
  initdb -D "$PG_DATA/data" -U postgres -A trust --no-instructions >/dev/null
  local tries
  for tries in 1 2 3 4 5; do
    PG_PORT="$(pick_port)"
    if pg_ctl -D "$PG_DATA/data" -w -t 30 \
      -o "-p $PG_PORT -k $PG_DATA -c listen_addresses=127.0.0.1" \
      -l "$PG_LOG" start >/dev/null 2>&1; then
      break
    fi
    if [ "$tries" = "5" ]; then
      echo "ERROR: could not start PostgreSQL; log follows" >&2
      cat "$PG_LOG" >&2 || true
      return 1
    fi
  done
  psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres \
    -c "CREATE DATABASE $PG_DB" >/dev/null
  CRABBOX_TEST_DATABASE_URL="postgres://postgres@127.0.0.1:$PG_PORT/$PG_DB?sslmode=disable"
}

if start_docker_postgres; then
  :
elif start_local_postgres; then
  echo "==> Started local PostgreSQL on 127.0.0.1:$PG_PORT (initdb fallback)"
else
  cat >&2 <<'EOF'
ERROR: no usable PostgreSQL found.
Install Docker, or install PostgreSQL client tools (initdb/pg_ctl/psql,
e.g. `brew install postgresql@16`), or set CRABBOX_TEST_DATABASE_URL to
an existing server.
EOF
  exit 1
fi

wait_ready
echo "==> CRABBOX_TEST_DATABASE_URL=$CRABBOX_TEST_DATABASE_URL"
export CRABBOX_TEST_DATABASE_URL

cd "$REPO_ROOT"
echo "==> Running: ${CMD[*]}"
"${CMD[@]}"
