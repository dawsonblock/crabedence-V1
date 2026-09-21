#!/usr/bin/env bash
# bootstrap-db.sh — provision the dedicated staging role and database.
#
# Idempotent: safe to re-run. Creates the staging role and database if
# absent. Schema is applied by the service at startup (schema_migrations);
# this script deliberately does NOT create tables — first boot on an
# empty database is itself part of qualification.
#
# Usage:
#   sudo -u postgres ./bootstrap-db.sh
# or:
#   PGADMIN_URL=postgres://postgres:...@host:5432/postgres ./bootstrap-db.sh
#
# Optional env:
#   STAGING_DB   (default crabedence_staging)
#   STAGING_ROLE (default crabedence_staging)
#   STAGING_DB_PASSWORD (required — prompted is not supported; pass via env)
set -euo pipefail

STAGING_DB="${STAGING_DB:-crabedence_staging}"
STAGING_ROLE="${STAGING_ROLE:-crabedence_staging}"
STAGING_DB_PASSWORD="${STAGING_DB_PASSWORD:?set STAGING_DB_PASSWORD in the environment}"

PSQL=(psql "${PGADMIN_URL:-postgres:///postgres}" -v ON_ERROR_STOP=1 -At)

# Create the role if absent (password is always set/updated to the
# supplied value — rotating the staging password is re-running this).
role_exists=$("${PSQL[@]}" -c "SELECT 1 FROM pg_roles WHERE rolname='$STAGING_ROLE'" || true)
if [ -z "$role_exists" ]; then
  "${PSQL[@]}" -c "CREATE ROLE $STAGING_ROLE LOGIN PASSWORD '$STAGING_DB_PASSWORD'"
  echo "created role $STAGING_ROLE"
else
  "${PSQL[@]}" -c "ALTER ROLE $STAGING_ROLE LOGIN PASSWORD '$STAGING_DB_PASSWORD'"
  echo "role $STAGING_ROLE exists; password updated"
fi

db_exists=$("${PSQL[@]}" -c "SELECT 1 FROM pg_database WHERE datname='$STAGING_DB'" || true)
if [ -z "$db_exists" ]; then
  "${PSQL[@]}" -c "CREATE DATABASE $STAGING_DB OWNER $STAGING_ROLE"
  echo "created database $STAGING_DB (owner $STAGING_ROLE)"
else
  echo "database $STAGING_DB exists"
fi

"${PSQL[@]}" -c "REVOKE ALL ON DATABASE $STAGING_DB FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE $STAGING_DB TO $STAGING_ROLE"

echo "bootstrap complete: db=$STAGING_DB role=$STAGING_ROLE"
echo "next: start the service — it migrates the schema itself."
