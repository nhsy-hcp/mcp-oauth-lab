#!/bin/bash
# Create Better Auth's own database and owner in the lab PostgreSQL. It is separate from the dev database. Safe to re-run.
#
# Usage: scripts/config-auth-db.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

password="$(kubectl get secret better-auth-env -n better-auth -o jsonpath='{.data.AUTH_DB_PASSWORD}' | base64 -d)"

# The password travels on stdin and reaches psql through its environment, never an argument.
# shellcheck disable=SC2016 # expanded by the pod's sh and by psql, not here
{
  printf '%s\n' "${password}"
  cat <<'SQL'
\set ON_ERROR_STOP on
\getenv auth_password AUTH_DB_PASSWORD
SELECT 'CREATE ROLE auth_owner LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auth_owner') \gexec
ALTER ROLE auth_owner PASSWORD :'auth_password';
SELECT 'CREATE DATABASE auth OWNER auth_owner' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'auth') \gexec
REVOKE ALL ON DATABASE auth FROM PUBLIC;
SQL
} | kubectl exec -i deploy/postgres -n "${POSTGRES_NS}" -- \
  sh -c 'IFS= read -r AUTH_DB_PASSWORD; export AUTH_DB_PASSWORD; exec psql -q -U postgres -d postgres' >/dev/null
log "Database auth and role auth_owner are ready"
