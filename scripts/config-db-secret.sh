#!/bin/bash
# Enable the database secrets engine at database/ (Vault's default path), write the pg-dev connection,
# the dev-orders role, then rotate the admin password so only Vault knows it.
# Safe to re-run: an existing connection is left alone (its root password is already rotated).
#
# Usage: scripts/config-db-secret.sh <default_ttl> <max_ttl>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

DEFAULT_TTL="${1:-10m}"
MAX_TTL="${2:-30m}"
PG_HOST="postgres.${POSTGRES_NS}.svc.cluster.local:5432"
CONN="pg-dev"
ADMIN="vault_admin_dev"
# role | group role
ROLES=(
  "dev-orders|dev_orders_ro"
)

VAULT_TOKEN="$(root_token)"
export VAULT_TOKEN

vault_cmd secrets enable database 2>/dev/null || log "database/ already enabled"

allowed="$(printf '%s\n' "${ROLES[@]}" | cut -d'|' -f1 | paste -sd, -)"

if vault_cmd read "database/config/${CONN}" >/dev/null 2>&1; then
  vault_cmd write "database/config/${CONN}" allowed_roles="${allowed}" >/dev/null
  log "database/config/${CONN} exists - updated allowed_roles only"
else
  # The bootstrap password goes on stdin (password=-), never on the command line.
  # shellcheck disable=SC2016 # {{username}}/{{password}} are Vault templates, not shell
  kubectl get secret postgres-credentials -n "${POSTGRES_NS}" -o jsonpath='{.data.vault-admin-dev-password}' | base64 --decode \
    | vault_cmd_in write "database/config/${CONN}" \
      plugin_name=postgresql-database-plugin \
      connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}/dev?sslmode=disable" \
      allowed_roles="${allowed}" \
      username="${ADMIN}" \
      password=- \
      password_authentication=scram-sha-256 >/dev/null
  vault_cmd write -f "database/rotate-root/${CONN}" >/dev/null
  log "Wrote database/config/${CONN} (${ADMIN}) and rotated its password"
fi

for row in "${ROLES[@]}"; do
  IFS='|' read -r role group <<<"${row}"
  # Revocation ends the user's sessions, then drops it. VALID UNTIL is a second guard.
  vault_cmd write "database/roles/${role}" \
    db_name="${CONN}" \
    default_ttl="${DEFAULT_TTL}" \
    max_ttl="${MAX_TTL}" \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE ${group};" \
    revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";" >/dev/null
  log "Wrote database/roles/${role} (${CONN}, ${group}, ttl ${DEFAULT_TTL}/${MAX_TTL})"
done
