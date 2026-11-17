#!/bin/bash
# Vault CE as identity broker for MCP auth. Safe to re-run.
#   1. identity/oidc issuer, signing key "mcp" and token role "mcp-orders" (aud = mcp-orders, short TTL,
#      claims: Vault group names + informational SA annotations)
#   2. policy and auth/kubernetes role "mcp-client": may only mint that token
#   3. client namespaces/ServiceAccounts, one Vault entity + alias per client SA (alias = SA UID), and the
#      internal groups that decide which MCP tools each client gets (membership replaced on every run)
#
# Usage: scripts/config-mcp-auth.sh <mcp_token_ttl> <token_ttl> <token_max_ttl>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

MCP_TOKEN_TTL="${1:-5m}"
TOKEN_TTL="${2:-15m}"
TOKEN_MAX_TTL="${3:-30m}"
ISSUER="http://vault.vault.svc.cluster.local:8200"
AUDIENCE="mcp-orders"
MCP_GROUPS="mcp-orders-reader mcp-orders-reporter"

VAULT_TOKEN="$(root_token)"
export VAULT_TOKEN
accessor="$(auth_accessor)"

# --- 1. Identity tokens --------------------------------------------------------------------------
# Every token's iss is <issuer>/v1/identity/oidc; the in-cluster address is what the MCP server checks.
vault_cmd write identity/oidc/config issuer="${ISSUER}" >/dev/null
# verification_ttl keeps a rotated-out public key in the JWKS long enough for tokens it signed to expire.
vault_cmd write identity/oidc/key/mcp algorithm=RS256 rotation_period=24h verification_ttl=24h allowed_client_ids="${AUDIENCE}" >/dev/null
sed "s/__ACCESSOR__/${accessor}/g" vault-ce/mcp-auth/mcp-orders-claims.json.tpl \
  | vault_cmd_in write "identity/oidc/role/${AUDIENCE}" key=mcp client_id="${AUDIENCE}" ttl="${MCP_TOKEN_TTL}" template=- >/dev/null
log "Wrote identity/oidc key mcp and role ${AUDIENCE} (aud=${AUDIENCE}, ttl=${MCP_TOKEN_TTL}, iss=${ISSUER}/v1/identity/oidc)"

# --- 2. Who may mint it ---------------------------------------------------------------------------
vault_cmd_in policy write mcp-client - <vault-ce/policies/mcp-client.hcl >/dev/null
jq --arg ttl "${TOKEN_TTL}" --arg max "${TOKEN_MAX_TTL}" '.token_ttl = $ttl | .token_max_ttl = $max' vault-ce/roles/mcp-client.json \
  | vault_cmd_in write "${AUTH_MOUNT}/role/mcp-client" - >/dev/null
log "Wrote policy mcp-client and ${AUTH_MOUNT}/role/mcp-client"

# --- 3. Client identities and groups --------------------------------------------------------------
# shellcheck disable=SC2016 # literal ${VAR} names for envsubst, not expansions
SUBST_VARS='${APP_NAME} ${APPLICATION} ${ENVIRONMENT} ${TEAM}'
members_file="$(mktemp "${TMPDIR:-/tmp}/mcp-members.XXXXXX")"
trap 'rm -f "${members_file}"' EXIT

while read -r row <&3; do
  APP_NAME="$(jq -r .name <<<"${row}")"
  APPLICATION="$(jq -r .application_name <<<"${row}")"
  ENVIRONMENT="$(jq -r .environment <<<"${row}")"
  TEAM="$(jq -r .team <<<"${row}")"
  group="$(jq -r '.group // ""' <<<"${row}")"
  export APP_NAME APPLICATION ENVIRONMENT TEAM
  envsubst "${SUBST_VARS}" <templates/namespace.yaml.tpl | kubectl apply -f - >/dev/null
  envsubst "${SUBST_VARS}" <templates/service-account.yaml.tpl | kubectl apply -f - >/dev/null
  if [ -z "${group}" ]; then
    log "${APP_NAME}: no group (logs in fine, gets no MCP tools)"
    continue
  fi

  uid="$(kubectl get sa "${APP_NAME}-sa" -n "${APP_NAME}" -o jsonpath='{.metadata.uid}')"
  # Reuse the entity Vault already created for this SA (alias = SA UID), else the named one, else create it
  entity_id="$(vault_cmd write -format=json identity/lookup/entity alias_name="${uid}" alias_mount_accessor="${accessor}" 2>/dev/null | jq -r '.data.id // empty' || true)"
  if [ -z "${entity_id}" ]; then
    entity_id="$(vault_cmd read -format=json "identity/entity/name/${APP_NAME}" 2>/dev/null | jq -r '.data.id // empty' || true)"
    if [ -z "${entity_id}" ]; then
      entity_id="$(vault_cmd write -format=json identity/entity name="${APP_NAME}" metadata=team="${TEAM}" | jq -r '.data.id')"
    fi
    vault_cmd write identity/entity-alias name="${uid}" canonical_id="${entity_id}" mount_accessor="${accessor}" >/dev/null
  fi
  printf '%s %s\n' "${group}" "${entity_id}" >>"${members_file}"
  log "${APP_NAME}: entity ${entity_id} (alias ${uid}) -> group ${group}"
done 3< <(jq -c '.[]' "${CLIENTS_FILE}")

for group in ${MCP_GROUPS}; do
  ids="$(awk -v g="${group}" '$1 == g {print $2}' "${members_file}" | paste -sd, -)"
  vault_cmd write "identity/group/name/${group}" type=internal member_entity_ids="${ids}" >/dev/null
  log "Group ${group}: members ${ids:-none}"
done
