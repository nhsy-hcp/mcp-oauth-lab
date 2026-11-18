#!/bin/bash
# Server-side scenarios M1-M8: the MCP server's own short-lived, least-privileged database access.
# Exits non-zero if any check fails. Safe to re-run.
#
# Usage: scripts/demo-mcp.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

FAILURES=0
token="$(scripts/oauth-login.sh testuser)"

log "M1  Tools work with no secret in the pod"
rows="$(mcp_tool "${token}" list_orders '{"status":"pending"}' | jq -r '.structuredContent.result[].customer' | paste -sd, -)"
check "list_orders returned pending orders (${rows})" grep -q acme-ltd <<<"${rows}"

log "M2  Dynamic database user per lease"
who="$(mcp_tool "${token}" whoami | jq -c '.structuredContent.database')"
user="$(jq -r .current_user <<<"${who}")"
left="$(jq -r '.lease_seconds_remaining // 9999 | floor' <<<"${who}")"
check "server uses a Vault-minted user (${user})" grep -q '^v-' <<<"${user}"
check "lease has <= 600 s left (${left})" test "${left}" -le 600

log "M3-M5  The server's Vault policy is one exact path"
check "M3 own path database/creds/dev-orders is readable" test "$(proxy_read "${SERVER_NS}" mcp-orders database/creds/dev-orders)" = ok
check "M4 other app database/creds/dev-payments is denied" test "$(proxy_read "${SERVER_NS}" mcp-orders database/creds/dev-payments)" = denied
check "M5 other environment database/creds/production-orders is denied" test "$(proxy_read "${SERVER_NS}" mcp-orders database/creds/production-orders)" = denied

log "M6  No secrets in the app container"
env_out="$(kubectl exec -n "${SERVER_NS}" deploy/mcp-orders -c app -- env)"
check "no VAULT_TOKEN or password in the app environment" bash -c '! grep -Eiq "^(VAULT_TOKEN|.*PASSWORD)=" <<<"$1"' _ "${env_out}"
# Ask the app container itself, so a failed kubectl exec is a FAIL rather than "nothing mounted"
mounted="$(kubectl exec -n "${SERVER_NS}" deploy/mcp-orders -c app -- python -c 'import os; print(os.path.exists("/var/run/secrets"))' 2>&1 || true)"
check "no ServiceAccount or Vault token mounted in the app container (exists: ${mounted})" test "${mounted}" = False

log "M7  Break-glass revoke, then the server recovers on its own"
scripts/vault.sh lease revoke -prefix database/creds/dev-orders >/dev/null
new_user=""
for _ in $(seq 1 30); do
  new_user="$(mcp_tool "${token}" whoami | jq -r '.structuredContent.database.current_user // empty' || true)"
  [ -n "${new_user}" ] && [ "${new_user}" != "${user}" ] && break
  sleep 2
done
check "new database user after revoke (${user} -> ${new_user:-none})" test -n "${new_user}" -a "${new_user}" != "${user}"
check "old user dropped from PostgreSQL" test "$(pg_role_count "${user}")" = 0

log "M8  Schema isolation: dev_orders_ro has no grant on payments"
check "no MCP tool touches payments" bash -c '! grep -q payments <<<"$1"' _ "$(mcp_rpc "${token}" tools/list)"
VAULT_TOKEN="$(root_token)"
export VAULT_TOKEN
lease="$(vault_cmd read -format=json database/creds/dev-orders)"
pg_user="$(jq -r .data.username <<<"${lease}")"
denied="$(psql_as "${pg_user}" "$(jq -r .data.password <<<"${lease}")" -d dev -Atc 'SELECT token FROM payments.card_tokens' 2>&1 || true)"
vault_cmd lease revoke "$(jq -r .lease_id <<<"${lease}")" >/dev/null
check "SELECT on payments.card_tokens is refused" grep -q 'permission denied' <<<"${denied}"
check "canary never returned" bash -c '! grep -q CANARY_NEVER_LEAK <<<"$1"' _ "${denied}"

echo
if [ "${FAILURES}" -gt 0 ]; then
  err "${FAILURES} check(s) failed"
  exit 1
fi
log "M1-M8 passed"
