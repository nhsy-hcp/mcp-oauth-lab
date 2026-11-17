#!/bin/bash
# Identity-broker scenarios A1-A11: Vault CE issues short-lived, audience-bound identity JWTs; the MCP server
# authorises tools by Vault group. Exits non-zero if any check fails. Restores any Vault change it makes.
#
# Usage: scripts/demo-mcp-auth.sh <mcp_token_ttl> <demo_token_ttl> <token_ttl> <token_max_ttl>
#   A6 (expiry) temporarily sets the identity token TTL to <demo_token_ttl> (e.g. 1m) and waits it out.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

MCP_TOKEN_TTL="${1:-5m}"
DEMO_TOKEN_TTL="${2:-1m}"
TOKEN_TTL="${3:-15m}"
TOKEN_MAX_TTL="${4:-30m}"
FAILURES=0
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VAULT_TOKEN="$(root_token)"
export VAULT_TOKEN

client_logs() { kubectl logs -n "$1" deploy/mcp-client -c app --since=10m; }
wait_for_log() { # wait_for_log <namespace> <jq-filter>: true once a log line matches (up to ~60 s)
  for _ in $(seq 1 30); do
    client_logs "$1" | grep '^{' | jq -e "select($2)" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
reader_members() { vault_cmd read -format=json identity/group/name/mcp-orders-reader | jq -r '.data.member_entity_ids // [] | join(",")'; }

restore() {
  [ -n "${READER_MEMBERS:-}" ] && vault_cmd write identity/group/name/mcp-orders-reader type=internal member_entity_ids="${READER_MEMBERS}" >/dev/null
  if [ "${TTL_CHANGED:-false}" = true ]; then
    scripts/config-mcp-auth.sh "${MCP_TOKEN_TTL}" "${TOKEN_TTL}" "${TOKEN_MAX_TTL}" >/dev/null
  fi
}
trap restore EXIT

log "A1  No token"
out="$(curl -s -D - -o /dev/null -X POST "${MCP_URL}" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
check "401 without a bearer token" grep -q '^HTTP/1.1 401' <<<"${out}"
check "WWW-Authenticate points at protected resource metadata" grep -qi '^www-authenticate: Bearer .*resource_metadata=' <<<"${out}"

log "A2  Authorised client pod (orders-agent, group mcp-orders-reader)"
check "lists 3 tools" wait_for_log mcp-client-orders-agent '.event == "tools_listed" and (.tools | length) == 3'
check "list_orders returns rows" wait_for_log mcp-client-orders-agent '.event == "tool_called" and .tool == "list_orders" and .is_error == false'

log "A3-A4  Each side can do exactly one thing in Vault"
check "A3 server pod cannot mint client tokens (identity/oidc/token/mcp-orders denied)" test "$(proxy_read "${SERVER_NS}" mcp-orders identity/oidc/token/mcp-orders)" = denied
check "A4 client pod cannot read database credentials" test "$(proxy_read mcp-client-orders-agent mcp-client database/creds/preview-orders)" = denied

log "A5  Forged token"
token="$(scripts/mcp-token.sh)"
sig="${token##*.}"
first="${sig:0:1}"
[ "${first}" = A ] && swap=B || swap=A
forged="${token%.*}.${swap}${sig:1}"
check "tampered signature -> 401" test "$(mcp_rpc "${forged}" tools/list | cut -d' ' -f1)" = 401
check "the genuine token still works" test "$(mcp_rpc "${token}" tools/list | cut -d' ' -f1)" = 200

log "A6  Expired token (identity token TTL temporarily ${DEMO_TOKEN_TTL})"
TTL_CHANGED=true
scripts/config-mcp-auth.sh "${DEMO_TOKEN_TTL}" "${TOKEN_TTL}" "${TOKEN_MAX_TTL}" >/dev/null
short="$(scripts/mcp-token.sh)"
exp="$(jq -R 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .exp' <<<"${short}" 2>/dev/null \
  || jq -R 'split(".")[1] | . + "=" | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .exp' <<<"${short}" 2>/dev/null \
  || jq -R 'split(".")[1] | . + "==" | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .exp' <<<"${short}")"
check "short token works while valid" test "$(mcp_rpc "${short}" tools/list | cut -d' ' -f1)" = 200
wait_s=$((exp - $(date +%s) + 3))
echo "    waiting ${wait_s}s for the token to expire..."
[ "${wait_s}" -gt 0 ] && sleep "${wait_s}"
check "replayed after expiry -> 401" test "$(mcp_rpc "${short}" tools/list | cut -d' ' -f1)" = 401
scripts/config-mcp-auth.sh "${MCP_TOKEN_TTL}" "${TOKEN_TTL}" "${TOKEN_MAX_TTL}" >/dev/null
TTL_CHANGED=false

log "A7  Tool outside the client's group (reporting-agent calls get_order)"
check "get_order -> tool error, not permitted" wait_for_log mcp-client-reporting-agent '.event == "tool_called" and .tool == "get_order" and .is_error == true and (.text | test("not permitted"))'
check "list_orders still allowed" wait_for_log mcp-client-reporting-agent '.event == "tool_called" and .tool == "list_orders" and .is_error == false'

log "A8  Valid Vault login, no group -> fail closed"
check "mcp-client-unlisted gets 401" wait_for_log mcp-client-unlisted '.event == "mcp_call_failed" and .status == 401'

log "A9  Central revocation: remove orders-agent from mcp-orders-reader in Vault"
READER_MEMBERS="$(reader_members)"
agent_id="$(vault_cmd read -format=json identity/entity/name/mcp-client-orders-agent | jq -r .data.id)"
without="$(tr ',' '\n' <<<"${READER_MEMBERS}" | grep -vx "${agent_id}" | paste -sd, - || true)"
vault_cmd write identity/group/name/mcp-orders-reader type=internal member_entity_ids="${without}" >/dev/null
fresh="$(kubectl exec -n mcp-client-orders-agent deploy/mcp-client -c vault-proxy -- vault read -address=unix:///run/vault/proxy.sock -field=token identity/oidc/token/mcp-orders)"
check "a freshly minted orders-agent token now gets 401" test "$(mcp_rpc "${fresh}" tools/list | cut -d' ' -f1)" = 401
vault_cmd write identity/group/name/mcp-orders-reader type=internal member_entity_ids="${READER_MEMBERS}" >/dev/null
READER_MEMBERS=""
fresh="$(kubectl exec -n mcp-client-orders-agent deploy/mcp-client -c vault-proxy -- vault read -address=unix:///run/vault/proxy.sock -field=token identity/oidc/token/mcp-orders)"
check "access returns once membership is restored" test "$(mcp_rpc "${fresh}" tools/list | cut -d' ' -f1)" = 200

log "A10 Laptop client via task mcp:token"
laptop="$(scripts/mcp-token.sh)"
rows="$(mcp_tool "${laptop}" list_orders '{"status":"pending"}' | jq -r '.structuredContent.result | length')"
check "laptop token lists pending orders (${rows} rows)" test "${rows:-0}" -ge 1

log "A11 Vault audit log: who touched what"
# Successful responses only (no error), excluding this script's own root-token calls
ok="$(kubectl logs vault-0 -n vault --since-time="${START}" | grep '^{' \
  | jq -c 'select(.type == "response" and (.error // "") == "" and .auth.display_name != "root") | {p: .request.path, ns: .auth.metadata.service_account_namespace}')"
db_ns="$(jq -r 'select(.p == "database/creds/preview-orders") | .ns' <<<"${ok}" | sort -u | paste -sd, -)"
mint_ns="$(jq -r 'select(.p == "identity/oidc/token/mcp-orders") | .ns' <<<"${ok}" | sort -u | paste -sd, -)"
# Proxy serves the server's lease from its cache, so there may be no fresh read in this window at all
check "database credentials issued only to the server (${db_ns:-no new lease in this window})" bash -c '[ -z "$1" ] || [ "$1" = "mcp-server-orders-preview" ]' _ "${db_ns}"
check "identity tokens issued only to mcp-client-* identities (${mint_ns})" bash -c '! tr , "\n" <<<"$1" | grep -qv "^mcp-client-"' _ "${mint_ns}"
denials="$(kubectl logs vault-0 -n vault --since-time="${START}" | grep '^{' | jq -r 'select(.type == "response" and (.error // "" | test("permission denied"))) | "\(.auth.metadata.service_account_namespace) \(.request.path)"' | sort -u)"
echo "${denials}" | sed 's/^/    denied: /'
check "A3 and A4 denials are in the audit log" bash -c 'grep -q "^mcp-server-orders-preview identity/oidc/token/mcp-orders$" <<<"$1" && grep -q "^mcp-client-orders-agent database/creds/preview-orders$" <<<"$1"' _ "${denials}"

echo
if [ "${FAILURES}" -gt 0 ]; then
  err "${FAILURES} check(s) failed"
  exit 1
fi
log "A1-A11 passed"
