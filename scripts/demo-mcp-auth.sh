#!/bin/bash
# Pod authentication scenarios A1-A12: pods log in to Better Auth with their ServiceAccount JWT and get
# short-lived, scope-limited tokens. Exits non-zero if any check fails. Restores every change it makes.
#
# Usage: scripts/demo-mcp-auth.sh [demo-token-ttl-seconds]
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

DEMO_TTL="${1:-20}"
NORMAL_TTL="${ACCESS_TOKEN_TTL_SECONDS:-300}"
FAILURES=0
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ORDERS=mcp-client-orders-agent
REPORTING=mcp-client-reporting-agent

client_logs() { kubectl logs -n "$1" deploy/mcp-client -c app --since-time="${START}"; }
wait_for_log() { # wait_for_log <namespace> <jq-filter>: true once a log line matches (up to ~60 s)
  for _ in $(seq 1 30); do
    client_logs "$1" | grep '^{' | jq -e "select($2)" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
# Every Better Auth pod: a pod replaced earlier in this run may still hold some of the events.
auth_logs() { kubectl logs -n better-auth -l app.kubernetes.io/name=better-auth --tail=-1 --since-time="${START}" | grep '^{'; }
set_client_disabled() { auth_sql "UPDATE \"oauthClient\" SET disabled = $2 WHERE \"clientId\" = '$1'" >/dev/null; }
set_token_ttl() {
  kubectl set env deploy/better-auth -n better-auth "ACCESS_TOKEN_TTL_SECONDS=$1" >/dev/null
  kubectl rollout status deploy/better-auth -n better-auth --timeout=2m >/dev/null
  wait_for_auth
}
wait_for_auth() { # until the laptop route has answered five times in a row
  local ok=0
  for _ in $(seq 1 60); do
    if curl -sf --noproxy '*' -m 2 -o /dev/null "http://localhost:${AUTH_HOST_PORT:-3000}/healthz"; then ok=$((ok + 1)); else ok=0; fi
    [ "${ok}" -lt 5 ] || return 0
    sleep 1
  done
  err "Better Auth did not become stable"
  return 1
}
token_of() { jq -r '.access_token // empty' <<<"$1"; }
error_of() { jq -r '.error // empty' <<<"$1"; }
vault_login_refused() { # vault_login_refused <namespace> <role>
  local token out
  token="$(kubectl create token "$1-sa" -n "$1" --audience vault --duration 10m)" || return 1
  if out="$(printf '%s' "${token}" | vault_cmd_notoken write -format=json auth/kubernetes/login role="$2" jwt=- 2>&1)"; then
    return 1
  fi
  grep -Eq 'permission denied|invalid role|service account name not authorized|namespace not authorized' <<<"${out}"
}

restore_service_account() { # The file was rendered by deploy-workloads.sh, so annotations and settings return too.
  kubectl apply -f ".tmp/rendered/${REPORTING}/service-account.yaml" >/dev/null
  kubectl rollout restart deploy/mcp-client -n "${REPORTING}" >/dev/null
}

restore() {
  [ "${CLIENT_DISABLED:-false}" = false ] || set_client_disabled orders-agent false
  [ "${TTL_CHANGED:-false}" = false ] || set_token_ttl "${NORMAL_TTL}"
  if [ "${SA_DELETED:-false}" = true ]; then
    restore_service_account
  fi
}
trap restore EXIT

log "A1  No token"
out="$(curl -s -D - -o /dev/null -X POST "${MCP_URL}" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
check "401 without a bearer token" grep -q '^HTTP/1.1 401' <<<"${out}"
check "WWW-Authenticate points at protected resource metadata" grep -qi '^www-authenticate: Bearer .*resource_metadata=' <<<"${out}"
metadata="$(curl -s "http://127.0.0.1:${MCP_HOST_PORT:-8000}/.well-known/oauth-protected-resource/mcp")"
check "resource metadata names Better Auth" test "$(jq -r '.authorization_servers[0]' <<<"${metadata}")" = "${AUTH_ISSUER}"

log "A2  Authorised client pod (orders-agent)"
check "lists 4 tools (delete_order listed but never granted)" wait_for_log "${ORDERS}" '.event == "tools_listed" and (.tools | length) == 4'
check "list_orders returns rows" wait_for_log "${ORDERS}" '.event == "tool_called" and .tool == "list_orders" and .is_error == false'
subset="$(machine_token "$(sa_assertion "${ORDERS}")" 'orders:list')"
check "a token holds only the requested scope" test "$(jwt_payload "$(token_of "${subset}")" | jq -r .scope)" = 'orders:list'

log "A3-A4  The server is not an OAuth client, and client pods have no Vault access"
check "A3 the server's ServiceAccount is refused at the token endpoint" test "$(error_of "$(machine_token "$(sa_assertion "${SERVER_NS}")")")" = invalid_client
check "A4 client ServiceAccount cannot use the server's Vault role" vault_login_refused "${ORDERS}" mcp-server
check "A4 no Vault role exists for MCP clients" vault_login_refused "${ORDERS}" mcp-client
containers="$(kubectl get deploy mcp-client -n "${ORDERS}" -o jsonpath='{.spec.template.spec.initContainers[*].name} {.spec.template.spec.containers[*].name}')"
check "A4 client pods run no Vault Proxy (${containers# })" bash -c '! grep -q vault-proxy <<<"$1"' _ "${containers}"

log "A5  Forged tokens"
token="$(token_of "$(machine_token "$(sa_assertion "${ORDERS}")")")"
sig="${token##*.}"
first="${sig:0:1}"
[ "${first}" = A ] && swap=B || swap=A
check "tampered signature -> 401" test "$(mcp_rpc "${token%.*}.${swap}${sig:1}" tools/list | cut -d' ' -f1)" = 401
payload="${token#*.}"
payload="${payload%%.*}"
none_header="$(printf '{"alg":"none","typ":"at+jwt"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
check "alg=none -> 401" test "$(mcp_rpc "${none_header}.${payload}." tools/list | cut -d' ' -f1)" = 401
jwt_header="$(printf '{"alg":"ES256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
check "wrong typ -> 401" test "$(mcp_rpc "${jwt_header}.${payload}.${sig}" tools/list | cut -d' ' -f1)" = 401
check "the genuine token still works" test "$(mcp_rpc "${token}" tools/list | cut -d' ' -f1)" = 200

log "A6  Expired token (access token TTL temporarily ${DEMO_TTL}s)"
TTL_CHANGED=true
set_token_ttl "${DEMO_TTL}"
short="$(token_of "$(machine_token "$(sa_assertion "${ORDERS}")")")"
exp="$(jwt_payload "${short}" | jq -r .exp)"
check "short token works while valid" test "$(mcp_rpc "${short}" tools/list | cut -d' ' -f1)" = 200
wait_s=$((exp - $(date +%s) + 3))
echo "    waiting ${wait_s}s for the token to expire..."
[ "${wait_s}" -le 0 ] || sleep "${wait_s}"
check "replayed after expiry -> 401" test "$(mcp_rpc "${short}" tools/list | cut -d' ' -f1)" = 401
set_token_ttl "${NORMAL_TTL}"
TTL_CHANGED=false

log "A7  Tool outside the client's scopes (reporting-agent calls get_order)"
check "get_order -> tool error, not permitted" wait_for_log "${REPORTING}" '.event == "tool_called" and .tool == "get_order" and .is_error == true and (.text | test("not permitted"))'
check "list_orders still allowed" wait_for_log "${REPORTING}" '.event == "tool_called" and .tool == "list_orders" and .is_error == false'

log "A8  Valid ServiceAccount, no OAuth client -> fail closed"
check "mcp-client-unlisted is refused at the token endpoint" wait_for_log mcp-client-unlisted '.event == "mcp_call_failed" and .error == "token_unavailable" and .status == 401'

log "A9  Central revocation: disable the orders-agent OAuth client"
CLIENT_DISABLED=true
set_client_disabled orders-agent true
check "a disabled client gets no new token" test "$(error_of "$(machine_token "$(sa_assertion "${ORDERS}")")")" = invalid_client
set_client_disabled orders-agent false
CLIENT_DISABLED=false
check "access returns once the client is enabled" test -n "$(token_of "$(machine_token "$(sa_assertion "${ORDERS}")")")"

log "A10 A pod cannot obtain a scope it was not granted"
check "reporting-agent asking for orders:get -> invalid_scope" test "$(error_of "$(machine_token "$(sa_assertion "${REPORTING}")" 'orders:get')")" = invalid_scope

log "A11 Audit: who received what"
ok="$(kubectl logs vault-0 -n vault --since-time="${START}" | grep '^{' \
  | jq -c 'select(.type == "response" and (.error // "") == "" and .auth.display_name != "root") | {p: .request.path, ns: .auth.metadata.service_account_namespace}')"
db_ns="$(jq -r 'select(.p == "database/creds/dev-orders") | .ns' <<<"${ok}" | sort -u | paste -sd, -)"
minted="$(jq -r 'select(.p | startswith("identity/oidc/token/")) | .p' <<<"${ok}" | wc -l | tr -d ' ')"
# Proxy serves the server's lease from its cache, so there may be no fresh read in this window at all
check "database credentials issued only to the server (${db_ns:-no new lease in this window})" bash -c '[ -z "$1" ] || [ "$1" = "$2" ]' _ "${db_ns}" "${SERVER_NS}"
check "Vault issued no identity tokens (${minted})" test "${minted}" = 0
scripts/oauth-login.sh reportuser >/dev/null
events="$(auth_logs)"
clients="$(jq -r 'select(.event == "client_authenticated") | "\(.client)=\(.service_account)"' <<<"${events}" | sort -u | paste -sd, -)"
expected="orders-agent=system:serviceaccount:${ORDERS}:${ORDERS}-sa"
check "the expected pod authenticated as its own client (${clients})" grep -q "${expected}" <<<"${clients}"
check "no ServiceAccount authenticated as another client" bash -c '! tr , "\n" <<<"$1" | grep -Ev "^(orders-agent=system:serviceaccount:$2:$2-sa|reporting-agent=system:serviceaccount:$3:$3-sa)$" | grep -q .' _ "${clients}" "${ORDERS}" "${REPORTING}"
check "user tokens were issued to the signed-in person" bash -c 'jq -e "select(.event == \"token_issued\" and .preferred_username == \"reportuser\")" <<<"$1" >/dev/null' _ "${events}"

log "A12 ServiceAccount tokens must be current and meant for Better Auth"
check "wrong audience -> invalid_client" test "$(error_of "$(machine_token "$(sa_assertion "${ORDERS}" https://kubernetes.default.svc)")")" = invalid_client
stale="$(sa_assertion "${REPORTING}")"
SA_DELETED=true
kubectl delete serviceaccount "${REPORTING}-sa" -n "${REPORTING}" >/dev/null
check "token of a deleted ServiceAccount -> invalid_client" test "$(error_of "$(machine_token "${stale}")")" = invalid_client
restore_service_account
kubectl rollout status deploy/mcp-client -n "${REPORTING}" --timeout=2m >/dev/null
SA_DELETED=false

echo
if [ "${FAILURES}" -gt 0 ]; then
  err "${FAILURES} check(s) failed"
  exit 1
fi
log "A1-A12 passed"
