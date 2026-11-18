#!/bin/bash
# H1-H13: people sign in through Better Auth and Dex, and only get the access their groups allow.
#
# Usage: scripts/demo-human-auth.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

API="http://localhost:${AUTH_HOST_PORT:-3000}/api/auth"
mkdir -p .tmp
work="$(mktemp -d .tmp/demo-human.XXXXXX)"
trap 'rm -rf "${work}"' EXIT

login() { scripts/oauth-login.sh "$@"; }
tool_ok() { [ "$(jq -r '.isError // false' <<<"$1")" = false ] && [ -n "$1" ]; }
tool_denied() { [ "$(jq -r '.isError // false' <<<"$1")" = true ] && grep -q 'permission denied' <<<"$1"; }

log "H1  testuser signs in and uses reader tools"
reader="$(login testuser)"
out="$(mcp_tool "${reader}" list_orders '{"status":"pending"}')"
check "H1 list_orders returns orders" grep -q acme-ltd <<<"${out}"
who="$(mcp_tool "${reader}" whoami)"
check "H1 whoami names testuser" grep -q testuser <<<"${who}"

log "H2  no user can delete orders"
check "H2 delete_order denied" tool_denied "$(mcp_tool "${reader}" delete_order '{"order_id":1}')"

log "H3  reportuser asks for everything and only receives orders:list"
report="$(login reportuser)"
scopes="$(jwt_payload "${report}" | jq -r .scope)"
check "H3 token has orders:list" grep -qw 'orders:list' <<<"${scopes}"
if grep -Eq 'orders:get|whoami' <<<"${scopes}"; then fail "H3 token has extra scopes: ${scopes}"; else pass "H3 token has no other tool scope"; fi
check "H3 get_order denied" tool_denied "$(mcp_tool "${report}" get_order '{"order_id":1}')"
check "H3 list_orders works" tool_ok "$(mcp_tool "${report}" list_orders)"

log "H4  a user with no mapped group gets no token"
if login nogroupuser >/dev/null 2>"${work}/h4"; then fail "H4 nogroupuser received a token"; fi
check "H4 refused at consent" grep -q 'no requested scope is allowed' "${work}/h4"

log "H5  a wrong password gets no token"
if DEX_STATIC_PASSWORD=wrong-password login testuser >/dev/null 2>"${work}/h5"; then fail "H5 wrong password received a token"; fi
check "H5 refused by Dex" grep -q 'login rejected' "${work}/h5"

log "H6  only access tokens are accepted as bearer tokens"
id_token="$(OAUTH_TOKEN_FIELD=id_token login testuser)"
status="$(mcp_rpc "${id_token}" tools/list | awk '{print $1}')"
check "H6 ID token gets 401 (got ${status})" [ "${status}" = 401 ]
session_jwt_status="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "${API}/token")"
check "H6 session JWT endpoint is disabled (got ${session_jwt_status})" [ "${session_jwt_status}" = 404 ]

log "H7  a user cannot change their own identity or groups"
OAUTH_COOKIE_JAR="${work}/report.jar" login reportuser >/dev/null
edit_status="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -b "${work}/report.jar" -H "Origin: http://localhost:${AUTH_HOST_PORT:-3000}" \
  -H 'Content-Type: application/json' -d '{"name":"testuser","groups":["mcp-orders-reader"]}' "${API}/update-user")"
check "H7 update-user is disabled (got ${edit_status})" [ "${edit_status}" = 404 ]
again="$(OAUTH_COOKIE_JAR="${work}/report.jar" login reportuser)"
check "H7 identity unchanged" [ "$(jwt_payload "${again}" | jq -r .preferred_username)" = reportuser ]
if jwt_payload "${again}" | jq -r .scope | grep -q 'orders:get'; then fail "H7 scopes widened"; else pass "H7 scopes unchanged"; fi

log "H8  a token request without a resource still gets the checked MCP token"
token="$(OAUTH_OMIT_RESOURCE=true login reportuser)"
check "H8 token is for the MCP server" bash -c 'jq -e --arg r "$2" "[.aud] | flatten | index(\$r)" <<<"$1" >/dev/null' _ "$(jwt_payload "${token}")" "${MCP_RESOURCE}"

log "H9  a direct consent request cannot add scopes"
scopes="$(jwt_payload "$(OAUTH_CONSENT_SCOPE='openid orders:list orders:get whoami' login reportuser)" | jq -r .scope)"
check "H9 token has only orders:list (${scopes})" test "${scopes}" = 'openid orders:list'

log "H10 a refresh cannot add scopes"
refresh="$(OAUTH_TOKEN_FIELD=refresh_token login reportuser)"
widened="$(printf '%s' "${refresh}" | curl -s --noproxy '*' -m 15 "${API}/oauth2/token" --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'client_id=lab-cli' --data-urlencode 'refresh_token@-' --data-urlencode 'scope=orders:list orders:get' --data-urlencode "resource=${MCP_RESOURCE}" | jq -r '.error // "issued"')"
check "H10 refresh refused (${widened})" test "${widened}" = invalid_scope

log "H11 stale or tampered consent cannot grant more than the user's groups"
OAUTH_COOKIE_JAR="${work}/stale.jar" login reportuser >/dev/null
auth_sql "UPDATE \"oauthConsent\" SET scopes = '[\"openid\",\"orders:list\",\"orders:get\"]' WHERE \"userId\" = (SELECT id FROM \"user\" WHERE email = 'reportuser@lab.local')" >/dev/null
if OAUTH_COOKIE_JAR="${work}/stale.jar" OAUTH_SCOPE='openid orders:list orders:get' login reportuser >/dev/null 2>"${work}/h11"; then fail "H11 tampered consent produced a token"; fi
check "H11 refused at token issue" grep -q 'scopes exceed' "${work}/h11"
scopes="$(jwt_payload "$(login reportuser)" | jq -r .scope)"
if grep -q 'orders:get' <<<"${scopes}"; then fail "H11 new sign-in kept stale consent"; else pass "H11 a new sign-in clears stale consent"; fi

log "H12 the sign-out page ends the browser session"
AUTH_URL="${API%/api/auth}"
OAUTH_COOKIE_JAR="${work}/signout.jar" login testuser >/dev/null
session_email() { curl -s --noproxy '*' -m 5 -b "${work}/signout.jar" "${API}/get-session" | jq -r '.user.email // "none"'; }
sign_out() { curl -s --noproxy '*' -m 5 -o /dev/null -w '%{http_code}' -b "${work}/signout.jar" -c "${work}/signout.jar" -H "Origin: $1" -X POST "${AUTH_URL}/sign-out"; }
check "H12 cross-site sign-out refused" test "$(sign_out http://evil.example)" = 403
check "H12 session survives the refused request" test "$(session_email)" = testuser@lab.local
check "H12 sign-out succeeds" test "$(sign_out "${AUTH_URL}")" = 303
check "H12 session has ended" test "$(session_email)" = none

log "H13 refreshing cannot extend a sign-in past its fixed limit"
refresh="$(OAUTH_TOKEN_FIELD=refresh_token login reportuser)"
owner="(SELECT id FROM \"user\" WHERE email = 'reportuser@lab.local')"
id_token="$(auth_sql "SELECT \"idToken\" FROM account WHERE \"providerId\" = 'dex' AND \"userId\" = ${owner}")"
aged="$(jwt_payload "${id_token}" | jq -c --argjson ttl "${SIGN_IN_TTL_SECONDS:-28800}" '.iat -= ($ttl + 60)' | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
# Better Auth verified this token at sign-in; only its stored issue time is aged here.
auth_sql "UPDATE account SET \"idToken\" = '${id_token%%.*}.${aged}.${id_token##*.}' WHERE \"providerId\" = 'dex' AND \"userId\" = ${owner}" >/dev/null
expired="$(printf '%s' "${refresh}" | curl -s --noproxy '*' -m 15 "${API}/oauth2/token" --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'client_id=lab-cli' --data-urlencode 'refresh_token@-' --data-urlencode "resource=${MCP_RESOURCE}")"
check "H13 refresh after the limit is refused ($(jq -r '.error_description // .error // "issued"' <<<"${expired}"))" test "$(jq -r '.error // "issued"' <<<"${expired}")" = invalid_grant
check "H13 a new sign-in works" test -n "$(login reportuser)"

if [ "${FAILURES:-0}" -gt 0 ]; then
  err "${FAILURES} check(s) failed"
  exit 1
fi
log "H1-H13 passed"
