#!/bin/bash
# Headless OAuth login for demos and CI: acts as the browser for a Dex static user and prints the access token.
# Runs the same authorization code + PKCE flow as a real client, through Better Auth, Dex and the consent page.
#
# Usage: scripts/oauth-login.sh <user>
# Env: DEX_STATIC_PASSWORD (default: password), OAUTH_SCOPE, OAUTH_TOKEN_FIELD (default: access_token),
#      OAUTH_COOKIE_JAR (keep the browser session), AUTH_HOST_PORT, MCP_HOST_PORT
#      For negative tests: OAUTH_CONSENT_SCOPE (post these scopes to the consent API), OAUTH_OMIT_RESOURCE=true
set -euo pipefail

LOGIN_USER="${1:?Usage: oauth-login.sh <user>}"
PASSWORD="${DEX_STATIC_PASSWORD:-password}"
AUTH_URL="http://localhost:${AUTH_HOST_PORT:-3000}"
API="${AUTH_URL}/api/auth"
RESOURCE="http://localhost:${MCP_HOST_PORT:-8000}/mcp"
CLIENT_ID="lab-cli"
REDIRECT_URI="http://127.0.0.1:8976/callback"
SCOPE="${OAUTH_SCOPE:-openid profile email offline_access orders:list orders:get whoami}"
TOKEN_FIELD="${OAUTH_TOKEN_FIELD:-access_token}"

tmp_root="$(cd "$(dirname "$0")/.." && pwd)/.tmp"
mkdir -p "${tmp_root}"
work="$(mktemp -d "${tmp_root}/oauth-login.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
jar="${OAUTH_COOKIE_JAR:-${work}/cookies}"
body="${work}/body"

die() {
  printf 'oauth-login: %s\n' "$*" >&2
  exit 1
}

uri() { jq -rn --arg v "$1" '$v | @uri'; }
query_param() { # query_param <url> <name>
  printf '%s\n' "${1#*\?}" | tr '&' '\n' | sed -n "s/^$2=//p" | head -1 # still URL-encoded
}
unescape_html() { sed -e 's/&#34;/"/g' -e 's/&#39;/'"'"'/g' -e 's/&#60;/</g' -e 's/&#62;/>/g' -e 's/&quot;/"/g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&#38;/\&/g' -e 's/&amp;/\&/g'; }
http() { curl -sS --noproxy '*' -m 15 -b "${jar}" -c "${jar}" -H 'Accept: text/html' -o "${body}" -w '%{http_code} %{redirect_url}' "$@"; }

verifier="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')"
challenge="$(printf '%s' "${verifier}" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
state="$(openssl rand -hex 16)"

url="${API}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(uri "${REDIRECT_URI}")&scope=$(uri "${SCOPE}")&state=${state}&code_challenge=${challenge}&code_challenge_method=S256&resource=$(uri "${RESOURCE}")"
result="$(http "${url}")"
code=""

for _ in $(seq 1 25); do
  status="${result%% *}"
  next="${result#* }"
  case "${status}" in
    30[1237])
      case "${next}" in
        "${REDIRECT_URI}"*)
          [ "$(query_param "${next}" state)" = "${state}" ] || die "state mismatch"
          code="$(query_param "${next}" code)"
          [ -n "${code}" ] || die "authorization refused: $(query_param "${next}" error)"
          break
          ;;
      esac
      url="${next}"
      result="$(http "${url}")"
      ;;
    200)
      if grep -q 'name="password"' "${body}"; then
        action="$(sed -n 's/.*<form[^>]*action="\([^"]*\)".*/\1/p' "${body}" | head -1 | unescape_html)"
        case "${action}" in
          http*) url="${action}" ;;
          /*) url="$(printf '%s' "${url}" | sed -E 's#^(https?://[^/]+).*#\1#')${action}" ;;
          "") ;;
          *) die "unexpected login form action" ;;
        esac
        result="$(printf '%s' "${PASSWORD}" | http --data-urlencode "login=${LOGIN_USER}@lab.local" --data-urlencode 'password@-' "${url}")"
      elif grep -q 'name="oauth_query"' "${body}"; then
        sed -n 's/.*name="oauth_query" value="\([^"]*\)".*/\1/p' "${body}" | head -1 | unescape_html | tr -d '\n' >"${work}/oauth_query"
        if [ -n "${OAUTH_CONSENT_SCOPE:-}" ]; then
          jq -n --arg scope "${OAUTH_CONSENT_SCOPE}" --rawfile query "${work}/oauth_query" '{accept: true, scope: $scope, oauth_query: $query}' \
            | curl -sS --noproxy '*' -m 15 -b "${jar}" -c "${jar}" -o "${body}" -H "Origin: ${AUTH_URL}" -H 'Content-Type: application/json' -H 'Accept: application/json' -d @- "${API}/oauth2/consent"
          next="$(jq -r '.url // empty' "${body}")"
          [ -n "${next}" ] || die "consent refused: $(jq -r '.error_description // .error // "unknown error"' "${body}")"
          case "${next}" in /*) next="${AUTH_URL}${next}" ;; esac
          result="302 ${next}"
        else
          url="${AUTH_URL}/consent"
          result="$(http -H "Origin: ${AUTH_URL}" --data-urlencode 'accept=true' --data-urlencode "oauth_query@${work}/oauth_query" "${url}")"
        fi
      else
        die "unexpected page at ${url%%\?*}"
      fi
      ;;
    401) die "login rejected for ${LOGIN_USER}" ;;
    *) die "HTTP ${status} at ${url%%\?*}: $(head -c 200 "${body}")" ;;
  esac
done
[ -n "${code}" ] || die "login did not finish"

resource_arg="resource=${RESOURCE}"
[ "${OAUTH_OMIT_RESOURCE:-false}" != true ] || resource_arg="unused=1"
curl -sS --noproxy '*' -m 15 -o "${body}" "${API}/oauth2/token" \
  --data-urlencode 'grant_type=authorization_code' --data-urlencode "client_id=${CLIENT_ID}" \
  --data "code=${code}" --data-urlencode "code_verifier=${verifier}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" --data-urlencode "${resource_arg}"
value="$(jq -r --arg f "${TOKEN_FIELD}" '.[$f] // empty' "${body}")"
[ -n "${value}" ] || die "no token issued: $(jq -r '.error_description // .error // "unknown error"' "${body}")"
printf '%s\n' "${value}"
