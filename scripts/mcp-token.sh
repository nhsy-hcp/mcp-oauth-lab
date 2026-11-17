#!/bin/bash
# Print a short-lived Vault identity JWT (aud=mcp-orders) for the laptop MCP client. Nothing long-lived is used:
#   1. a 10-minute ServiceAccount token for mcp-client-laptop-sa (audience vault)
#   2. Kubernetes-auth login on localhost:8200 -> a Vault token that can only mint this JWT
#   3. read identity/oidc/token/mcp-orders, then revoke the Vault token straight away
# Only the JWT reaches stdout. The root token from .env is never used.
#
# Usage: scripts/mcp-token.sh | sed 's/^/Authorization: Bearer /' | curl -H @- ...   (header on stdin, not argv)
set -euo pipefail

NS="mcp-client-laptop"
SA="${NS}-sa"
ROLE="${MCP_TOKEN_ROLE:-mcp-orders}"
export VAULT_ADDR="${MCP_VAULT_ADDR:-http://127.0.0.1:8200}"
unset VAULT_TOKEN VAULT_NAMESPACE # never fall back to the root token loaded from .env

sa_jwt="$(kubectl create token "${SA}" -n "${NS}" --audience vault --duration 10m)"
# The SA token goes on stdin (jwt=-), never on the command line
vault_token="$(printf '%s' "${sa_jwt}" | vault write -field=token auth/kubernetes/login role=mcp-client jwt=-)"
unset sa_jwt
export VAULT_TOKEN="${vault_token}"
unset vault_token

status=0
jwt="$(vault read -field=token "identity/oidc/token/${ROLE}")" || status=$?
vault token revoke -self >/dev/null 2>&1 || echo "WARNING: could not revoke the laptop's Vault token" >&2
[ "${status}" -eq 0 ] || exit "${status}"
printf '%s\n' "${jwt}"
