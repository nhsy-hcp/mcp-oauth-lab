#!/bin/bash
# Enable auth/kubernetes (Vault's default path) with ServiceAccount annotations as alias metadata, then
# write the templated mcp-server policy (accessor substituted) and the mcp-server role. Safe to re-run.
#
# Usage: scripts/config-k8s-auth.sh <token_ttl> <token_max_ttl>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

TOKEN_TTL="${1:-15m}"
TOKEN_MAX_TTL="${2:-30m}"

VAULT_TOKEN="$(root_token)"
export VAULT_TOKEN

vault_cmd auth enable kubernetes 2>/dev/null || log "${AUTH_MOUNT} already enabled"

kube_host="$(kubectl exec "${VAULT_POD}" -n "${VAULT_NS}" -- printenv KUBERNETES_PORT_443_TCP_ADDR)"
# Vault reads ServiceAccounts with this token, so the SA also needs the vault-sa-reader ClusterRole
reviewer_b64="$(kubectl get secret vault-token-secret -n "${VAULT_NS}" -o jsonpath='{.data.token}')"
[ -n "${reviewer_b64}" ] || { err "vault-token-secret has no token yet - run task config:vault"; exit 1; }
# The JWT goes on stdin (token_reviewer_jwt=-), never on the command line
base64 --decode <<<"${reviewer_b64}" | vault_cmd_in write "${AUTH_MOUNT}/config" \
  kubernetes_host="https://${kube_host}:443" \
  token_reviewer_jwt=- \
  use_annotations_as_alias_metadata=true >/dev/null
log "Configured ${AUTH_MOUNT} (host https://${kube_host}:443, annotations as alias metadata)"

accessor="$(auth_accessor)"
log "Using ${AUTH_MOUNT} accessor ${accessor}"

# Alias metadata is addressed by mount accessor, which is only known after enabling the mount
sed "s/__ACCESSOR__/${accessor}/g" vault/policies/mcp-server.hcl | vault_cmd_in policy write mcp-server - >/dev/null
log "Wrote policy mcp-server"

jq --arg ttl "${TOKEN_TTL}" --arg max "${TOKEN_MAX_TTL}" '.token_ttl = $ttl | .token_max_ttl = $max' vault/roles/mcp-server.json \
  | vault_cmd_in write "${AUTH_MOUNT}/role/mcp-server" - >/dev/null
log "Wrote ${AUTH_MOUNT}/role/mcp-server (token_ttl=${TOKEN_TTL}, token_max_ttl=${TOKEN_MAX_TTL})"
