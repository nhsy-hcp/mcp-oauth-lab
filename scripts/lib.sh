#!/bin/bash
# Shared helpers, sourced by other scripts (not run directly).
#
# Secrets (root token, unseal keys, passwords, JWTs) are always passed on stdin, never as
# command-line arguments, so they do not show up in `ps` or in the kubectl exec request URL.
#
# Usage: source "$(dirname "$0")/lib.sh"
set -euo pipefail

VAULT_NS="${VAULT_NS:-vault}"
VAULT_POD="${VAULT_POD:-vault-0}"
INIT_FILE="${INIT_FILE:-vault-init.json}"
SERVERS_FILE="${SERVERS_FILE:-vault/servers.json}"
CLIENTS_FILE="${CLIENTS_FILE:-vault/mcp-clients.json}"
AUTH_MOUNT="auth/kubernetes"
KUBECONTEXT="${KUBECONTEXT:-k3d-vault-mcp-lab}" # set by Taskfile.yml; the default is for scripts run directly

log() { printf '==> %s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

# Always target the lab, whichever kubectl context is currently selected.
kubectl() { command kubectl --context "${KUBECONTEXT}" "$@"; }

# Root token from vault-init.json (demo only; production revokes the root token).
root_token() {
  [ -f "${INIT_FILE}" ] || { err "${INIT_FILE} not found - run task init:vault"; return 1; }
  jq -r '.root_token' "${INIT_FILE}"
}

# Inside vault-0: read the token from the first stdin line, then exec vault with the rest of stdin.
# shellcheck disable=SC2016 # expanded by the pod's sh, not here
VAULT_EXEC_WRAPPER='IFS= read -r VAULT_TOKEN; export VAULT_TOKEN; exec vault "$@"'

# Run a vault CLI command inside vault-0 with VAULT_TOKEN (sent on stdin). No other stdin.
vault_cmd() {
  printf '%s\n' "${VAULT_TOKEN:?VAULT_TOKEN must be set}" \
    | kubectl exec -i "${VAULT_POD}" -n "${VAULT_NS}" -- sh -c "${VAULT_EXEC_WRAPPER}" sh "$@"
}

# Like vault_cmd, but forwards the caller's stdin after the token, for `vault ... -` or key=- inputs.
vault_cmd_in() {
  { printf '%s\n' "${VAULT_TOKEN:?VAULT_TOKEN must be set}"; cat; } \
    | kubectl exec -i "${VAULT_POD}" -n "${VAULT_NS}" -- sh -c "${VAULT_EXEC_WRAPPER}" sh "$@"
}

# Run a vault CLI command inside vault-0 without a token (status, init, unseal). Stdin is passed through.
vault_cmd_notoken() {
  kubectl exec -i "${VAULT_POD}" -n "${VAULT_NS}" -- vault "$@"
}

# Run psql inside the postgres pod as <user> with <password> sent on stdin.
# Usage: psql_as <user> <password> <psql args...>
psql_as() {
  local user="$1" password="$2"
  shift 2
  # shellcheck disable=SC2016 # expanded by the pod's sh, not here
  printf '%s\n' "${password}" | kubectl exec -i deploy/postgres -n postgres -- \
    sh -c 'IFS= read -r PGPASSWORD; export PGPASSWORD; exec psql "$@"' sh -h 127.0.0.1 -U "${user}" "$@"
}

# Number of PostgreSQL roles named <role>: 1 while a dynamic user exists, 0 once Vault dropped it.
# Usage: pg_role_count <role>
pg_role_count() {
  kubectl exec deploy/postgres -n postgres -- psql -U postgres -Atc \
    "SELECT count(*) FROM pg_roles WHERE rolname = '$1'"
}

# Accessor of auth/kubernetes (alias metadata in templates is addressed by accessor). Needs VAULT_TOKEN.
auth_accessor() {
  local accessor
  accessor="$(vault_cmd auth list -format=json | jq -r --arg m "${AUTH_MOUNT#auth/}/" '.[$m].accessor // empty')"
  [ -n "${accessor}" ] || { err "${AUTH_MOUNT} is not enabled - run task config:k8s-auth"; return 1; }
  printf '%s\n' "${accessor}"
}

# --- MCP helpers (demo scripts) --------------------------------------------------------------------
MCP_URL="http://127.0.0.1:${MCP_HOST_PORT:-8000}/mcp"
SERVER_NS="${SERVER_NS:-mcp-server-orders-preview}"

pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; FAILURES=$((${FAILURES:-0} + 1)); }
check() { # check <description> <command...>: PASS if the command succeeds
  local desc="$1"
  shift
  if "$@"; then pass "${desc}"; else fail "${desc}"; fi
}

# POST one JSON-RPC request to the MCP server (stateless, JSON responses).
# Usage: mcp_rpc <bearer-token|""> <method> [params-json]   -> prints "<http-status> <body>"
mcp_rpc() {
  local token="$1" method="$2" params="${3:-}"
  [ -n "${params}" ] || params='{}'
  # The bearer header goes to curl on stdin (-H @-), never on its command line; printf is a builtin.
  { [ -z "${token}" ] || printf 'Authorization: Bearer %s\n' "${token}"; } \
    | curl -s -o /dev/stdout -w ' %{http_code}' -X POST "${MCP_URL}" -H @- \
      -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
      -d "$(jq -cn --arg m "${method}" --argjson p "${params}" '{jsonrpc: "2.0", id: 1, method: $m, params: $p}')" \
      | awk '{status=$NF; $NF=""; print status, $0}'
}

# Call a tool and print the JSON-RPC result (or nothing on HTTP error). Usage: mcp_tool <token> <tool> [args-json]
mcp_tool() {
  local out args="${3:-}"
  [ -n "${args}" ] || args='{}'
  out="$(mcp_rpc "$1" tools/call "$(jq -cn --arg n "$2" --argjson a "${args}" '{name: $n, arguments: $a}')")"
  [ "${out%% *}" = 200 ] && printf '%s\n' "${out#* }" | jq -c '.result'
}

# vault read through a pod's own Proxy (its identity, its policy). Prints the HTTP-ish outcome: ok | denied | error
# Usage: proxy_read <namespace> <deployment> <path>
proxy_read() {
  local out
  if out="$(kubectl exec -n "$1" "deploy/$2" -c vault-proxy -- vault read -address=unix:///run/vault/proxy.sock -format=json "$3" 2>&1)"; then
    echo ok
  elif grep -q 'permission denied' <<<"${out}"; then
    echo denied
  else
    echo error
  fi
}
