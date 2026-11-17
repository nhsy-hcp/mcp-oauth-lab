#!/bin/bash
# Open the MCP Inspector web UI on the MCP server, already authenticated with a fresh 5-minute Vault identity JWT.
#
# The JWT goes into a read-only Inspector config file (.tmp/mcp-inspector.json, mode 600, same shape as
# .mcp.json), never into argv (visible in ps). The file exists only while the Inspector runs; one Inspector at a time.
#
# Usage: scripts/mcp-inspector.sh <inspector-version> <mcp-url>   start the Inspector
#        scripts/mcp-inspector.sh --refresh                        new token for the running Inspector, then reconnect
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG=".tmp/mcp-inspector.json"
# Matches the Inspector process started below (npm exec and node both carry these arguments)
RUNNING_PATTERN="inspector.* --config ${CONFIG}"

inspector_running() { pgrep -f -- "${RUNNING_PATTERN}" >/dev/null 2>&1; }

write_config() {
  local url="$1" tmp
  mkdir -p .tmp
  tmp="$(umask 077 && mktemp .tmp/mcp-inspector.XXXXXX)"
  # The JWT reaches jq on stdin (-R), never as an argument
  if ! scripts/mcp-token.sh | jq -R --arg url "${url}" \
    '{mcpServers: {orders: {type: "http", url: $url, headers: {Authorization: ("Bearer " + .)}}}}' >"${tmp}"; then
    rm -f "${tmp}"
    return 1
  fi
  mv -f "${tmp}" "${CONFIG}"
}

case "${1:-}" in
  --refresh)
    [ $# -eq 1 ] || { echo "Usage: $0 --refresh" >&2; exit 2; }
    if [ ! -f "${CONFIG}" ] || ! inspector_running; then
      echo "ERROR: no running Inspector - start one with: task mcp:inspector" >&2
      exit 1
    fi
    # Keep the URL the running Inspector was started with
    url="$(jq -r '.mcpServers.orders.url' "${CONFIG}")"
    write_config "${url}"
    echo "New 5-minute token written to ${CONFIG}. In the Inspector, disconnect and connect again (reload if needed)."
    ;;
  "" | -*)
    echo "Usage: $0 <inspector-version> <mcp-url> | --refresh" >&2
    exit 2
    ;;
  *)
    [ $# -eq 2 ] || { echo "Usage: $0 <inspector-version> <mcp-url>" >&2; exit 2; }
    version="$1"
    url="$2"
    if inspector_running; then
      echo "ERROR: an Inspector is already running on ${CONFIG} - use it, or stop it first (Ctrl+C)" >&2
      exit 1
    fi
    write_config "${url}"
    trap 'rm -f "${CONFIG}"' EXIT
    # Third-party code: never hand it the root token that the Taskfile loads from .env
    unset VAULT_TOKEN VAULT_NAMESPACE
    echo "Inspector server 'orders' -> ${url}, Authorization header pre-set (token valid 5 minutes)."
    echo "When calls return 401, run: task mcp:inspector:refresh, then reconnect."
    npx -y "@modelcontextprotocol/inspector@${version}" --web --config "${CONFIG}"
    ;;
esac
