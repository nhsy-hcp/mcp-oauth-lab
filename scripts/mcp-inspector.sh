#!/bin/bash
# Open the MCP Inspector web UI on the MCP server. Sign-in is standard MCP OAuth through Better Auth and Dex.
#
# Usage: scripts/mcp-inspector.sh <inspector-version> <mcp-url>
set -euo pipefail
cd "$(dirname "$0")/.."

[ $# -eq 2 ] || { echo "Usage: $0 <inspector-version> <mcp-url>" >&2; exit 2; }
version="$1"
url="$2"
config=".tmp/mcp-inspector.json"

mkdir -p .tmp
jq -n --arg url "${url}" '{mcpServers: {orders: {type: "http", url: $url}}}' >"${config}"
trap 'rm -f "${config}"' EXIT
# Third-party code: never hand it the root token that the Taskfile loads from .env
unset VAULT_TOKEN VAULT_NAMESPACE
echo "Inspector server 'orders' -> ${url}"
echo "Use OAuth client ID mcp-inspector, then sign in as testuser with the lab password."
npx -y "@modelcontextprotocol/inspector@${version}" --web --config "${config}"
