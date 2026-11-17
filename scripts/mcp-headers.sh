#!/bin/bash
# Claude Code headersHelper (see .mcp.json): prints the Authorization header as JSON with a fresh
# Vault identity JWT, so the MCP client never stores a long-lived credential.
set -euo pipefail
cd "$(dirname "$0")/.."
jwt="$(scripts/mcp-token.sh)"
jq -cn --arg jwt "${jwt}" '{Authorization: ("Bearer " + $jwt)}'
