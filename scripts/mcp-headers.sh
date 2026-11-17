#!/bin/bash
# Claude Code headersHelper (see .mcp.json): prints the Authorization header as JSON with a fresh
# Vault identity JWT, so the MCP client never stores a long-lived credential.
set -euo pipefail
cd "$(dirname "$0")/.."
# The JWT reaches jq on stdin, never as an argument (visible in ps).
scripts/mcp-token.sh | jq -cR '{Authorization: ("Bearer " + .)}'
