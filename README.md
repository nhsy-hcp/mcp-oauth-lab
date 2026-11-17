# vault-mcp-identity-broker

HashiCorp Vault as an **identity broker for MCP auth**, on a local k3d cluster.

- **Clients** prove their Kubernetes identity to Vault and receive a **5-minute, audience-bound JWT**:
  - pods, through a Vault Proxy sidecar;
  - your laptop, through `task mcp:token`.
- **The MCP server** on `http://localhost:8000/mcp` verifies the JWT against Vault's public keys. It allows tools
  according to the caller's **Vault identity group**.
- **The server** reads PostgreSQL as a **10-minute, `SELECT`-only user** that Vault creates for it and drops when
  the pod stops.
- **No long-lived secret** anywhere: no API keys, client secrets or static Vault tokens. To revoke a client, remove
  it from a Vault group.

![Architecture](docs/images/architecture.png)

## Quick start

```bash
task init     # pre-commit hooks, Helm repo, .env, Python venv
task all      # k3d cluster, Vault, PostgreSQL, auth, MCP server, identity broker, client pods
task test:all # unit tests + live scenarios M1-M8 and A1-A11

TOKEN=$(task mcp:token)
curl -s -X POST localhost:8000/mcp -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_orders","arguments":{"status":"pending"}}}'
```

Claude Code picks up `.mcp.json` from the project root. Approve the `orders` server once; it fetches a fresh token
through `scripts/mcp-headers.sh`.

Requirements: Docker or Podman, k3d, kubectl, helm, the vault CLI, jq, uv and task. Port `127.0.0.1:8000` must be
free; otherwise run `task all mcp_host_port=<port>`. Check with `task deps`.

## Docs

- [Solution design](docs/solution-design.md): identities, policies, token flow, threat model.
- [Walkthrough](docs/walkthrough.md): every scenario, step by step.
- [Troubleshooting](docs/troubleshooting.md).

## Related lab

[`learn-vault-proxy`](../learn-vault-proxy) is the same Vault Proxy socket pattern applied to plain apps. It
covers KV v2 and outage behaviour, and this lab reuses its credential code.
