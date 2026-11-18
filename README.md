# vault-mcp-identity-broker

HashiCorp Vault as an identity broker for MCP auth, on a local k3d cluster.

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

> Disclaimer: lab demo only. This repository is for learning and is not a production reference architecture.
> It runs plain HTTP and a single Vault node.
>
> Enterprise MCP deployments need a production-grade OAuth 2.1 authorization server (an enterprise IdP), as
> described in the [MCP authorization specification](https://modelcontextprotocol.io/specification/latest/basic/authorization).
> Clients then use standard discovery and per-user consent instead of the pre-minted bearer tokens
> used here. See [Limits and next steps](docs/solution-design.md#9-limits-and-next-steps).

## Quick start

```bash
task init     # pre-commit hooks, Helm repo, .env, Python venv
task all      # k3d cluster, Vault, PostgreSQL, auth, MCP server, identity broker, client pods
task test:all # unit tests + live scenarios M1-M8 and A1-A12

# Decode the JWT header and claims (the signature is not printed)
task mcp:token | jq -R 'split(".")[:2][] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson'

# The header goes to curl on stdin (-H @-), so the token never appears in `ps`
task mcp:token | sed 's/^/Authorization: Bearer /' | curl -s -X POST localhost:8000/mcp -H @- \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_orders","arguments":{"status":"pending"}}}'

# No Vault group grants delete_order, so every caller gets "permission denied" and the order is untouched
task mcp:token | sed 's/^/Authorization: Bearer /' | curl -s -X POST localhost:8000/mcp -H @- \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_order","arguments":{"order_id":1}}}'
```

The decode command prints the JWT header and claims. `groups` decides which tools the caller can use, and `exp` is
5 minutes after `iat`:

```json
{
  "alg": "RS256",
  "kid": "6494e274-9b13-55df-41b5-d2b20b4c3679"
}
{
  "application_name": "laptop",
  "aud": "mcp-orders",
  "environment": "preview",
  "exp": 1794996793,
  "groups": [
    "mcp-orders-reader"
  ],
  "iat": 1794996493,
  "iss": "http://vault.vault.svc.cluster.local:8200/v1/identity/oidc",
  "namespace": "root",
  "sub": "5bdf0378-4918-3fc2-41a5-e361b0e26f59",
  "team": "ai-platform"
}
```

For the MCP Inspector web UI (header pre-set), run `task mcp:inspector`; for the Vault UI, run `task ui` (the root
token is copied to the clipboard).

Requirements: Docker or Podman, k3d, kubectl, helm, the vault CLI, jq, uv and task. Port `127.0.0.1:8000` must be
free; otherwise run `task all mcp_host_port=<port>`. Check with `task deps`.

## Docs

- [Solution design](docs/solution-design.md): identities, policies, token flow, threat model.
- [Walkthrough](docs/walkthrough.md): every scenario, step by step.
- [Troubleshooting](docs/troubleshooting.md).

## Related lab

[`learn-vault-proxy`](https://github.com/nhsy-hcp/learn-vault-proxy) is the same Vault Proxy socket pattern applied to plain apps. It
covers KV v2 and outage behaviour, and this lab reuses its credential code.
