# learn-vault-mcp

Vault Community Edition as an identity broker for MCP auth, on a local k3d cluster.

- Client pods, and your laptop, swap a Kubernetes ServiceAccount identity for a 5-minute Vault identity JWT.
- The MCP server on `http://localhost:8000/mcp` verifies that JWT against Vault's public keys. It allows tools
  according to the client's Vault group.
- The server reads PostgreSQL with dynamic, read-only credentials that last 10 minutes.
- No pod holds a long-lived secret.

Work in progress. See `docs/solution-design.md` once it lands.

## Quick start

```bash
task init
task all
```
