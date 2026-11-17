# Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `task cluster:up`: `127.0.0.1:8000 is already in use` | Another process owns the port (seen: a terminal app) | Free it, or `task clean` then `task all mcp_host_port=<free port>` |
| Every MCP call returns `401` | Token expired (5 min), wrong `aud`/`iss`, or the client is in no known group | Decode the payload: `cut -d. -f2`; check `groups`; `task logs C=app \| grep token_rejected` shows the reason |
| `401` with `reason=no_allowed_group` for a listed client | The ServiceAccount was recreated (new UID), so the alias and group membership no longer match | `task config:mcp-auth` moves the alias to the named entity and rewrites the groups. A pod that logged in before that still holds a token for the old entity: restart it, or wait for Proxy to log in again |
| Tool returns "permission denied: ... not permitted" | The client's group does not map to that tool (`delete_order` maps to none) | Expected (A7, A10). Change `GROUP_TOOLS` in `app/src/mcp_lab/auth.py` or the client's Vault group |
| `421 Invalid Host header` | Host header not in `MCP_ALLOWED_HOSTS` (DNS-rebinding protection) | Use `localhost:<mcp_host_port>` or `127.0.0.1:<mcp_host_port>`; in-cluster use the `mcp-orders.<ns>.svc` name |
| `task mcp:token`: `permission denied` | `config:mcp-auth` not run, or `mcp-client-laptop-sa` missing | `task config:mcp-auth` |
| Client pod logs `identity_token_failed status=403` | The pod's identity lacks the `mcp-client` policy (wrong namespace or SA name) | Namespace must match `mcp-client-*` and the SA `mcp-client-*-sa` |
| Server not ready, `vault_denied` in logs | Proxy not logged in yet, or the SA annotations are missing (templated path does not resolve) | `kubectl get sa -n mcp-server-orders-preview -o yaml`; `task logs C=vault-proxy` |
| After a laptop restart nothing works | Vault is sealed | `task cluster:up` then `task unseal:vault` |
| `task docs:diagrams` fails with `syntax error near '>'` | Raw `<`, `>` or `->` in a Graphviz HTML label | Use `→`, `&lt;` or `&gt;`; line breaks are `<br/>` |
