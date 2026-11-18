# Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `task cluster:up`: `127.0.0.1:<port> is already in use` | Another process owns the MCP, Better Auth or Dex port | Free it, or `task clean` then use `mcp_host_port`, `auth_host_port` or `dex_host_port` |
| Better Auth or Dex is unreachable on an existing cluster | The cluster was created before those port mappings existed | `task clean`, then `task all` |
| Claude Code: `Refusing to send credentials to non-https token endpoint` | The authorization server metadata does not use an exact loopback host | Better Auth's public URL must be `http://localhost:<auth_host_port>`; redeploy it, then authenticate again |
| A pod cannot resolve `auth.localhost` | The CoreDNS override is missing or was not reloaded | `task config:aliases` |
| Every MCP call returns `401` | Token expired (5 min), wrong `aud` or `iss`, or no known scope | Decode the payload with `cut -d. -f2`; `task logs C=app \| grep token_rejected` shows the reason |
| Client pod logs `access_token_failed status=401` | Its ServiceAccount is not mapped to an enabled OAuth client | Expected for `mcp-client-unlisted`. Otherwise check `auth/mcp-clients.json`, run `task auth:deploy`, then `task deploy:mcp-clients` |
| Client pod logs `access_token_failed status=400` with `invalid_scope` | `scopes` in `auth/mcp-clients.json` differs from the deployed client | `task auth:seed-clients`, then `task deploy:mcp-clients` |
| Tool returns "permission denied: ... not permitted" | The token has no scope mapped to that tool (`delete_order` maps to none) | Expected (A7, H2, H3). Change `auth/group_scopes.json` or `auth/mcp-clients.json`, or `app/src/mcp_lab/scope_tools.toml` |
| `oauth-login: no requested scope is allowed` | The user's Dex groups map to no scope | Expected for `nogroupuser`. Otherwise check `templates/dex-config-secret.yaml.tpl` and `auth/group_scopes.json`, run `task install:dex`, then sign in again |
| `oauth-login: login rejected` | Wrong lab password | Use `DEX_STATIC_PASSWORD`, or rerun `task install:dex` after changing it |
| A user's new group has no effect, or the browser signs in as the wrong user | The browser session is still active, and groups are read at the last Dex sign-in | Open `http://localhost:3000/sign-out`, run `claude mcp logout orders`, then sign in again |
| Claude Code says the service doesn't accept sign-ins, or its callback fails | Stored credentials are from an earlier lab, or port `33418` is in use | Free the port, then run `claude mcp logout orders` and `claude mcp login orders` |
| Claude Code asks you to sign in again, or a refresh returns `sign-in has expired` | The sign-in limit passed | Open `http://localhost:3000/sign-out` if the browser is still signed in, then run `claude mcp login orders`. Change the limit with `sign_in_ttl_seconds` |
| Better Auth returns `429` | Too many sign-ins from one address | Wait a few seconds |
| MCP server exits at startup with `scope_tools_invalid` | `scope_tools.toml` is malformed, names a tool the server does not register, or grants `delete_order` | Fix the file named in the error, then `task deploy:mcp-server` |
| `421 Invalid Host header` | Host header not in `MCP_ALLOWED_HOSTS` (DNS-rebinding protection) | Use `localhost:<mcp_host_port>` or `127.0.0.1:<mcp_host_port>`; in-cluster use the `mcp-orders.<ns>.svc` name |
| Server not ready, `vault_denied` in logs | Proxy not logged in yet, or the SA annotations are missing (templated path does not resolve) | `kubectl get sa -n mcp-server-dev -o yaml`; `task logs C=vault-proxy` |
| After a laptop restart nothing works | Vault is sealed | `task cluster:up` then `task unseal:vault` |
| `task docs:diagrams` fails with `syntax error near '>'` | Raw `<`, `>` or `->` in a Graphviz HTML label | Use `→`, `&lt;` or `&gt;`; line breaks are `<br/>` |
