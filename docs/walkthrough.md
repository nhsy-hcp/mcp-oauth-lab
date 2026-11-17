# Walkthrough

Build the lab, then go through the scenarios in demo order. Every scenario is automated, so
`task demo:mcp demo:mcp-auth` runs them all and exits non-zero on any failure.

## Build

```bash
task init           # hooks, Helm repo, .env, app venv
task all            # cluster -> Vault -> PostgreSQL -> database/ -> auth/kubernetes -> server -> broker -> clients
task status
```

`127.0.0.1:8000` must be free; check with `lsof -nP -iTCP:8000 -sTCP:LISTEN`. To use another port, run
`task all mcp_host_port=8001`. The port is fixed when the cluster is created.

## 1. The endpoint is closed without a Vault identity (A1)

```bash
curl -si -X POST localhost:8000/mcp -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer error="invalid_token", ..., resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp"
```

## 2. The laptop gets a 5-minute token from Vault (A10)

```bash
TOKEN=$(task mcp:token)
cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null; echo   # iss, aud=mcp-orders, groups, exp
```

Call a tool with the MCP Inspector CLI. Its flags vary by version; `curl` in the README always works. The
Inspector only takes the header as an argument, so the token is visible in `ps` for the run; the README `curl` and
`headersHelper` keep it on stdin.

```bash
npx @modelcontextprotocol/inspector --cli http://localhost:8000/mcp --transport http \
  --header "Authorization: Bearer $TOKEN" --method tools/call --tool-name list_orders --tool-arg status=pending
```

Or with Claude Code. Approve the project server in `.mcp.json` the first time:

```bash
claude   # then: "Which preview orders are pending, and which database user did the server use?"
```

`.mcp.json` runs `scripts/mcp-headers.sh` as a `headersHelper`, so Claude Code always gets a fresh token.

## 3. Client pods authenticate with nothing but their ServiceAccount (A2, A7, A8)

```bash
task logs NS=mcp-client-orders-agent      # tools_listed (3), tool_called ... is_error=false
task logs NS=mcp-client-reporting-agent   # get_order -> "not permitted" (group mcp-orders-reporter)
task logs NS=mcp-client-unlisted          # mcp_call_failed status=401 (valid Vault login, no group)
task logs NS=mcp-client-orders-agent C=vault-proxy
```

## 4. Each side can do exactly one thing in Vault (A3, A4, M3–M5)

```bash
kubectl exec -n mcp-server-orders-preview deploy/mcp-orders -c vault-proxy -- \
  vault read -address=unix:///run/vault/proxy.sock identity/oidc/token/mcp-orders     # 403
kubectl exec -n mcp-client-orders-agent deploy/mcp-client -c vault-proxy -- \
  vault read -address=unix:///run/vault/proxy.sock database/creds/preview-orders       # 403
```

## 5. Forged and expired tokens (A5, A6)

`task demo:mcp-auth` flips one character of a real token's signature and gets `401`. It then sets the token TTL to
`demo_token_ttl` (1 minute), waits for a token to expire, replays it (`401`) and restores the TTL.

## 6. Central revocation (A9)

Removing a client from its Vault group takes effect on its next token:

```bash
scripts/vault.sh read identity/group/name/mcp-orders-reader
# demo:mcp-auth removes orders-agent, shows a fresh token gets 401, then restores membership
```

## 7. The server's own credentials (M1, M2, M6–M8)

```bash
task demo:mcp
task logs C=app | grep -E 'creds_acquired|pool_opened'
scripts/vault.sh lease revoke -prefix database/creds/preview-orders   # server recovers with a new user (M7)
```

## 8. Audit (A11)

```bash
kubectl logs vault-0 -n vault | grep '^{' | jq -c 'select(.type=="response") |
  {path: .request.path, ns: .auth.metadata.service_account_namespace, error}' | sort | uniq -c
```

Only `mcp-server-orders-preview` receives `database/creds/preview-orders`. Only `mcp-client-*` identities receive
`identity/oidc/token/mcp-orders`. The denied attempts are logged too.

## 9. Recreated ServiceAccounts (A12)

A recreated ServiceAccount has a new UID, so Vault sees a new alias. `task config:mcp-auth` moves the client's
named entity onto the new UID, including when the new SA already logged in and Vault made an unnamed entity for
it. `demo:mcp-auth` simulates both cases on orders-agent and re-runs the script.

## Scenario index

| # | Scenario | Expected |
| --- | --- | --- |
| M1 | Tools work with no secret in the pod | Rows from `orders.items` |
| M2 | Dynamic user per lease | `v-…` user, ≤ 10 min left |
| M3–M5 | Server policy is one exact path | Own path 200; other app or environment 403 |
| M6 | No secrets in the app container | No token, no password, no `/var/run/secrets` |
| M7 | Break-glass revoke | New user within seconds; old one dropped |
| M8 | Schema isolation | No tool for `payments`; `SELECT` refused; canary never returned |
| A1 | No token | `401` + `WWW-Authenticate` with `resource_metadata` |
| A2 | Authorised client pod | 3 tools, rows returned |
| A3 | Server cannot mint client tokens | `403` |
| A4 | Client cannot read database credentials | `403` |
| A5 | Forged signature | `401` |
| A6 | Expired token replayed | `401` |
| A7 | Tool outside the client's group | Tool error: not permitted |
| A8 | Valid Vault login, no group | `401` |
| A9 | Group membership removed in Vault | Fresh token `401`; restored → `200` |
| A10 | Laptop via `task mcp:token` | Rows returned; no laptop Vault token left alive |
| A11 | Audit log | Credentials and tokens issued only to the expected identities; denials recorded |
| A12 | `config:mcp-auth` re-run after a ServiceAccount is recreated | Alias follows the new UID; group membership kept |
