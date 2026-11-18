# Walkthrough

Build the lab, then go through the scenarios in demo order. Every scenario is automated, so
`task demo:mcp demo:mcp-auth demo:human-auth` runs them all and exits non-zero on any failure.

## Build

```bash
task init   # hooks, Helm repos, .env, Python and Node packages
task all    # cluster -> aliases -> Vault -> PostgreSQL -> Dex -> Better Auth -> server -> clients
task status
```

`127.0.0.1:8000`, `3000`, `5556` and `8200` must be free. Use `mcp_host_port`, `auth_host_port` or `dex_host_port` to
change the first three, for example `task all auth_host_port=3100`. Ports are fixed when the cluster is created.

## 1. The endpoint is closed without a token (A1)

```bash
curl -si -X POST localhost:8000/mcp -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer error="invalid_token", ..., resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp"

curl -s localhost:8000/.well-known/oauth-protected-resource/mcp | jq .authorization_servers
# ["http://localhost:3000/api/auth"]
```

## 2. A person signs in (H1-H3)

Claude Code reads `.mcp.json`, which holds the pre-registered client ID and callback port. Run `claude`, approve the
`orders` server, and use `/mcp` to authenticate it. Sign in as `testuser@lab.local` with password `password`, allow
access, then ask for the pending orders.

For the MCP Inspector, run `task mcp:inspector` and use OAuth client ID `mcp-inspector`.

Without a browser, `task mcp:login` runs the same flow:

```bash
TOKEN=$(task mcp:login LAB_USER=reportuser)
cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null; echo
# "preferred_username":"reportuser", "scope":"openid profile email offline_access orders:list", ...
```

`oauth-login.sh` asks for every scope. `reportuser` still receives only `orders:list`, because Better Auth narrows the
request at consent.

## 3. Access is decided by Better Auth (H2-H13)

`task demo:human-auth` shows that:

- nobody can call `delete_order`;
- `reportuser` cannot call `get_order`;
- `nogroupuser` gets no token, and neither does a wrong password;
- an ID token is not accepted as an access token;
- a user cannot edit their own identity or groups;
- direct consent requests, widened refreshes and tampered consent records cannot add scopes;
- refreshing cannot extend a sign-in past 8 hours.

To switch user, open http://localhost:3000/sign-out. Dex keeps no login session, so this ends the browser sign-in.
For Claude Code, also run `claude mcp logout orders`.

## 4. Client pods log in with their ServiceAccount (A2, A7, A8, A10)

```bash
task logs NS=mcp-client-orders-agent      # access_token_issued, tools_listed (4), tool_called ... is_error=false
task logs NS=mcp-client-reporting-agent   # get_order -> "not permitted"
task logs NS=mcp-client-unlisted          # mcp_call_failed error=token_unavailable status=401
kubectl --context k3d-mcp-oauth-lab logs -n better-auth deploy/better-auth | grep client_authenticated
```

## 5. Who cannot log in (A3, A4, A12)

The server's ServiceAccount is not an OAuth client. A client's ServiceAccount has no Vault role, and its pod has no Vault
Proxy. A token with the wrong audience, or from a deleted ServiceAccount, is refused.

## 6. Forged and expired tokens (A5, A6)

`task demo:mcp-auth` tampers with a real token and tries `alg=none` and a wrong `typ`, all `401`. It then sets the access
token TTL to `demo_token_ttl_seconds`, waits for a token to expire, replays it (`401`) and restores the TTL.

## 7. Central revocation (A9)

`task demo:mcp-auth` disables the `orders-agent` OAuth client, shows that it gets no new token, then enables it again.
Tokens already issued stop working when they expire, within 5 minutes.

## 8. The server's own credentials (M1-M8)

```bash
task demo:mcp
task logs C=app | grep -E 'creds_acquired|pool_opened'
scripts/vault.sh lease revoke -prefix database/creds/dev-orders   # server recovers with a new user (M7)
```

## 9. Audit (A11)

```bash
kubectl --context k3d-mcp-oauth-lab logs -n better-auth deploy/better-auth | grep -E 'client_authenticated|token_issued|token_refused'
kubectl --context k3d-mcp-oauth-lab logs vault-0 -n vault | grep '^{' | jq -c 'select(.type=="response") |
  {path: .request.path, ns: .auth.metadata.service_account_namespace, error}' | sort | uniq -c
```

Only `mcp-server-dev` receives `database/creds/dev-orders`, and Vault issues no MCP tokens.

## Scenario index

| # | Scenario | Expected |
| --- | --- | --- |
| M1 | Tools work with no secret in the pod | Rows from `orders.items` |
| M2 | Dynamic user per lease | `v-…` user, ≤ 10 min left |
| M3-M5 | Server policy is one exact path | Own path 200; other app or environment 403 |
| M6 | No secrets in the app container | No token, no password, no `/var/run/secrets` |
| M7 | Break-glass revoke | New user within seconds; old one dropped |
| M8 | Schema isolation | No tool for `payments`; `SELECT` refused; canary never returned |
| A1 | No token | `401`, with metadata naming Better Auth |
| A2 | Authorised client pod | 4 tools listed, rows returned; a token holds only requested scopes |
| A3 | MCP server's ServiceAccount at the token endpoint | `invalid_client` |
| A4 | Client ServiceAccount and Vault | No Vault login; no Vault Proxy in the pod |
| A5 | Bad signature, `alg=none`, wrong `typ` | `401` |
| A6 | Expired token replayed | `401` |
| A7 | Tool outside the client's scopes | Tool error: not permitted |
| A8 | Valid ServiceAccount, no OAuth client | Token endpoint refuses it |
| A9 | OAuth client disabled, then restored | No new token, then access returns |
| A10 | Pod requests an ungranted scope | `invalid_scope` |
| A11 | Audit | Only expected signers and subjects; database credentials only to the server |
| A12 | Wrong audience or deleted ServiceAccount | `invalid_client` |
| H1 | `testuser` signs in | Reader tools work; `whoami` shows `testuser` |
| H2 | `delete_order` | Denied |
| H3 | `reportuser` requests every scope | Token holds only `orders:list`; `get_order` denied |
| H4 | `nogroupuser` signs in | No token |
| H5 | Wrong password | Login refused |
| H6 | ID token as bearer; session JWT endpoint | `401`; `404` |
| H7 | User edits identity or groups | Refused; identity and scopes unchanged |
| H8 | Token request without a resource | Token is still issued for the MCP server, after the scope check |
| H9 | Direct consent request with extra scopes | Token holds only allowed scopes |
| H10 | Refresh asking for more scopes | `invalid_scope` |
| H11 | Stale or tampered consent | Refused at token issue; a new sign-in clears it |
| H12 | Sign-out page | Cross-site request refused; a normal sign-out ends the session |
| H13 | Refresh after the 8-hour sign-in limit | `invalid_grant`; a new sign-in works |
