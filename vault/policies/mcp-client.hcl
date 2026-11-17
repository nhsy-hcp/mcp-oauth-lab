# mcp-client: the only thing an MCP client workload may do in Vault is mint an identity token for the
# orders MCP server (aud = mcp-orders). No secrets, no database credentials, no other OIDC roles.
path "identity/oidc/token/mcp-orders" {
  capabilities = ["read"]
}
