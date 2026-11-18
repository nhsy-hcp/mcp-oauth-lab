# mcp-server: one templated policy for MCP server workloads. __ACCESSOR__ is replaced with the
# auth/kubernetes mount accessor at config time (scripts/config-k8s-auth.sh).
# Missing annotations -> the template cannot resolve -> the path matches nothing (fail closed).

# Dynamic PostgreSQL credentials for <environment>-<application_name> only
path "database/creds/{{identity.entity.aliases.__ACCESSOR__.metadata.environment}}-{{identity.entity.aliases.__ACCESSOR__.metadata.application_name}}" {
  capabilities = ["read"]
}
