# Vault copies these alias-metadata-* annotations onto the entity alias at login, and the mcp-server policy is
# templated on them. They never grant MCP tools, and client pods do not log in to Vault.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${APP_NAME}-sa
  namespace: ${APP_NAME}
  annotations:
    vault.hashicorp.com/alias-metadata-application_name: ${APPLICATION}
    vault.hashicorp.com/alias-metadata-environment: ${ENVIRONMENT}
    vault.hashicorp.com/alias-metadata-team: ${TEAM}
automountServiceAccountToken: false
