# Dex configuration, including the static lab users. Rendered by scripts/install-dex.sh and never written to disk.
apiVersion: v1
kind: Secret
metadata:
  name: dex-config
  namespace: dex
type: Opaque
stringData:
  config.yaml: |
    issuer: http://dex.localhost:${DEX_HOST_PORT}/dex
    storage:
      type: memory
    web:
      http: 0.0.0.0:5556
    oauth2:
      skipApprovalScreen: true
    enablePasswordDB: true
    staticClients:
      - id: better-auth
        name: Better Auth
        secret: ${DEX_CLIENT_SECRET}
        redirectURIs:
          - http://localhost:${AUTH_HOST_PORT}/api/auth/callback/dex
    staticPasswords:
      - email: testuser@lab.local
        username: testuser
        preferredUsername: testuser
        userID: testuser
        hash: "${DEX_PASSWORD_HASH}"
        groups: [mcp-orders-reader]
      - email: reportuser@lab.local
        username: reportuser
        preferredUsername: reportuser
        userID: reportuser
        hash: "${DEX_PASSWORD_HASH}"
        groups: [mcp-orders-reporter]
      - email: nogroupuser@lab.local
        username: nogroupuser
        preferredUsername: nogroupuser
        userID: nogroupuser
        hash: "${DEX_PASSWORD_HASH}"
