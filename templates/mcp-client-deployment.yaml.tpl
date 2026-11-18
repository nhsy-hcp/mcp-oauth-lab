# MCP client: logs in to Better Auth with a projected ServiceAccount token and calls the MCP server.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-client
  namespace: ${APP_NAME}
  labels:
    app.kubernetes.io/name: mcp-client
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: mcp-client
  template:
    metadata:
      labels:
        app.kubernetes.io/name: mcp-client
    spec:
      serviceAccountName: ${APP_NAME}-sa
      automountServiceAccountToken: false
      securityContext:
        runAsUser: 10001
        runAsGroup: 10001
        runAsNonRoot: true
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: ${APP_IMAGE}
          imagePullPolicy: Never # imported with k3d image import
          command: ["mcp-orders-client"]
          env:
            - {name: MCP_URL, value: "http://mcp-orders.${SERVER_NAME}.svc/mcp"}
            - {name: MCP_TOKEN_URL, value: "http://auth.localhost:${AUTH_HOST_PORT}/api/auth/oauth2/token"}
            - {name: MCP_RESOURCE_URL, value: "http://localhost:${MCP_HOST_PORT}/mcp"}
            - {name: CLIENT_SCOPES, value: "${CLIENT_SCOPES}"}
            - {name: CLIENT_TOOLS, value: "${CLIENT_TOOLS}"}
            - {name: CLIENT_INTERVAL_SECONDS, value: "${CLIENT_INTERVAL_SECONDS}"}
          resources:
            requests: {cpu: 20m, memory: 64Mi}
            limits: {memory: 256Mi}
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - {name: oauth-token, mountPath: /var/run/secrets/tokens, readOnly: true}
            - {name: app-tmp, mountPath: /tmp}
      volumes:
        - name: app-tmp
          emptyDir: {medium: Memory}
        - name: oauth-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  audience: "http://localhost:${AUTH_HOST_PORT}/api/auth"
                  expirationSeconds: 600
