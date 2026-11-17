# MCP client: Vault Proxy native sidecar (role mcp-client) mints identity JWTs; the app calls the MCP server with them.
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
      initContainers:
        - name: vault-proxy
          image: ${PROXY_IMAGE}
          imagePullPolicy: IfNotPresent
          restartPolicy: Always # native sidecar: starts before the app, stops after it
          # Bypass the image entrypoint (it does not recognise the proxy subcommand)
          command: ["vault"]
          args: ["proxy", "-config=/etc/vault-proxy/proxy.hcl"]
          # No VAULT_ADDR env here: it would override vault.address in proxy.hcl and loop Proxy onto itself
          # Passes only once Proxy holds a valid auto-auth token (force mode answers lookup-self with it),
          # so the app never starts before Proxy has logged in. `vault status` alone is not enough.
          startupProbe:
            exec:
              command: ["vault", "token", "lookup", "-address=unix:///run/vault/proxy.sock", "-format=json"]
            timeoutSeconds: 3
            periodSeconds: 2
            failureThreshold: 30
          resources:
            requests: {cpu: 20m, memory: 32Mi}
            limits: {memory: 128Mi}
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - {name: proxy-config, mountPath: /etc/vault-proxy, readOnly: true}
            - {name: vault-token, mountPath: /var/run/secrets/vault, readOnly: true}
            - {name: proxy-socket, mountPath: /run/vault}
            - {name: proxy-tmp, mountPath: /tmp}
      containers:
        - name: app
          image: ${APP_IMAGE}
          imagePullPolicy: Never # imported with k3d image import
          command: ["mcp-orders-client"]
          env:
            - {name: VAULT_SOCKET, value: /run/vault/proxy.sock}
            - {name: MCP_URL, value: "http://mcp-orders.${SERVER_NAME}.svc/mcp"}
            - {name: MCP_TOKEN_ROLE, value: mcp-orders}
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
            - {name: proxy-socket, mountPath: /run/vault}
            - {name: app-tmp, mountPath: /tmp}
      volumes:
        - name: proxy-socket
          emptyDir: {medium: Memory}
        - name: proxy-tmp
          emptyDir: {medium: Memory}
        - name: app-tmp
          emptyDir: {medium: Memory}
        - name: proxy-config
          configMap:
            name: vault-proxy-config
        - name: vault-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  audience: vault
                  expirationSeconds: 600
