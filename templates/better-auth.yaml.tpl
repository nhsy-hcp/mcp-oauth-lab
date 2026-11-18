# Better Auth: the OAuth 2.1 authorization server. The issuer is on localhost because MCP clients allow plain HTTP
# only for loopback names. Pods reach the same service as auth.localhost (auth/coredns-custom.yaml).
apiVersion: v1
kind: ServiceAccount
metadata:
  name: better-auth
  namespace: better-auth
---
# Only what SA JWT client login needs: ask Kubernetes whether a token is valid.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: better-auth-tokenreview
rules:
  - apiGroups: [authentication.k8s.io]
    resources: [tokenreviews]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: better-auth-tokenreview
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: better-auth-tokenreview
subjects:
  - kind: ServiceAccount
    name: better-auth
    namespace: better-auth
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: better-auth
  namespace: better-auth
  labels:
    app.kubernetes.io/name: better-auth
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: better-auth
  template:
    metadata:
      labels:
        app.kubernetes.io/name: better-auth
    spec:
      serviceAccountName: better-auth
      securityContext:
        runAsUser: 10001
        runAsGroup: 10001
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: auth
          image: ${AUTH_IMAGE}
          imagePullPolicy: Never # imported with k3d image import
          ports:
            - {name: http, containerPort: 3000}
          env:
            - {name: BETTER_AUTH_URL, value: "http://localhost:${AUTH_HOST_PORT}"}
            - {name: DEX_ISSUER, value: "http://dex.localhost:${DEX_HOST_PORT}/dex"}
            - {name: MCP_RESOURCE, value: "http://localhost:${MCP_HOST_PORT}/mcp"}
            - {name: ACCESS_TOKEN_TTL_SECONDS, value: "${ACCESS_TOKEN_TTL_SECONDS}"}
            - {name: SIGN_IN_TTL_SECONDS, value: "${SIGN_IN_TTL_SECONDS}"}
            - name: BETTER_AUTH_SECRET
              valueFrom: {secretKeyRef: {name: better-auth-env, key: BETTER_AUTH_SECRET}}
            - name: DEX_CLIENT_SECRET
              valueFrom: {secretKeyRef: {name: better-auth-env, key: DEX_CLIENT_SECRET}}
            - name: AUTH_DB_PASSWORD
              valueFrom: {secretKeyRef: {name: better-auth-env, key: AUTH_DB_PASSWORD}}
            - {name: DATABASE_URL, value: "postgres://auth_owner:$(AUTH_DB_PASSWORD)@postgres.postgres-dev.svc.cluster.local:5432/auth"}
          readinessProbe:
            httpGet: {path: /healthz, port: http}
            periodSeconds: 5
          lifecycle:
            preStop:
              sleep: {seconds: 5} # keeps serving while traffic moves to the new pod during a rollout
          resources:
            requests: {cpu: 20m, memory: 96Mi}
            limits: {memory: 384Mi}
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - {name: tmp, mountPath: /tmp}
      volumes:
        - name: tmp
          emptyDir: {medium: Memory}
---
apiVersion: v1
kind: Service
metadata:
  name: better-auth
  namespace: better-auth
  labels:
    app.kubernetes.io/name: better-auth
spec:
  type: NodePort
  selector:
    app.kubernetes.io/name: better-auth
  ports:
    - {name: http, port: ${AUTH_HOST_PORT}, targetPort: http, nodePort: 30300}
