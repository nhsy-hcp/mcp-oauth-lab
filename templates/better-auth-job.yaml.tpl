# One-shot Better Auth maintenance job: database migration or OAuth client seeding.
apiVersion: batch/v1
kind: Job
metadata:
  name: better-auth-${JOB_NAME}
  namespace: better-auth
spec:
  backoffLimit: 2
  ttlSecondsAfterFinished: 600
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: better-auth
      automountServiceAccountToken: false
      securityContext:
        runAsUser: 10001
        runAsGroup: 10001
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: job
          image: ${AUTH_IMAGE}
          imagePullPolicy: Never
          command: ["node", "dist/${JOB_NAME}.js"]
          env:
            - {name: BETTER_AUTH_URL, value: "http://localhost:${AUTH_HOST_PORT}"}
            - {name: DEX_ISSUER, value: "http://dex.localhost:${DEX_HOST_PORT}/dex"}
            - {name: MCP_RESOURCE, value: "http://localhost:${MCP_HOST_PORT}/mcp"}
            - name: BETTER_AUTH_SECRET
              valueFrom: {secretKeyRef: {name: better-auth-env, key: BETTER_AUTH_SECRET}}
            - name: DEX_CLIENT_SECRET
              valueFrom: {secretKeyRef: {name: better-auth-env, key: DEX_CLIENT_SECRET}}
            - name: AUTH_DB_PASSWORD
              valueFrom: {secretKeyRef: {name: better-auth-env, key: AUTH_DB_PASSWORD}}
            - {name: DATABASE_URL, value: "postgres://auth_owner:$(AUTH_DB_PASSWORD)@postgres.postgres-dev.svc.cluster.local:5432/auth"}
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
