apiVersion: v1
kind: Namespace
metadata:
  name: ${APP_NAME}
  labels:
    app.kubernetes.io/part-of: mcp-lab
    mcp-lab/application: ${APPLICATION}
    mcp-lab/environment: ${ENVIRONMENT}
