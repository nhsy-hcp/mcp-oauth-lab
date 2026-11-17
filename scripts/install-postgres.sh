#!/bin/bash
# Deploy PostgreSQL 16 into namespace postgres: random credentials Secret (created once),
# bootstrap ConfigMap, PVC, Service and Deployment. Safe to re-run.
#
# Usage: scripts/install-postgres.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

NS="postgres"
DIR="vault-ce/postgres"

kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# Generated once and never printed. Vault rotates the vault_admin_preview password (rotate-root) later.
if kubectl get secret postgres-credentials -n "${NS}" >/dev/null 2>&1; then
  log "Secret postgres-credentials already exists"
else
  kubectl create secret generic postgres-credentials -n "${NS}" \
    --from-literal=postgres-password="$(openssl rand -hex 24)" \
    --from-literal=vault-admin-preview-password="$(openssl rand -hex 24)" >/dev/null
  log "Created Secret postgres-credentials (random passwords)"
fi

kubectl create configmap postgres-bootstrap -n "${NS}" \
  --from-file="${DIR}/00-bootstrap.sh" \
  --from-file="${DIR}/postgres-bootstrap.sql" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl apply -f "${DIR}/postgres.yaml"
kubectl rollout status deploy/postgres -n "${NS}" --timeout=5m

log "Schemas in database preview:"
kubectl exec deploy/postgres -n "${NS}" -- psql -U postgres -d preview -Atc \
  "SELECT nspname FROM pg_namespace WHERE nspname IN ('orders','payments') ORDER BY 1"
