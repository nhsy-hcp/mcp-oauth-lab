#!/bin/bash
# Deploy Dex with the lab's static users, and create the Better Auth Secret once. Safe to re-run.
# Every lab user signs in with DEX_STATIC_PASSWORD (default: password). Dex is only bound to 127.0.0.1.
#
# Usage: scripts/install-dex.sh <chart-version> <image-tag> <dex-port> <auth-port>
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

USAGE="Usage: install-dex.sh <chart-version> <image-tag> <dex-port> <auth-port>"
CHART_VERSION="${1:?${USAGE}}"
IMAGE_TAG="${2:?${USAGE}}"
export DEX_HOST_PORT="${3:?${USAGE}}"
export AUTH_HOST_PORT="${4:?${USAGE}}"
PASSWORD="${DEX_STATIC_PASSWORD:-password}"

for ns in dex better-auth; do
  kubectl create namespace "${ns}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
done

# Generated once: a new BETTER_AUTH_SECRET would make the stored signing keys undecryptable.
if kubectl get secret better-auth-env -n better-auth >/dev/null 2>&1; then
  log "Secret better-auth-env already exists"
else
  # Values go through stdin, so they never appear in a process list.
  printf 'BETTER_AUTH_SECRET=%s\nDEX_CLIENT_SECRET=%s\nAUTH_DB_PASSWORD=%s\n' \
    "$(openssl rand -hex 32)" "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" \
    | kubectl create secret generic better-auth-env -n better-auth --from-env-file=/dev/stdin >/dev/null
  log "Created Secret better-auth-env (random values)"
fi

DEX_CLIENT_SECRET="$(kubectl get secret better-auth-env -n better-auth -o jsonpath='{.data.DEX_CLIENT_SECRET}' | base64 -d)"
DEX_PASSWORD_HASH="$(printf '%s' "${PASSWORD}" | htpasswd -niBC 10 lab | cut -d: -f2 | tr -d '\n' | sed 's/^\$2y\$/$2a$/')"
export DEX_CLIENT_SECRET DEX_PASSWORD_HASH

# Only these variables are substituted. The rendered Secret goes straight to kubectl.
# shellcheck disable=SC2016 # literal ${VAR} names for envsubst, not expansions
envsubst '${DEX_HOST_PORT} ${AUTH_HOST_PORT} ${DEX_CLIENT_SECRET} ${DEX_PASSWORD_HASH}' <templates/dex-config-secret.yaml.tpl | kubectl apply -f - >/dev/null

helm upgrade --install dex dex/dex --version "${CHART_VERSION}" -n dex \
  --values auth/dex-values.yaml \
  --set image.tag="${IMAGE_TAG}" \
  --set service.ports.http.port="${DEX_HOST_PORT}" >/dev/null
kubectl rollout restart deploy/dex -n dex >/dev/null # picks up a changed dex-config Secret
kubectl rollout status deploy/dex -n dex --timeout=3m
log "Dex ready at http://dex.localhost:${DEX_HOST_PORT}/dex (users: testuser, reportuser, nogroupuser)"
