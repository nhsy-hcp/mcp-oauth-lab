#!/bin/bash
# Render and apply one namespace, annotated ServiceAccount, app-team RBAC, Proxy ConfigMap and (when
# "pod" is not false) a Deployment per entry in a workloads file, then wait for the rollouts. Safe to re-run.
#
# Usage: scripts/deploy-workloads.sh <workloads.json> <deployment-template> <deployment-name> <vault-role> <app-image> <proxy-image>
#   e.g. scripts/deploy-workloads.sh vault-ce/servers.json mcp-server-deployment mcp-orders mcp-server ...
# Env: MCP_HOST_PORT (server), CLIENT_INTERVAL_SECONDS (clients)
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

USAGE="Usage: deploy-workloads.sh <workloads.json> <deployment-template> <deployment-name> <vault-role> <app-image> <proxy-image>"
FILE="${1:?${USAGE}}"
DEPLOY_TPL="${2:?${USAGE}}"
DEPLOY_NAME="${3:?${USAGE}}"
VAULT_ROLE="${4:?${USAGE}}"
APP_IMAGE="${5:?${USAGE}}"
PROXY_IMAGE="${6:?${USAGE}}"
MCP_HOST_PORT="${MCP_HOST_PORT:-8000}"
CLIENT_INTERVAL_SECONDS="${CLIENT_INTERVAL_SECONDS:-30}"
SERVER_NAME="$(jq -r '.[0].name' "${SERVERS_FILE}")"
OUT_DIR=".tmp/rendered"
BASE_TEMPLATES=(service-account app-team-rbac proxy-config)
# Only these variables are substituted; anything else in the templates is left untouched
# shellcheck disable=SC2016 # literal ${VAR} names for envsubst, not expansions
SUBST_VARS='${APP_NAME} ${APPLICATION} ${ENVIRONMENT} ${TEAM} ${APP_IMAGE} ${PROXY_IMAGE} ${VAULT_ROLE} ${MCP_HOST_PORT} ${SERVER_NAME} ${CLIENT_TOOLS} ${CLIENT_INTERVAL_SECONDS}'

export APP_IMAGE PROXY_IMAGE VAULT_ROLE MCP_HOST_PORT SERVER_NAME CLIENT_INTERVAL_SECONDS

with_pods=""
while read -r row <&3; do
  APP_NAME="$(jq -r .name <<<"${row}")"
  APPLICATION="$(jq -r .application_name <<<"${row}")"
  ENVIRONMENT="$(jq -r .environment <<<"${row}")"
  TEAM="$(jq -r .team <<<"${row}")"
  CLIENT_TOOLS="$(jq -r '.tools // ""' <<<"${row}")"
  has_pod="$(jq -r 'if .pod == false then "false" else "true" end' <<<"${row}")"
  export APP_NAME APPLICATION ENVIRONMENT TEAM CLIENT_TOOLS

  templates=("${BASE_TEMPLATES[@]}")
  [ "${has_pod}" = true ] && templates+=("${DEPLOY_TPL}")

  existed=false
  kubectl get "deploy/${DEPLOY_NAME}" -n "${APP_NAME}" >/dev/null 2>&1 && existed=true

  mkdir -p "${OUT_DIR}/${APP_NAME}"
  envsubst "${SUBST_VARS}" < templates/namespace.yaml.tpl > "${OUT_DIR}/${APP_NAME}/namespace.yaml"
  kubectl apply -f "${OUT_DIR}/${APP_NAME}/namespace.yaml" >/dev/null # first, so namespaced objects can land
  for t in "${templates[@]}"; do
    envsubst "${SUBST_VARS}" < "templates/${t}.yaml.tpl" > "${OUT_DIR}/${APP_NAME}/${t}.yaml"
    kubectl apply -f "${OUT_DIR}/${APP_NAME}/${t}.yaml" >/dev/null
  done
  # Re-deploys pick up a rebuilt image (same tag) or changed Proxy config; a first deploy needs no restart.
  if [ "${existed}" = true ]; then
    kubectl rollout restart "deploy/${DEPLOY_NAME}" -n "${APP_NAME}" >/dev/null
  fi
  [ "${has_pod}" = true ] && with_pods="${with_pods} ${APP_NAME}"
  log "Applied ${APP_NAME} (${APPLICATION} / ${ENVIRONMENT} / ${TEAM}, role ${VAULT_ROLE}, pod ${has_pod})"
done 3< <(jq -c '.[]' "${FILE}")

for ns in ${with_pods}; do
  kubectl rollout status "deploy/${DEPLOY_NAME}" -n "${ns}" --timeout=3m
done
