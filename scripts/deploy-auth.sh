#!/bin/bash
# Migrate the database, seed the OAuth clients and deploy Better Auth. Safe to re-run.
#
# Usage: scripts/deploy-auth.sh [all|migrate|seed|deploy]
# Env: AUTH_IMAGE, AUTH_HOST_PORT, DEX_HOST_PORT, MCP_HOST_PORT, ACCESS_TOKEN_TTL_SECONDS, SIGN_IN_TTL_SECONDS
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

STEP="${1:-all}"
export AUTH_IMAGE="${AUTH_IMAGE:?AUTH_IMAGE is required}"
export AUTH_HOST_PORT="${AUTH_HOST_PORT:-3000}" DEX_HOST_PORT="${DEX_HOST_PORT:-5556}" MCP_HOST_PORT="${MCP_HOST_PORT:-8000}"
export ACCESS_TOKEN_TTL_SECONDS="${ACCESS_TOKEN_TTL_SECONDS:-300}" SIGN_IN_TTL_SECONDS="${SIGN_IN_TTL_SECONDS:-28800}"
# shellcheck disable=SC2016 # literal ${VAR} names for envsubst, not expansions
SUBST_VARS='${AUTH_IMAGE} ${AUTH_HOST_PORT} ${DEX_HOST_PORT} ${MCP_HOST_PORT} ${ACCESS_TOKEN_TTL_SECONDS} ${SIGN_IN_TTL_SECONDS} ${JOB_NAME}'
OUT_DIR=".tmp/rendered/better-auth"
mkdir -p "${OUT_DIR}"

render() { # render <template> <output-name>
  envsubst "${SUBST_VARS}" <"templates/$1.yaml.tpl" >"${OUT_DIR}/$2.yaml"
  printf '%s\n' "${OUT_DIR}/$2.yaml"
}

run_job() { # run_job <migrate|seed>
  export JOB_NAME="$1"
  kubectl delete job "better-auth-${JOB_NAME}" -n better-auth --ignore-not-found >/dev/null
  # The Deployment's ServiceAccount must exist before the first job.
  kubectl apply -f "$(render better-auth-job "job-${JOB_NAME}")" >/dev/null
  if ! kubectl wait --for=condition=complete "job/better-auth-${JOB_NAME}" -n better-auth --timeout=3m >/dev/null; then
    err "job better-auth-${JOB_NAME} did not complete"
    kubectl logs "job/better-auth-${JOB_NAME}" -n better-auth --tail=30 >&2 || true
    exit 1
  fi
  kubectl logs "job/better-auth-${JOB_NAME}" -n better-auth --tail=20
}

deploy() {
  export JOB_NAME=""
  local existed=false
  kubectl get deploy/better-auth -n better-auth >/dev/null 2>&1 && existed=true
  kubectl apply -f "$(render better-auth better-auth)" >/dev/null
  [ "${existed}" = false ] || kubectl rollout restart deploy/better-auth -n better-auth >/dev/null
  kubectl rollout status deploy/better-auth -n better-auth --timeout=3m
}

ensure_service_account() {
  kubectl create serviceaccount better-auth -n better-auth --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

case "${STEP}" in
  migrate) ensure_service_account; run_job migrate ;;
  seed) ensure_service_account; run_job seed ;;
  deploy) deploy ;;
  all) ensure_service_account; run_job migrate; run_job seed; deploy ;;
  *) err "unknown step ${STEP}"; exit 2 ;;
esac
