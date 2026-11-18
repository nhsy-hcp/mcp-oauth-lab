#!/bin/bash
# Create (or start) the k3d cluster and switch kubectl context to it. Safe to re-run.
#
# Usage: scripts/cluster-up.sh <cluster-name> <k3s-image> [mcp-host-port] [auth-host-port] [dex-host-port]
set -euo pipefail

CLUSTER_NAME="${1:?Usage: cluster-up.sh <cluster-name> <k3s-image>}"
K3S_IMAGE="${2:?Usage: cluster-up.sh <cluster-name> <k3s-image>}"
MCP_HOST_PORT="${3:-8000}"
AUTH_HOST_PORT="${4:-3000}"
DEX_HOST_PORT="${5:-5556}"

cluster_exists() {
  k3d cluster list --no-headers 2>/dev/null | awk '{print $1}' | grep -qx "${CLUSTER_NAME}"
}

if cluster_exists; then
  echo "Cluster '${CLUSTER_NAME}' already exists - starting if stopped."
  k3d cluster start "${CLUSTER_NAME}" 2>/dev/null || true
else
  for entry in "mcp_host_port:${MCP_HOST_PORT}" "auth_host_port:${AUTH_HOST_PORT}" "dex_host_port:${DEX_HOST_PORT}"; do
    if lsof -nP -iTCP:"${entry#*:}" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "ERROR: 127.0.0.1:${entry#*:} is already in use; set ${entry%%:*}=<free port>" >&2
      exit 1
    fi
  done
  echo "Creating cluster '${CLUSTER_NAME}' (${K3S_IMAGE})..."
  # --wait=false: Podman's journald log driver causes log-read failures during wait;
  # cluster-ready.sh is the readiness gate instead.
  # Vault, the MCP server, Better Auth and Dex are bound to 127.0.0.1, so none is reachable from the LAN.
  # Unlike the reference repo, anonymous-auth stays off: Kubernetes auth uses TokenReview.
  # Podman occasionally fails k3d's log read during create; k3d rolls back, so retry once.
  for attempt in 1 2; do
    if k3d cluster create "${CLUSTER_NAME}" \
      --image "${K3S_IMAGE}" \
      --wait=false \
      --port 127.0.0.1:8200:30820@server:0 \
      --port "127.0.0.1:${MCP_HOST_PORT}:30800@server:0" \
      --port "127.0.0.1:${AUTH_HOST_PORT}:30300@server:0" \
      --port "127.0.0.1:${DEX_HOST_PORT}:30556@server:0" \
      --k3s-arg "--disable=traefik,servicelb@server:0"; then
      break
    fi
    [ "${attempt}" -eq 2 ] && { echo "ERROR: k3d cluster create failed twice" >&2; exit 1; }
    echo "k3d cluster create failed - retrying in 5s..."
    sleep 5
  done
fi

k3d kubeconfig merge "${CLUSTER_NAME}" --kubeconfig-merge-default --kubeconfig-switch-context
echo "cluster-up complete."
