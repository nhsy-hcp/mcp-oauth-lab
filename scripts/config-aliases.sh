#!/bin/bash
# Make auth.localhost and dex.localhost resolve to their Services inside the cluster. Safe to re-run.
#
# Usage: scripts/config-aliases.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

kubectl apply -f auth/coredns-custom.yaml >/dev/null
kubectl rollout restart deploy/coredns -n kube-system >/dev/null
kubectl rollout status deploy/coredns -n kube-system --timeout=2m
log "CoreDNS aliases ready: auth.localhost, dex.localhost"
