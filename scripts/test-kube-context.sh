#!/bin/bash
# Regression test: lab commands must target the lab's kubectl context, not whichever context is selected.
# Uses stub kubectl, vault and k3d commands, so it needs no cluster.
#
# Usage: scripts/test-kube-context.sh
set -euo pipefail

cd "$(dirname "$0")/.."
unset KUBECONTEXT
stubs="$(mktemp -d)"
trap 'rm -rf "${stubs}"' EXIT
export KUBECTL_LOG="${stubs}/kubectl.log"
: >"${KUBECTL_LOG}"

cat >"${stubs}/kubectl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${KUBECTL_LOG}"
echo stub-token
EOF
printf '#!/bin/sh\necho stub-token\n' >"${stubs}/vault"
printf '#!/bin/sh\necho test-cluster\n' >"${stubs}/k3d"
chmod +x "${stubs}/kubectl" "${stubs}/vault" "${stubs}/k3d"
export PATH="${stubs}:${PATH}"

fail() {
  echo "FAIL  $1" >&2
  exit 1
}

pass_if_logged() {
  grep -Fq -- "$1" "${KUBECTL_LOG}" || fail "$2"
  echo "PASS  $2"
}

bash -c 'source scripts/lib.sh; kubectl get pods' >/dev/null
pass_if_logged "--context k3d-mcp-oauth-lab get pods" "scripts using lib.sh default to the lab"

KUBECONTEXT=k3d-other bash -c 'source scripts/lib.sh; kubectl get nodes' >/dev/null
pass_if_logged "--context k3d-other get nodes" "lib.sh uses KUBECONTEXT"

scripts/config-aliases.sh >/dev/null
pass_if_logged "--context k3d-mcp-oauth-lab rollout status deploy/coredns" "config-aliases.sh targets the lab"

scripts/cluster-ready.sh test-cluster >/dev/null
pass_if_logged "--context k3d-test-cluster wait node" "cluster-ready.sh targets the named cluster"

# Read the Taskfile directly: task --summary would print the root token loaded from .env.
# shellcheck disable=SC2016 # literal text in Taskfile.yml
unpinned="$(sed 's/kubectl --context "$KUBECONTEXT"//g' Taskfile.yml | grep -E 'kubectl (get|logs|apply|create|wait|exec|rollout)' || true)"
[ -z "${unpinned}" ] || fail "Taskfile kubectl commands without --context: ${unpinned}"
echo "PASS  Taskfile kubectl commands use KUBECONTEXT"

for setting in 'KUBECONTEXT: k3d-{{.cluster_name}}' 'HELM_KUBECONTEXT: k3d-{{.cluster_name}}'; do
  grep -Fxq "  ${setting}" Taskfile.yml || fail "Taskfile must set ${setting}"
done
echo "PASS  Taskfile pins kubectl and Helm to the lab"

grep -Eq '^  cluster_name: mcp-oauth-lab$' Taskfile.yml || fail "Taskfile cluster_name must match the lib.sh default"
echo "PASS  Taskfile cluster_name matches the lib.sh default"
