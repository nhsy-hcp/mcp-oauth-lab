#!/bin/bash
# Regression test for scripts/check-deps.sh: --lint must pass with only the lint tools installed (no k3d, as on the
# CI lint runner), and the default mode must still fail when a lab tool is missing.
#
# Usage: scripts/test-check-deps.sh
set -euo pipefail

cd "$(dirname "$0")/.."
stubs="$(mktemp -d)"
trap 'rm -rf "${stubs}"' EXIT
for bin in task uv node npm pre-commit shellcheck gitleaks yamllint hadolint ruff; do
  printf '#!/bin/sh\nexit 0\n' >"${stubs}/${bin}"
  chmod +x "${stubs}/${bin}"
done
# Only the stubs plus a minimal system PATH: no k3d, kubectl, helm or vault.
path="${stubs}:/usr/bin:/bin"

fail() {
  echo "FAIL  $1" >&2
  exit 1
}

PATH="${path}" /bin/bash scripts/check-deps.sh --lint >/dev/null 2>&1 || fail "--lint fails without the cluster tools"
echo "PASS  --lint passes with only the lint tools"

if PATH="${path}" /bin/bash scripts/check-deps.sh >/dev/null 2>&1; then
  fail "default mode passes without k3d"
fi
echo "PASS  default mode still requires the lab tools"
