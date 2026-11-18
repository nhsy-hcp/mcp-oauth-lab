#!/bin/bash
# Regression test for task ci:act: act reads .env by default, and .env holds the Vault root token, so the
# task must tell act not to load it into the job container.
#
# Usage: scripts/test-ci-act.sh
set -euo pipefail

cd "$(dirname "$0")/.."
stubs="$(mktemp -d)"
trap 'rm -rf "${stubs}"' EXIT
# The task's precondition only needs act on PATH; --dry never runs it.
printf '#!/bin/sh\nexit 0\n' >"${stubs}/act"
chmod +x "${stubs}/act"

output="$(PATH="${stubs}:${PATH}" task --dry ci:act 2>&1)"

case "${output}" in
  *"act push"*"--env-file /dev/null"*) echo "PASS  ci:act does not load .env into the container" ;;
  *)
    echo "FAIL  ci:act must pass --env-file /dev/null to act" >&2
    exit 1
    ;;
esac
