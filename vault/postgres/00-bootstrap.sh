#!/bin/bash
# docker-entrypoint-initdb.d hook: run the bootstrap SQL with the vault_admin_dev bootstrap password
# taken from the environment (Kubernetes Secret), so no password is stored in the repo.
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
  --username "${POSTGRES_USER}" \
  --dbname postgres \
  -v vault_admin_dev_password="${VAULT_ADMIN_DEV_PASSWORD:?missing}" \
  -f /bootstrap/postgres-bootstrap.sql
