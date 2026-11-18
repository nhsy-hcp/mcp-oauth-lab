# AGENTS.md

Rules and orientation for AI agents working in this repository.

## Purpose

A local lab showing standard OAuth for an MCP server on k3d. People sign in through **Better Auth** and **Dex** static
users, and client pods log in to Better Auth with their Kubernetes ServiceAccount JWT. Better Auth decides scopes and
issues short-lived, audience-bound JWTs. The MCP server verifies them by JWKS and authorises tools by scope. It gets
dynamic PostgreSQL credentials from **HashiCorp Vault** through a Vault Proxy native sidecar on a UNIX socket. The
design is `docs/solution-design.md`.

## Rules

- Write files only inside this project. `../learn-vault-proxy` and `../../training/learn-vault-secrets-operator`
  are read-only references.
- Temporary files go in `.tmp/`, plans go in `.plans/`.
- All automation runs through `task`. Logic longer than about 20 lines goes in `scripts/*.sh`, which must start with
  `#!/bin/bash` and `set -euo pipefail` and pass shellcheck. Scripts must run on macOS `/bin/bash` 3.2: no
  associative arrays and no `mapfile`.
- Never hardcode secrets. `vault-init.json` and `.env` are git-ignored. Add new environment variables to
  `.env.template`. The only exception is the documented public lab password for static Dex users.
- Stage files by explicit path only, and never use `--no-verify`. Run `task lint` before every commit.
- Commit messages follow Conventional Commits (`type: description`, lowercase).
- GitHub runs the e2e job on branch pushes. Add `[skip e2e]` to the commit message to skip it for that push.
- Use Vault's default mount paths: `auth/kubernetes` and `database/`.
- Python 3.12 managed with uv (`app/pyproject.toml`); ruff with a 200-character line length. The MCP server talks to
  Vault only through Vault Proxy over the UNIX socket, with the standard library (no `hvac`). Client pods do not use
  Vault.
- The auth service is TypeScript on Node 22 (`auth/`), with exact package pins, Biome, `tsc` and Vitest. Better Auth is
  the only place that decides which scopes a user or client may hold.
- Vault configuration runs as `kubectl exec vault-0 -n vault -- vault ...` through `vault_cmd` / `vault_cmd_in` in
  `scripts/lib.sh`, with the root token read from `vault-init.json` and sent on stdin, never as an argument. Every
  config step must be safe to re-run.
- Diagrams are PNGs rendered from Python sources in `docs/diagrams/` (`task docs:diagrams`), using `diagrams`, plus
  matplotlib for the token-flow sequence diagram. Never edit the PNGs by hand.

## Layout

| Path | Contents |
| --- | --- |
| `Taskfile.yml` | All tasks; version pins and TTL variables at the top |
| `scripts/` | Bash helpers invoked from the Taskfile |
| `vault/` | Vault Helm values, RBAC, policies, roles, PostgreSQL manifests and SQL |
| `auth/` | Better Auth service, Dex values, CoreDNS aliases, group-to-scope map and OAuth client lists |
| `templates/` | Per-workload manifest templates rendered with `envsubst` |
| `app/` | `mcp_lab` Python package (MCP server and client), tests and Dockerfile |
| `docs/` | Design, walkthrough, troubleshooting, diagram sources and PNGs |

## Common tasks

| Task | Does |
| --- | --- |
| `task init` | Installs pre-commit hooks, adds the Helm repos, creates `.env`, syncs the Python and Node packages |
| `task deps` | Checks the CLI tools the lab needs |
| `task all` (`up`) | Builds the whole lab |
| `task down` | Stops the cluster, keeping its data; afterwards run `task cluster:up` and `task unseal:vault` |
| `task lint` | Runs every pre-commit hook plus a full-history gitleaks scan |
| `task test` | Runs the Python and Better Auth unit tests and the script tests (no cluster) |
| `task test:all` | Unit tests plus `demo:mcp` (M1-M8), `demo:mcp-auth` (A1-A12) and `demo:human-auth` (H1-H13) on the running lab |
| `task auth:deploy` | Builds Better Auth, migrates its database, seeds OAuth clients and deploys it |
| `task mcp:login` | Prints an access token for a lab user without a browser (`LAB_USER=testuser`) |
| `task mcp:inspector` | Opens the MCP Inspector web UI, with OAuth sign-in |
| `task ui` | Copies the Vault root token to the clipboard (`task token`) and opens the Vault UI |
| `task docs:diagrams` | Renders `docs/diagrams/*.py` to `docs/images/*.png` (needs Graphviz) |
| `task test:ci` | Lint, unit tests and `ci:act`; with `E2E=true`, also builds the lab and runs `test:all` |
| `task ci:act` | Runs the GitHub `lint and unit tests` job locally with act (needs act and Docker) |
| `task clean` | Deletes the cluster, `vault-init.json` and temporary files |

For the full list, run `task --list`.

## Workflow for agents

1. Run `task deps` first and stop if anything is missing.
2. Run tasks in order. If a step fails, stop and report rather than improvising changes.
3. From the laptop, use `localhost:8200` for Vault, `localhost:8000/mcp` for the MCP server,
   `localhost:3000` for Better Auth and `dex.localhost:5556` for Dex. Use `kubectl exec vault-0` inside the cluster.
