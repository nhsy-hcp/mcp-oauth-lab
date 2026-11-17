# AGENTS.md

Rules and orientation for AI agents working in this repository.

## Purpose

A local lab showing Vault Community Edition as an **identity broker for MCP auth** on k3d. Client pods (and the
operator's laptop) log in to Vault with Kubernetes auth and receive a short-lived, audience-bound Vault identity
JWT. The MCP server verifies the JWT against Vault's JWKS and authorises tools by Vault identity group. The server
itself gets dynamic PostgreSQL credentials through a Vault Proxy native sidecar on a UNIX socket. The design is
`docs/solution-design.md`.

## Rules

- Write files only inside this project. `../learn-vault-proxy` and `../../training/learn-vault-secrets-operator`
  are read-only references.
- Temporary files go in `.tmp/`, plans go in `.plans/`.
- All automation runs through `task`. Logic longer than about 20 lines goes in `scripts/*.sh`, which must start with
  `#!/bin/bash` and `set -euo pipefail` and pass shellcheck. Scripts must run on macOS `/bin/bash` 3.2: no
  associative arrays and no `mapfile`.
- Never hardcode secrets. `vault-init.json` and `.env` are git-ignored. Add new environment variables to
  `.env.template`.
- Stage files by explicit path only, and never use `--no-verify`. Run `task lint` before every commit.
- Commit messages follow Conventional Commits (`type: description`, lowercase).
- Vault Community Edition only, with Vault's default mount paths: `auth/kubernetes`, `database/`, and the built-in
  `identity/oidc`.
- Python 3.12 managed with uv (`app/pyproject.toml`); ruff with a 200-character line length. The app talks to Vault
  only through Vault Proxy over the UNIX socket, with the standard library (no `hvac`).
- Vault configuration runs as `kubectl exec vault-0 -n vault -- vault ...` through `vault_cmd` / `vault_cmd_in` in
  `scripts/lib.sh`, with the root token read from `vault-init.json` and sent on stdin, never as an argument. Every
  config step must be safe to re-run.
- Diagrams are PNGs rendered from Python `diagrams` sources in `docs/diagrams/` (`task docs:diagrams`). Never edit
  the PNGs by hand.

## Layout

| Path | Contents |
| --- | --- |
| `Taskfile.yml` | All tasks; version pins and TTL variables at the top |
| `scripts/` | Bash helpers invoked from the Taskfile |
| `vault-ce/` | Vault Helm values, RBAC, policies, roles, identity config, PostgreSQL manifests and SQL |
| `templates/` | Per-workload manifest templates rendered with `envsubst` |
| `app/` | `mcp_lab` Python package (server and client), tests and Dockerfile |
| `docs/` | Design, walkthrough, troubleshooting, diagram sources and PNGs |

## Common tasks

| Task | Does |
| --- | --- |
| `task init` | Installs pre-commit hooks, adds the Helm repo, creates `.env`, syncs the app venv |
| `task deps` | Checks the CLI tools the lab needs |
| `task all` (`up`) | Builds the whole lab |
| `task down` | Stops the cluster, keeping its data; afterwards run `task cluster:up` and `task unseal:vault` |
| `task lint` | Runs every pre-commit hook plus a full-history gitleaks scan |
| `task test` | Runs the unit tests (no cluster) |
| `task test:all` | Unit tests plus `demo:mcp` (M1-M8) and `demo:mcp-auth` (A1-A11) on the running lab |
| `task mcp:token` | Prints a 5-minute Vault identity JWT for the laptop client |
| `task docs:diagrams` | Renders `docs/diagrams/*.py` to `docs/images/*.png` (needs Graphviz) |
| `task test:ci` | Lint and unit tests; with `E2E=true`, also builds the lab and runs `test:all` |
| `task clean` | Deletes the cluster, `vault-init.json` and temporary files |

For the full list, run `task --list`.

## Workflow for agents

1. Run `task deps` first and stop if anything is missing.
2. Run tasks in order. If a step fails, stop and report rather than improvising changes.
3. Use `localhost:8200` for Vault and `localhost:8000/mcp` for the MCP server from the laptop, and
   `kubectl exec vault-0` inside the cluster.
