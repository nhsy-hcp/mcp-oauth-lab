"""Orders MCP server (Streamable HTTP on :8080/mcp).

* Every request needs a Vault identity JWT (``Authorization: Bearer``); see :mod:`mcp_lab.auth`.
* Tools run fixed SQL with a PostgreSQL user Vault minted for this pod (Proxy socket, ``CredentialManager``).
* On SIGTERM uvicorn stops serving, then the pool closes and the Proxy token is revoked, which drops
  the database user straight away.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import anyio
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_lab import tools
from mcp_lab.auth import GroupToolsError, VaultJwtVerifier, check_group_tools, packaged_group_tools, require
from mcp_lab.config import ConfigError, ServerConfig
from mcp_lab.creds import CredentialManager
from mcp_lab.logging_setup import configure_logging, log_event
from mcp_lab.vault_client import VaultClient

log = logging.getLogger(__name__)

INSTRUCTIONS = "Read-only access to preview orders. Every call is authorised by the caller's Vault identity group."


def build_mcp(config: ServerConfig, creds: tools.QueryRunner, verifier: VaultJwtVerifier) -> MCPServer:
    mcp = MCPServer(
        "orders",
        instructions=INSTRUCTIONS,
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=config.issuer,
            resource_server_url=config.resource_url,
            # The verifier checks aud itself (Vault sets aud = the OIDC role's client_id, not a URL).
            validate_token_resource=False,
        ),
    )
    registered: set[str] = set()

    def tool(**kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        """``mcp.tool`` that also records the name, so the group map can be checked against what is served."""

        def register(fn: Callable[..., Any]) -> Any:
            registered.add(kwargs.get("name") or fn.__name__)
            return mcp.tool(**kwargs)(fn)

        return register

    @tool()
    def list_orders(status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """List preview orders, optionally filtered by status (pending, shipped, cancelled). At most 50 rows."""
        require("list_orders")
        return tools.list_orders(creds, status, limit)

    @tool()
    def get_order(order_id: int) -> dict[str, Any] | None:
        """Get one preview order by id."""
        require("get_order")
        return tools.get_order(creds, order_id)

    # Listed so clients see it is refused; annotated destructive so a model client treats it with care
    @tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=True), structured_output=False)
    def delete_order(order_id: int) -> None:
        """Delete one preview order. Always denied: no Vault group is granted it, and orders are read-only."""
        require("delete_order")  # no group in group_tools.toml grants delete_order, so this raises for every caller
        # Defence in depth if a group is ever granted it: there is no DELETE path, and the DB grant is SELECT only.
        raise ToolError(f"permission denied: delete_order is not supported (order {int(order_id)} untouched; orders are read-only)")

    @tool()
    def whoami() -> dict[str, Any]:
        """The calling client's Vault identity and the database user this server is using (never a password)."""
        token = require("whoami")
        claims = token.claims or {}
        return {
            "caller": {"client": token.client_id, "entity_id": token.subject, "groups": claims.get("groups"), "token_expires_at": token.expires_at},
            "database": tools.whoami(creds),
        }

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        ok = creds.is_healthy()  # type: ignore[attr-defined]
        return JSONResponse({"ok": ok}, status_code=200 if ok else 503)

    check_group_tools(verifier.group_tools, registered)
    return mcp


def revoke_on_shutdown(vault: VaultClient) -> None:
    """Best effort: revoke Proxy's token (and the DB lease) on the way out; never raise."""
    try:
        status = vault.revoke_self()
    except OSError as exc:
        log_event(log, logging.WARNING, "revoke_self_failed", error=type(exc).__name__)
        return
    if status != 204:
        log_event(log, logging.WARNING, "revoke_self_failed", status=status)


async def serve(config: ServerConfig) -> None:
    vault = VaultClient(config.vault_socket)
    if not await anyio.to_thread.run_sync(vault.wait_for_socket):
        raise SystemExit(1)
    creds = CredentialManager(
        vault,
        config.db_creds_path,
        host=config.db_host,
        port=config.db_port,
        dbname=config.db_name,
        max_refresh_seconds=config.creds_refresh_max_seconds,
    )
    try:
        verifier = VaultJwtVerifier(vault.read, issuer=config.issuer, audience=config.audience, group_tools=packaged_group_tools())
        mcp = build_mcp(config, creds, verifier)
    except GroupToolsError as exc:
        log_event(log, logging.ERROR, "group_tools_invalid", error=str(exc))
        raise SystemExit(2) from exc
    creds.start()
    try:
        log_event(log, logging.INFO, "listening", port=config.port, issuer=config.issuer, audience=config.audience)
        await mcp.run_streamable_http_async(
            host="0.0.0.0",  # noqa: S104 - container port
            port=config.port,
            stateless_http=True,
            json_response=True,
            transport_security=TransportSecuritySettings(allowed_hosts=list(config.allowed_hosts)),
        )
    finally:
        # uvicorn returned (SIGTERM/SIGINT): close the pool first so revocation never kills a session in use.
        log_event(log, logging.INFO, "stopping")
        creds.stop()
        revoke_on_shutdown(vault)


def main() -> int:
    configure_logging("INFO")
    try:
        config = ServerConfig.from_env()
    except ConfigError as exc:
        log_event(log, logging.ERROR, "config_invalid", error=str(exc))
        return 2
    configure_logging(config.log_level)
    log_event(log, logging.INFO, "startup_config", creds_path=config.db_creds_path, db_host=config.db_host, db_name=config.db_name, allowed_hosts=list(config.allowed_hosts))
    anyio.run(serve, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
