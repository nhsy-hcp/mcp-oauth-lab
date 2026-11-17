"""MCP client pod: proves its identity to Vault, then calls the orders MCP server with a short-lived JWT.

Every ``CLIENT_INTERVAL_SECONDS`` it lists the server's tools and calls each tool in ``CLIENT_TOOLS``,
logging one JSON line per result. The bearer token comes from :class:`VaultIdentityAuth`, which reads
``identity/oidc/token/<role>`` over this pod's own Vault Proxy socket (Proxy adds the pod's Vault
token; the pod never holds it). The JWT is cached until shortly before it expires and is never logged.
On SIGTERM the client revokes its Proxy token.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any

import anyio
import httpx2
import jwt
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from mcp_lab.config import ClientConfig, ConfigError
from mcp_lab.logging_setup import configure_logging, log_event
from mcp_lab.vault_client import VaultClient

log = logging.getLogger(__name__)

REFRESH_BEFORE_EXPIRY = 60.0
TOOL_ARGS: dict[str, dict[str, Any]] = {
    "list_orders": {"status": "pending"},
    "get_order": {"order_id": 1},
    "whoami": {},
}

VaultRead = Callable[[str], tuple[int, Any, Any]]


class TokenUnavailable(Exception):
    def __init__(self, status: int | None) -> None:
        super().__init__(f"vault identity token unavailable (status {status})")
        self.status = status


class VaultIdentityAuth(httpx2.Auth):
    """Adds a Vault identity JWT to every MCP request, minting a new one shortly before expiry."""

    def __init__(self, vault_read: VaultRead, role: str, clock: Callable[[], float] = time.time) -> None:
        self._read = vault_read
        self.role = role
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if self._token is None or self._clock() > self._expires_at - REFRESH_BEFORE_EXPIRY:
                status, _, body = self._read(f"identity/oidc/token/{self.role}")
                data = body.get("data") if isinstance(body, dict) else None
                if status != 200 or not isinstance(data, dict) or not data.get("token"):
                    log_event(log, logging.WARNING, "identity_token_failed", role=self.role, status=status)
                    raise TokenUnavailable(status)
                self._token = str(data["token"])
                self._expires_at = self._clock() + float(data.get("ttl", 0))
                claims = jwt.decode(self._token, options={"verify_signature": False})  # for logging only
                log_event(log, logging.INFO, "identity_token_minted", role=self.role, sub=claims.get("sub"), groups=claims.get("groups"), aud=claims.get("aud"), ttl=data.get("ttl"))
            return self._token

    def auth_flow(self, request: httpx2.Request):
        request.headers["Authorization"] = f"Bearer {self.token()}"
        yield request

    async def async_auth_flow(self, request: httpx2.Request) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        token = await anyio.to_thread.run_sync(self.token)  # blocking socket read off the event loop
        request.headers["Authorization"] = f"Bearer {token}"
        yield request


def _root_cause(exc: BaseException) -> BaseException:
    """The first leaf of an (anyio task group) ExceptionGroup, e.g. the HTTPStatusError for a 401."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def _summary(result: Any) -> dict[str, Any]:
    text = " ".join(getattr(c, "text", "") for c in (result.content or []))
    return {"is_error": bool(result.is_error), "text": text[:300]}


async def run_once(config: ClientConfig, auth: httpx2.Auth) -> None:
    try:
        async with create_mcp_http_client(auth=auth) as http_client, Client(streamable_http_client(config.mcp_url, http_client=http_client)) as client:
            listed = await client.list_tools()
            log_event(log, logging.INFO, "tools_listed", tools=sorted(t.name for t in listed.tools))
            for name in config.tools:
                result = await client.call_tool(name, TOOL_ARGS.get(name, {}))
                log_event(log, logging.WARNING if result.is_error else logging.INFO, "tool_called", tool=name, **_summary(result))
    except TokenUnavailable as exc:
        log_event(log, logging.WARNING, "mcp_call_failed", error="token_unavailable", status=exc.status)
    except Exception as exc:
        cause = _root_cause(exc)
        status = getattr(getattr(cause, "response", None), "status_code", None)
        log_event(log, logging.WARNING, "mcp_call_failed", error=type(cause).__name__, status=status, detail=str(cause)[:200])


async def loop(config: ClientConfig, auth: httpx2.Auth, stop: threading.Event) -> None:
    while not stop.is_set():
        await run_once(config, auth)
        await anyio.to_thread.run_sync(stop.wait, config.interval_seconds)


def main() -> int:
    configure_logging("INFO")
    try:
        config = ClientConfig.from_env()
    except ConfigError as exc:
        log_event(log, logging.ERROR, "config_invalid", error=str(exc))
        return 2
    configure_logging(config.log_level)
    logging.getLogger("httpx2").setLevel(logging.WARNING)  # one line per HTTP request is noise here
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    vault = VaultClient(config.vault_socket)
    if not vault.wait_for_socket(max_wait=30.0):
        return 1
    log_event(log, logging.INFO, "client_started", mcp_url=config.mcp_url, role=config.token_role, tools=list(config.tools), interval=config.interval_seconds)
    anyio.run(loop, config, VaultIdentityAuth(vault.read, config.token_role), stop)
    try:
        status = vault.revoke_self()
        if status != 204:
            log_event(log, logging.WARNING, "revoke_self_failed", status=status)
    except OSError as exc:
        log_event(log, logging.WARNING, "revoke_self_failed", error=type(exc).__name__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
