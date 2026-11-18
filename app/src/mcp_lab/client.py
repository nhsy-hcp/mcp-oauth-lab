"""MCP client pod: logs in to Better Auth with its ServiceAccount JWT, then calls the orders MCP server.

Every ``CLIENT_INTERVAL_SECONDS`` it lists the server's tools and calls each tool in ``CLIENT_TOOLS``,
logging one JSON line per result. The bearer token comes from :class:`ClientCredentialsAuth`, an OAuth
``client_credentials`` grant authenticated by the pod's projected ServiceAccount token. The access token
is cached until shortly before it expires. Neither token is ever logged.
"""

from __future__ import annotations

import json
import logging
import signal
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import AsyncGenerator, Callable, Iterable
from typing import Any

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from mcp_lab.config import ClientConfig, ConfigError
from mcp_lab.logging_setup import configure_logging, log_event

log = logging.getLogger(__name__)

REFRESH_BEFORE_EXPIRY = 60.0  # or a quarter of the token lifetime, if that is shorter
TOKEN_TIMEOUT_SECONDS = 10
SERVICE_ACCOUNT_ASSERTION = "urn:lab:params:oauth:client-assertion-type:kubernetes-service-account"
TOOL_ARGS: dict[str, dict[str, Any]] = {
    "list_orders": {"status": "pending"},
    "get_order": {"order_id": 1},
    "whoami": {},
}

TokenPost = Callable[[str, dict[str, str]], tuple[int, Any]]


class TokenUnavailable(Exception):
    def __init__(self, status: int | None) -> None:
        super().__init__(f"access token unavailable (status {status})")
        self.status = status


def post_token_request(url: str, form: dict[str, str]) -> tuple[int, Any]:
    """POST a form to the token endpoint. Returns the status and JSON body, for error responses too."""
    request = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), headers={"Accept": "application/json"})  # noqa: S310 - configured http(s) URL
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=TOKEN_TIMEOUT_SECONDS) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        with exc:
            try:
                return exc.code, json.load(exc)
            except ValueError:
                return exc.code, None
    except ValueError:
        return 502, None


class ClientCredentialsAuth(httpx2.Auth):
    """Adds a Better Auth access token to every MCP request, requesting a new one shortly before expiry."""

    def __init__(
        self,
        token_url: str,
        resource: str,
        scopes: Iterable[str],
        service_account_token: str,
        post: TokenPost = post_token_request,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.token_url = token_url
        self.resource = resource
        self.scopes = tuple(scopes)
        self.service_account_token = service_account_token
        self._post = post
        self._clock = clock
        self._token: str | None = None
        self._refresh_at = 0.0
        self._lock = threading.Lock()

    def _request_token(self) -> None:
        try:
            with open(self.service_account_token, encoding="utf-8") as handle:
                assertion = handle.read().strip()
            form = {
                "grant_type": "client_credentials",
                "client_assertion_type": SERVICE_ACCOUNT_ASSERTION,
                "client_assertion": assertion,
                "resource": self.resource,
            }
            if self.scopes:
                form["scope"] = " ".join(self.scopes)
            status, body = self._post(self.token_url, form)
        except OSError as exc:
            log_event(log, logging.WARNING, "access_token_failed", error=type(exc).__name__)
            raise TokenUnavailable(None) from exc
        token = body.get("access_token") if isinstance(body, dict) else None
        if status != 200 or not token:
            log_event(log, logging.WARNING, "access_token_failed", status=status, error=body.get("error") if isinstance(body, dict) else None)
            raise TokenUnavailable(status)
        self._token = str(token)
        lifetime = float(body.get("expires_in", 0))
        self._refresh_at = self._clock() + lifetime - min(REFRESH_BEFORE_EXPIRY, lifetime / 4)
        log_event(log, logging.INFO, "access_token_issued", scopes=list(self.scopes), expires_in=body.get("expires_in"))

    def token(self) -> str:
        with self._lock:
            if self._token is None or self._clock() > self._refresh_at:
                self._request_token()
            assert self._token is not None  # noqa: S101 - set by _request_token or it raised
            return self._token

    def auth_flow(self, request: httpx2.Request):
        request.headers["Authorization"] = f"Bearer {self.token()}"
        yield request

    async def async_auth_flow(self, request: httpx2.Request) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        token = await anyio.to_thread.run_sync(self.token)  # blocking file and network I/O off the event loop
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
    last_status: dict[str, int] = {}

    async def record_status(response: httpx2.Response) -> None:
        # The SDK turns an HTTP 401 into a generic MCPError; keep the status for the log line.
        last_status["code"] = response.status_code

    try:
        async with create_mcp_http_client(auth=auth) as http_client:
            http_client.event_hooks["response"].append(record_status)
            async with Client(streamable_http_client(config.mcp_url, http_client=http_client)) as client:
                listed = await client.list_tools()
                log_event(log, logging.INFO, "tools_listed", tools=sorted(t.name for t in listed.tools))
                for name in config.tools:
                    result = await client.call_tool(name, TOOL_ARGS.get(name, {}))
                    log_event(log, logging.WARNING if result.is_error else logging.INFO, "tool_called", tool=name, **_summary(result))
    except Exception as exc:
        cause = _root_cause(exc)
        if isinstance(cause, TokenUnavailable):  # raised inside the SDK's task group, so it arrives wrapped
            log_event(log, logging.WARNING, "mcp_call_failed", error="token_unavailable", status=cause.status)
            return
        status = getattr(getattr(cause, "response", None), "status_code", None) or last_status.get("code")
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
    log_event(log, logging.INFO, "client_started", mcp_url=config.mcp_url, scopes=list(config.scopes), tools=list(config.tools), interval=config.interval_seconds)
    auth = ClientCredentialsAuth(config.token_url, config.resource, config.scopes, config.service_account_token)
    anyio.run(loop, config, auth, stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
