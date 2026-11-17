"""The real MCP SDK auth stack in-process: bearer middleware, Vault JWT verifier, per-tool group checks."""

from __future__ import annotations

import contextlib

import anyio
import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.transport_security import TransportSecuritySettings

from conftest import AUDIENCE, ISSUER
from mcp_lab.auth import VaultJwtVerifier
from mcp_lab.client import VaultIdentityAuth
from mcp_lab.config import ServerConfig
from mcp_lab.server import build_mcp

URL = "http://localhost:8000/mcp"


def _config() -> ServerConfig:
    return ServerConfig.from_env({"DB_CREDS_PATH": "database/creds/preview-orders", "DB_HOST": "pg", "DB_NAME": "preview"})


@contextlib.asynccontextmanager
async def _server(vault, creds):
    mcp = build_mcp(_config(), creds, VaultJwtVerifier(vault.read, ISSUER, AUDIENCE))
    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=["localhost:8000"]),
    )
    async with mcp.session_manager.run():
        yield app


def _http(app, auth=None, headers=None) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://localhost:8000", auth=auth, headers=headers)


async def _call(app, auth, tool, args=None):
    async with _http(app, auth) as http, Client(streamable_http_client(URL, http_client=http)) as client:
        tools = await client.list_tools()
        result = await client.call_tool(tool, args or {})
        return sorted(t.name for t in tools.tools), result


def run(coro_fn, *args):
    return anyio.run(coro_fn, *args)


def test_no_token_gets_401_with_resource_metadata(vault, creds):
    async def go():
        async with _server(vault, creds) as app, _http(app) as http:
            return await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Accept": "application/json, text/event-stream"})

    resp = run(go)
    assert resp.status_code == 401
    assert "resource_metadata=" in resp.headers["www-authenticate"]


def test_forged_token_gets_401(vault, creds):
    async def go():
        # Correct kid and claims, but signed with a key Vault never published
        forged = vault.mint(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
        async with _server(vault, creds) as app, _http(app, headers={"Authorization": f"Bearer {forged}"}) as http:
            return await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Accept": "application/json, text/event-stream"})

    assert run(go).status_code == 401


def test_reader_group_calls_all_tools(vault, creds):
    async def go():
        async with _server(vault, creds) as app:
            return await _call(app, VaultIdentityAuth(vault.read, "mcp-orders"), "list_orders", {"status": "pending"})

    tools, result = run(go)
    assert tools == ["get_order", "list_orders", "whoami"]
    assert not result.is_error
    assert "acme-ltd" in result.content[0].text
    assert creds.queries[-1][1] == ["pending", 20]


def test_reporter_group_cannot_call_get_order(vault, creds):
    vault.groups = ["mcp-orders-reporter"]

    async def go():
        async with _server(vault, creds) as app:
            return await _call(app, VaultIdentityAuth(vault.read, "mcp-orders"), "get_order", {"order_id": 1})

    _, result = run(go)
    assert result.is_error
    assert "not permitted" in result.content[0].text
    assert creds.queries == []


def test_whoami_shows_caller_and_db_user_never_password(vault, creds):
    async def go():
        async with _server(vault, creds) as app:
            return await _call(app, VaultIdentityAuth(vault.read, "mcp-orders"), "whoami")

    _, result = run(go)
    text = result.content[0].text
    assert "entity-1234" in text and "v-kubernetes-preview-orders-abc" in text
    assert "password" not in text


@pytest.mark.parametrize("groups", [[], ["some-other-group"]])
def test_no_allowed_group_fails_closed(vault, creds, groups):
    vault.groups = groups

    async def go():
        async with _server(vault, creds) as app, _http(app, auth=VaultIdentityAuth(vault.read, "mcp-orders")) as http:
            return await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Accept": "application/json, text/event-stream"})

    assert run(go).status_code == 401


def test_client_run_once_logs_401_status_for_unlisted_identity(vault, creds, monkeypatch, caplog):
    """Regression: the SDK wraps a 401 in a generic MCPError; the client must still log status=401."""
    import logging

    from mcp_lab import client as client_mod
    from mcp_lab.config import ClientConfig

    vault.groups = []  # valid Vault identity, no group -> server answers 401

    async def go():
        async with _server(vault, creds) as app:
            monkeypatch.setattr(client_mod, "create_mcp_http_client", lambda auth=None: _http(app, auth=auth))
            config = ClientConfig.from_env({"MCP_URL": URL, "CLIENT_TOOLS": "list_orders"})
            await client_mod.run_once(config, VaultIdentityAuth(vault.read, "mcp-orders"))

    with caplog.at_level(logging.WARNING, logger="mcp_lab.client"):
        run(go)
    failed = [r for r in caplog.records if r.getMessage() == "mcp_call_failed"]
    assert failed and failed[-1].fields["status"] == 401
