"""The real MCP SDK auth stack in-process: bearer middleware, OAuth JWT verifier, per-tool scope checks."""

from __future__ import annotations

import contextlib
import logging

import anyio
import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.transport_security import TransportSecuritySettings

from conftest import OAUTH_ISSUER, RESOURCE
from mcp_lab import client as client_mod
from mcp_lab import server
from mcp_lab.auth import OAuthJwtVerifier, ScopeToolsError
from mcp_lab.client import ClientCredentialsAuth
from mcp_lab.config import ClientConfig, ServerConfig
from mcp_lab.server import build_mcp

URL = RESOURCE
LIST_REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}


def _config() -> ServerConfig:
    return ServerConfig.from_env({"DB_CREDS_PATH": "database/creds/dev-orders", "DB_HOST": "pg", "DB_NAME": "dev"})


def _verifier(auth_server, **kwargs) -> OAuthJwtVerifier:
    return OAuthJwtVerifier(auth_server.jwks, OAUTH_ISSUER, RESOURCE, **kwargs)


@contextlib.asynccontextmanager
async def _server(auth_server, creds, **verifier_kwargs):
    mcp = build_mcp(_config(), creds, _verifier(auth_server, **verifier_kwargs))
    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=["localhost:8000"]),
    )
    async with mcp.session_manager.run():
        yield app


def _http(app, token=None, auth=None) -> httpx2.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else None
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://localhost:8000", auth=auth, headers=headers)


async def _call(app, token, tool, args=None):
    async with _http(app, token) as http, Client(streamable_http_client(URL, http_client=http)) as client:
        tools = await client.list_tools()
        result = await client.call_tool(tool, args or {})
        return sorted(t.name for t in tools.tools), result


def run(coro_fn, *args):
    return anyio.run(coro_fn, *args)


def call(auth_server, creds, token, tool, args=None, **verifier_kwargs):
    async def go():
        async with _server(auth_server, creds, **verifier_kwargs) as app:
            return await _call(app, token, tool, args)

    return run(go)


def post_list(auth_server, creds, token=None):
    async def go():
        async with _server(auth_server, creds) as app, _http(app, token) as http:
            return await http.post("/mcp", json=LIST_REQUEST, headers=MCP_ACCEPT)

    return run(go)


def test_no_token_gets_401_with_resource_metadata(auth_server, creds):
    resp = post_list(auth_server, creds)
    assert resp.status_code == 401
    assert "resource_metadata=" in resp.headers["www-authenticate"]


def test_protected_resource_metadata_names_better_auth(auth_server, creds):
    async def go():
        async with _server(auth_server, creds) as app, _http(app) as http:
            return await http.get("/.well-known/oauth-protected-resource/mcp")

    body = run(go).json()
    assert body["authorization_servers"] == [OAUTH_ISSUER]
    assert body["resource"] == RESOURCE


def test_forged_token_gets_401(auth_server, creds):
    assert post_list(auth_server, creds, auth_server.mint(key=ec.generate_private_key(ec.SECP256R1()))).status_code == 401


def test_token_for_another_resource_gets_401(auth_server, creds):
    assert post_list(auth_server, creds, auth_server.mint(aud="http://localhost:9000/mcp")).status_code == 401


def test_reader_lists_all_tools_and_calls_list_orders(auth_server, creds):
    tools, result = call(auth_server, creds, auth_server.mint(), "list_orders", {"status": "pending"})
    assert tools == ["delete_order", "get_order", "list_orders", "whoami"]
    assert not result.is_error
    assert "acme-ltd" in result.content[0].text
    assert creds.queries[-1][1] == ["pending", 20]


def test_missing_scope_denies_the_tool(auth_server, creds):
    _, result = call(auth_server, creds, auth_server.mint(scope="orders:list"), "get_order", {"order_id": 1})
    assert result.is_error
    assert "not permitted" in result.content[0].text
    assert creds.queries == []


@pytest.mark.parametrize("scope", ["orders:list", "orders:get", "orders:list orders:get whoami"])
def test_delete_order_is_denied_for_every_scope(auth_server, creds, scope):
    _, result = call(auth_server, creds, auth_server.mint(scope=scope), "delete_order", {"order_id": 1})
    assert result.is_error
    assert "permission denied" in result.content[0].text
    assert creds.queries == []


def test_delete_order_denied_even_if_a_scope_granted_it(auth_server, creds, monkeypatch):
    # Defence in depth: even if the startup check were bypassed, a scope granting delete_order still cannot delete anything
    monkeypatch.setattr(server, "check_scope_tools", lambda *_: None)
    granted = {"orders:list": frozenset({"delete_order", "list_orders"}), "orders:get": frozenset({"get_order"}), "whoami": frozenset({"whoami"})}
    _, result = call(auth_server, creds, auth_server.mint(), "delete_order", {"order_id": 1}, scope_tools=granted)
    assert result.is_error
    assert "permission denied" in result.content[0].text
    assert "not supported" in result.content[0].text
    assert creds.queries == []


def test_delete_order_is_annotated_destructive(auth_server, creds):
    async def go():
        async with _server(auth_server, creds) as app, _http(app, auth_server.mint()) as http, Client(streamable_http_client(URL, http_client=http)) as client:
            return {t.name: t for t in (await client.list_tools()).tools}["delete_order"]

    tool = run(go)
    assert tool.annotations.destructive_hint is True
    assert tool.output_schema is None


def test_whoami_shows_the_person_and_db_user_never_password(auth_server, creds):
    _, result = call(auth_server, creds, auth_server.mint(), "whoami")
    text = result.content[0].text
    assert "testuser" in text and "user-1" in text and "lab-cli" in text and "v-kubernetes-dev-orders-abc" in text
    assert "password" not in text


@pytest.mark.parametrize("scope", ["", "openid"])
def test_no_known_scope_fails_closed(auth_server, creds, scope):
    assert post_list(auth_server, creds, auth_server.mint(scope=scope)).status_code == 401


def test_client_run_once_logs_401_status_for_rejected_token(auth_server, creds, monkeypatch, caplog):
    """Regression: the SDK wraps a 401 in a generic MCPError; the client must still log status=401."""

    class Auth(ClientCredentialsAuth):
        def token(self) -> str:
            return auth_server.mint(scope="openid")

    async def go():
        async with _server(auth_server, creds) as app:
            monkeypatch.setattr(client_mod, "create_mcp_http_client", lambda auth=None: _http(app, auth=auth))
            config = ClientConfig.from_env({"MCP_URL": URL, "MCP_TOKEN_URL": f"{OAUTH_ISSUER}/oauth2/token", "CLIENT_TOOLS": "list_orders"})
            await client_mod.run_once(config, Auth(config.token_url, config.resource, config.scopes, config.service_account_token))

    with caplog.at_level(logging.WARNING, logger="mcp_lab.client"):
        run(go)
    failed = [r for r in caplog.records if r.getMessage() == "mcp_call_failed"]
    assert failed and failed[-1].fields["status"] == 401


def test_client_run_once_logs_token_endpoint_status(auth_server, creds, monkeypatch, caplog):
    """Regression: a refused client login arrives wrapped by the SDK; A8 relies on its status in the log."""

    class Auth(ClientCredentialsAuth):
        def token(self) -> str:
            raise client_mod.TokenUnavailable(401)

    async def go():
        async with _server(auth_server, creds) as app:
            monkeypatch.setattr(client_mod, "create_mcp_http_client", lambda auth=None: _http(app, auth=auth))
            config = ClientConfig.from_env({"MCP_URL": URL, "MCP_TOKEN_URL": f"{OAUTH_ISSUER}/oauth2/token", "CLIENT_TOOLS": "list_orders"})
            await client_mod.run_once(config, Auth(config.token_url, config.resource, config.scopes, config.service_account_token))

    with caplog.at_level(logging.WARNING, logger="mcp_lab.client"):
        run(go)
    failed = [r for r in caplog.records if r.getMessage() == "mcp_call_failed"]
    assert failed[-1].fields["error"] == "token_unavailable"
    assert failed[-1].fields["status"] == 401


def test_build_mcp_rejects_unknown_tool_in_scope_map(auth_server, creds):
    # A typo in scope_tools.toml must stop startup, not silently deny the tool
    with pytest.raises(ScopeToolsError, match="unknown tool"):
        build_mcp(_config(), creds, _verifier(auth_server, scope_tools={"orders:list": frozenset({"list_order"})}))


def test_build_mcp_rejects_a_map_granting_delete_order(auth_server, creds):
    with pytest.raises(ScopeToolsError, match="never be granted"):
        build_mcp(_config(), creds, _verifier(auth_server, scope_tools={"orders:list": frozenset({"delete_order"})}))


def test_serve_exits_2_and_logs_when_scope_tools_is_invalid(monkeypatch, caplog):
    class Proxy:
        def __init__(self, _socket):
            self.read = lambda _path: (404, {}, None)

        def wait_for_socket(self):
            return True

    def broken():
        raise ScopeToolsError("scope_tools.toml: broken")

    monkeypatch.setattr(server, "VaultClient", Proxy)
    monkeypatch.setattr(server, "packaged_scope_tools", broken)
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exit_info:
        run(server.serve, _config())
    assert exit_info.value.code == 2
    assert [r.getMessage() for r in caplog.records] == ["scope_tools_invalid"]
