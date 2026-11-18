"""Test fixtures: a fake Vault Proxy on a UNIX socket, fake connection pools (from learn-vault-proxy), and a fake
OAuth authorization server (ES256 key, JWKS, signed access tokens) with a fake DB runner for the MCP layer."""

from __future__ import annotations

import json
import shutil
import socketserver
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from mcp_lab.vault_client import VaultClient

Route = tuple[int, dict[str, str], Any]
OAUTH_ISSUER = "http://localhost:3000/api/auth"
RESOURCE = "http://localhost:8000/mcp"


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


@dataclass
class FakeProxyState:
    routes: dict[str, Route | Callable[[], Route] | list[Route]] = field(default_factory=dict)
    requests: list[Recorded] = field(default_factory=list)

    def calls(self, method: str, path: str) -> list[Recorded]:
        return [r for r in self.requests if r.method == method and r.path == path]


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def _make_handler(state: FakeProxyState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw) if raw else None
            state.requests.append(Recorded(self.command, self.path, dict(self.headers), body))
            if self.headers.get("X-Vault-Request") != "true":
                self._reply(412, {}, {"errors": ["missing X-Vault-Request header"]})
                return
            key = f"{self.command} {self.path}"
            route = state.routes.get(key)
            if route is None:
                route = (200, {}, None) if self.command == "POST" and self.path == "/proxy/v1/cache-clear" else (404, {}, {"errors": []})
            if isinstance(route, list):
                route = route.pop(0) if len(route) > 1 else route[0]
            if callable(route):
                route = route()
            self._reply(*route)

        do_GET = _handle
        do_POST = _handle

        def _reply(self, status: int, headers: dict[str, str], body: Any) -> None:
            payload = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            # A route may set its own Content-Length to simulate a truncated body (IncompleteRead).
            if "Content-Length" not in headers:
                self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def address_string(self) -> str:
            return "unix"

    return Handler


@pytest.fixture
def socket_dir() -> Iterator[Path]:
    # Short path: AF_UNIX paths are limited to ~104 bytes on macOS.
    path = Path(tempfile.mkdtemp(prefix="vp-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def fake_proxy(socket_dir: Path) -> Iterator[tuple[FakeProxyState, VaultClient]]:
    state = FakeProxyState()
    sock = str(socket_dir / "proxy.sock")
    server = _UnixHTTPServer(sock, _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield state, VaultClient(sock, timeout=2.0)
    finally:
        server.shutdown()
        server.server_close()


def creds_response(
    username: str,
    lease_id: str = "db/creds/dev-payments/abc123XYZ789",
    lease_duration: int = 600,
) -> Route:
    return (
        200,
        {},
        {
            "lease_id": lease_id,
            "lease_duration": lease_duration,
            "renewable": True,
            "data": {"username": username, "password": f"pw-{username}-secret"},
        },
    )


def truncated_response() -> Route:
    """Promise more bytes than are sent: the client sees ``http.client.IncompleteRead``."""
    return (200, {"Content-Length": "4096"}, {"data": {}})


def kv_response(api_key: str, version: int, headers: dict[str, str] | None = None) -> Route:
    return (
        200,
        headers or {},
        {
            "data": {
                "data": {"api_key": api_key, "issuer": "demo-partner-api"},
                "metadata": {"version": version},
            }
        },
    )


class FakeCursor:
    def __init__(self, conn: FakeConn) -> None:
        self.conn = conn

    def execute(self, query: Any) -> FakeCursor:
        self.conn.executed.append(query)
        return self

    def fetchone(self) -> tuple[str]:
        return (self.conn.user,)

    def fetchall(self) -> list[dict[str, Any]]:
        return [{"id": 1, "name": "widget"}]

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        pass


class FakeConn:
    def __init__(self, user: str) -> None:
        self.user = user
        self.executed: list[Any] = []

    def execute(self, query: Any) -> FakeCursor:
        return FakeCursor(self).execute(query)

    def cursor(self, row_factory: Any = None) -> FakeCursor:
        return FakeCursor(self)

    def close(self) -> None:
        pass


class FakePool:
    def __init__(self, conninfo: str) -> None:
        self.conninfo = conninfo
        self.closed = False
        self.user = dict(p.split("=", 1) for p in conninfo.split())["user"]
        # Exceptions to raise from successive connection() calls before succeeding.
        self.failures: list[BaseException] = []

    @contextmanager
    def connection(self) -> Iterator[FakeConn]:
        if self.failures:
            raise self.failures.pop(0)
        yield FakeConn(self.user)

    def close(self) -> None:
        self.closed = True


class PoolFactory:
    def __init__(self) -> None:
        self.pools: list[FakePool] = []

    def __call__(self, conninfo: str) -> FakePool:
        pool = FakePool(conninfo)
        self.pools.append(pool)
        return pool


class Connector:
    """Probe-connection factory; raise queued errors, else succeed."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.failures: list[BaseException] = []

    def __call__(self, conninfo: str) -> FakeConn:
        self.calls.append(conninfo)
        if self.failures:
            raise self.failures.pop(0)
        return FakeConn("probe")


# --- MCP layer fakes ------------------------------------------------------------------------


@dataclass
class FakeAuthServer:
    """Stands in for Better Auth: an ES256 JWKS and RFC 9068 access tokens."""

    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    kid: str = "es-1"
    fetches: int = 0
    fail: bool = False

    def jwks(self) -> dict[str, Any]:
        self.fetches += 1
        if self.fail:
            raise OSError("auth server down")
        jwk = ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, **overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": OAUTH_ISSUER,
            "aud": [RESOURCE, f"{OAUTH_ISSUER}/oauth2/userinfo"],
            "sub": "user-1",
            "azp": "lab-cli",
            "client_id": "lab-cli",
            "scope": "openid orders:list orders:get whoami",
            "preferred_username": "testuser",
            "iat": now,
            "exp": now + 300,
        }
        key = overrides.pop("key", self.key)
        alg = overrides.pop("alg", "ES256")
        typ = overrides.pop("typ", "at+jwt")
        kid = overrides.pop("kid", self.kid)
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid, "typ": typ})


class FakeCreds:
    """Stands in for CredentialManager: records SQL, returns canned rows."""

    def __init__(self, rows: list[tuple[Any, ...]] | None = None) -> None:
        self.rows = rows if rows is not None else [(1, "acme-ltd", "pending", 4200), (3, "initech", "pending", 750)]
        self.queries: list[tuple[str, list[Any]]] = []

    def run_query(self, fn: Any) -> Any:
        return fn(_FakeConn(self))

    def whoami(self) -> dict[str, Any]:
        return {"current_user": "v-kubernetes-dev-orders-abc", "creds_path": "database/creds/dev-orders", "lease_id_suffix": "xyz", "lease_seconds_remaining": 540}

    def is_healthy(self) -> bool:
        return True


class _Col:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeCursor:
    def __init__(self, creds: FakeCreds) -> None:
        self.creds = creds
        self.description = [_Col(n) for n in ("id", "customer", "status", "total_pence")]

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, sql: str, params: list[Any]) -> None:
        self.creds.queries.append((sql, list(params)))

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.creds.rows


class _FakeConn:
    def __init__(self, creds: FakeCreds) -> None:
        self.creds = creds

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self.creds)


@pytest.fixture
def auth_server() -> FakeAuthServer:
    return FakeAuthServer()


@pytest.fixture
def creds() -> FakeCreds:
    return FakeCreds()
