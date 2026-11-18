"""Test fixtures: a fake Vault Proxy on a UNIX socket, fake connection pools (from learn-vault-proxy), and a fake
Vault OIDC issuer (RSA keys, JWKS, signed identity tokens) with a fake DB runner for the MCP layer."""

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
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from mcp_lab.vault_client import VaultClient

Route = tuple[int, dict[str, str], Any]
ISSUER = "http://vault.vault.svc.cluster.local:8200/v1/identity/oidc"
AUDIENCE = "mcp-orders"


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


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class FakeVault:
    """Stands in for VaultClient.read: serves JWKS and identity tokens like Vault's identity/oidc."""

    keys: dict[str, rsa.RSAPrivateKey] = field(default_factory=lambda: {"kid-1": _key()})
    active_kid: str = "kid-1"
    groups: list[str] = field(default_factory=lambda: ["mcp-orders-reader"])
    ttl: int = 300
    token_status: int = 200
    jwks_status: int = 200
    reads: list[str] = field(default_factory=list)

    def jwks(self) -> dict[str, Any]:
        out = []
        for kid, key in self.keys.items():
            jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
            jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
            out.append(jwk)
        return {"keys": out}

    def mint(self, **overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "entity-1234",
            "iat": now,
            "exp": now + self.ttl,
            "namespace": "root",
            "groups": self.groups,
            "environment": "dev",
            "application_name": "orders-agent",
        }
        kid = overrides.pop("kid", self.active_kid)
        key = overrides.pop("key", self.keys.get(kid) or _key())
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key, algorithm=overrides.pop("alg", "RS256"), headers={"kid": kid})

    def read(self, path: str) -> tuple[int, dict[str, str], Any]:
        self.reads.append(path)
        if path == "identity/oidc/.well-known/keys":
            return self.jwks_status, {}, self.jwks() if self.jwks_status == 200 else {"errors": ["sealed"]}
        if path.startswith("identity/oidc/token/"):
            if self.token_status != 200:
                return self.token_status, {}, {"errors": ["permission denied"]}
            return 200, {}, {"data": {"token": self.mint(), "client_id": AUDIENCE, "ttl": self.ttl}}
        return 404, {}, None


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
def vault() -> FakeVault:
    return FakeVault()


@pytest.fixture
def creds() -> FakeCreds:
    return FakeCreds()
