"""Shared fakes: a Vault OIDC issuer (RSA keys, JWKS, signed identity tokens) and a fake DB runner."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "http://vault.vault.svc.cluster.local:8200/v1/identity/oidc"
AUDIENCE = "mcp-orders"


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
            "environment": "preview",
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
        return {"current_user": "v-kubernetes-preview-orders-abc", "creds_path": "database/creds/preview-orders", "lease_id_suffix": "xyz", "lease_seconds_remaining": 540}

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
