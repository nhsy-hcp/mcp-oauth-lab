"""OAuthJwtVerifier and scope_tools.toml: what an access token must prove, and failing closed."""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from conftest import OAUTH_ISSUER, RESOURCE
from mcp_lab.auth import (
    MIN_REFRESH_SECONDS,
    JwksUnavailable,
    OAuthJwtVerifier,
    ScopeToolsError,
    check_scope_tools,
    fetch_jwks_url,
    load_scope_tools,
    packaged_scope_tools,
    tools_for_scopes,
)

SCOPE_TOOLS = packaged_scope_tools()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def verifier(auth_server, clock=None) -> OAuthJwtVerifier:
    return OAuthJwtVerifier(auth_server.jwks, OAUTH_ISSUER, RESOURCE, clock=clock or Clock())


def test_valid_token_maps_known_scopes_to_tools(auth_server):
    token = verifier(auth_server).verify(auth_server.mint())
    assert token.scopes == ["orders:get", "orders:list", "whoami"]
    assert token.tools == {"list_orders", "get_order", "whoami"}
    assert token.client_id == "lab-cli"
    assert token.subject == "user-1"
    assert token.resource == RESOURCE


def test_reporter_scope_gets_only_its_tool(auth_server):
    token = verifier(auth_server).verify(auth_server.mint(scope="openid orders:list"))
    assert token.scopes == ["orders:list"]
    assert token.tools == {"list_orders"}


def test_machine_token_with_single_audience(auth_server):
    token = verifier(auth_server).verify(auth_server.mint(aud=RESOURCE, sub="orders-agent", azp="orders-agent", scope="orders:list", preferred_username=None))
    assert token.client_id == "orders-agent"


@pytest.mark.parametrize(
    "overrides",
    [
        {"key": ec.generate_private_key(ec.SECP256R1())},
        {"aud": "http://localhost:9999/mcp"},
        {"iss": "http://evil.example/api/auth"},
        {"exp": int(time.time()) - 120},
        {"exp": None},
        {"iat": None},
        {"sub": None},
        {"azp": None},
        {"azp": ""},
        {"azp": 7},
        {"scope": None},
        {"scope": ["orders:list"]},
        {"typ": "JWT"},
        {"typ": None},
        {"kid": "unknown"},
    ],
    ids=["forged", "wrong-aud", "wrong-iss", "expired", "no-exp", "no-iat", "no-sub", "no-azp", "empty-azp", "bad-azp", "no-scope", "scope-list", "jwt-typ", "no-typ", "unknown-kid"],
)
def test_rejected_tokens(auth_server, overrides):
    assert verifier(auth_server).verify(auth_server.mint(**overrides)) is None


@pytest.mark.parametrize("scope", ["", "openid profile", "orders:delete", "ORDERS:LIST"])
def test_no_known_scope_fails_closed(auth_server, scope):
    assert verifier(auth_server).verify(auth_server.mint(scope=scope)) is None


def test_other_algorithms_rejected(auth_server):
    now = int(time.time())
    claims = {"iss": OAUTH_ISSUER, "aud": RESOURCE, "sub": "x", "azp": "x", "scope": "orders:list", "iat": now, "exp": now + 60}
    headers = {"kid": auth_server.kid, "typ": "at+jwt"}
    v = verifier(auth_server)
    assert v.verify(jwt.encode(claims, "attacker-guess-of-a-shared-secret-32b", algorithm="HS256", headers=headers)) is None
    assert v.verify(jwt.encode(claims, None, algorithm="none", headers=headers)) is None
    assert v.verify(jwt.encode(claims, rsa.generate_private_key(public_exponent=65537, key_size=2048), algorithm="RS256", headers=headers)) is None


def test_garbage_token(auth_server):
    assert verifier(auth_server).verify("not-a-jwt") is None


def test_key_rotation_refetches_jwks_once(auth_server):
    clock = Clock()
    v = verifier(auth_server, clock)
    assert v.verify(auth_server.mint()) is not None
    auth_server.key = ec.generate_private_key(ec.SECP256R1())
    auth_server.kid = "es-2"
    clock.now += MIN_REFRESH_SECONDS
    assert v.verify(auth_server.mint()) is not None
    assert auth_server.fetches == 2


def test_unknown_kid_refetch_is_rate_limited(auth_server):
    v = verifier(auth_server)
    v.verify(auth_server.mint())
    for _ in range(5):
        assert v.verify(auth_server.mint(kid="forged")) is None
    assert auth_server.fetches == 1


def test_jwks_failures_reject_are_throttled_and_recover(auth_server):
    clock = Clock()
    auth_server.fail = True
    v = verifier(auth_server, clock)
    for _ in range(3):
        assert v.verify(auth_server.mint()) is None
    assert auth_server.fetches == 1
    auth_server.fail = False
    clock.now += MIN_REFRESH_SECONDS
    assert v.verify(auth_server.mint()) is not None


def test_jwks_fetch_does_not_block_cached_keys(auth_server):
    """Regression: a slow JWKS fetch (forged kid) must not hold the lock that verifying a known kid needs."""
    clock = Clock()
    v = verifier(auth_server, clock)
    assert v.verify(auth_server.mint()) is not None
    clock.now += MIN_REFRESH_SECONDS
    started, release = threading.Event(), threading.Event()
    real_fetch = v._jwks_fetch

    def slow_fetch():
        started.set()
        release.wait(5)
        return real_fetch()

    v._jwks_fetch = slow_fetch
    forged = threading.Thread(target=v.verify, args=(auth_server.mint(kid="forged"),))
    forged.start()
    try:
        assert started.wait(5)
        done = threading.Event()
        result = []
        threading.Thread(target=lambda: (result.append(v.verify(auth_server.mint())), done.set())).start()
        assert done.wait(2), "valid token blocked behind the JWKS fetch"
        assert result[0] is not None
    finally:
        release.set()
        forged.join(5)


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, *_args):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None


@pytest.mark.parametrize("body", [b"not json", b"[]"])
def test_fetch_jwks_rejects_bad_bodies(monkeypatch, body):
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda *_a, **_k: _Response(body))
    with pytest.raises(JwksUnavailable):
        fetch_jwks_url("http://auth.localhost:3000/api/auth/jwks")


def test_fetch_jwks_returns_object(monkeypatch):
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda *_a, **_k: _Response(json.dumps({"keys": []}).encode()))
    assert fetch_jwks_url("http://auth.localhost:3000/api/auth/jwks") == {"keys": []}


def test_no_scope_grants_delete_order():
    assert all("delete_order" not in tools for tools in SCOPE_TOOLS.values())


def test_tools_for_scopes_ignores_unknown_scopes():
    assert tools_for_scopes(["orders:list", "openid", "orders:delete"]) == frozenset({"list_orders"})


def test_packaged_scope_tools_file():
    assert dict(SCOPE_TOOLS) == {
        "orders:list": frozenset({"list_orders"}),
        "orders:get": frozenset({"get_order"}),
        "whoami": frozenset({"whoami"}),
    }


def test_scope_tools_is_read_only():
    with pytest.raises(TypeError):
        SCOPE_TOOLS["orders:delete"] = frozenset({"delete_order"})  # type: ignore[index]


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("not = [toml", "scope_tools.toml"),
        ("", "non-empty [scopes] table"),
        ("scopes = 1", "non-empty [scopes] table"),
        ("[scopes]", "non-empty [scopes] table"),
        ("[scopes.reader]\ntools = ['list_orders']", "must map to a list"),
        ('[scopes]\nreader = ["list_orders", "list_orders"]', "lists a tool twice"),
        ('[scopes]\nreader = [" list_orders"]', "surrounding spaces"),
        ('[scopes]\n" reader" = ["list_orders"]', "scope name"),
        ('[scopes]\nreader = "list_orders"', "must map to a list"),
        ("[scopes]\nreader = [1]", "non-empty string"),
        ('[scopes]\nreader = [" "]', "non-empty string"),
        ('[scopes]\n"" = ["list_orders"]', "scope name"),
    ],
)
def test_load_scope_tools_rejects_bad_files(text, error):
    with pytest.raises(ScopeToolsError, match=re.escape(error)):
        load_scope_tools(text)


def test_load_scope_tools_empty_list_grants_nothing():
    assert load_scope_tools("[scopes]\nreader = []") == {"reader": frozenset()}


def test_check_scope_tools_rejects_unknown_tool():
    with pytest.raises(ScopeToolsError, match="unknown tool"):
        check_scope_tools({"reader": frozenset({"list_order"})}, {"list_orders"})
    check_scope_tools({"reader": frozenset({"list_orders"})}, {"list_orders", "whoami"})


def test_check_scope_tools_rejects_delete_order_even_though_registered():
    with pytest.raises(ScopeToolsError, match="never be granted: delete_order"):
        check_scope_tools({"admin": frozenset({"delete_order", "list_orders"})}, {"delete_order", "list_orders"})


def test_packaged_scope_tools_pass_the_startup_check():
    check_scope_tools(SCOPE_TOOLS, {"list_orders", "get_order", "delete_order", "whoami"})
