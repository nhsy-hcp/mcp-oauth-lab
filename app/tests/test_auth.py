"""VaultJwtVerifier: signature, alg, iss, aud, exp, kid rotation, JWKS failures and group mapping (fail closed)."""

from __future__ import annotations

import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import AUDIENCE, ISSUER
from mcp_lab.auth import MIN_REFRESH_SECONDS, VaultJwtVerifier, tools_for_groups


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def verifier(vault, clock=None) -> VaultJwtVerifier:
    return VaultJwtVerifier(vault.read, ISSUER, AUDIENCE, clock=clock or Clock())


def test_valid_reader_token(vault):
    token = verifier(vault).verify(vault.mint())
    assert token is not None
    assert token.scopes == ["get_order", "list_orders", "whoami"]
    assert token.client_id == "preview/orders-agent"
    assert token.subject == "entity-1234"


def test_reporter_gets_list_orders_only(vault):
    vault.groups = ["mcp-orders-reporter"]
    assert verifier(vault).verify(vault.mint()).scopes == ["list_orders"]


def test_union_of_groups(vault):
    vault.groups = ["mcp-orders-reporter", "mcp-orders-reader"]
    assert verifier(vault).verify(vault.mint()).scopes == ["get_order", "list_orders", "whoami"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"key": rsa.generate_private_key(public_exponent=65537, key_size=2048)},  # forged signature
        {"aud": "another-server"},
        {"iss": "http://evil.example/v1/identity/oidc"},
        {"exp": int(time.time()) - 120},  # expired (beyond pyjwt's zero leeway)
        {"exp": None},  # exp missing
        {"iat": None},  # iat missing
        {"kid": "kid-unknown"},
    ],
    ids=["forged", "wrong-aud", "wrong-iss", "expired", "no-exp", "no-iat", "unknown-kid"],
)
def test_rejected_tokens(vault, overrides):
    assert verifier(vault).verify(vault.mint(**overrides)) is None


def test_hs256_and_none_algorithms_rejected(vault):
    import jwt

    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": int(time.time()), "exp": int(time.time()) + 60, "groups": ["mcp-orders-reader"]}
    hs = jwt.encode(claims, "attacker-guess-of-a-shared-secret-32b", algorithm="HS256", headers={"kid": "kid-1"})
    none = jwt.encode(claims, None, algorithm="none", headers={"kid": "kid-1"})
    v = verifier(vault)
    assert v.verify(hs) is None
    assert v.verify(none) is None


@pytest.mark.parametrize("groups", [[], ["other"], None, "mcp-orders-reader"], ids=["empty", "unknown", "missing", "not-a-list"])
def test_no_allowed_group_fails_closed(vault, groups):
    vault.groups = groups
    assert verifier(vault).verify(vault.mint(groups=groups)) is None


def test_garbage_token(vault):
    assert verifier(vault).verify("not-a-jwt") is None


def test_key_rotation_refetches_jwks_once(vault):
    clock = Clock()
    v = verifier(vault, clock)
    assert v.verify(vault.mint()) is not None
    vault.keys["kid-2"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vault.active_kid = "kid-2"
    clock.now += MIN_REFRESH_SECONDS
    assert v.verify(vault.mint()) is not None
    assert vault.reads.count("identity/oidc/.well-known/keys") == 2


def test_unknown_kid_refetch_is_rate_limited(vault):
    clock = Clock()
    v = verifier(vault, clock)
    v.verify(vault.mint())
    for _ in range(5):
        assert v.verify(vault.mint(kid="kid-forged")) is None
    assert vault.reads.count("identity/oidc/.well-known/keys") == 1


def test_jwks_unavailable_rejects_and_recovers(vault):
    clock = Clock()
    vault.jwks_status = 503  # e.g. Vault sealed
    v = verifier(vault, clock)
    assert v.verify(vault.mint()) is None
    vault.jwks_status = 200
    clock.now += MIN_REFRESH_SECONDS
    assert v.verify(vault.mint()) is not None


def test_failed_jwks_fetch_is_rate_limited(vault):
    """Regression: a failed fetch must count towards the limit, or a down Vault gets one fetch per request."""
    clock = Clock()
    vault.jwks_status = 503
    v = verifier(vault, clock)
    for _ in range(5):
        assert v.verify(vault.mint()) is None
    assert vault.reads.count("identity/oidc/.well-known/keys") == 1


def test_jwks_fetch_does_not_block_cached_keys(vault):
    """Regression: a slow JWKS fetch (forged kid) must not hold the lock that verifying a known kid needs."""
    clock = Clock()
    v = verifier(vault, clock)
    assert v.verify(vault.mint()) is not None
    clock.now += MIN_REFRESH_SECONDS
    started, release = threading.Event(), threading.Event()
    real_read = v._read

    def slow_read(path):
        started.set()
        release.wait(5)
        return real_read(path)

    v._read = slow_read
    forged = threading.Thread(target=v.verify, args=(vault.mint(kid="kid-forged"),))
    forged.start()
    try:
        assert started.wait(5)
        done = threading.Event()
        result = []
        threading.Thread(target=lambda: (result.append(v.verify(vault.mint())), done.set())).start()
        assert done.wait(2), "valid token blocked behind the JWKS fetch"
        assert result[0] is not None
    finally:
        release.set()
        forged.join(5)


def test_tools_for_groups_ignores_non_strings():
    assert tools_for_groups(["mcp-orders-reporter", 7, None]) == frozenset({"list_orders"})
