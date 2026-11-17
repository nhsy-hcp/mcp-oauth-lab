"""VaultIdentityAuth: mints over the Proxy socket, caches until shortly before expiry, never sends a stale token."""

from __future__ import annotations

import httpx2
import pytest

from mcp_lab.client import REFRESH_BEFORE_EXPIRY, TokenUnavailable, VaultIdentityAuth, _root_cause


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def test_token_cached_then_refreshed_before_expiry(vault):
    clock = Clock()
    auth = VaultIdentityAuth(vault.read, "mcp-orders", clock=clock)
    first = auth.token()
    assert auth.token() == first
    assert vault.reads.count("identity/oidc/token/mcp-orders") == 1
    clock.now += vault.ttl - REFRESH_BEFORE_EXPIRY + 1
    auth.token()
    assert vault.reads.count("identity/oidc/token/mcp-orders") == 2


def test_denied_mint_raises(vault):
    vault.token_status = 403  # e.g. a db-app style identity without the mcp-client policy
    with pytest.raises(TokenUnavailable) as err:
        VaultIdentityAuth(vault.read, "mcp-orders").token()
    assert err.value.status == 403


def test_auth_flow_sets_bearer_header(vault):
    auth = VaultIdentityAuth(vault.read, "mcp-orders")
    request = httpx2.Request("POST", "http://mcp/mcp")
    flow = auth.auth_flow(request)
    sent = next(flow)
    assert sent.headers["Authorization"].startswith("Bearer ey")


def test_root_cause_unwraps_exception_groups():
    inner = ValueError("401")
    assert _root_cause(ExceptionGroup("outer", [ExceptionGroup("mid", [inner])])) is inner
