"""ClientCredentialsAuth: logs in with the pod's ServiceAccount JWT, caches the access token, never sends a stale one."""

from __future__ import annotations

import httpx2
import pytest

from mcp_lab.client import REFRESH_BEFORE_EXPIRY, SERVICE_ACCOUNT_ASSERTION, ClientCredentialsAuth, TokenUnavailable, _root_cause

TOKEN_URL = "http://auth.localhost:3000/api/auth/oauth2/token"
RESOURCE = "http://localhost:8000/mcp"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


class FakeTokenEndpoint:
    def __init__(self, status=200, body=None):
        self.status = status
        self.body = body if body is not None else {"access_token": "ey.access.1", "expires_in": 300, "token_type": "Bearer"}
        self.requests = []

    def __call__(self, url, form):
        self.requests.append((url, form))
        return self.status, self.body


@pytest.fixture
def sa_token(tmp_path):
    path = tmp_path / "token"
    path.write_text("sa-jwt-1\n")
    return path


def make(sa_token, post, clock=None, scopes=("orders:list",)):
    return ClientCredentialsAuth(TOKEN_URL, RESOURCE, scopes, str(sa_token), post=post, clock=clock or Clock())


def test_requests_a_client_credentials_token_with_the_service_account_jwt(sa_token):
    post = FakeTokenEndpoint()
    assert make(sa_token, post, scopes=("orders:list", "whoami")).token() == "ey.access.1"
    url, form = post.requests[0]
    assert url == TOKEN_URL
    assert form == {
        "grant_type": "client_credentials",
        "client_assertion_type": SERVICE_ACCOUNT_ASSERTION,
        "client_assertion": "sa-jwt-1",
        "resource": RESOURCE,
        "scope": "orders:list whoami",
    }


def test_token_cached_then_refreshed_before_expiry_with_a_fresh_service_account_jwt(sa_token):
    clock = Clock()
    post = FakeTokenEndpoint()
    auth = make(sa_token, post, clock)
    first = auth.token()
    assert auth.token() == first
    assert len(post.requests) == 1
    sa_token.write_text("sa-jwt-2")
    clock.now += 300 - REFRESH_BEFORE_EXPIRY + 1
    auth.token()
    assert len(post.requests) == 2
    assert post.requests[1][1]["client_assertion"] == "sa-jwt-2"


def test_short_lived_token_is_reused_for_most_of_its_life(sa_token):
    # Regression: a fixed 60-second margin requested a new token for every HTTP request when the TTL was 60 s or less
    clock = Clock()
    post = FakeTokenEndpoint(body={"access_token": "ey.short", "expires_in": 20})
    auth = make(sa_token, post, clock)
    auth.token()
    clock.now += 14
    auth.token()
    assert len(post.requests) == 1
    clock.now += 2
    auth.token()
    assert len(post.requests) == 2


@pytest.mark.parametrize(("status", "body"), [(401, {"error": "invalid_client"}), (400, {"error": "invalid_scope"}), (200, {}), (200, {"access_token": ""})])
def test_refused_or_malformed_responses_raise(sa_token, status, body):
    with pytest.raises(TokenUnavailable) as err:
        make(sa_token, FakeTokenEndpoint(status, body)).token()
    assert err.value.status == status


def test_missing_service_account_token_raises(tmp_path):
    with pytest.raises(TokenUnavailable):
        make(tmp_path / "missing", FakeTokenEndpoint()).token()


def test_auth_flow_sets_bearer_header(sa_token):
    request = httpx2.Request("POST", "http://mcp/mcp")
    sent = next(make(sa_token, FakeTokenEndpoint()).auth_flow(request))
    assert sent.headers["Authorization"] == "Bearer ey.access.1"


def test_root_cause_unwraps_exception_groups():
    inner = ValueError("401")
    assert _root_cause(ExceptionGroup("outer", [ExceptionGroup("mid", [inner])])) is inner
