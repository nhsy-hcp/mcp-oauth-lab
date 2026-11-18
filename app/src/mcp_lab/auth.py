"""Verify OAuth access tokens on the MCP server and authorise tools by scope.

Better Auth decides who gets which scope and signs the token. This server is the resource server:

* signature against the issuer's JWKS, with ES256 pinned;
* ``typ=at+jwt``, ``iss``, ``aud``, ``exp``, ``iat``, ``sub``, ``azp`` and ``scope``;
* the ``scope`` claim mapped to tools through ``scope_tools.toml``, shipped inside this package and
  read by :func:`packaged_scope_tools`.

A token with no known scope fails closed (401). The token itself is never logged or forwarded.
"""

from __future__ import annotations

import functools
import json
import logging
import threading
import time
import tomllib
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from importlib import resources
from types import MappingProxyType
from typing import Any

import anyio
import jwt
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.exceptions import ToolError

from mcp_lab.logging_setup import log_event

log = logging.getLogger(__name__)

ALGORITHMS = ["ES256"]
AT_JWT_TYP = "at+jwt"
JWKS_TIMEOUT_SECONDS = 5
SCOPE_TOOLS_FILE = "scope_tools.toml"
# Tools no scope may ever grant, whatever the file says. delete_order also refuses on its own.
NEVER_GRANTED = frozenset({"delete_order"})
# Never fetch JWKS more often than this, whether the last attempt worked or not: a stream of forged kids,
# or the issuer being down, must not hammer it or queue requests behind a slow fetch.
MIN_REFRESH_SECONDS = 10.0


class ScopeToolsError(ValueError):
    """``scope_tools.toml`` is unreadable, malformed, or grants a tool it must not."""


class JwksUnavailable(Exception):
    pass


class ToolAccessToken(AccessToken):
    """An access token plus the tools its scopes allow."""

    tools: frozenset[str] = frozenset()


def _name(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ScopeToolsError(f"{SCOPE_TOOLS_FILE}: {what} must be a non-empty string without surrounding spaces, got {value!r}")
    return value


def load_scope_tools(text: str | None = None) -> Mapping[str, frozenset[str]]:
    """Parse the scope -> tools map (the packaged file unless ``text`` is given). Raises :class:`ScopeToolsError`."""
    try:
        if text is None:
            text = resources.files("mcp_lab").joinpath(SCOPE_TOOLS_FILE).read_text(encoding="utf-8")
        data = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ScopeToolsError(f"{SCOPE_TOOLS_FILE}: {exc}") from exc
    scopes = data.get("scopes")
    if not isinstance(scopes, dict) or not scopes:
        raise ScopeToolsError(f"{SCOPE_TOOLS_FILE}: a non-empty [scopes] table is required")
    result: dict[str, frozenset[str]] = {}
    for scope, tools in scopes.items():
        _name(scope, "scope name")
        if not isinstance(tools, list):
            raise ScopeToolsError(f"{SCOPE_TOOLS_FILE}: scope {scope!r} must map to a list of tool names")
        names = [_name(tool, f"tool in scope {scope!r}") for tool in tools]
        if len(set(names)) != len(names):
            raise ScopeToolsError(f"{SCOPE_TOOLS_FILE}: scope {scope!r} lists a tool twice")
        result[scope] = frozenset(names)
    return MappingProxyType(result)


@functools.cache
def packaged_scope_tools() -> Mapping[str, frozenset[str]]:
    """OAuth scope -> tools it allows, from the packaged file."""
    return load_scope_tools()


def check_scope_tools(scope_tools: Mapping[str, frozenset[str]], registered: Iterable[str]) -> None:
    """Fail closed at startup if the map grants a forbidden tool, or one the server does not register (a typo would silently deny)."""
    granted = set().union(*scope_tools.values())
    forbidden = sorted(granted & NEVER_GRANTED)
    if forbidden:
        raise ScopeToolsError(f"{SCOPE_TOOLS_FILE}: tool(s) must never be granted: {', '.join(forbidden)}")
    unknown = sorted(granted - set(registered))
    if unknown:
        raise ScopeToolsError(f"{SCOPE_TOOLS_FILE}: unknown tool(s) {', '.join(unknown)}")


def tools_for_scopes(scopes: Iterable[str], scope_tools: Mapping[str, frozenset[str]] | None = None) -> frozenset[str]:
    if scope_tools is None:
        scope_tools = packaged_scope_tools()
    allowed: set[str] = set()
    for scope in scopes:
        allowed |= scope_tools.get(scope, frozenset())
    return frozenset(allowed)


def fetch_jwks_url(url: str) -> dict[str, Any]:
    """Read a JWKS over HTTP. Proxies are ignored: this is an in-cluster request."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=JWKS_TIMEOUT_SECONDS) as response:
        try:
            body = json.load(response)
        except ValueError as exc:
            raise JwksUnavailable("jwks is not JSON") from exc
    if not isinstance(body, dict):
        raise JwksUnavailable("jwks is not an object")
    return body


class OAuthJwtVerifier:
    """``mcp`` TokenVerifier for Better Auth access tokens. Returns ``None`` for every rejection (401)."""

    def __init__(
        self,
        jwks_fetch: Callable[[], dict[str, Any]],
        issuer: str,
        audience: str,
        scope_tools: Mapping[str, frozenset[str]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._jwks_fetch = jwks_fetch
        self.issuer = issuer
        self.audience = audience
        self.scope_tools = packaged_scope_tools() if scope_tools is None else scope_tools
        self._clock = clock
        self._jwks: jwt.PyJWKSet | None = None
        self._attempted_at = float("-inf")
        self._lock = threading.Lock()

    def signing_key(self, kid: str | None) -> jwt.PyJWK | None:
        """Key for ``kid``; fetches JWKS when the kid is unknown (first use, key rotation).

        At most one attempt per :data:`MIN_REFRESH_SECONDS`, counted from the attempt rather than a
        success, so failures are throttled too. The lock only guards the cache; the fetch runs outside
        it, so a hanging issuer never blocks verification of tokens whose key is already cached.
        """
        if not kid:
            return None
        with self._lock:
            key = self._find(kid)
            now = self._clock()
            if key is not None or now - self._attempted_at < MIN_REFRESH_SECONDS:
                return key
            self._attempted_at = now
        jwks = jwt.PyJWKSet.from_dict(self._jwks_fetch())
        with self._lock:
            self._jwks = jwks
            return self._find(kid)

    def _find(self, kid: str) -> jwt.PyJWK | None:
        if self._jwks is None:
            return None
        for key in self._jwks.keys:
            if key.key_id == kid:
                return key
        return None

    def verify(self, token: str) -> AccessToken | None:
        """Synchronous core of :meth:`verify_token` (blocking network I/O on a JWKS refetch)."""
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in ALGORITHMS:
                raise jwt.InvalidAlgorithmError("unexpected alg")
            if header.get("typ") != AT_JWT_TYP:
                raise jwt.InvalidTokenError("not an access token")
            key = self.signing_key(header.get("kid"))
            if key is None:
                raise jwt.InvalidKeyError("unknown kid")
            claims = jwt.decode(
                token,
                key.key,
                algorithms=ALGORITHMS,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "azp", "scope"]},
            )
            if not isinstance(claims["azp"], str) or not claims["azp"] or not isinstance(claims["scope"], str):
                raise jwt.InvalidTokenError("malformed azp or scope")
        except (jwt.PyJWTError, JwksUnavailable, OSError) as exc:
            log_event(log, logging.WARNING, "token_rejected", reason=type(exc).__name__)
            return None
        scopes = sorted(scope for scope in claims["scope"].split() if scope in self.scope_tools)
        tools = tools_for_scopes(scopes, self.scope_tools)
        client = claims["azp"]
        if not tools:
            log_event(log, logging.WARNING, "token_rejected", reason="no_allowed_scope", sub=claims["sub"], client=client)
            return None
        log_event(log, logging.INFO, "token_accepted", sub=claims["sub"], user=claims.get("preferred_username"), client=client, scopes=scopes, tools=sorted(tools))
        return ToolAccessToken(
            token=token,
            client_id=client,
            scopes=scopes,
            tools=tools,
            expires_at=int(claims["exp"]),
            resource=self.audience,
            subject=claims["sub"],
            claims=claims,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        return await anyio.to_thread.run_sync(self.verify, token)


def require(tool: str) -> AccessToken:
    """First line of every tool: the caller's token scopes must allow ``tool``."""
    token = get_access_token()
    if not isinstance(token, ToolAccessToken) or tool not in token.tools:
        log_event(log, logging.WARNING, "tool_denied", tool=tool, client=token.client_id if token else None)
        raise ToolError(f"permission denied: {tool} is not permitted for this client")
    return token
