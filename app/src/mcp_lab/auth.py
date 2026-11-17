"""Verify Vault identity JWTs on the MCP server and authorise tools by Vault identity group.

Vault is the identity broker: a client logs in with its Kubernetes ServiceAccount, reads
``identity/oidc/token/<role>`` and sends the JWT as a bearer token. This module checks it:

* signature against Vault's JWKS (``identity/oidc/.well-known/keys``), read through the server's own
  Vault Proxy socket - so the MCP pod needs no network path to Vault and holds no Vault credential;
* ``RS256`` only, ``iss``, ``aud``, ``exp`` and ``iat`` required;
* the ``groups`` claim (from ``{{identity.entity.groups.names}}``) mapped through ``group_tools.toml``,
  shipped inside this package and read by :func:`packaged_group_tools`.

Who is in a group is decided in Vault (``identity/group``); what a group may call is that versioned
file, baked into the image. ServiceAccount annotations only feed informational claims and never grant a tool. A token
with no known group fails closed (401). The token itself is never logged or forwarded.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
import tomllib
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

JWKS_PATH = "identity/oidc/.well-known/keys"
ALGORITHMS = ["RS256"]
GROUP_TOOLS_FILE = "group_tools.toml"
# Tools no group may ever be granted, whatever the file says. delete_order also refuses on its own.
NEVER_GRANTED = frozenset({"delete_order"})


class GroupToolsError(ValueError):
    """``group_tools.toml`` is unreadable, malformed, or grants a tool it must not."""


def _name(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GroupToolsError(f"{GROUP_TOOLS_FILE}: {what} must be a non-empty string without surrounding spaces, got {value!r}")
    return value


def load_group_tools(text: str | None = None) -> Mapping[str, frozenset[str]]:
    """Parse the group -> tools map (the packaged file unless ``text`` is given). Raises :class:`GroupToolsError`."""
    try:
        if text is None:
            text = resources.files("mcp_lab").joinpath(GROUP_TOOLS_FILE).read_text(encoding="utf-8")
        data = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GroupToolsError(f"{GROUP_TOOLS_FILE}: {exc}") from exc
    groups = data.get("groups")
    if not isinstance(groups, dict) or not groups:
        raise GroupToolsError(f"{GROUP_TOOLS_FILE}: a non-empty [groups] table is required")
    result: dict[str, frozenset[str]] = {}
    for group, tools in groups.items():
        _name(group, "group name")
        if not isinstance(tools, list):
            raise GroupToolsError(f"{GROUP_TOOLS_FILE}: group {group!r} must map to a list of tool names")
        names = [_name(tool, f"tool in group {group!r}") for tool in tools]
        if len(set(names)) != len(names):
            raise GroupToolsError(f"{GROUP_TOOLS_FILE}: group {group!r} lists a tool twice")
        result[group] = frozenset(names)
    return MappingProxyType(result)


@functools.cache
def packaged_group_tools() -> Mapping[str, frozenset[str]]:
    """Vault group -> tools it may call, from the packaged file. Membership lives in Vault; the tool set is reviewed here."""
    return load_group_tools()


def check_group_tools(group_tools: Mapping[str, frozenset[str]], registered: Iterable[str]) -> None:
    """Fail closed at startup if the map grants a forbidden tool, or one the server does not register (a typo would silently deny)."""
    granted = set().union(*group_tools.values())
    forbidden = sorted(granted & NEVER_GRANTED)
    if forbidden:
        raise GroupToolsError(f"{GROUP_TOOLS_FILE}: tool(s) must never be granted: {', '.join(forbidden)}")
    unknown = sorted(granted - set(registered))
    if unknown:
        raise GroupToolsError(f"{GROUP_TOOLS_FILE}: unknown tool(s) {', '.join(unknown)}")


# Never fetch JWKS more often than this, whether the last attempt worked or not: a stream of forged kids,
# or Vault being down, must not hammer Vault or queue requests behind a slow fetch.
MIN_REFRESH_SECONDS = 10.0

# (status, headers, json body) - the shape of VaultClient.read
VaultRead = Callable[[str], tuple[int, Any, Any]]


class JwksUnavailable(Exception):
    pass


def tools_for_groups(groups: Any, group_tools: Mapping[str, frozenset[str]] | None = None) -> frozenset[str]:
    if group_tools is None:
        group_tools = packaged_group_tools()
    if not isinstance(groups, list):
        return frozenset()
    allowed: set[str] = set()
    for group in groups:
        if isinstance(group, str):
            allowed |= group_tools.get(group, frozenset())
    return frozenset(allowed)


class VaultJwtVerifier:
    """``mcp`` TokenVerifier for Vault identity tokens. Returns ``None`` for every rejection (401)."""

    def __init__(
        self,
        vault_read: VaultRead,
        issuer: str,
        audience: str,
        group_tools: Mapping[str, frozenset[str]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._read = vault_read
        self.issuer = issuer
        self.audience = audience
        self.group_tools = packaged_group_tools() if group_tools is None else group_tools
        self._clock = clock
        self._jwks: jwt.PyJWKSet | None = None
        self._attempted_at = float("-inf")
        self._lock = threading.Lock()

    def _fetch_jwks(self) -> jwt.PyJWKSet:
        status, _, body = self._read(JWKS_PATH)
        if status != 200 or not isinstance(body, dict):
            raise JwksUnavailable(f"jwks status {status}")
        return jwt.PyJWKSet.from_dict(body)

    def signing_key(self, kid: str | None) -> jwt.PyJWK | None:
        """Key for ``kid``; fetches JWKS when the kid is unknown (first use, key rotation).

        At most one attempt per :data:`MIN_REFRESH_SECONDS`, counted from the attempt rather than a
        success, so failures are throttled too. The lock only guards the cache; the fetch runs outside
        it, so a hanging Vault never blocks verification of tokens whose key is already cached.
        """
        if not kid:
            return None
        with self._lock:
            key = self._find(kid)
            now = self._clock()
            if key is not None or now - self._attempted_at < MIN_REFRESH_SECONDS:
                return key
            self._attempted_at = now
        jwks = self._fetch_jwks()
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
        """Synchronous core of :meth:`verify_token` (blocking socket I/O on a JWKS refetch)."""
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in ALGORITHMS:
                raise jwt.InvalidAlgorithmError("unexpected alg")
            key = self.signing_key(header.get("kid"))
            if key is None:
                raise jwt.InvalidKeyError("unknown kid")
            claims = jwt.decode(
                token,
                key.key,
                algorithms=ALGORITHMS,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, JwksUnavailable, OSError) as exc:
            log_event(log, logging.WARNING, "token_rejected", reason=type(exc).__name__)
            return None
        tools = tools_for_groups(claims.get("groups"), self.group_tools)
        who = f"{claims.get('environment')}/{claims.get('application_name')}"
        if not tools:
            log_event(log, logging.WARNING, "token_rejected", reason="no_allowed_group", sub=claims.get("sub"), client=who, groups=claims.get("groups"))
            return None
        log_event(log, logging.INFO, "token_accepted", sub=claims.get("sub"), client=who, groups=claims.get("groups"), tools=sorted(tools))
        return AccessToken(
            token=token,
            client_id=who,
            scopes=sorted(tools),
            expires_at=int(claims["exp"]),
            resource=self.audience,
            subject=claims["sub"],
            claims=claims,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        return await anyio.to_thread.run_sync(self.verify, token)


def require(tool: str) -> AccessToken:
    """First line of every tool: the caller's Vault group must allow ``tool``."""
    token = get_access_token()
    if token is None or tool not in token.scopes:
        log_event(log, logging.WARNING, "tool_denied", tool=tool, client=token.client_id if token else None)
        raise ToolError(f"permission denied: {tool} is not permitted for this client")
    return token
