"""Verify Vault identity JWTs on the MCP server and authorise tools by Vault identity group.

Vault is the identity broker: a client logs in with its Kubernetes ServiceAccount, reads
``identity/oidc/token/<role>`` and sends the JWT as a bearer token. This module checks it:

* signature against Vault's JWKS (``identity/oidc/.well-known/keys``), read through the server's own
  Vault Proxy socket - so the MCP pod needs no network path to Vault and holds no Vault credential;
* ``RS256`` only, ``iss``, ``aud``, ``exp`` and ``iat`` required;
* the ``groups`` claim (from ``{{identity.entity.groups.names}}``) mapped through :data:`GROUP_TOOLS`.

Who is in a group is decided in Vault (``identity/group``); what a group may call is this versioned
map. ServiceAccount annotations only feed informational claims and never grant a tool. A token
with no known group fails closed (401). The token itself is never logged or forwarded.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Mapping
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
# Vault group -> tools it may call. Membership lives in Vault; the tool set is reviewed in code.
GROUP_TOOLS: Mapping[str, frozenset[str]] = {
    "mcp-orders-reader": frozenset({"list_orders", "get_order", "whoami"}),
    "mcp-orders-reporter": frozenset({"list_orders"}),
}
# Never fetch JWKS more often than this, whether the last attempt worked or not: a stream of forged kids,
# or Vault being down, must not hammer Vault or queue requests behind a slow fetch.
MIN_REFRESH_SECONDS = 10.0

# (status, headers, json body) - the shape of VaultClient.read
VaultRead = Callable[[str], tuple[int, Any, Any]]


class JwksUnavailable(Exception):
    pass


def tools_for_groups(groups: Any, group_tools: Mapping[str, frozenset[str]] = GROUP_TOOLS) -> frozenset[str]:
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
        group_tools: Mapping[str, frozenset[str]] = GROUP_TOOLS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._read = vault_read
        self.issuer = issuer
        self.audience = audience
        self.group_tools = group_tools
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
