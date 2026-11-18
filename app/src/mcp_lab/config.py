"""Configuration from environment variables. Every setting is non-secret."""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_SOCKET = "/run/vault/proxy.sock"
DEFAULT_ISSUER = "http://localhost:3000/api/auth"
DEFAULT_RESOURCE = "http://localhost:8000/mcp"
DEFAULT_SERVICE_ACCOUNT_TOKEN = "/var/run/secrets/tokens/token"  # noqa: S105 - a file path, not a secret


class ConfigError(ValueError):
    pass


def _positive_seconds(env: Mapping[str, str], name: str, default: str) -> float:
    """An interval: 0, negative or NaN would make a loop poll without pausing."""
    value = float(env.get(name, default))
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{name} must be a positive number of seconds")
    return value


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class ServerConfig:
    """The orders MCP server: dynamic DB credentials via Proxy, OAuth access tokens for callers."""

    vault_socket: str
    db_creds_path: str
    db_host: str
    db_name: str
    db_port: int
    issuer: str
    jwks_url: str
    resource_url: str
    allowed_hosts: tuple[str, ...]
    log_level: str
    port: int
    creds_refresh_max_seconds: float = 60.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServerConfig:
        env = os.environ if env is None else env
        try:
            issuer = env.get("MCP_ISSUER", DEFAULT_ISSUER).strip().rstrip("/")
            return cls(
                vault_socket=env.get("VAULT_SOCKET", DEFAULT_SOCKET),
                db_creds_path=_required(env, "DB_CREDS_PATH").strip("/"),
                db_host=_required(env, "DB_HOST"),
                db_name=_required(env, "DB_NAME"),
                db_port=int(env.get("DB_PORT", "5432")),
                issuer=issuer,
                jwks_url=env.get("MCP_JWKS_URL", f"{issuer}/jwks").strip(),
                resource_url=env.get("MCP_RESOURCE_URL", DEFAULT_RESOURCE).strip(),
                allowed_hosts=_csv(env.get("MCP_ALLOWED_HOSTS", "localhost:8000,127.0.0.1:8000")),
                log_level=env.get("LOG_LEVEL", "INFO").strip().upper() or "INFO",
                port=int(env.get("PORT", "8080")),
                creds_refresh_max_seconds=_positive_seconds(env, "CREDS_REFRESH_MAX_SECONDS", "60"),
            )
        except ValueError as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(str(exc)) from exc


@dataclass(frozen=True)
class ClientConfig:
    """An MCP client pod: logs in to Better Auth with its ServiceAccount JWT and calls the server."""

    mcp_url: str
    token_url: str
    resource: str
    scopes: tuple[str, ...]
    service_account_token: str
    tools: tuple[str, ...]
    interval_seconds: float
    log_level: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ClientConfig:
        env = os.environ if env is None else env
        try:
            return cls(
                mcp_url=_required(env, "MCP_URL"),
                token_url=_required(env, "MCP_TOKEN_URL"),
                resource=env.get("MCP_RESOURCE_URL", DEFAULT_RESOURCE).strip(),
                scopes=tuple(env.get("CLIENT_SCOPES", "").split()),
                service_account_token=env.get("SERVICE_ACCOUNT_TOKEN_FILE", DEFAULT_SERVICE_ACCOUNT_TOKEN).strip(),
                tools=_csv(env.get("CLIENT_TOOLS", "list_orders,get_order,whoami")),
                interval_seconds=_positive_seconds(env, "CLIENT_INTERVAL_SECONDS", "30"),
                log_level=env.get("LOG_LEVEL", "INFO").strip().upper() or "INFO",
            )
        except ValueError as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(str(exc)) from exc
