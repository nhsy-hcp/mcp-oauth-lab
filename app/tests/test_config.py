from __future__ import annotations

import pytest

from mcp_lab.config import DEFAULT_AUDIENCE, DEFAULT_ISSUER, ClientConfig, ConfigError, ServerConfig

SERVER_ENV = {"DB_CREDS_PATH": "/database/creds/dev-orders/", "DB_HOST": "pg", "DB_NAME": "dev"}


def test_server_defaults():
    c = ServerConfig.from_env(SERVER_ENV)
    assert c.db_creds_path == "database/creds/dev-orders"
    assert c.issuer == DEFAULT_ISSUER
    assert c.audience == DEFAULT_AUDIENCE
    assert c.allowed_hosts == ("localhost:8000", "127.0.0.1:8000")


def test_server_requires_db_settings():
    with pytest.raises(ConfigError, match="DB_HOST"):
        ServerConfig.from_env({"DB_CREDS_PATH": "x", "DB_NAME": "y"})


def test_client_tools_and_interval():
    c = ClientConfig.from_env({"MCP_URL": "http://mcp/mcp", "CLIENT_TOOLS": " list_orders , ,get_order", "CLIENT_INTERVAL_SECONDS": "5"})
    assert c.tools == ("list_orders", "get_order")
    assert c.interval_seconds == 5


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "abc"])
def test_client_interval_must_be_positive(value):
    with pytest.raises(ConfigError):
        ClientConfig.from_env({"MCP_URL": "http://mcp/mcp", "CLIENT_INTERVAL_SECONDS": value})
