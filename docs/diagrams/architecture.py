"""High-level view: HashiCorp Vault as identity broker between MCP clients and the orders MCP server on k3d."""

from common import (
    GREY,
    box,
    client_ns,
    data_ns,
    deliver,
    diagram,
    group,
    icon,
    laptop,
    ref,
    same_rank,
    server_ns,
    step,
    vault_ns,
)
from diagrams.k8s.compute import Pod
from diagrams.onprem.client import User
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.security import Vault

# Grid (LR): clients (laptop + client pods) · MCP server · Vault + PostgreSQL
with diagram("architecture", direction="LR"):
    with laptop("Laptop"):
        you = icon(User, "Claude Code / Inspector", "task mcp:token")

    with group("k3d cluster vault-mcp-lab", GREY, "white"):
        with client_ns("mcp-client-* namespaces"):
            agent = icon(Pod, "orders-agent", "group mcp-orders-reader")
            reporter = icon(Pod, "reporting-agent", "group mcp-orders-reporter")
            unlisted = icon(Pod, "unlisted", "no group → 401")
        with server_ns("mcp-server-orders-preview"):
            server = icon(
                Pod, "orders MCP server", "Streamable HTTP :8080/mcp\nNodePort 30800"
            )
        with vault_ns():
            vault = icon(
                Vault,
                "HashiCorp Vault 2.2.2",
                "auth/kubernetes · identity/oidc\ndatabase/",
            )
            groups = box("identity groups", "who may call which tools")
        with data_ns():
            pg = icon(PostgreSQL, "PostgreSQL", "preview.orders.items")

    same_rank(agent, reporter, unlisted)
    same_rank(vault, pg)

    you >> step(1, "SA token → Vault login → 5-min JWT") >> vault
    agent >> step(1, "Proxy: K8s login, mint JWT") >> vault
    you >> deliver(2, "127.0.0.1:8000 · Bearer JWT") >> server
    agent >> deliver(2, "Bearer JWT") >> server
    reporter >> deliver(2) >> server
    unlisted >> deliver(2) >> server
    server >> ref("JWKS via own Proxy") >> vault
    server >> step(3, "Proxy: database/creds/preview-orders") >> vault
    server >> deliver(4, "10-min SELECT-only user") >> pg
    groups >> ref("groups claim") >> vault
