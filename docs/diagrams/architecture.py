"""High-level view of the lab's components on k3d; the flows are in the other diagrams."""

from common import (
    GREY,
    box,
    client_ns,
    data_ns,
    diagram,
    group,
    hidden,
    icon,
    same_rank,
    server_ns,
    vault_ns,
)
from diagrams.k8s.compute import Pod
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.security import Vault

# Two rows: client pods above the MCP server, Vault and PostgreSQL
with diagram("architecture", direction="TB", nodesep="0.8", ranksep="0.9"):
    with group("k3d cluster", GREY, "white"):
        with client_ns("mcp-client-* namespaces"):
            agent = icon(Pod, "orders-agent", "group mcp-orders-reader")
            reporter = icon(Pod, "reporting-agent", "group mcp-orders-reporter")
            unlisted = icon(Pod, "unlisted", "no group: 401")
        with server_ns("mcp-server-orders-preview"):
            server = icon(Pod, "orders MCP server", "HTTP :8080/mcp\nNodePort 30800")
        with vault_ns("vault"):
            vault = icon(
                Vault,
                "HashiCorp Vault",
                "auth/kubernetes\nidentity/oidc · database/",
            )
            groups = box("identity groups", "who may call which tools")
        with data_ns():
            # Two detail lines, like its neighbours, so the row's boxes are the same height
            pg = icon(PostgreSQL, "PostgreSQL", "database preview\ntable orders.items")

    same_rank(agent, reporter, unlisted)
    same_rank(server, groups, vault, pg)

    # Invisible edges only set the layout
    # weight 0 keeps the order without pulling an icon off centre in its box
    hidden(agent, server, weight="0")
    hidden(reporter, vault)
    hidden(reporter, groups)
    hidden(unlisted, pg, weight="0")
    hidden(server, vault, weight="0")
    hidden(vault, groups)
    hidden(groups, pg)
