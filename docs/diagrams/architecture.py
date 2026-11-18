"""High-level view of the lab's components on k3d; the flows are in the other diagrams."""

from common import (
    BLUE,
    BLUE_FILL,
    GREY,
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

# Three rows: clients, identity services, then the server and its data
with diagram("architecture", direction="TB", nodesep="0.8", ranksep="0.9"):
    with group("k3d cluster", GREY, "white"):
        with client_ns("mcp-client-* namespaces"):
            agent = icon(Pod, "orders-agent", "all tool scopes")
            reporter = icon(Pod, "reporting-agent", "orders:list")
            unlisted = icon(Pod, "unlisted", "no OAuth client")
        with group("identity", BLUE, BLUE_FILL):
            auth = icon(Pod, "Better Auth", "OAuth server\nlocalhost:3000")
            dex = icon(Pod, "Dex", "static users and groups\ndex.localhost:5556")
        with server_ns("mcp-server-dev"):
            server = icon(Pod, "orders MCP server", "HTTP :8080/mcp\nNodePort 30800")
        with vault_ns("vault"):
            vault = icon(Vault, "HashiCorp Vault", "auth/kubernetes\ndatabase/")
        with data_ns():
            pg = icon(PostgreSQL, "PostgreSQL", "databases dev and auth")

    same_rank(agent, reporter, unlisted)
    same_rank(auth, dex)
    same_rank(server, vault, pg)

    # Invisible edges only set the layout
    hidden(reporter, auth)
    hidden(agent, auth, weight="0")
    hidden(unlisted, dex, weight="0")
    hidden(auth, server)
    hidden(dex, vault)
    hidden(server, vault, weight="0")
    hidden(vault, pg)
