"""A person signs in: the MCP client, Better Auth, Dex and the MCP server."""

from common import (
    BLUE,
    BLUE_FILL,
    box,
    deliver,
    diagram,
    group,
    icon,
    laptop,
    note,
    ref,
    same_rank,
    server_ns,
    step,
)
from diagrams.k8s.compute import Pod
from diagrams.onprem.client import User

with diagram("human-login", direction="LR", nodesep="1.0", ranksep="1.8"):
    with laptop("Laptop"):
        you = User(label="")
    with group("localhost:3000", BLUE, BLUE_FILL):
        auth = box("Better Auth", "authorization server\nnarrows scopes by group")
    with group("dex.localhost:5556", BLUE, BLUE_FILL):
        dex = box("Dex", "static users and groups")
    with server_ns("MCP server · localhost:8000"):
        mcp = icon(Pod, "orders MCP server")

    you >> step(1, "call without a token: 401 + metadata") >> mcp
    you >> step(2, "authorize, PKCE") >> auth
    auth >> step(3, "sign in") >> dex
    dex >> deliver(4, "ID token with groups") >> auth
    auth >> deliver(5, "access token after consent") >> you
    you >> deliver(6, "Bearer token") >> mcp
    mcp >> ref("JWKS") >> auth
    same_rank(auth, mcp)
    (
        note("Every token issue and refresh<br/>re-checks the user's groups.")
        >> ref()
        >> auth
    )
