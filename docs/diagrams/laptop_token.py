"""task mcp:token: the laptop gets a 5-minute MCP token without any long-lived credential."""

from common import (
    box,
    deliver,
    diagram,
    icon,
    laptop,
    note,
    ref,
    server_ns,
    step,
    vault_ns,
)
from diagrams.k8s.compute import Pod
from diagrams.k8s.controlplane import APIServer
from diagrams.onprem.client import User
from diagrams.onprem.security import Vault

with diagram("laptop-token", direction="LR"):
    with laptop("Laptop"):
        you = icon(User, "scripts/mcp-token.sh", "or .mcp.json headersHelper")
    api = icon(
        APIServer,
        "k3s API server",
        "kubectl create token\nmcp-client-laptop-sa · aud vault · 10m",
    )
    with vault_ns("Vault CE · localhost:8200"):
        login = box("auth/kubernetes/login", "role mcp-client")
        mint = box("identity/oidc/token/mcp-orders", "5-min JWT")
        revoke = box("auth/token/revoke-self", "Vault token gone at once")
        vault = icon(Vault, "Vault CE")
    with server_ns("MCP server · 127.0.0.1:8000"):
        mcp = icon(Pod, "orders MCP server")

    you >> step(1, "SA token") >> api
    you >> step(2, "login (JWT on stdin)") >> login
    you >> step(3, "mint") >> mint
    you >> step(4) >> revoke
    you >> deliver(5, "Bearer JWT") >> mcp
    (
        note("Root token from .env is never used.<br/>Only the JWT reaches stdout.")
        >> ref()
        >> you
    )
    vault >> ref() >> login
