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
        you = icon(User, "scripts/<br/>mcp-token.sh", "or .mcp.json\nheadersHelper")
    api = icon(
        APIServer,
        "k3s API server",
        "kubectl create token\nmcp-client-laptop-sa · aud vault · 10m",
    )
    with vault_ns("HashiCorp Vault · localhost:8200"):
        login = box("auth/kubernetes/login", "role mcp-client")
        mint = box("identity/oidc/token/mcp-orders", "5-min JWT")
        revoke = box("auth/token/revoke-self", "Vault token gone at once")
        vault = icon(Vault, "HashiCorp Vault")
    with server_ns("MCP server · 127.0.0.1:8000"):
        mcp = icon(Pod, "orders MCP server")

    # tailport: start every edge at the icon, not at the top of the padded node
    you >> step(1, "SA token", tailport="e") >> api
    you >> step(2, "login (JWT on stdin)", tailport="e") >> login
    you >> step(3, "mint", tailport="e") >> mint
    you >> step(4, tailport="e") >> revoke
    you >> deliver(5, "Bearer JWT", tailport="e") >> mcp
    (
        note("Root token from .env is never used.<br/>Only the JWT reaches stdout.")
        >> ref()
        >> you
    )
    vault >> ref() >> login
