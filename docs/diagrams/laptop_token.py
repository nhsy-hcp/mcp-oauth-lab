"""task mcp:token: the laptop uses the operator's kubeconfig to get a 5-minute MCP token."""

from common import (
    box,
    deliver,
    diagram,
    icon,
    laptop,
    note,
    ref,
    same_rank,
    server_ns,
    step,
    vault_ns,
)
from diagrams.k8s.compute import Pod
from diagrams.k8s.controlplane import APIServer
from diagrams.onprem.client import User
from diagrams.onprem.security import Vault

with diagram("laptop-token", direction="LR"):
    # The label is in the group title: an unlabelled icon keeps the node small, so edges start at the icon
    with laptop("Laptop · mcp-token.sh"):
        you = User(label="")
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

    you >> step(1, "SA token") >> api
    # Vault's icon shares the boxes' column, so edges 2-4 reach them without bending around it
    same_rank(vault, login, mint, revoke)
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
