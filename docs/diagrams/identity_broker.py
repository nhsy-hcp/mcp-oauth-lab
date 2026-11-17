"""Token flow: a client pod proves its Kubernetes identity to Vault and calls the MCP server with a Vault-signed JWT."""

from common import (
    box,
    client_ns,
    deliver,
    diagram,
    icon,
    note,
    ref,
    same_rank,
    server_ns,
    step,
    vault_ns,
)
from diagrams.k8s.compute import Pod
from diagrams.k8s.controlplane import APIServer
from diagrams.onprem.security import Vault

with diagram("identity-broker", direction="LR", nodesep="1.0", ranksep="1.6"):
    with client_ns("mcp-client-orders-agent"):
        sa = box("projected SA token", "aud=vault · 10 min · Proxy only")
        proxy_c = box("vault-proxy sidecar", "role mcp-client · token in memory")
        app_c = icon(Pod, "client app", "VaultIdentityAuth")
    api = icon(APIServer, "k3s API server", "TokenReview + SA annotations")
    with vault_ns():
        auth = box(
            "auth/kubernetes/role/mcp-client",
            "policy mcp-client: read identity/oidc/token/mcp-orders only",
        )
        grp = box("identity/group mcp-orders-reader", "member: orders-agent entity")
        oidc = box(
            "identity/oidc/role/mcp-orders", "key mcp (RS256) · aud mcp-orders · ttl 5m"
        )
        jwks = box("identity/oidc/.well-known/keys", "public JWKS (unauthenticated)")
        vault = icon(Vault, "Vault CE")
    with server_ns("mcp-server-orders-preview"):
        mcp = icon(Pod, "orders MCP server", "VaultJwtVerifier")
        proxy_s = box("vault-proxy sidecar", "role mcp-server")
        tools = box("tool check", "groups → {list_orders, get_order, whoami}")

    same_rank(sa, proxy_c, app_c)
    same_rank(auth, grp, oidc, jwks)

    sa >> step(1, "login") >> proxy_c
    proxy_c >> step(2, "K8s login") >> auth
    auth >> ref("TokenReview") >> api
    app_c >> step(3, "read token over socket") >> proxy_c
    proxy_c >> step(4) >> oidc
    grp >> ref("groups claim") >> oidc
    oidc >> deliver(5, "JWT: iss, aud, exp, sub, groups") >> app_c
    app_c >> deliver(6, "Authorization: Bearer") >> mcp
    mcp >> step(7, "JWKS (cached, refetch on new kid)") >> proxy_s >> jwks
    mcp >> step(8, "verify sig, iss, aud, exp → allowed tools") >> tools
    (
        note(
            "No shared secret, nothing long-lived.<br/>Revoke = remove from the Vault group."
        )
        >> ref()
        >> grp
    )
    vault >> ref() >> oidc
