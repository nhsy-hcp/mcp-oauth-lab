"""Server side: the MCP server's own short-lived, least-privileged PostgreSQL user via its Vault Proxy sidecar."""

from common import (
    box,
    data_ns,
    deliver,
    diagram,
    exchange,
    icon,
    note,
    ref,
    same_rank,
    server_ns,
    step,
    vault_ns,
)
from diagrams.k8s.compute import Pod
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.security import Vault

with diagram("dynamic-db", direction="LR"):
    with server_ns("mcp-server-orders-preview"):
        sa = box("projected SA token", "aud=vault · Proxy container only")
        proxy = box(
            "vault-proxy sidecar",
            "UNIX socket · force auto-auth token\ncaches and renews the lease",
        )
        app = icon(Pod, "orders MCP server")
    with vault_ns():
        role = box(
            "auth/kubernetes/role/mcp-server",
            "policy: read database/creds/&lt;env&gt;-&lt;app&gt;",
        )
        creds = box("database/creds/preview-orders", "10m default · 30m max")
        vault = icon(Vault, "HashiCorp Vault")
    with data_ns():
        pg = icon(
            PostgreSQL,
            "PostgreSQL preview",
            "orders.items: SELECT\npayments.*: no grant",
        )

    same_rank(sa, proxy, app)
    same_rank(role, creds)

    sa >> step(1, "login", external=True) >> proxy >> step(2) >> role
    (
        app
        >> exchange(
            (3, "GET /v1/database/creds/... over socket"),
            (5, "username + password (memory only)"),
        )
        >> proxy
        >> step(4)
        >> creds
    )
    (
        creds
        >> ref("CREATE ROLE v-... IN ROLE preview_orders_ro<br/>VALID UNTIL expiry")
        >> pg
    )
    app >> deliver(6, "fixed, parameterised SELECTs") >> pg
    (
        note(
            "SIGTERM: close pool, then revoke-self<br/>→ user dropped at once, not at max_ttl"
        )
        >> ref()
        >> app
    )
    vault >> ref() >> creds
