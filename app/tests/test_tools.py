"""Tool SQL: fixed statements, parameters only, row cap."""

from __future__ import annotations

from mcp_lab import tools


def test_list_orders_parameterised(creds):
    rows = tools.list_orders(creds, "pending", 5)
    sql, params = creds.queries[-1]
    assert sql == "SELECT id, customer, status, total_pence FROM orders.items WHERE status = %s ORDER BY id LIMIT %s"
    assert params == ["pending", 5]
    assert rows[0] == {"id": 1, "customer": "acme-ltd", "status": "pending", "total_pence": 4200}


def test_list_orders_without_status(creds):
    tools.list_orders(creds)
    sql, params = creds.queries[-1]
    assert "WHERE" not in sql
    assert params == [20]


def test_injection_stays_a_parameter(creds):
    tools.list_orders(creds, "x' OR 1=1; DROP TABLE orders.items; --")
    sql, params = creds.queries[-1]
    assert "DROP" not in sql
    assert params[0].startswith("x' OR 1=1")


def test_limit_clamped():
    assert tools.clamp_limit(0) == 1
    assert tools.clamp_limit(-5) == 1
    assert tools.clamp_limit(10_000) == tools.MAX_ROWS


def test_get_order(creds):
    assert tools.get_order(creds, 1)["customer"] == "acme-ltd"
    assert creds.queries[-1][1] == [1]
    creds.rows = []
    assert tools.get_order(creds, 99) is None


def test_whoami_never_returns_password(creds):
    creds.whoami = lambda: {"current_user": "v-x", "password": "hunter2"}
    assert tools.whoami(creds) == {"current_user": "v-x"}
