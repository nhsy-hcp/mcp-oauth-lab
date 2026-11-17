"""Read-only order queries. Fixed, parameterised SQL only; the DB grant is SELECT on orders.items alone."""

from __future__ import annotations

from typing import Any, Protocol

MAX_ROWS = 50
COLUMNS = "id, customer, status, total_pence"


class QueryRunner(Protocol):
    def run_query(self, fn: Any) -> Any: ...

    def whoami(self) -> dict[str, Any]: ...


def clamp_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_ROWS))


def _rows(sql: str, params: list[Any]):
    def fetch(conn: Any) -> list[dict[str, Any]]:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [c.name for c in cur.description]
            return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    return fetch


def list_orders(creds: QueryRunner, status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    sql = f"SELECT {COLUMNS} FROM orders.items"  # noqa: S608 - constant column list, values are parameters
    params: list[Any] = []
    if status:
        sql += " WHERE status = %s"
        params.append(status)
    sql += " ORDER BY id LIMIT %s"
    params.append(clamp_limit(limit))
    return creds.run_query(_rows(sql, params))


def get_order(creds: QueryRunner, order_id: int) -> dict[str, Any] | None:
    sql = f"SELECT {COLUMNS} FROM orders.items WHERE id = %s"  # noqa: S608 - constant column list
    rows = creds.run_query(_rows(sql, [int(order_id)]))
    return rows[0] if rows else None


def whoami(creds: QueryRunner) -> dict[str, Any]:
    """Database user and lease info for this server's own credentials. Never the password."""
    info = creds.whoami()
    return {k: v for k, v in info.items() if k != "password"}
