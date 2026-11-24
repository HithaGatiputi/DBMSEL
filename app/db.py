"""PostgreSQL access: a read/write pool for the application and a
separate pool bound to the read-only role used by the AI layer."""
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import config

_pools: dict[str, ConnectionPool] = {}


def pool(kind: str = "app") -> ConnectionPool:
    if kind not in _pools:
        dsn = config.DSN_APP if kind == "app" else config.DSN_RO
        _pools[kind] = ConnectionPool(dsn, min_size=1, max_size=8, open=True,
                                      kwargs={"row_factory": dict_row})
    return _pools[kind]


@contextmanager
def conn(kind: str = "app"):
    with pool(kind).connection() as c:
        yield c


def query(sql: str, params: Any = None, kind: str = "app") -> list[dict]:
    with conn(kind) as c, c.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall() if cur.description else []
        c.commit()
        return rows


def one(sql: str, params: Any = None, kind: str = "app") -> dict | None:
    rows = query(sql, params, kind)
    return rows[0] if rows else None


def direct(dsn: str | None = None) -> psycopg.Connection:
    """Standalone connection (CLI jobs, seeding)."""
    return psycopg.connect(dsn or config.DSN_APP, row_factory=dict_row)
