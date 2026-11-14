from __future__ import annotations

import sqlite3
import time
from collections import defaultdict, deque
from typing import Iterator

from fastapi import Depends, HTTPException, Query, Request

from riskpatch import auth
from riskpatch.auth import Principal
from riskpatch.db import connect


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    conn = connect(request.app.state.settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


def bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def principal_from(request: Request, conn: sqlite3.Connection, cookie: bool = False) -> Principal | None:
    """The API only trusts the Authorization header; the web UI only trusts its account session cookie."""
    if cookie:
        return auth.authenticate_session(conn, request.cookies.get("rp_session", ""))
    who = auth.authenticate(conn, bearer(request))
    if who:
        auth.touch(conn, who.token_id)
    return who


def require(scope: str):
    def dep(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> Principal:
        who = principal_from(request, conn)
        if who is None:
            raise HTTPException(401, "token invalid or missing", headers={"WWW-Authenticate": "Bearer"})
        if not who.has(scope):
            raise HTTPException(403, f"scope '{scope}' required")
        return who

    return dep


class ListParams:
    def __init__(
        self,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        sort: str | None = Query(None, description="nama kolom; lihat enum di tiap endpoint"),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        updated_since: str | None = Query(None, description="ISO-8601, mis. 2026-10-26T00:00:00Z"),
    ):
        self.limit, self.offset, self.sort, self.order, self.updated_since = limit, offset, sort, order, updated_since


def listing(conn: sqlite3.Connection, select: str, frm: str, where: list[str], params: list, sort_cols: dict[str, str], default_sort: str,
            lp: ListParams, tiebreak: str, updated_col: str | None = None) -> tuple[list[sqlite3.Row], int]:
    if lp.updated_since:
        if not updated_col:
            raise HTTPException(400, "updated_since not supported on this endpoint")
        where = where + [f"{updated_col} >= ?"]
        params = params + [lp.updated_since]
    column = sort_cols.get(lp.sort or default_sort)
    if column is None:
        raise HTTPException(400, f"sort must be one of {sorted(sort_cols)}")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM {frm}{clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT {select} FROM {frm}{clause} ORDER BY {column} {lp.order}, {tiebreak} {lp.order} LIMIT ? OFFSET ?",
        params + [lp.limit, lp.offset],
    ).fetchall()
    return rows, total


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        if len(self.hits) > 10000:  # bound memory
            self.hits = defaultdict(deque, {k: v for k, v in self.hits.items() if v and now - v[-1] < 60})
        return True
