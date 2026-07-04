"""Audit trail (decisions D3/D4).

The writer applies :func:`fluffy.redact` to the detail JSON unconditionally —
it is structurally impossible to write an unredacted audit row.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .context import CallContext
from .db import utc_now_iso
from .exceptions import Blocked
from .redact import redact

__all__ = ["AuditInterceptor", "audit_grep", "audit_tail", "write_audit_row"]


def write_audit_row(
    conn: sqlite3.Connection,
    *,
    call_id: str,
    tool: str,
    event: str,
    decision: str,
    detail: dict[str, Any],
) -> None:
    """Insert one audit row. Detail JSON is redacted here, never by callers.

    Executes only — transaction control belongs to the caller, so audit events
    emitted inside a larger transaction (e.g. the spend ledger's
    ``BEGIN IMMEDIATE``) stay atomic with it.
    """
    detail_json = redact(json.dumps(detail, default=repr, sort_keys=True))
    conn.execute(
        "INSERT INTO audit_log (call_id, ts, tool, event, decision, detail_json)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (call_id, utc_now_iso(), tool, event, decision, detail_json),
    )


def audit_tail(conn: sqlite3.Connection, n: int = 20) -> list[sqlite3.Row]:
    """The last ``n`` audit rows, oldest first."""
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(n),)).fetchall()
    rows.reverse()
    return rows


def audit_grep(conn: sqlite3.Connection, term: str, limit: int = 200) -> list[sqlite3.Row]:
    """Case-insensitive substring match over every text column, oldest first."""
    like = f"%{term}%"
    rows = conn.execute(
        "SELECT * FROM audit_log"
        " WHERE tool LIKE ? OR event LIKE ? OR decision LIKE ?"
        " OR call_id LIKE ? OR detail_json LIKE ?"
        " ORDER BY id DESC LIMIT ?",
        (like, like, like, like, like, int(limit)),
    ).fetchall()
    rows.reverse()
    return rows


class AuditInterceptor:
    """Writes one audit row per guarded call after execution.

    The pipeline only routes calls with guard tags through this interceptor
    (D8 fast path — see :data:`fluffy.guard.GUARD_TAGS`), so no tag check is
    re-implemented here. This interceptor owns the commit; the writer only
    executes.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def before(self, ctx: CallContext) -> None:
        return None

    def after(self, ctx: CallContext) -> None:
        if ctx.error is None:
            decision = "ok"
        elif isinstance(ctx.error, Blocked):
            decision = "blocked"
        else:
            decision = "error"
        detail: dict[str, Any] = {
            "args": list(ctx.args),
            "kwargs": ctx.kwargs,
            "started_at": ctx.started_at,
            "ended_at": ctx.ended_at,
        }
        if ctx.error is None:
            detail["result"] = ctx.result
        else:
            detail["error"] = f"{type(ctx.error).__name__}: {ctx.error}"
        if ctx.decisions:
            detail["decisions"] = [
                {"approved": d.approved, "decider": d.decider, "message": d.message}
                for d in ctx.decisions
            ]
        write_audit_row(
            self._conn,
            call_id=ctx.call_id,
            tool=ctx.tool.name,
            event="call",
            decision=decision,
            detail=detail,
        )
        self._conn.commit()
