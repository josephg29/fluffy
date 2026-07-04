from __future__ import annotations

import contextlib
import json
import sqlite3

from conftest import grant_access
from fluffy import Guard, ToolMeta
from fluffy.audit import audit_tail, write_audit_row
from fluffy.secrets import MemorySecretStore


def test_writer_redacts_unconditionally(
    conn: sqlite3.Connection, registered_store: MemorySecretStore
) -> None:
    """It is structurally impossible to write an unredacted audit row."""
    registered_store.put("pw", "very-hidden-value")
    write_audit_row(
        conn,
        call_id="c1",
        tool="t",
        event="call",
        decision="ok",
        detail={"note": "password is very-hidden-value and card 4242 4242 4242 4242"},
    )
    row = audit_tail(conn, 1)[0]
    assert "very-hidden-value" not in row["detail_json"]
    assert "{{secret:pw}}" in row["detail_json"]
    assert "4242 4242 4242 4242" not in row["detail_json"]


def test_audit_tail_returns_last_n_oldest_first(conn: sqlite3.Connection) -> None:
    for i in range(5):
        write_audit_row(
            conn, call_id=f"c{i}", tool="t", event="call", decision="ok", detail={"i": i}
        )
    rows = audit_tail(conn, 3)
    assert [row["call_id"] for row in rows] == ["c2", "c3", "c4"]


def test_blocked_error_audited_as_blocked(guard: Guard) -> None:
    from fluffy.exceptions import Blocked

    def denied() -> None:
        raise Blocked("Blocked: nope.", reason="test")

    grant_access(guard, "t.denied")
    wrapped = guard.wrap(denied, meta=ToolMeta(name="t.denied", tags={"restricted"}))
    with contextlib.suppress(Blocked):
        wrapped()
    rows = guard.audit_tail(1)
    assert rows[0]["decision"] == "blocked"
    detail = json.loads(rows[0]["detail_json"])
    assert "nope" in detail["error"]
